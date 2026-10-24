//! The daemon on a private bus (a `dbus-daemon` started for each test), with
//! the emulated sensor, a test polkit authority and a fake logind, driven by
//! zbus clients the way fprintd's clients drive fprintd.
//!
//! Needs `dbus-daemon` on the PATH (Debian: dbus-daemon; Fedora/Arch: dbus;
//! Alpine: dbus). A missing binary fails the test: it is a requirement, not
//! something to skip.

use std::collections::{BTreeSet, HashMap};
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use validity_daemon::fake::{FakeSensor, Touch, blobs};
use validity_daemon::polkit::{Authority, Check, ENROLL, SETUSERNAME, VERIFY};
use validity_daemon::service::{self, Bus, Deps, Options, Setup};
use validity_daemon::users::{SidMap, User, UserDb, sid_for_uid};
use validity_daemon::worker::Timing;
use zbus::Connection;

// ---------------------------------------------------------------- the bus

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "validity-daemon-test-{}-{tag}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A private `dbus-daemon`, killed on drop.
struct PrivateBus {
    child: Child,
    address: String,
    _dir: TempDir,
}

impl PrivateBus {
    fn start() -> Self {
        let dir = TempDir::new("bus");
        let config = dir.0.join("bus.conf");
        std::fs::write(
            &config,
            format!(
                r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>validity-test</type>
  <listen>unix:path={}/socket</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#,
                dir.0.display()
            ),
        )
        .unwrap();
        let mut child = Command::new("dbus-daemon")
            .arg(format!("--config-file={}", config.display()))
            .arg("--nofork")
            .arg("--print-address=1")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("dbus-daemon must be installed to run these tests");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let address = line.trim().to_string();
        assert!(address.starts_with("unix:"), "dbus-daemon said {line:?}");
        PrivateBus {
            child,
            address,
            _dir: dir,
        }
    }
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ------------------------------------------------- polkit and accounts

/// Allows everything unless told otherwise; records what was asked.
#[derive(Default)]
struct TestAuthority {
    denied: Mutex<BTreeSet<&'static str>>,
    asked: Mutex<Vec<String>>,
}

impl TestAuthority {
    fn deny(&self, action: &'static str) {
        self.denied.lock().unwrap().insert(action);
    }
    fn allow(&self, action: &'static str) {
        self.denied.lock().unwrap().remove(action);
    }
    fn asked(&self) -> Vec<String> {
        std::mem::take(&mut *self.asked.lock().unwrap())
    }
}

impl Authority for TestAuthority {
    fn check<'a>(&'a self, _conn: &'a Connection, _sender: &'a str, action: &'a str) -> Check<'a> {
        Box::pin(async move {
            self.asked.lock().unwrap().push(action.to_string());
            Ok(!self.denied.lock().unwrap().contains(action))
        })
    }
}

/// The test process's uid is "alice"; "bob" is another account.
struct TestUsers {
    me: u32,
}

const BOB_UID: u32 = 4242;

impl UserDb for TestUsers {
    fn by_uid(&self, uid: u32) -> Option<User> {
        match uid {
            u if u == self.me => Some(User {
                name: "alice".into(),
                uid,
            }),
            BOB_UID => Some(User {
                name: "bob".into(),
                uid,
            }),
            _ => None,
        }
    }
    fn by_name(&self, name: &str) -> Option<User> {
        match name {
            "alice" => self.by_uid(self.me),
            "bob" => self.by_uid(BOB_UID),
            _ => None,
        }
    }
}

fn alice_sid() -> validity_proto::sid::Sid {
    sid_for_uid(nix::unistd::getuid().as_raw())
}

// ------------------------------------------------------------ fake logind

/// One flag per inhibitor handed out: set once the daemon closed it.
type Inhibitors = Arc<Mutex<Vec<Arc<std::sync::atomic::AtomicBool>>>>;

struct Logind {
    inhibitors: Inhibitors,
}

#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl Logind {
    fn inhibit(
        &self,
        what: &str,
        _who: &str,
        _why: &str,
        mode: &str,
    ) -> zbus::fdo::Result<zbus::OwnedFd> {
        assert_eq!((what, mode), ("sleep", "delay"));
        let (mut r, w) = std::io::pipe().map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.inhibitors.lock().unwrap().push(released.clone());
        // The read end sees EOF once every copy of the write end is closed:
        // ours goes with the reply, the daemon's when it lets go.
        std::thread::spawn(move || {
            let mut sink = Vec::new();
            if r.read_to_end(&mut sink).is_ok() {
                released.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
        Ok(zbus::OwnedFd::from(std::os::fd::OwnedFd::from(w)))
    }

    #[zbus(signal)]
    async fn prepare_for_sleep(
        emitter: &zbus::object_server::SignalEmitter<'_>,
        start: bool,
    ) -> zbus::Result<()>;
}

struct FakeLogind {
    conn: Connection,
    inhibitors: Inhibitors,
}

impl FakeLogind {
    async fn start(address: &str) -> Self {
        let inhibitors: Inhibitors = Arc::new(Mutex::new(Vec::new()));
        let conn = zbus::connection::Builder::address(address)
            .serve_at(
                "/org/freedesktop/login1",
                Logind {
                    inhibitors: inhibitors.clone(),
                },
            )
            .name("org.freedesktop.login1")
            .build()
            .await
            .unwrap();
        FakeLogind { conn, inhibitors }
    }

    async fn prepare_for_sleep(&self, start: bool) {
        let em =
            zbus::object_server::SignalEmitter::new(&self.conn, "/org/freedesktop/login1").unwrap();
        Logind::prepare_for_sleep(&em, start).await.unwrap();
    }

    fn inhibitors(&self) -> usize {
        self.inhibitors.lock().unwrap().len()
    }

    /// Whether the daemon closed inhibitor `i`.
    fn inhibitor_released(&self, i: usize) -> bool {
        self.inhibitors.lock().unwrap()[i].load(std::sync::atomic::Ordering::SeqCst)
    }
}

// ---------------------------------------------------------- the daemon

#[zbus::proxy(
    interface = "net.reactivated.Fprint.Manager",
    default_service = "net.reactivated.Fprint",
    default_path = "/net/reactivated/Fprint/Manager"
)]
trait Manager {
    fn get_devices(&self) -> zbus::Result<Vec<zbus::OwnedObjectPath>>;
    fn get_default_device(&self) -> zbus::Result<zbus::OwnedObjectPath>;
}

#[zbus::proxy(
    interface = "net.reactivated.Fprint.Device",
    default_service = "net.reactivated.Fprint",
    default_path = "/net/reactivated/Fprint/Device/0"
)]
trait Device {
    fn list_enrolled_fingers(&self, username: &str) -> zbus::Result<Vec<String>>;
    fn delete_enrolled_fingers(&self, username: &str) -> zbus::Result<()>;
    fn delete_enrolled_fingers2(&self) -> zbus::Result<()>;
    fn delete_enrolled_finger(&self, finger_name: &str) -> zbus::Result<()>;
    fn claim(&self, username: &str) -> zbus::Result<()>;
    fn release(&self) -> zbus::Result<()>;
    fn verify_start(&self, finger_name: &str) -> zbus::Result<()>;
    fn verify_stop(&self) -> zbus::Result<()>;
    fn enroll_start(&self, finger_name: &str) -> zbus::Result<()>;
    fn enroll_stop(&self) -> zbus::Result<()>;

    #[zbus(signal)]
    fn verify_finger_selected(&self, finger_name: String) -> zbus::Result<()>;
    #[zbus(signal)]
    fn verify_status(&self, result: String, done: bool) -> zbus::Result<()>;
    #[zbus(signal)]
    fn enroll_status(&self, result: String, done: bool) -> zbus::Result<()>;

    #[zbus(property, name = "name")]
    fn name(&self) -> zbus::Result<String>;
    #[zbus(property, name = "num-enroll-stages")]
    fn num_enroll_stages(&self) -> zbus::Result<i32>;
    #[zbus(property, name = "scan-type")]
    fn scan_type(&self) -> zbus::Result<String>;
    #[zbus(property, name = "finger-present")]
    fn finger_present(&self) -> zbus::Result<bool>;
    #[zbus(property, name = "finger-needed")]
    fn finger_needed(&self) -> zbus::Result<bool>;
}

fn fast_options() -> Options {
    Options {
        ready_timeout: Duration::from_secs(3),
        stop_timeout: Duration::from_secs(4),
        delete_timeout: Duration::from_secs(10),
        sleep_timeout: Duration::from_secs(4),
        timing: Timing {
            attempts: [0, 20, 40, 80, 160]
                .into_iter()
                .map(Duration::from_millis)
                .collect(),
            absent_first: Duration::from_millis(20),
            absent_max: Duration::from_millis(200),
            failed_cooldown: Duration::from_secs(1),
            max_capture_failures: 10,
            reappear: Duration::from_secs(1),
            reappear_poll: Duration::from_millis(20),
        },
    }
}

struct Daemon {
    stop: zruntime::mpmc::Sender<()>,
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
}

impl Daemon {
    fn start(
        address: &str,
        fake: &FakeSensor,
        authority: Arc<TestAuthority>,
        blobs_ok: bool,
        state: &TempDir,
    ) -> Self {
        let (stop, stopped) = zruntime::mpmc::bounded::<()>(std::num::NonZeroUsize::MIN);
        let hw = fake.hardware();
        let bus = Bus::Address(address.to_string());
        let setup = Setup {
            blobs: if blobs_ok {
                Ok(blobs())
            } else {
                Err("vendor driver DLL /nonexistent not readable".into())
            },
            calibration: state.0.join("calibration.bin"),
        };
        let deps = Deps {
            authority,
            users: Arc::new(TestUsers {
                me: nix::unistd::getuid().as_raw(),
            }),
            sids: SidMap::default(),
        };
        let thread = std::thread::spawn(move || {
            zbus::block_on(service::run(
                bus,
                hw,
                setup,
                deps,
                fast_options(),
                async move {
                    let _ = stopped.recv().await;
                },
            ))
        });
        Daemon {
            stop,
            thread: Some(thread),
        }
    }

    fn stop(mut self) -> Result<(), String> {
        let _ = self.stop.try_send(());
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.stop.try_send(());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Everything a test needs.
struct Env {
    bus: PrivateBus,
    fake: FakeSensor,
    authority: Arc<TestAuthority>,
    daemon: Option<Daemon>,
    logind: Option<FakeLogind>,
    state: TempDir,
}

impl Env {
    fn new(prepare: impl FnOnce(&FakeSensor)) -> Self {
        Self::with(prepare, true, false)
    }

    fn with(prepare: impl FnOnce(&FakeSensor), blobs_ok: bool, logind: bool) -> Self {
        let bus = PrivateBus::start();
        let fake = FakeSensor::new();
        prepare(&fake);
        let authority = Arc::new(TestAuthority::default());
        let logind = logind.then(|| zbus::block_on(FakeLogind::start(&bus.address)));
        let state = TempDir::new("state");
        let daemon = Daemon::start(&bus.address, &fake, authority.clone(), blobs_ok, &state);
        let env = Env {
            bus,
            fake,
            authority,
            daemon: Some(daemon),
            logind,
            state,
        };
        zbus::block_on(async {
            let c = env.client().await;
            let dbus = zbus::fdo::DBusProxy::new(&c).await.unwrap();
            let end = Instant::now() + Duration::from_secs(10);
            while !dbus
                .name_has_owner("net.reactivated.Fprint".try_into().unwrap())
                .await
                .unwrap()
            {
                assert!(Instant::now() < end, "the daemon did not take its name");
                sleep(Duration::from_millis(10)).await;
            }
        });
        env
    }

    /// Stops the daemon (it closes the sensor, which reboots) and starts a new
    /// one at once, as a service restart does.
    fn restart_daemon(&mut self) {
        self.daemon.take().unwrap().stop().unwrap();
        self.daemon = Some(Daemon::start(
            &self.bus.address,
            &self.fake,
            self.authority.clone(),
            true,
            &self.state,
        ));
    }

    async fn client(&self) -> Connection {
        zbus::connection::Builder::address(self.bus.address.as_str())
            .build()
            .await
            .unwrap()
    }

    async fn device(&self) -> (Connection, DeviceProxy<'static>) {
        let c = self.client().await;
        let d = DeviceProxy::new(&c).await.unwrap();
        (c, d)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if let Some(d) = self.daemon.take() {
            let r = d.stop();
            if !std::thread::panicking() {
                r.expect("the daemon stopped cleanly");
            }
        }
    }
}

fn err_name<T: std::fmt::Debug>(r: zbus::Result<T>) -> String {
    match r {
        Err(zbus::Error::MethodError(name, _, _)) => name.to_string(),
        other => panic!("expected a D-Bus error, got {other:?}"),
    }
}

async fn sleep(d: Duration) {
    zruntime::SharedRuntime::current().unwrap().sleep(d).await;
}

async fn wait_until<F: AsyncFnMut() -> bool>(what: &str, mut f: F) {
    let end = Instant::now() + Duration::from_secs(10);
    while !f().await {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        // Yield to this thread's runtime: it also runs the fake logind and
        // the proxies' signal handling.
        sleep(Duration::from_millis(10)).await;
    }
}

/// Collects a device's statuses until a final one.
async fn statuses(
    stream: &mut (impl futures_core::Stream<Item = (String, bool)> + Unpin),
) -> Vec<String> {
    let mut out = Vec::new();
    let end = Duration::from_secs(15);
    loop {
        let next = std::future::poll_fn(|cx| std::pin::Pin::new(&mut *stream).poll_next(cx));
        let rt = zruntime::SharedRuntime::current().unwrap();
        let (result, done) = rt
            .timeout(end, next)
            .await
            .expect("a status within 15 s")
            .expect("the signal stream is open");
        out.push(result);
        if done {
            return out;
        }
    }
}

async fn next_with_timeout<S: futures_core::Stream + Unpin>(
    s: &mut S,
    d: Duration,
) -> Option<S::Item> {
    let rt = zruntime::SharedRuntime::current().unwrap();
    rt.timeout(
        d,
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut *s).poll_next(cx)),
    )
    .await
    .ok()
    .flatten()
}

async fn selected(s: &mut VerifyFingerSelectedStream) -> String {
    let sig = next_with_timeout(s, Duration::from_secs(5))
        .await
        .expect("VerifyFingerSelected");
    sig.args().unwrap().finger_name().clone()
}

fn verify_stream(
    s: VerifyStatusStream,
) -> impl futures_core::Stream<Item = (String, bool)> + Unpin {
    MapStream(s, |sig: VerifyStatus| {
        let a = sig.args().unwrap();
        (a.result().clone(), *a.done())
    })
}

fn enroll_stream(
    s: EnrollStatusStream,
) -> impl futures_core::Stream<Item = (String, bool)> + Unpin {
    MapStream(s, |sig: EnrollStatus| {
        let a = sig.args().unwrap();
        (a.result().clone(), *a.done())
    })
}

struct MapStream<S, F>(S, F);

impl<S: futures_core::Stream + Unpin, F: FnMut(S::Item) -> T + Unpin, T> futures_core::Stream
    for MapStream<S, F>
{
    type Item = T;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<T>> {
        let this = &mut *self;
        std::pin::Pin::new(&mut this.0)
            .poll_next(cx)
            .map(|o| o.map(&mut this.1))
    }
}

// ------------------------------------------------------------ the tests

const NO_PRINTS: &str = "net.reactivated.Fprint.Error.NoEnrolledPrints";
const CLAIM: &str = "net.reactivated.Fprint.Error.ClaimDevice";
const IN_USE: &str = "net.reactivated.Fprint.Error.AlreadyInUse";
const INTERNAL: &str = "net.reactivated.Fprint.Error.Internal";
const DENIED: &str = "net.reactivated.Fprint.Error.PermissionDenied";
const BAD_FINGER: &str = "net.reactivated.Fprint.Error.InvalidFingername";
const NO_ACTION: &str = "net.reactivated.Fprint.Error.NoActionInProgress";
const NO_DEVICE: &str = "net.reactivated.Fprint.Error.NoSuchDevice";

/// Six touches of finger `f` that enrol it (duplicate check + five images).
fn enrol_touches(f: u32) -> Vec<Touch> {
    vec![Touch::Finger(f); 6]
}

async fn ready(d: &DeviceProxy<'_>) {
    // Ready once a list answers (NoEnrolledPrints included).
    wait_until("the sensor to be ready", async || {
        match d.list_enrolled_fingers("").await {
            Ok(_) => true,
            Err(zbus::Error::MethodError(n, _, _)) => n.as_str() == NO_PRINTS,
            Err(_) => false,
        }
    })
    .await;
}

#[test]
fn claim_enroll_verify_delete_release() {
    let env = Env::new(|_| {});
    zbus::block_on(async {
        let c = env.client().await;
        let mgr = ManagerProxy::new(&c).await.unwrap();
        let (_dc, d) = env.device().await;
        ready(&d).await;
        assert_eq!(
            mgr.get_devices().await.unwrap(),
            ["/net/reactivated/Fprint/Device/0".try_into().unwrap()]
        );
        assert_eq!(
            mgr.get_default_device().await.unwrap().as_str(),
            "/net/reactivated/Fprint/Device/0"
        );
        assert_eq!(err_name(d.list_enrolled_fingers("").await), NO_PRINTS);
        assert_eq!(err_name(d.verify_start("any").await), CLAIM);
        assert_eq!(err_name(d.release().await), CLAIM);
        assert_eq!(d.num_enroll_stages().await.unwrap(), 6);
        assert_eq!(d.scan_type().await.unwrap(), "press");
        assert_eq!(
            d.name().await.unwrap(),
            "Synaptics/Validity fingerprint sensor (06cb:009a)"
        );
        assert!(!d.finger_present().await.unwrap());
        assert!(!d.finger_needed().await.unwrap());

        d.claim("").await.unwrap();
        // A second client cannot claim or use it.
        let (_c2, d2) = env.device().await;
        assert_eq!(err_name(d2.claim("").await), IN_USE);
        assert_eq!(err_name(d2.verify_start("any").await), IN_USE);
        assert_eq!(err_name(d.claim("").await), IN_USE);
        assert_eq!(err_name(d.verify_stop().await), NO_ACTION);
        assert_eq!(err_name(d.verify_start("any").await), NO_PRINTS);

        // Enrolment: duplicate check, then five images; a redundant image and a
        // failed capture in between.
        assert_eq!(err_name(d.enroll_start("any").await), BAD_FINGER);
        let mut es = enroll_stream(d.receive_enroll_status().await.unwrap());
        env.fake.touch([
            Touch::Finger(1),
            Touch::Finger(1),
            Touch::Redundant(1),
            Touch::ScanError,
            Touch::Finger(1),
            Touch::Finger(1),
            Touch::Finger(1),
            Touch::Finger(1),
        ]);
        d.enroll_start("right-index-finger").await.unwrap();
        assert_eq!(
            statuses(&mut es).await,
            [
                "enroll-stage-passed",
                "enroll-stage-passed",
                "enroll-remove-and-retry",
                "enroll-retry-scan",
                "enroll-stage-passed",
                "enroll-stage-passed",
                "enroll-stage-passed",
                "enroll-completed"
            ]
        );
        assert_eq!(err_name(d.enroll_start("left-thumb").await), IN_USE);
        d.enroll_stop().await.unwrap();
        assert_eq!(err_name(d.enroll_stop().await), NO_ACTION);
        assert_eq!(env.fake.records(), [(alice_sid(), 2, 1)]);
        assert_eq!(
            d.list_enrolled_fingers("").await.unwrap(),
            ["right-index-finger"]
        );
        assert_eq!(
            d.list_enrolled_fingers("alice").await.unwrap(),
            ["right-index-finger"]
        );

        // Verify: the single print is selected, then a match.
        let mut sel = d.receive_verify_finger_selected().await.unwrap();
        let mut vs = verify_stream(d.receive_verify_status().await.unwrap());
        env.fake.touch([Touch::Finger(1)]);
        d.verify_start("any").await.unwrap();
        assert_eq!(selected(&mut sel).await, "right-index-finger");
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
        // Finished but not stopped: busy until VerifyStop.
        assert_eq!(err_name(d.verify_start("any").await), IN_USE);
        d.verify_stop().await.unwrap();

        // An unknown finger.
        env.fake.touch([Touch::Finger(2)]);
        d.verify_start("any").await.unwrap();
        assert_eq!(selected(&mut sel).await, "right-index-finger");
        assert_eq!(statuses(&mut vs).await, ["verify-no-match"]);
        d.verify_stop().await.unwrap();

        // A failed capture first: retry, then match.
        env.fake.touch([Touch::ScanError, Touch::Finger(1)]);
        d.verify_start("right-index-finger").await.unwrap();
        assert_eq!(selected(&mut sel).await, "right-index-finger");
        assert_eq!(
            statuses(&mut vs).await,
            ["verify-retry-scan", "verify-match"]
        );
        d.verify_stop().await.unwrap();
        assert_eq!(err_name(d.verify_start("left-thumb").await), NO_PRINTS);

        // Re-enrolling the same finger replaces its print.
        env.fake.touch(enrol_touches(1));
        d.enroll_start("right-index-finger").await.unwrap();
        // The old print is deleted first, so the duplicate check passes.
        assert_eq!(statuses(&mut es).await.last().unwrap(), "enroll-completed");
        d.enroll_stop().await.unwrap();
        assert_eq!(env.fake.records(), [(alice_sid(), 2, 1)]);

        // An enrolled finger cannot be enrolled again as another one.
        env.fake.touch([Touch::Finger(1)]);
        d.enroll_start("left-thumb").await.unwrap();
        assert_eq!(statuses(&mut es).await, ["enroll-duplicate"]);
        d.enroll_stop().await.unwrap();
        assert_eq!(env.fake.pending_touches(), 0);

        // A second finger, then delete one, then all.
        env.fake.touch(enrol_touches(5));
        d.enroll_start("left-thumb").await.unwrap();
        assert_eq!(statuses(&mut es).await.last().unwrap(), "enroll-completed");
        d.enroll_stop().await.unwrap();
        assert_eq!(
            d.list_enrolled_fingers("").await.unwrap(),
            ["left-thumb", "right-index-finger"]
        );
        // Two prints: "any" is selected.
        env.fake.touch([Touch::Finger(5)]);
        d.verify_start("any").await.unwrap();
        assert_eq!(selected(&mut sel).await, "any");
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
        d.verify_stop().await.unwrap();

        assert_eq!(
            err_name(d.delete_enrolled_finger("bogus").await),
            BAD_FINGER
        );
        assert_eq!(
            err_name(d.delete_enrolled_finger("right-thumb").await),
            NO_PRINTS
        );
        d.delete_enrolled_finger("left-thumb").await.unwrap();
        assert_eq!(
            d.list_enrolled_fingers("").await.unwrap(),
            ["right-index-finger"]
        );
        d.delete_enrolled_fingers2().await.unwrap();
        assert_eq!(err_name(d.list_enrolled_fingers("").await), NO_PRINTS);
        assert_eq!(err_name(d.delete_enrolled_fingers2().await), NO_PRINTS);
        assert!(env.fake.records().is_empty());

        d.release().await.unwrap();
        assert_eq!(err_name(d.release().await), CLAIM);
        // Now the other client can claim.
        d2.claim("").await.unwrap();
        d2.release().await.unwrap();
    });
}

#[test]
fn verify_never_matches_another_users_finger() {
    let env = Env::new(|f| {
        // Alice's left index; Bob's right index; a Windows account's thumb.
        f.enroll_directly(&alice_sid(), 7, 10);
        f.enroll_directly(&sid_for_uid(BOB_UID), 2, 20);
        f.enroll_directly(
            &"S-1-5-21-1000000001-1000000002-1000000003-1001"
                .parse()
                .unwrap(),
            1,
            30,
        );
    });
    zbus::block_on(async {
        let (_c, d) = env.device().await;
        ready(&d).await;
        d.claim("").await.unwrap();
        let mut vs = verify_stream(d.receive_verify_status().await.unwrap());
        for (finger, want) in [
            (20, "verify-no-match"),
            (30, "verify-no-match"),
            (10, "verify-match"),
        ] {
            let before = env.fake.counters().matches;
            env.fake.touch([Touch::Finger(finger)]);
            d.verify_start("any").await.unwrap();
            assert_eq!(statuses(&mut vs).await, [want], "finger {finger}");
            // The sensor did match a record each time.
            assert_eq!(env.fake.counters().matches, before + 1);
            d.verify_stop().await.unwrap();
        }
        // A named finger: the user's other finger does not count.
        env.fake.enroll_directly(&alice_sid(), 8, 11);
        d.release().await.unwrap();
        d.claim("").await.unwrap();
        env.fake.touch([Touch::Finger(11)]);
        d.verify_start("left-index-finger").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-no-match"]);
        d.verify_stop().await.unwrap();
        d.release().await.unwrap();
    });
}

#[test]
fn cancel_stops_the_capture_and_reports_nothing() {
    let env = Env::new(|f| f.enroll_directly(&alice_sid(), 2, 1));
    zbus::block_on(async {
        let (_c, d) = env.device().await;
        ready(&d).await;
        d.claim("").await.unwrap();
        let mut vs = verify_stream(d.receive_verify_status().await.unwrap());
        let mut es = enroll_stream(d.receive_enroll_status().await.unwrap());
        for _ in 0..3 {
            d.verify_start("any").await.unwrap();
            assert!(env.fake.wait_for_capture(Duration::from_secs(5)));
            wait_until("finger-needed", async || d.finger_needed().await.unwrap()).await;
            d.verify_stop().await.unwrap();
            assert!(!env.fake.waiting_for_finger());
            assert!(!d.finger_needed().await.unwrap());
        }
        assert!(
            next_with_timeout(&mut vs, Duration::from_millis(300))
                .await
                .is_none()
        );
        // Stop immediately after start, before the capture even began.
        d.verify_start("any").await.unwrap();
        d.verify_stop().await.unwrap();
        // Enrolment cancelled mid-way.
        env.fake.touch([Touch::Finger(9)]);
        d.enroll_start("left-thumb").await.unwrap();
        let first = next_with_timeout(&mut es, Duration::from_secs(5)).await;
        assert_eq!(first, Some(("enroll-stage-passed".to_string(), false)));
        assert!(env.fake.wait_for_capture(Duration::from_secs(5)));
        d.enroll_stop().await.unwrap();
        assert!(
            next_with_timeout(&mut es, Duration::from_millis(300))
                .await
                .is_none()
        );
        assert_eq!(env.fake.records(), [(alice_sid(), 2, 1)]);
        // Still usable.
        env.fake.touch([Touch::Finger(1)]);
        d.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
        d.verify_stop().await.unwrap();
        // Release during a run stops it.
        d.verify_start("any").await.unwrap();
        assert!(env.fake.wait_for_capture(Duration::from_secs(5)));
        d.release().await.unwrap();
        assert!(!env.fake.waiting_for_finger());
    });
}

#[test]
fn a_client_leaving_the_bus_releases_the_device() {
    let env = Env::new(|f| f.enroll_directly(&alice_sid(), 2, 1));
    zbus::block_on(async {
        let (c1, d1) = env.device().await;
        ready(&d1).await;
        d1.claim("").await.unwrap();
        d1.verify_start("any").await.unwrap();
        assert!(env.fake.wait_for_capture(Duration::from_secs(5)));
        // pam_fprintd disconnects without Release.
        drop(d1);
        drop(c1);
        let (_c2, d2) = env.device().await;
        wait_until("the claim to be released", async || {
            d2.claim("").await.is_ok()
        })
        .await;
        wait_until("the capture to stop", async || {
            !env.fake.waiting_for_finger()
        })
        .await;
        env.fake.touch([Touch::Finger(1)]);
        let mut vs = verify_stream(d2.receive_verify_status().await.unwrap());
        d2.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
    });
}

#[test]
fn polkit_decides() {
    let env = Env::new(|f| f.enroll_directly(&sid_for_uid(BOB_UID), 1, 7));
    zbus::block_on(async {
        let (_c, d) = env.device().await;
        ready(&d).await;
        env.authority.asked();
        env.authority.deny(VERIFY);
        assert_eq!(err_name(d.list_enrolled_fingers("").await), DENIED);
        assert_eq!(env.authority.asked(), [VERIFY]);
        // Claim needs verify or enroll.
        d.claim("").await.unwrap();
        assert_eq!(env.authority.asked(), [VERIFY, ENROLL]);
        assert_eq!(err_name(d.verify_start("any").await), DENIED);
        env.authority.deny(ENROLL);
        assert_eq!(err_name(d.enroll_start("left-thumb").await), DENIED);
        assert_eq!(err_name(d.delete_enrolled_fingers2().await), DENIED);
        // Stop and Release need nothing.
        env.authority.asked();
        d.release().await.unwrap();
        assert!(env.authority.asked().is_empty());
        assert_eq!(err_name(d.claim("").await), DENIED);
        env.authority.allow(VERIFY);
        env.authority.allow(ENROLL);

        // Another user needs setusername.
        env.authority.deny(SETUSERNAME);
        assert_eq!(err_name(d.list_enrolled_fingers("bob").await), DENIED);
        assert_eq!(err_name(d.claim("bob").await), DENIED);
        assert_eq!(err_name(d.delete_enrolled_fingers("bob").await), DENIED);
        env.authority.allow(SETUSERNAME);
        assert_eq!(
            d.list_enrolled_fingers("bob").await.unwrap(),
            ["right-thumb"]
        );
        assert_eq!(err_name(d.list_enrolled_fingers("nobody").await), NO_PRINTS);
        assert_eq!(err_name(d.claim("nobody").await), INTERNAL);
        d.claim("bob").await.unwrap();
        let mut vs = verify_stream(d.receive_verify_status().await.unwrap());
        env.fake.touch([Touch::Finger(7)]);
        d.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
        d.verify_stop().await.unwrap();
        d.release().await.unwrap();
        // The deprecated unclaimed delete.
        d.delete_enrolled_fingers("bob").await.unwrap();
        assert_eq!(err_name(d.list_enrolled_fingers("bob").await), NO_PRINTS);
        assert_eq!(err_name(d.delete_enrolled_fingers("bob").await), NO_PRINTS);
    });
}

#[test]
fn unplug_reports_disconnected_then_recovers() {
    let env = Env::new(|f| f.enroll_directly(&alice_sid(), 2, 1));
    zbus::block_on(async {
        let c = env.client().await;
        let mgr = ManagerProxy::new(&c).await.unwrap();
        let (_c1, d) = env.device().await;
        ready(&d).await;
        d.claim("").await.unwrap();
        let mut vs = verify_stream(d.receive_verify_status().await.unwrap());
        d.verify_start("any").await.unwrap();
        assert!(env.fake.wait_for_capture(Duration::from_secs(5)));
        env.fake.unplug();
        assert_eq!(statuses(&mut vs).await, ["verify-disconnected"]);
        d.verify_stop().await.unwrap();
        wait_until("the device to be absent", async || {
            mgr.get_devices().await.unwrap().is_empty()
        })
        .await;
        assert_eq!(err_name(mgr.get_default_device().await), NO_DEVICE);
        // Fails fast: PAM moves on to the password.
        let t = Instant::now();
        assert_eq!(err_name(d.verify_start("any").await), INTERNAL);
        assert_eq!(err_name(d.list_enrolled_fingers("").await), INTERNAL);
        d.release().await.unwrap();
        assert_eq!(err_name(d.claim("").await), INTERNAL);
        assert!(
            t.elapsed() < Duration::from_millis(500),
            "{:?}",
            t.elapsed()
        );

        // Back, at another address: found again without a restart.
        env.fake.plug();
        ready(&d).await;
        assert_eq!(mgr.get_devices().await.unwrap().len(), 1);
        d.claim("").await.unwrap();
        env.fake.touch([Touch::Finger(1)]);
        d.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
        d.verify_stop().await.unwrap();
        d.release().await.unwrap();
        assert_eq!(env.fake.counters().opens, 2);

        // Unplugged while idle: noticed through hotplug, not at the next use.
        env.fake.unplug();
        wait_until("the device to be absent", async || {
            mgr.get_devices().await.unwrap().is_empty()
        })
        .await;
        env.fake.plug();
        ready(&d).await;
        assert_eq!(env.fake.counters().opens, 3);
    });
}

#[test]
fn a_stuck_sensor_is_reset_once_and_recovers() {
    let env = Env::new(|f| {
        f.enroll_directly(&alice_sid(), 2, 1);
        f.set_stuck(true);
    });
    zbus::block_on(async {
        let (_c, d) = env.device().await;
        ready(&d).await;
        let n = env.fake.counters();
        assert_eq!(n.resets, 1);
        assert_eq!(n.opens, 3, "two failed opens, the reset, then success");
        d.claim("").await.unwrap();
        let mut vs = verify_stream(d.receive_verify_status().await.unwrap());
        env.fake.touch([Touch::Finger(1)]);
        d.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
        d.verify_stop().await.unwrap();

        // Stuck mid-session: the run fails, the sensor is reopened and works.
        env.fake.set_stuck(true);
        d.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-disconnected"]);
        d.verify_stop().await.unwrap();
        // The status comes before the reconnection: until the worker drops the
        // session the device still reads as ready.
        wait_until("the second reset", async || env.fake.counters().resets == 2).await;
        ready(&d).await;
        assert_eq!(env.fake.counters().resets, 2);
        env.fake.touch([Touch::Finger(1)]);
        d.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
        d.verify_stop().await.unwrap();
    });
}

#[test]
fn no_finger_in_time_ends_a_verify_and_rearms_an_enrolment() {
    let env = Env::new(|f| {
        f.enroll_directly(&alice_sid(), 2, 1);
        f.set_finger_deadline(Duration::from_millis(200));
    });
    zbus::block_on(async {
        let (_c, d) = env.device().await;
        ready(&d).await;
        let before = env.fake.counters();
        d.claim("").await.unwrap();
        let mut vs = verify_stream(d.receive_verify_status().await.unwrap());
        let mut es = enroll_stream(d.receive_enroll_status().await.unwrap());

        // No finger: the verification ends with no match (fprintd's result for
        // a verification that ended without a matching finger).
        d.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-no-match"]);
        d.verify_stop().await.unwrap();
        assert!(!d.finger_needed().await.unwrap());

        // Enrolment: each missed finger asks again and re-arms the scan, in
        // the duplicate check as for the images; the enrolment goes on.
        d.enroll_start("left-thumb").await.unwrap();
        for _ in 0..2 {
            assert_eq!(
                next_with_timeout(&mut es, Duration::from_secs(5)).await,
                Some(("enroll-retry-scan".to_string(), false))
            );
        }
        env.fake.touch([Touch::Finger(9)]);
        let mut got = Vec::new();
        while got.last().map(String::as_str) != Some("enroll-stage-passed") {
            let (r, done) = next_with_timeout(&mut es, Duration::from_secs(5))
                .await
                .expect("a status");
            assert!(!done, "{r}");
            got.push(r);
        }
        // An image missed too: asked again, then the finger comes.
        assert_eq!(
            next_with_timeout(&mut es, Duration::from_secs(5)).await,
            Some(("enroll-retry-scan".to_string(), false))
        );
        env.fake.touch(vec![Touch::Finger(9); 5]);
        let rest = statuses(&mut es).await;
        assert_eq!(rest.last().map(String::as_str), Some("enroll-completed"));
        assert_eq!(
            rest.iter()
                .filter(|r| r.as_str() == "enroll-stage-passed")
                .count(),
            4,
            "{rest:?}"
        );
        assert!(
            rest.iter().all(|r| matches!(
                r.as_str(),
                "enroll-retry-scan" | "enroll-stage-passed" | "enroll-completed"
            )),
            "{rest:?}"
        );
        d.enroll_stop().await.unwrap();
        let records = env.fake.records();
        assert!(
            records
                .iter()
                .any(|(sid, _, f)| *sid == alice_sid() && *f == 9),
            "{records:?}"
        );
        assert_eq!(
            d.list_enrolled_fingers("").await.unwrap(),
            ["left-thumb", "right-index-finger"]
        );

        // The sensor was fine all along: never rebooted, reset or reopened.
        let after = env.fake.counters();
        assert_eq!(
            (after.reboots, after.resets, after.opens),
            (before.reboots, before.resets, before.opens)
        );
        env.fake.touch([Touch::Finger(1)]);
        d.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
        d.verify_stop().await.unwrap();
    });
}

#[test]
fn a_sensor_that_stops_answering_is_rebooted_and_reopened() {
    let env = Env::new(|f| f.enroll_directly(&alice_sid(), 2, 1));
    zbus::block_on(async {
        let (_c, d) = env.device().await;
        ready(&d).await;
        let before = env.fake.counters();
        d.claim("").await.unwrap();
        let mut vs = verify_stream(d.receive_verify_status().await.unwrap());
        let mut es = enroll_stream(d.receive_enroll_status().await.unwrap());

        // The scan never starts (issue #2): the run fails at once, the sensor
        // is rebooted and reopened, and works again.
        env.fake.hang_next_capture();
        d.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-disconnected"]);
        d.verify_stop().await.unwrap();
        // The status comes first; the reboot and the reopening follow.
        let reopened = async |reboots: u32, resets: u32, opens: u32| {
            wait_until("the sensor to be reopened", async || {
                let n = env.fake.counters();
                (n.reboots, n.resets, n.opens)
                    == (
                        before.reboots + reboots,
                        before.resets + resets,
                        before.opens + opens,
                    )
            })
            .await;
            ready(&d).await;
        };
        reopened(1, 0, 1).await;
        env.fake.touch([Touch::Finger(1)]);
        d.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
        d.verify_stop().await.unwrap();

        // Same during an enrolment.
        env.fake.hang_next_capture();
        d.enroll_start("left-thumb").await.unwrap();
        assert_eq!(statuses(&mut es).await, ["enroll-disconnected"]);
        d.enroll_stop().await.unwrap();
        reopened(2, 0, 2).await;

        // A sensor that does not even take the reboot gets a USB port reset.
        env.fake.hang_next_capture();
        env.fake.refuse_reboot(true);
        d.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-disconnected"]);
        d.verify_stop().await.unwrap();
        reopened(2, 1, 3).await;
        env.fake.touch([Touch::Finger(1)]);
        d.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
        d.verify_stop().await.unwrap();
        d.release().await.unwrap();
    });
}

#[test]
fn opening_failures_are_bounded_and_retried_later() {
    let env = Env::new(|f| f.fail_opens(1000));
    zbus::block_on(async {
        let (_c, d) = env.device().await;
        // Five attempts, then parked; Claim fails at once.
        wait_until("the attempts to end", async || {
            matches!(d.claim("").await, Err(zbus::Error::MethodError(n, Some(m), _))
                if n.as_str() == INTERNAL && m.contains("cannot open the USB device"))
        })
        .await;
        env.fake.fail_opens(0);
        // The cooldown (1 s in tests) brings the next cycle.
        ready(&d).await;
        d.claim("").await.unwrap();
        d.release().await.unwrap();
    });
}

#[test]
fn setup_problems_fail_fast_but_keep_the_device_listed() {
    for (what, prepare, blobs_ok, msg) in [
        (
            "blank flash",
            Box::new(|f: &FakeSensor| f.set_paired(false)) as Box<dyn Fn(&FakeSensor)>,
            true,
            "not paired",
        ),
        (
            "paired elsewhere",
            Box::new(|f: &FakeSensor| f.set_paired_elsewhere(true)),
            true,
            "another computer",
        ),
        (
            "no firmware",
            Box::new(|f: &FakeSensor| f.set_firmware(false)),
            true,
            "firmware extension",
        ),
        (
            "no vendor DLL",
            Box::new(|_: &FakeSensor| {}),
            false,
            "vendor driver DLL",
        ),
        (
            "unvalidated device",
            Box::new(|f: &FakeSensor| f.set_usb_id((0x138a, 0x0097))),
            true,
            "not supported yet",
        ),
    ] {
        let env = Env::with(|f| prepare(f), blobs_ok, false);
        zbus::block_on(async {
            let c = env.client().await;
            let mgr = ManagerProxy::new(&c).await.unwrap();
            let (_c, d) = env.device().await;
            wait_until(what, async || {
                matches!(d.claim("").await, Err(zbus::Error::MethodError(n, Some(m), _))
                    if n.as_str() == INTERNAL && m.contains(msg))
            })
            .await;
            let t = Instant::now();
            assert_eq!(err_name(d.list_enrolled_fingers("").await), INTERNAL);
            assert!(t.elapsed() < Duration::from_millis(500));
            assert_eq!(mgr.get_devices().await.unwrap().len(), 1, "{what}");
            // Nothing destructive happened: no pairing, no reboot.
            assert_eq!(env.fake.counters().reboots, 0, "{what}");
        });
    }
}

#[test]
fn absent_sensor() {
    // With or without the vendor DLL: no sensor is "no device", not "needs setup".
    for blobs_ok in [true, false] {
        let env = Env::with(|f| f.unplug(), blobs_ok, false);
        zbus::block_on(async {
            let c = env.client().await;
            let mgr = ManagerProxy::new(&c).await.unwrap();
            let (_c, d) = env.device().await;
            wait_until("absent", async || {
                mgr.get_devices().await.unwrap().is_empty()
            })
            .await;
            assert_eq!(err_name(mgr.get_default_device().await), NO_DEVICE);
            let t = Instant::now();
            assert_eq!(err_name(d.claim("").await), INTERNAL);
            assert!(t.elapsed() < Duration::from_millis(500));
            // The device object stays.
            assert_eq!(d.scan_type().await.unwrap(), "press");
            // Re-checking for the sensor does not make the device flicker.
            let end = Instant::now() + Duration::from_millis(700);
            while Instant::now() < end {
                assert!(mgr.get_devices().await.unwrap().is_empty());
                sleep(Duration::from_millis(5)).await;
            }
            assert!(
                env.fake.counters().probes >= 3,
                "the sensor is looked for again"
            );
            assert_eq!(env.fake.counters().opens, 0);
        });
    }
}

#[test]
fn suspend_closes_and_resume_reopens_with_the_verify_still_running() {
    let env = Env::with(|f| f.enroll_directly(&alice_sid(), 2, 1), true, true);
    zbus::block_on(async {
        let logind = env.logind.as_ref().unwrap();
        let (_c, d) = env.device().await;
        ready(&d).await;
        wait_until("the inhibitor", async || logind.inhibitors() == 1).await;
        assert!(!logind.inhibitor_released(0));
        d.claim("").await.unwrap();
        let mut vs = verify_stream(d.receive_verify_status().await.unwrap());
        d.verify_start("any").await.unwrap();
        assert!(env.fake.wait_for_capture(Duration::from_secs(5)));

        logind.prepare_for_sleep(true).await;
        wait_until("the inhibitor release", async || {
            logind.inhibitor_released(0)
        })
        .await;
        // The session was closed cleanly (sensor rebooted) before sleep.
        assert_eq!(env.fake.counters().reboots, 1);
        assert!(!env.fake.waiting_for_finger());
        // Nothing reported: the verify is still running for the client.
        assert!(
            next_with_timeout(&mut vs, Duration::from_millis(200))
                .await
                .is_none()
        );

        logind.prepare_for_sleep(false).await;
        wait_until("a new inhibitor", async || logind.inhibitors() == 2).await;
        assert!(env.fake.wait_for_capture(Duration::from_secs(5)));
        assert_eq!(env.fake.counters().opens, 2);
        env.fake.touch([Touch::Finger(1)]);
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
        d.verify_stop().await.unwrap();
        d.release().await.unwrap();
    });
}

/// Polls GetDevices from its own thread and counts what it sees.
struct DeviceWatch {
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<(u32, u32, u32)>>,
}

impl DeviceWatch {
    fn start(address: &str) -> Self {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (address, s2) = (address.to_string(), stop.clone());
        let thread = std::thread::spawn(move || {
            zbus::block_on(async move {
                let c = zbus::connection::Builder::address(address.as_str())
                    .build()
                    .await
                    .unwrap();
                let (mut listed, mut empty, mut no_daemon) = (0, 0, 0);
                while !s2.load(std::sync::atomic::Ordering::SeqCst) {
                    // Without caching: every call reaches the daemon.
                    let r = c
                        .call_method(
                            Some("net.reactivated.Fprint"),
                            "/net/reactivated/Fprint/Manager",
                            Some("net.reactivated.Fprint.Manager"),
                            "GetDevices",
                            &(),
                        )
                        .await;
                    match r.map(|m| {
                        m.body()
                            .deserialize::<Vec<zbus::OwnedObjectPath>>()
                            .unwrap()
                    }) {
                        Ok(v) if v.is_empty() => empty += 1,
                        Ok(_) => listed += 1,
                        // Between two daemons: nobody owns the name.
                        Err(_) => no_daemon += 1,
                    }
                    sleep(Duration::from_millis(5)).await;
                }
                (listed, empty, no_daemon)
            })
        });
        DeviceWatch {
            stop,
            thread: Some(thread),
        }
    }

    fn finish(mut self) -> (u32, u32, u32) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap()
    }
}

#[test]
fn a_rebooting_sensor_is_never_reported_gone() {
    // Every close reboots the sensor, which leaves the bus for 0.5 s and comes
    // back at a new address (as on a T480).
    let mut env = Env::with(
        |f| {
            f.enroll_directly(&alice_sid(), 2, 1);
            f.set_reboot_absence(Duration::from_millis(500));
        },
        true,
        true,
    );
    let watch = DeviceWatch::start(&env.bus.address);
    zbus::block_on(async {
        let logind = env.logind.as_ref().unwrap();
        let (_c, d) = env.device().await;
        ready(&d).await;
        d.claim("").await.unwrap();
        let mut vs = verify_stream(d.receive_verify_status().await.unwrap());
        d.verify_start("any").await.unwrap();
        assert!(env.fake.wait_for_capture(Duration::from_secs(5)));

        // Suspend, and resume while the sensor is still off the bus.
        logind.prepare_for_sleep(true).await;
        wait_until("the sensor reboot", async || {
            env.fake.counters().reboots == 1
        })
        .await;
        assert!(
            env.fake.hardware_probe().is_none(),
            "off the bus right after the reboot"
        );
        logind.prepare_for_sleep(false).await;
        // Back, reopened, the verify carries on.
        assert!(env.fake.wait_for_capture(Duration::from_secs(5)));
        env.fake.touch([Touch::Finger(1)]);
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
        d.verify_stop().await.unwrap();

        // A stuck sensor: the USB reset takes it off the bus too.
        env.fake.set_stuck(true);
        d.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-disconnected"]);
        d.verify_stop().await.unwrap();
        ready(&d).await;
        d.release().await.unwrap();
    });
    // A service restart: the old daemon's close reboots the sensor, the new
    // daemon starts while it is off the bus.
    env.restart_daemon();
    zbus::block_on(async {
        let (_c, d) = env.device().await;
        ready(&d).await;
        d.claim("").await.unwrap();
        let mut vs = verify_stream(d.receive_verify_status().await.unwrap());
        env.fake.touch([Touch::Finger(1)]);
        d.verify_start("any").await.unwrap();
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
        d.verify_stop().await.unwrap();
        d.release().await.unwrap();
    });
    let (listed, empty, no_daemon) = watch.finish();
    let c = env.fake.counters();
    eprintln!("GetDevices: {listed} listed, {empty} empty, {no_daemon} without a daemon; {c:?}");
    assert_eq!(empty, 0, "the device was reported gone");
    assert!(listed > 100);
    assert!(c.reboots >= 2 && c.resets >= 1);
}

#[test]
fn prepare_for_sleep_from_anyone_but_logind_is_ignored() {
    let env = Env::with(|_| {}, true, true);
    zbus::block_on(async {
        let (_c, d) = env.device().await;
        ready(&d).await;
        let impostor = env.client().await;
        let em =
            zbus::object_server::SignalEmitter::new(&impostor, "/org/freedesktop/login1").unwrap();
        Logind::prepare_for_sleep(&em, true).await.unwrap();
        sleep(Duration::from_millis(300)).await;
        assert_eq!(env.fake.counters().reboots, 0);
        d.claim("").await.unwrap();
    });
}

#[test]
fn shutdown_closes_the_sensor() {
    let mut env = Env::new(|_| {});
    zbus::block_on(async {
        let (_c, d) = env.device().await;
        ready(&d).await;
    });
    env.daemon.take().unwrap().stop().unwrap();
    assert_eq!(env.fake.counters().reboots, 1);
    // Calibration was saved for the next start.
    assert!(env.state.0.join("calibration.bin").exists());
}

#[test]
fn verify_start_reply_precedes_its_signals() {
    let env = Env::new(|f| f.enroll_directly(&alice_sid(), 2, 1));
    zbus::block_on(async {
        let (c, d) = env.device().await;
        ready(&d).await;
        d.claim("").await.unwrap();
        // Make sure the match rules for the signals are in place.
        let _vs = d.receive_verify_status().await.unwrap();
        let _sel = d.receive_verify_finger_selected().await.unwrap();
        let mut all = zbus::MessageStream::from(&c);
        for round in 0..20 {
            // The finger is already there: the result is immediate.
            env.fake.touch([Touch::Finger(1)]);
            let call = zbus::message::Message::method_call(
                "/net/reactivated/Fprint/Device/0",
                "VerifyStart",
            )
            .destination("net.reactivated.Fprint")
            .interface("net.reactivated.Fprint.Device")
            .build(&("any",))
            .unwrap();
            let serial = call.primary_header().serial_num();
            c.send(&call).await.unwrap();
            let mut seen = Vec::new();
            while seen.len() < 3 {
                let m = next_with_timeout(&mut all, Duration::from_secs(5))
                    .await
                    .expect("a message")
                    .unwrap();
                let h = m.header();
                match m.message_type() {
                    zbus::message::Type::MethodReturn if h.reply_serial() == Some(serial) => {
                        // fprintd's VerifyStart returns nothing.
                        assert!(
                            m.body().signature().to_string().is_empty(),
                            "{:?}",
                            m.body().signature()
                        );
                        seen.push("reply".to_string());
                    }
                    zbus::message::Type::Signal
                        if h.interface().map(|i| i.as_str())
                            == Some("net.reactivated.Fprint.Device") =>
                    {
                        seen.push(h.member().unwrap().to_string());
                    }
                    _ => {}
                }
            }
            assert_eq!(
                seen,
                ["reply", "VerifyFingerSelected", "VerifyStatus"],
                "round {round}"
            );
            d.verify_stop().await.unwrap();
        }
    });
}

#[test]
fn a_claim_while_suspended_waits_for_the_resume() {
    let env = Env::with(|_| {}, true, true);
    zbus::block_on(async {
        let logind = env.logind.as_ref().unwrap();
        let (_c, d) = env.device().await;
        ready(&d).await;
        wait_until("the inhibitor", async || logind.inhibitors() == 1).await;
        logind.prepare_for_sleep(true).await;
        wait_until("the inhibitor release", async || {
            logind.inhibitor_released(0)
        })
        .await;
        // The claim comes from another client while the sensor sleeps; the
        // ready wait (3 s here) covers a resume 300 ms later.
        let address = env.bus.address.clone();
        let claimer = std::thread::spawn(move || {
            zbus::block_on(async {
                let c = zbus::connection::Builder::address(address.as_str())
                    .build()
                    .await
                    .unwrap();
                let d = DeviceProxy::new(&c).await.unwrap();
                let t = Instant::now();
                let r = d.claim("").await;
                if r.is_ok() {
                    d.release().await.unwrap();
                }
                (r, t.elapsed())
            })
        });
        sleep(Duration::from_millis(300)).await;
        logind.prepare_for_sleep(false).await;
        let (r, took) = claimer.join().unwrap();
        r.expect("the claim succeeds once the sensor is back");
        assert!(took >= Duration::from_millis(250), "claimed after {took:?}");
        // As soon as the sensor is back, not when the ready wait (3 s) ends.
        assert!(took < Duration::from_millis(2500), "claimed after {took:?}");
    });
}

#[test]
fn finger_present_is_signalled() {
    let env = Env::new(|f| f.enroll_directly(&alice_sid(), 2, 1));
    zbus::block_on(async {
        let (c, d) = env.device().await;
        ready(&d).await;
        let props = zbus::fdo::PropertiesProxy::builder(&c)
            .destination("net.reactivated.Fprint")
            .path("/net/reactivated/Fprint/Device/0")
            .build()
            .await
            .unwrap();
        let mut changes = props.receive_properties_changed().await.unwrap();
        d.claim("").await.unwrap();
        let mut vs = verify_stream(d.receive_verify_status().await.unwrap());
        d.verify_start("any").await.unwrap();
        assert!(env.fake.wait_for_capture(Duration::from_secs(5)));
        env.fake.touch([Touch::Finger(1)]);
        assert_eq!(statuses(&mut vs).await, ["verify-match"]);
        // finger-present goes true when the finger is detected, false when
        // the capture is over.
        let mut present = Vec::new();
        while present != [true, false] {
            let sig = next_with_timeout(&mut changes, Duration::from_secs(5))
                .await
                .unwrap_or_else(|| panic!("finger-present changes so far: {present:?}"));
            let args = sig.args().unwrap();
            if let Some(v) = args.changed_properties().get("finger-present") {
                present.push(bool::try_from(v).unwrap());
            }
        }
        d.verify_stop().await.unwrap();
        d.release().await.unwrap();
    });
}

#[test]
fn release_stops_watching_the_client() {
    let env = Env::new(|_| {});
    zbus::block_on(async {
        let (c, d) = env.device().await;
        ready(&d).await;
        let me = c.unique_name().unwrap().to_string();
        // A monitor sees the daemon add, then drop, the match rule with which
        // it notices this client leaving the bus.
        let monitor = env.client().await;
        let mut seen = zbus::MessageStream::from(&monitor);
        zbus::fdo::MonitoringProxy::new(&monitor)
            .await
            .unwrap()
            .become_monitor(
                &[
                    zbus::MatchRule::try_from("type='method_call',member='AddMatch'").unwrap(),
                    zbus::MatchRule::try_from("type='method_call',member='RemoveMatch'").unwrap(),
                ],
                0,
            )
            .await
            .unwrap();
        let mut next_rule = async |member: &str| {
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                let left = end.saturating_duration_since(Instant::now());
                let m = next_with_timeout(&mut seen, left)
                    .await
                    .unwrap_or_else(|| panic!("no {member} for the client's watch"))
                    .unwrap();
                if m.header().member().map(|n| n.as_str()) != Some(member) {
                    continue;
                }
                let rule: String = m.body().deserialize().unwrap();
                if rule.contains("NameOwnerChanged") && rule.contains(&me) {
                    return;
                }
            }
        };
        d.claim("").await.unwrap();
        // The watch is in place (it is set up after the reply)...
        next_rule("AddMatch").await;
        d.release().await.unwrap();
        // ... and gone with the claim.
        next_rule("RemoveMatch").await;
        // The client is still on the bus.
        assert!(d.list_enrolled_fingers("").await.is_err());
    });
}

// ------------------------------------------------- interface conformance

/// fprintd 1.94.5's API (net.reactivated.Fprint.{Manager,Device}.xml).
const FPRINTD_MANAGER: &[&str] = &[
    "method GetDefaultDevice out:o:device",
    "method GetDevices out:ao:devices",
];

const FPRINTD_DEVICE: &[&str] = &[
    "method Claim in:s:username",
    "method DeleteEnrolledFinger in:s:finger_name",
    "method DeleteEnrolledFingers in:s:username",
    "method DeleteEnrolledFingers2",
    "method EnrollStart in:s:finger_name",
    "method EnrollStop",
    "method ListEnrolledFingers in:s:username out:as:enrolled_fingers",
    "method Release",
    "method VerifyStart in:s:finger_name",
    "method VerifyStop",
    "property finger-needed b read",
    "property finger-present b read",
    "property name s read",
    "property num-enroll-stages i read",
    "property scan-type s read",
    "signal EnrollStatus s:result b:done",
    "signal VerifyFingerSelected s:finger_name",
    "signal VerifyStatus s:result b:done",
];

fn attrs(tag: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut rest = tag;
    while let Some(eq) = rest.find("=\"") {
        let key = rest[..eq]
            .rsplit(|c: char| c.is_whitespace())
            .next()
            .unwrap();
        let after = &rest[eq + 2..];
        let end = after.find('"').unwrap();
        out.insert(key.to_string(), after[..end].to_string());
        rest = &after[end + 1..];
    }
    out
}

/// The members of `iface` in an introspection document, one line each.
fn api(xml: &str, iface: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut inside = false;
    let mut current: Option<(String, String)> = None;
    for tag in xml.split('<').skip(1).map(|t| t.split('>').next().unwrap()) {
        let name = tag.split_whitespace().next().unwrap_or("");
        let a = attrs(tag);
        match name {
            "interface" => inside = a.get("name").map(String::as_str) == Some(iface),
            "/interface" => inside = false,
            _ if !inside => {}
            "method" | "signal" => {
                let line = format!("{name} {}", a["name"]);
                if tag.ends_with('/') {
                    out.insert(line);
                } else {
                    current = Some((name.to_string(), line));
                }
            }
            "arg" => {
                if let Some((kind, line)) = &mut current {
                    if kind == "method" {
                        let dir = a.get("direction").map(String::as_str).unwrap_or("in");
                        line.push_str(&format!(" {dir}:{}:{}", a["type"], a["name"]));
                    } else {
                        line.push_str(&format!(" {}:{}", a["type"], a["name"]));
                    }
                }
            }
            "/method" | "/signal" => {
                if let Some((_, line)) = current.take() {
                    out.insert(line);
                }
            }
            "property" => {
                out.insert(format!(
                    "property {} {} {}",
                    a["name"], a["type"], a["access"]
                ));
            }
            _ => {}
        }
    }
    out
}

#[test]
fn interfaces_match_fprintd() {
    let env = Env::new(|_| {});
    zbus::block_on(async {
        let c = env.client().await;
        for (path, iface, want) in [
            (
                "/net/reactivated/Fprint/Manager",
                "net.reactivated.Fprint.Manager",
                FPRINTD_MANAGER,
            ),
            (
                "/net/reactivated/Fprint/Device/0",
                "net.reactivated.Fprint.Device",
                FPRINTD_DEVICE,
            ),
        ] {
            let p = zbus::fdo::IntrospectableProxy::builder(&c)
                .destination("net.reactivated.Fprint")
                .path(path)
                .build()
                .await
                .unwrap();
            let xml = p.introspect().await.unwrap();
            // zbus's interface macro describes the return value of
            // ResponseDispatchNotifier<()> (which VerifyStart and EnrollStart
            // return, to send their signals only after their reply) as an
            // out argument of empty type. It carries nothing on the wire
            // (see verify_start_reply_precedes_its_signals); it is the only
            // difference, on those two methods exactly.
            let artefact = "<arg type=\"\" direction=\"out\"/>";
            let with_artefact: Vec<&str> = xml
                .split("<method ")
                .filter(|m| m.contains(artefact))
                .map(|m| m.split('"').nth(1).unwrap())
                .collect();
            if iface.ends_with("Device") {
                assert_eq!(with_artefact, ["VerifyStart", "EnrollStart"]);
            } else {
                assert!(with_artefact.is_empty());
            }
            let xml = xml.replace(artefact, "");
            let got = api(&xml, iface);
            let want: BTreeSet<String> = want.iter().map(|s| s.to_string()).collect();
            assert_eq!(got, want, "{iface}");
            // Where fprintd is installed (the end-to-end container), compare
            // with its own interface files too.
            let installed = format!("/usr/share/dbus-1/interfaces/{iface}.xml");
            if let Ok(theirs) = std::fs::read_to_string(&installed) {
                assert_eq!(got, api(&theirs, iface), "{installed}");
                eprintln!("checked against {installed}");
            }
            // No raw command method, no ObjectManager.
            assert!(!xml.contains("RunCmd"));
            assert!(!xml.contains("org.freedesktop.DBus.ObjectManager"));
        }
    });
}
