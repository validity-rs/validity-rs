//! The module as libpam runs it: `pam_start_confdir` with a service file
//! naming the freshly built `libpam_validity.so`, `pam_authenticate`, and a
//! fake fprintd (scripted Manager and Device objects) on a private
//! `dbus-daemon`, which the module reaches through its `bus=` option.
//!
//! Needs `dbus-daemon` and libpam (`libpam.so.0`). Not built where the
//! toolchain links statically (musl crt-static): no shared object, no module.

#![cfg(not(target_feature = "crt-static"))]
#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zbus::object_server::SignalEmitter;
use zbus::{Connection, OwnedObjectPath};

const DEVICE_PATH: &str = "/net/reactivated/Fprint/Device/0";

// ------------------------------------------------------------- the bus

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "pam-validity-test-{}-{tag}-{n}",
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
  <type>pam-validity-test</type>
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

// ------------------------------------------------------- a fake fprintd

/// What the fake does.
#[derive(Clone)]
struct Script {
    device: bool,
    /// `None`: ListEnrolledFingers fails (fprintd's NoEnrolledPrints).
    fingers: Option<Vec<&'static str>>,
    claim_ok: bool,
    start_ok: bool,
    /// The VerifyStatus signals (result, done) after each VerifyStart.
    attempts: Vec<Vec<(&'static str, bool)>>,
    /// The signals come from another peer on the bus, not from the owner
    /// of net.reactivated.Fprint.
    forged: bool,
}

impl Default for Script {
    fn default() -> Self {
        Script {
            device: true,
            fingers: Some(vec!["right-index-finger"]),
            claim_ok: true,
            start_ok: true,
            attempts: vec![vec![("verify-match", true)]],
            forged: false,
        }
    }
}

/// What the fake was asked.
#[derive(Debug, Default, PartialEq, Eq)]
struct Calls {
    listed: Vec<String>,
    claimed: Vec<String>,
    started: Vec<String>,
    stopped: usize,
    released: usize,
}

struct Manager {
    script: Script,
}

#[zbus::interface(name = "net.reactivated.Fprint.Manager")]
impl Manager {
    fn get_default_device(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        if !self.script.device {
            return Err(zbus::fdo::Error::Failed("No devices available".into()));
        }
        Ok(OwnedObjectPath::try_from(DEVICE_PATH).unwrap())
    }
}

struct Device {
    script: Script,
    calls: Arc<Mutex<Calls>>,
    forger: Connection,
}

fn failed(what: &str) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(what.to_string())
}

#[zbus::interface(name = "net.reactivated.Fprint.Device")]
impl Device {
    fn list_enrolled_fingers(&self, username: &str) -> zbus::fdo::Result<Vec<String>> {
        self.calls.lock().unwrap().listed.push(username.to_string());
        let fingers = self
            .script
            .fingers
            .as_ref()
            .ok_or_else(|| failed("no enrolled prints"))?;
        Ok(fingers.iter().map(|s| s.to_string()).collect())
    }
    fn claim(&self, username: &str) -> zbus::fdo::Result<()> {
        self.calls
            .lock()
            .unwrap()
            .claimed
            .push(username.to_string());
        if self.script.claim_ok {
            Ok(())
        } else {
            Err(failed("in use"))
        }
    }
    fn release(&self) {
        self.calls.lock().unwrap().released += 1;
    }
    fn verify_stop(&self) {
        self.calls.lock().unwrap().stopped += 1;
    }
    fn verify_start(
        &self,
        finger_name: &str,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> zbus::fdo::Result<()> {
        let n = {
            let mut calls = self.calls.lock().unwrap();
            calls.started.push(finger_name.to_string());
            calls.started.len() - 1
        };
        if !self.script.start_ok {
            return Err(failed("cannot verify"));
        }
        let statuses = self.script.attempts.get(n).cloned().unwrap_or_default();
        let sender = hdr.sender().unwrap().to_owned();
        let (conn, forged) = (conn.clone(), self.script.forged);
        let forger = self.forger.clone();
        zruntime::spawn(async move {
            zruntime::SharedRuntime::current()
                .unwrap()
                .sleep(Duration::from_millis(50))
                .await;
            for (result, done) in statuses {
                if forged {
                    forger
                        .emit_signal(
                            None::<&str>,
                            DEVICE_PATH,
                            "net.reactivated.Fprint.Device",
                            "VerifyStatus",
                            &(result, done),
                        )
                        .await
                        .unwrap();
                } else {
                    // Unicast to the claimant, as validity-daemon sends them.
                    let em = SignalEmitter::new(&conn, DEVICE_PATH)
                        .unwrap()
                        .set_destination(sender.clone().into());
                    Device::verify_status(&em, result, done).await.unwrap();
                }
            }
        })
        .detach();
        Ok(())
    }

    #[zbus(signal)]
    async fn verify_status(
        emitter: &SignalEmitter<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;
}

/// Serves the script on `address` (as net.reactivated.Fprint unless `own` is false).
fn serve(address: &str, script: Script, own: bool) -> Arc<Mutex<Calls>> {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let (address, c) = (address.to_string(), calls.clone());
    let (ready, wait) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        zbus::block_on(async move {
            let forger = zbus::connection::Builder::address(address.as_str())
                .build()
                .await
                .unwrap();
            let mut b = zbus::connection::Builder::address(address.as_str())
                .serve_at(
                    "/net/reactivated/Fprint/Manager",
                    Manager {
                        script: script.clone(),
                    },
                )
                .serve_at(
                    DEVICE_PATH,
                    Device {
                        script,
                        calls: c,
                        forger,
                    },
                );
            if own {
                b = b.name("net.reactivated.Fprint");
            }
            let _conn = b.build().await.unwrap();
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        })
    });
    wait.recv_timeout(Duration::from_secs(10))
        .expect("fake fprintd up");
    calls
}

// ----------------------------------------------------------- libpam

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}
#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}
type ConvFn = unsafe extern "C" fn(
    c_int,
    *mut *const PamMessage,
    *mut *mut PamResponse,
    *mut c_void,
) -> c_int;
#[repr(C)]
struct PamConv {
    conv: Option<ConvFn>,
    appdata_ptr: *mut c_void,
}
#[repr(C)]
struct PamHandle {
    _private: [u8; 0],
}

#[link(name = "libpam.so.0", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn pam_start_confdir(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        confdir: *const c_char,
        pamh: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_setcred(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_end(pamh: *mut PamHandle, status: c_int) -> c_int;
}

const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERR: c_int = 7;
const PAM_AUTHINFO_UNAVAIL: c_int = 9;
const PAM_CONV_ERR: c_int = 19;
const PAM_TEXT_INFO: c_int = 4;
const PAM_SILENT: c_int = 0x8000;
const PAM_ESTABLISH_CRED: c_int = 2;

/// Records every message, prompts included; answers none (prompts fail).
unsafe extern "C" fn record(
    n: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    data: *mut c_void,
) -> c_int {
    let mut rc = PAM_SUCCESS;
    // SAFETY: libpam passes `n` messages and our `Mutex<Vec<..>>` as `data`.
    unsafe {
        *resp = std::ptr::null_mut();
        let seen = &*data.cast::<Mutex<Vec<(c_int, String)>>>();
        for i in 0..usize::try_from(n).unwrap() {
            let m = &**msg.add(i);
            if m.msg_style != PAM_TEXT_INFO {
                rc = PAM_CONV_ERR;
            }
            let text = CStr::from_ptr(m.msg).to_string_lossy().into_owned();
            seen.lock().unwrap().push((m.msg_style, text));
        }
    }
    rc
}

struct Run {
    rc: c_int,
    setcred: c_int,
    said: Vec<(c_int, String)>,
    took: Duration,
}

/// What a match with `confirm` says, and all the module ever says.
fn granted() -> Vec<(c_int, String)> {
    vec![(PAM_TEXT_INFO, "Access granted".to_string())]
}

/// `pam_authenticate` (then `pam_setcred`) for `user` with the module line's
/// `args` and `conv` (or a conversation without a function).
fn pam_with(bus: &str, args: &str, user: Option<&str>, flags: c_int, conv: bool) -> Run {
    let module = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("libpam_validity.so");
    assert!(module.exists(), "{} not built", module.display());
    let dir = TempDir::new("conf");
    std::fs::write(
        dir.0.join("validity-test"),
        format!("auth required {} bus={bus} {args}\n", module.display()),
    )
    .unwrap();
    let seen: Mutex<Vec<(c_int, String)>> = Mutex::new(Vec::new());
    let conv = PamConv {
        conv: if conv { Some(record) } else { None },
        appdata_ptr: (&raw const seen).cast_mut().cast(),
    };
    let service = CString::new("validity-test").unwrap();
    let user = user.map(|u| CString::new(u).unwrap());
    let confdir = CString::new(dir.0.to_str().unwrap()).unwrap();
    let mut pamh: *mut PamHandle = std::ptr::null_mut();
    // SAFETY: valid strings and conversation, alive until pam_end.
    let (rc, setcred, took) = unsafe {
        let user = user.as_ref().map_or(std::ptr::null(), |u| u.as_ptr());
        assert_eq!(
            pam_start_confdir(service.as_ptr(), user, &conv, confdir.as_ptr(), &mut pamh),
            PAM_SUCCESS
        );
        let start = Instant::now();
        let rc = pam_authenticate(pamh, flags);
        let took = start.elapsed();
        let setcred = pam_setcred(pamh, PAM_ESTABLISH_CRED);
        pam_end(pamh, rc);
        (rc, setcred, took)
    };
    Run {
        rc,
        setcred,
        said: seen.into_inner().unwrap(),
        took,
    }
}

fn pam(bus: &str, args: &str) -> Run {
    pam_with(bus, args, Some("alice"), 0, true)
}

/// A private bus with the fake on it, and one authentication.
fn run(script: Script, args: &str) -> (Run, Calls) {
    let bus = PrivateBus::start();
    let calls = serve(&bus.address, script, true);
    let r = pam(&bus.address, args);
    let c = std::mem::take(&mut *calls.lock().unwrap());
    (r, c)
}

fn calls(started: usize, stopped: usize) -> Calls {
    Calls {
        listed: vec!["alice".into()],
        claimed: vec!["alice".into()],
        started: vec!["any".into(); started],
        stopped,
        released: 1,
    }
}

// ------------------------------------------------------------ the tests

#[test]
fn match_confirmed_with_one_line() {
    let (r, c) = run(Script::default(), "max-tries=1 timeout=5 confirm");
    assert_eq!((r.rc, r.said), (PAM_SUCCESS, granted()));
    assert_eq!(c, calls(1, 1));
    assert_eq!(r.setcred, PAM_SUCCESS);
}

#[test]
fn match_without_confirm_says_nothing() {
    let script = Script {
        fingers: Some(vec!["left-thumb", "right-index-finger"]),
        ..Script::default()
    };
    let (r, c) = run(script, "max-tries=1 timeout=5");
    assert_eq!((r.rc, r.said), (PAM_SUCCESS, vec![]));
    assert_eq!(c, calls(1, 1));
}

#[test]
fn refused_finger() {
    let script = Script {
        attempts: vec![vec![("verify-no-match", true)]],
        ..Script::default()
    };
    let (r, c) = run(script, "max-tries=1 timeout=5 confirm");
    assert_eq!((r.rc, r.said), (PAM_AUTH_ERR, vec![]));
    assert_eq!(c, calls(1, 1));
}

#[test]
fn second_try_matches() {
    let script = Script {
        attempts: vec![
            vec![("verify-no-match", true)],
            vec![("verify-match", true)],
        ],
        ..Script::default()
    };
    let (r, c) = run(script.clone(), "max-tries=2 timeout=5 confirm");
    assert_eq!((r.rc, r.said), (PAM_SUCCESS, granted()));
    assert_eq!(c, calls(2, 2));
    // The default is three tries.
    let (r, c) = run(script, "timeout=5");
    assert_eq!((r.rc, r.said), (PAM_SUCCESS, vec![]));
    assert_eq!(c, calls(2, 2));
}

#[test]
fn tries_run_out() {
    let script = Script {
        attempts: vec![
            vec![("verify-no-match", true)],
            vec![("verify-no-match", true)],
            vec![("verify-match", true)],
        ],
        ..Script::default()
    };
    let (r, c) = run(script, "max-tries=2 timeout=5 confirm");
    assert_eq!((r.rc, r.said), (PAM_AUTH_ERR, vec![]));
    assert_eq!(c, calls(2, 2));
}

#[test]
fn retry_statuses_keep_waiting() {
    let script = Script {
        attempts: vec![vec![
            ("verify-retry-scan", false),
            ("verify-no-match", false),
            ("verify-match", true),
        ]],
        ..Script::default()
    };
    let (r, c) = run(script, "max-tries=1 timeout=5 confirm");
    assert_eq!((r.rc, r.said), (PAM_SUCCESS, granted()));
    assert_eq!(c, calls(1, 1));
}

#[test]
fn final_failures() {
    for (status, rc) in [
        ("verify-disconnected", PAM_AUTHINFO_UNAVAIL),
        ("verify-unknown-error", PAM_AUTHINFO_UNAVAIL),
        ("verify-something-new", PAM_AUTH_ERR),
    ] {
        // Never retried, whatever max-tries says, except a no-match.
        let script = Script {
            attempts: vec![vec![(status, true)], vec![("verify-match", true)]],
            ..Script::default()
        };
        let max = if rc == PAM_AUTH_ERR {
            "max-tries=1"
        } else {
            "max-tries=3"
        };
        let (r, c) = run(script, &format!("{max} timeout=5 confirm"));
        assert_eq!((r.rc, r.said), (rc, vec![]), "{status}");
        assert_eq!(c, calls(1, 1), "{status}");
    }
}

#[test]
fn no_finger_in_time() {
    let script = Script {
        attempts: vec![vec![]],
        ..Script::default()
    };
    let (r, c) = run(script, "max-tries=3 timeout=1 confirm");
    assert_eq!((r.rc, &r.said), (PAM_AUTHINFO_UNAVAIL, &vec![]));
    assert!(
        r.took >= Duration::from_secs(1) && r.took < Duration::from_secs(3),
        "{:?}",
        r.took
    );
    assert_eq!(c, calls(1, 1));
}

#[test]
fn forged_match_from_another_peer_is_ignored() {
    let script = Script {
        forged: true,
        ..Script::default()
    };
    let (r, c) = run(script, "max-tries=1 timeout=1 confirm");
    assert_eq!((r.rc, r.said), (PAM_AUTHINFO_UNAVAIL, vec![]));
    assert_eq!(c, calls(1, 1));
}

#[test]
fn no_device() {
    let script = Script {
        device: false,
        ..Script::default()
    };
    let (r, c) = run(script, "confirm");
    assert_eq!((r.rc, r.said), (PAM_AUTHINFO_UNAVAIL, vec![]));
    assert_eq!(c, Calls::default());
}

#[test]
fn no_enrolled_finger() {
    for fingers in [None, Some(vec![])] {
        let (r, c) = run(
            Script {
                fingers,
                ..Script::default()
            },
            "confirm",
        );
        assert_eq!((r.rc, r.said), (PAM_AUTHINFO_UNAVAIL, vec![]));
        assert_eq!(
            c,
            Calls {
                listed: vec!["alice".into()],
                ..Calls::default()
            }
        );
    }
}

#[test]
fn claim_refused() {
    let script = Script {
        claim_ok: false,
        ..Script::default()
    };
    let (r, c) = run(script, "confirm");
    assert_eq!((r.rc, r.said), (PAM_AUTHINFO_UNAVAIL, vec![]));
    assert_eq!(
        c,
        Calls {
            listed: vec!["alice".into()],
            claimed: vec!["alice".into()],
            ..Calls::default()
        }
    );
}

#[test]
fn verify_refused_released() {
    let script = Script {
        start_ok: false,
        ..Script::default()
    };
    let (r, c) = run(script, "confirm");
    assert_eq!((r.rc, r.said), (PAM_AUTHINFO_UNAVAIL, vec![]));
    assert_eq!(c, calls(1, 0));
}

#[test]
fn nobody_owns_the_name() {
    let bus = PrivateBus::start();
    let calls = serve(&bus.address, Script::default(), false);
    let r = pam(&bus.address, "confirm");
    assert_eq!((r.rc, &r.said), (PAM_AUTHINFO_UNAVAIL, &vec![]));
    assert!(r.took < Duration::from_secs(2), "{:?}", r.took);
    assert_eq!(*calls.lock().unwrap(), Calls::default());
}

#[test]
fn no_bus() {
    let dir = TempDir::new("nobus");
    let r = pam(&format!("unix:path={}/socket", dir.0.display()), "confirm");
    assert_eq!((r.rc, &r.said), (PAM_AUTHINFO_UNAVAIL, &vec![]));
    assert!(r.took < Duration::from_secs(2), "{:?}", r.took);
}

#[test]
fn silent_or_no_conversation_matches_without_a_word() {
    let bus = PrivateBus::start();
    let _calls = serve(&bus.address, Script::default(), true);
    let r = pam_with(
        &bus.address,
        "timeout=5 confirm",
        Some("alice"),
        PAM_SILENT,
        true,
    );
    assert_eq!((r.rc, r.said), (PAM_SUCCESS, vec![]));
    // A fresh fake: its script answers one VerifyStart.
    let bus = PrivateBus::start();
    let _calls = serve(&bus.address, Script::default(), true);
    let r = pam_with(&bus.address, "timeout=5 confirm", Some("alice"), 0, false);
    assert_eq!(r.rc, PAM_SUCCESS);
}

#[test]
fn no_user_no_question() {
    let bus = PrivateBus::start();
    let calls = serve(&bus.address, Script::default(), true);
    // No user: the module fails without asking for one.
    let r = pam_with(&bus.address, "timeout=5 confirm", None, 0, true);
    assert_eq!((r.rc, r.said), (PAM_AUTHINFO_UNAVAIL, vec![]));
    assert_eq!(*calls.lock().unwrap(), Calls::default());
}
