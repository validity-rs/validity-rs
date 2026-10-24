//! The D-Bus side: `net.reactivated.Fprint` with fprintd 1.94.5's Manager and
//! Device interfaces, served with zbus.
//!
//! zbus 6 is async only. The whole D-Bus side runs on one thread
//! (`zbus::block_on`, zruntime's single-threaded runtime): method handlers,
//! the task forwarding the sensor thread's events as signals, the watcher of
//! claiming clients, and the logind sleep watcher. Handlers never block: they
//! take the state lock for a few instructions, send the sensor thread a
//! command, and await replies, polkit and the bus. Sensor I/O is blocking and
//! lives on its own thread (`worker`).

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use futures_core::Stream;
use validity_proto::vendor::Blobs;
use zbus::message::{Header, Message};
use zbus::names::BusName;
use zbus::object_server::{ResponseDispatchNotifier, SignalEmitter};
use zbus::{Connection, MatchRule, MessageStream, OwnedFd, OwnedObjectPath, fdo, interface};

use crate::errors::FprintError;
use crate::machine::{ActionKind, Availability, Emit, Event, Machine, OpId, Stop};
use crate::polkit::{self, Authority};
use crate::sensor::{self, Canceller, Hardware, Sink};
use crate::users::{SidMap, User, UserDb, finger_subtype};
use crate::worker::{Command, DeleteError, Timing, Worker};

pub const BUS_NAME: &str = "net.reactivated.Fprint";
pub const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
pub const DEVICE_PATH: &str = "/net/reactivated/Fprint/Device/0";

/// Delays of the D-Bus side.
#[derive(Debug, Clone)]
pub struct Options {
    /// How long Claim and ListEnrolledFingers wait for a sensor that is coming
    /// up (start, resume, recovery).
    pub ready_timeout: Duration,
    /// How long VerifyStop / EnrollStop / Release wait for the sensor thread to
    /// end a run.
    pub stop_timeout: Duration,
    /// How long a delete may take.
    pub delete_timeout: Duration,
    /// How long the sensor is given to close before sleep (logind's default
    /// InhibitDelayMaxSec is 5 s).
    pub sleep_timeout: Duration,
    pub timing: Timing,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            ready_timeout: Duration::from_secs(3),
            stop_timeout: Duration::from_secs(4),
            delete_timeout: Duration::from_secs(30),
            sleep_timeout: Duration::from_secs(4),
            timing: Timing::default(),
        }
    }
}

/// Who decides and who is who.
pub struct Deps {
    pub authority: Arc<dyn Authority>,
    pub users: Arc<dyn UserDb>,
    pub sids: SidMap,
}

/// What the sensor thread needs besides the hardware.
#[derive(Debug)]
pub struct Setup {
    /// The vendor blobs, or why they are missing.
    pub blobs: Result<Blobs, String>,
    pub calibration: std::path::PathBuf,
}

pub use crate::config::Bus;

impl std::fmt::Debug for Deps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deps")
            .field("sids", &self.sids)
            .finish_non_exhaustive()
    }
}

struct Ctx {
    machine: Mutex<Machine>,
    /// Notified after every change of `machine`.
    changed: zruntime::Event,
    commands: mpsc::Sender<Command>,
    canceller: Arc<Canceller>,
    deps: Deps,
    opts: Options,
    /// Watchers of claiming clients, by claim id.
    watchers: Mutex<HashMap<u64, zruntime::Task<(), zruntime::Shared>>>,
}

fn rt() -> zruntime::SharedRuntime {
    zruntime::SharedRuntime::current().expect("the D-Bus side runs inside zbus::block_on")
}

/// `None` if `f` did not finish within `d`.
async fn timeout<F: Future + Send>(d: Duration, f: F) -> Option<F::Output>
where
    F::Output: Send,
{
    rt().timeout(d, f).await.ok()
}

async fn next<S: Stream + Unpin>(s: &mut S) -> Option<S::Item> {
    poll_fn(|cx| Pin::new(&mut *s).poll_next(cx)).await
}

fn sender_of(hdr: &Header<'_>) -> Result<String, FprintError> {
    hdr.sender()
        .map(|s| s.to_string())
        .ok_or_else(|| FprintError::Internal("method call without a sender".into()))
}

impl Ctx {
    fn m(&self) -> MutexGuard<'_, Machine> {
        self.machine.lock().expect("state lock")
    }

    fn send(&self, c: Command) {
        if self.commands.send(c).is_err() {
            log::error!("the sensor thread is gone");
        }
    }

    fn notify(&self) {
        self.changed.notify(usize::MAX);
    }

    /// Waits until `ready` says something about the state, or `d`.
    async fn wait_for<R>(&self, d: Duration, ready: impl Fn(&Machine) -> Option<R>) -> Option<R> {
        let deadline = Instant::now() + d;
        loop {
            let listener = self.changed.listen();
            if let Some(r) = ready(&self.m()) {
                return Some(r);
            }
            if rt().timeout_at(deadline, listener).await.is_err() {
                return ready(&self.m());
            }
        }
    }

    /// Ready now, or soon (bounded wait), or an error at once.
    async fn wait_available(&self) -> Result<(), FprintError> {
        let r = self
            .wait_for(self.opts.ready_timeout, |m| match m.device.availability() {
                Availability::Ready => Some(Ok(())),
                Availability::Unavailable(why) => Some(Err(FprintError::Internal(why))),
                Availability::Soon => None,
            })
            .await;
        r.unwrap_or_else(|| {
            Err(FprintError::Internal(format!(
                "fingerprint sensor not ready ({})",
                self.m().device.label()
            )))
        })
    }

    async fn caller(&self, conn: &Connection, sender: &str) -> Result<User, FprintError> {
        let dbus = fdo::DBusProxy::new(conn)
            .await
            .map_err(|e| FprintError::Internal(e.to_string()))?;
        let name = BusName::try_from(sender).map_err(|e| FprintError::Internal(e.to_string()))?;
        let uid = dbus.get_connection_unix_user(name).await.map_err(|e| {
            FprintError::Internal(format!("Could not get connection unix user ID: {e}"))
        })?;
        let users = self.deps.users.clone();
        zruntime::unblock(move || users.by_uid(uid))
            .await
            .ok_or_else(|| {
                FprintError::Internal(format!("Failed to get information about user UID {uid}"))
            })
    }

    /// The user a call is for: the caller for "" or their own name; another
    /// user needs `setusername`. `None` when that user does not exist.
    async fn target(
        &self,
        conn: &Connection,
        sender: &str,
        username: &str,
    ) -> Result<Option<User>, FprintError> {
        let me = self.caller(conn, sender).await?;
        if username.is_empty() || username == me.name {
            return Ok(Some(me));
        }
        polkit::require_any(
            self.deps.authority.as_ref(),
            conn,
            sender,
            &[polkit::SETUSERNAME],
        )
        .await?;
        let users = self.deps.users.clone();
        let name = username.to_string();
        Ok(zruntime::unblock(move || users.by_name(&name)).await)
    }

    async fn authorize(
        &self,
        conn: &Connection,
        sender: &str,
        actions: &[&str],
    ) -> Result<(), FprintError> {
        polkit::require_any(self.deps.authority.as_ref(), conn, sender, actions).await
    }

    /// Cancels `op` and waits (bounded) for the sensor thread to end it.
    async fn stop_run(&self, op: OpId) {
        self.canceller.cancel(op);
        let done = self
            .wait_for(self.opts.stop_timeout, |m| {
                (m.last_ended >= op).then_some(())
            })
            .await;
        if done.is_none() {
            log::warn!("the sensor did not stop run {op} in time");
        }
    }

    async fn delete(
        &self,
        sid: validity_proto::sid::Sid,
        finger: Option<u16>,
    ) -> Result<(), FprintError> {
        let (tx, rx) = zruntime::mpmc::bounded(std::num::NonZeroUsize::MIN);
        self.send(Command::Delete {
            sid,
            finger,
            reply: tx,
        });
        match timeout(self.opts.delete_timeout, rx.recv()).await {
            Some(Ok(Ok(()))) => Ok(()),
            Some(Ok(Err(DeleteError::NotEnrolled))) => Err(FprintError::NoEnrolledPrints(
                "No fingerprint enrolled".into(),
            )),
            Some(Ok(Err(DeleteError::Unavailable(m)))) => Err(FprintError::Internal(m)),
            Some(Ok(Err(DeleteError::Failed(m)))) => Err(FprintError::PrintsNotDeleted(format!(
                "Failed to delete print from the sensor: {m}"
            ))),
            Some(Err(_)) => Err(FprintError::Internal("the sensor thread is gone".into())),
            None => Err(FprintError::PrintsNotDeleted(
                "the sensor did not answer in time".into(),
            )),
        }
    }

    fn end_watch(&self, claim_id: u64) {
        self.watchers
            .lock()
            .expect("watcher lock")
            .remove(&claim_id);
    }
}

pub struct Manager {
    ctx: Arc<Ctx>,
}

impl std::fmt::Debug for Manager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Manager")
    }
}

#[interface(name = "net.reactivated.Fprint.Manager")]
impl Manager {
    /// The device, unless no supported sensor is plugged in. A sensor that is
    /// coming up, broken or needing setup is listed (calls on it fail fast).
    #[zbus(out_args("devices"))]
    async fn get_devices(&self) -> Vec<OwnedObjectPath> {
        if self.ctx.m().device == crate::machine::DeviceState::Absent {
            return Vec::new();
        }
        vec![OwnedObjectPath::try_from(DEVICE_PATH).expect("valid path")]
    }

    #[zbus(out_args("device"))]
    async fn get_default_device(&self) -> Result<OwnedObjectPath, FprintError> {
        if self.ctx.m().device == crate::machine::DeviceState::Absent {
            return Err(FprintError::NoSuchDevice("No devices available".into()));
        }
        Ok(OwnedObjectPath::try_from(DEVICE_PATH).expect("valid path"))
    }
}

pub struct Device {
    ctx: Arc<Ctx>,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never waits for the state lock: Debug may run while it is held.
        let state = self.ctx.machine.try_lock().map(|m| m.device.clone()).ok();
        f.debug_struct("Device")
            .field("state", &state)
            .finish_non_exhaustive()
    }
}

impl Device {
    /// Starts a watcher that releases the claim when its client leaves the bus
    /// (pam_fprintd disconnects without Release after a match).
    fn watch_claimant(&self, conn: &Connection, sender: String, claim_id: u64) {
        let ctx = self.ctx.clone();
        let conn = conn.clone();
        let task = zruntime::spawn(async move {
            let gone = async {
                let dbus = fdo::DBusProxy::new(&conn).await?;
                let mut changes = dbus
                    .receive_name_owner_changed_with_args(&[(0, sender.as_str())])
                    .await?;
                let name = BusName::try_from(sender.as_str())?;
                if !dbus.name_has_owner(name).await? {
                    return Ok::<_, zbus::Error>(());
                }
                while let Some(sig) = next(&mut changes).await {
                    if let Ok(a) = sig.args()
                        && a.new_owner().is_none()
                    {
                        break;
                    }
                }
                Ok(())
            };
            if let Err(e) = gone.await {
                log::warn!("cannot watch client {sender}: {e}");
                return;
            }
            let op = ctx.m().vanished(&sender);
            if let Some(op) = op {
                log::info!("client {sender} left the bus: device released");
                if let Some(op) = op {
                    ctx.canceller.cancel(op);
                }
                ctx.notify();
            }
            ctx.watchers.lock().expect("watcher lock").remove(&claim_id);
        });
        self.ctx
            .watchers
            .lock()
            .expect("watcher lock")
            .insert(claim_id, task);
    }

    async fn stop(&self, hdr: Header<'_>, kind: ActionKind) -> Result<(), FprintError> {
        let sender = sender_of(&hdr)?;
        let r = self.ctx.m().stop(&sender, kind)?;
        self.ctx.notify();
        if let Stop::Cancel(op) = r {
            self.ctx.stop_run(op).await;
        }
        Ok(())
    }

    async fn delete_claimed(
        &self,
        hdr: Header<'_>,
        conn: &Connection,
        finger: Option<u16>,
    ) -> Result<(), FprintError> {
        let sender = sender_of(&hdr)?;
        self.ctx.m().claimant(&sender)?;
        self.ctx.authorize(conn, &sender, &[polkit::ENROLL]).await?;
        let (sid, op) = self.ctx.m().start_delete(&sender, finger)?;
        let r = self.ctx.delete(sid, finger).await;
        self.ctx.m().finish_delete(op);
        self.ctx.notify();
        r
    }
}

#[interface(name = "net.reactivated.Fprint.Device")]
impl Device {
    #[zbus(out_args("enrolled_fingers"))]
    async fn list_enrolled_fingers(
        &self,
        username: &str,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<Vec<String>, FprintError> {
        let sender = sender_of(&hdr)?;
        let user = self.ctx.target(conn, &sender, username).await?;
        self.ctx.authorize(conn, &sender, &[polkit::VERIFY]).await?;
        let Some(user) = user else {
            return Err(FprintError::NoEnrolledPrints(
                "Failed to discover prints".into(),
            ));
        };
        self.ctx.wait_available().await?;
        let sid = self.ctx.deps.sids.sid(&user);
        self.ctx.m().list(&sid)
    }

    async fn delete_enrolled_fingers(
        &self,
        username: &str,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), FprintError> {
        let sender = sender_of(&hdr)?;
        log::warn!(
            "a client uses the deprecated DeleteEnrolledFingers; DeleteEnrolledFingers2 replaces it"
        );
        {
            let m = self.ctx.m();
            if m.claim.is_some() {
                m.claimant(&sender)?;
            }
        }
        let user = self.ctx.target(conn, &sender, username).await?;
        self.ctx.authorize(conn, &sender, &[polkit::ENROLL]).await?;
        let Some(user) = user else {
            return Err(FprintError::NoEnrolledPrints(
                "No fingerprint enrolled".into(),
            ));
        };
        self.ctx.wait_available().await?;
        let sid = self.ctx.deps.sids.sid(&user);
        self.ctx.m().check_legacy_delete(&sender, &sid)?;
        self.ctx.delete(sid, None).await
    }

    async fn delete_enrolled_fingers2(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), FprintError> {
        self.delete_claimed(hdr, conn, None).await
    }

    async fn delete_enrolled_finger(
        &self,
        finger_name: &str,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), FprintError> {
        {
            let sender = sender_of(&hdr)?;
            self.ctx.m().claimant(&sender)?;
        }
        let finger = finger_subtype(finger_name)
            .ok_or_else(|| FprintError::InvalidFingername("Invalid finger name".into()))?;
        self.delete_claimed(hdr, conn, Some(finger)).await
    }

    async fn claim(
        &self,
        username: &str,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), FprintError> {
        let sender = sender_of(&hdr)?;
        self.ctx.m().check_unclaimed()?;
        let user = self.ctx.target(conn, &sender, username).await?;
        self.ctx
            .authorize(conn, &sender, &[polkit::VERIFY, polkit::ENROLL])
            .await?;
        let user =
            user.ok_or_else(|| FprintError::Internal(format!("unknown user {username:?}")))?;
        self.ctx.wait_available().await?;
        let sid = self.ctx.deps.sids.sid(&user);
        let name = user.name.clone();
        let id = self.ctx.m().claim(&sender, user, sid)?;
        self.ctx.notify();
        log::info!("device claimed by {sender} for user {name}");
        self.watch_claimant(conn, sender, id);
        Ok(())
    }

    async fn release(&self, #[zbus(header)] hdr: Header<'_>) -> Result<(), FprintError> {
        let sender = sender_of(&hdr)?;
        let (op, id) = {
            let mut m = self.ctx.m();
            let id = m.claimant(&sender)?.id;
            (m.release(&sender)?, id)
        };
        self.ctx.notify();
        self.ctx.end_watch(id);
        if let Some(op) = op {
            log::info!("released during a run: stopping it");
            self.ctx.stop_run(op).await;
        }
        log::info!("device released by {sender}");
        Ok(())
    }

    async fn verify_start(
        &self,
        finger_name: &str,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<ResponseDispatchNotifier<()>, FprintError> {
        let sender = sender_of(&hdr)?;
        self.ctx.m().claimant(&sender)?;
        self.ctx.authorize(conn, &sender, &[polkit::VERIFY]).await?;
        let v = self.ctx.m().start_verify(&sender, finger_name)?;
        self.ctx.notify();
        log::debug!("run {}: verify {}", v.op, v.selected);
        // Signals go out after the reply: clients ignore them before.
        let (reply, sent) = ResponseDispatchNotifier::new(());
        let ctx = self.ctx.clone();
        let conn = conn.clone();
        zruntime::spawn(async move {
            sent.await;
            emit(
                &conn,
                Emit::VerifyFingerSelected {
                    dest: sender,
                    finger: v.selected,
                },
            )
            .await;
            ctx.send(Command::Verify {
                op: v.op,
                sid: v.sid,
                finger: v.finger,
            });
        })
        .detach();
        Ok(reply)
    }

    async fn verify_stop(&self, #[zbus(header)] hdr: Header<'_>) -> Result<(), FprintError> {
        self.stop(hdr, ActionKind::Verify).await
    }

    async fn enroll_start(
        &self,
        finger_name: &str,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<ResponseDispatchNotifier<()>, FprintError> {
        let sender = sender_of(&hdr)?;
        self.ctx.m().claimant(&sender)?;
        if finger_subtype(finger_name).is_none() {
            return Err(FprintError::InvalidFingername("Invalid finger name".into()));
        }
        self.ctx.authorize(conn, &sender, &[polkit::ENROLL]).await?;
        let e = self.ctx.m().start_enroll(&sender, finger_name)?;
        self.ctx.notify();
        log::debug!("run {}: enroll {finger_name}", e.op);
        let (reply, sent) = ResponseDispatchNotifier::new(());
        let ctx = self.ctx.clone();
        zruntime::spawn(async move {
            sent.await;
            ctx.send(Command::Enroll {
                op: e.op,
                sid: e.sid,
                finger: e.finger,
                replace: e.replace,
            });
        })
        .detach();
        Ok(reply)
    }

    async fn enroll_stop(&self, #[zbus(header)] hdr: Header<'_>) -> Result<(), FprintError> {
        self.stop(hdr, ActionKind::Enroll).await
    }

    #[zbus(signal)]
    async fn verify_finger_selected(
        emitter: &SignalEmitter<'_>,
        finger_name: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn verify_status(
        emitter: &SignalEmitter<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn enroll_status(
        emitter: &SignalEmitter<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;

    #[zbus(property, name = "name")]
    fn name(&self) -> String {
        self.ctx.m().name.clone()
    }

    #[zbus(property, name = "num-enroll-stages")]
    fn num_enroll_stages(&self) -> i32 {
        sensor::ENROLL_STAGES
    }

    #[zbus(property, name = "scan-type")]
    fn scan_type(&self) -> String {
        "press".into()
    }

    #[zbus(property, name = "finger-present")]
    fn finger_present(&self) -> bool {
        self.ctx.m().finger_present
    }

    #[zbus(property, name = "finger-needed")]
    fn finger_needed(&self) -> bool {
        self.ctx.m().finger_needed
    }
}

async fn emit(conn: &Connection, e: Emit) {
    let unicast = |dest: &str| -> zbus::Result<SignalEmitter<'static>> {
        Ok(SignalEmitter::new(conn, DEVICE_PATH)?
            .set_destination(BusName::try_from(dest.to_string())?))
    };
    let r: zbus::Result<()> = async {
        match e {
            Emit::VerifyStatus { dest, result, done } => {
                Device::verify_status(&unicast(&dest)?, result, done).await
            }
            Emit::EnrollStatus { dest, result, done } => {
                Device::enroll_status(&unicast(&dest)?, result, done).await
            }
            Emit::VerifyFingerSelected { dest, finger } => {
                Device::verify_finger_selected(&unicast(&dest)?, finger).await
            }
            Emit::FingerPresent(_) | Emit::FingerNeeded(_) | Emit::Name => {
                let iface = conn
                    .object_server()
                    .interface::<_, Device>(DEVICE_PATH)
                    .await?;
                let dev = iface.get().await;
                let em = iface.signal_emitter();
                match e {
                    Emit::FingerPresent(_) => dev.finger_present_changed(em).await,
                    Emit::FingerNeeded(_) => dev.finger_needed_changed(em).await,
                    _ => dev.name_changed(em).await,
                }
            }
        }
    }
    .await;
    if let Err(err) = r {
        log::debug!("signal not sent: {err}");
    }
}

/// Applies the sensor thread's events and sends the resulting signals.
async fn forward(ctx: Arc<Ctx>, conn: Connection, events: zruntime::mpmc::Receiver<Event>) {
    while let Ok(ev) = events.recv().await {
        let emits = ctx.m().on_event(ev);
        ctx.notify();
        for e in emits {
            emit(&conn, e).await;
        }
    }
}

async fn take_inhibitor(conn: &Connection) -> Option<OwnedFd> {
    let r = conn
        .call_method(
            Some("org.freedesktop.login1"),
            "/org/freedesktop/login1",
            Some("org.freedesktop.login1.Manager"),
            "Inhibit",
            &(
                "sleep",
                "validity-daemon",
                "Close the fingerprint sensor session",
                "delay",
            ),
        )
        .await;
    match r.and_then(|m: Message| m.body().deserialize::<OwnedFd>()) {
        Ok(fd) => Some(fd),
        Err(e) => {
            log::info!("no logind sleep inhibitor: {e}");
            None
        }
    }
}

/// Whether `msg` comes from the owner of `org.freedesktop.login1`.
async fn from_logind(conn: &Connection, msg: &Message) -> bool {
    let Some(sender) = msg.header().sender().map(|s| s.to_string()) else {
        return false;
    };
    let Ok(dbus) = fdo::DBusProxy::new(conn).await else {
        return false;
    };
    let Ok(name) = BusName::try_from("org.freedesktop.login1") else {
        return false;
    };
    matches!(dbus.get_name_owner(name).await, Ok(owner) if owner.as_str() == sender)
}

/// Follows logind's PrepareForSleep: close the sensor before sleep (holding a
/// delay inhibitor until it is closed), open it again after.
async fn watch_sleep(ctx: Arc<Ctx>, conn: Connection) {
    let rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.login1.Manager")
        .member("PrepareForSleep")
        .path("/org/freedesktop/login1")
        .build();
    let mut stream = match rule {
        Ok(rule) => match MessageStream::for_match_rule(rule, &conn, None).await {
            Ok(s) => s,
            Err(e) => {
                log::warn!("cannot follow suspend/resume: {e}");
                return;
            }
        },
        Err(e) => {
            log::warn!("cannot follow suspend/resume: {e}");
            return;
        }
    };
    let mut inhibitor = take_inhibitor(&conn).await;
    while let Some(msg) = next(&mut stream).await {
        let Ok(msg) = msg else { continue };
        if !from_logind(&conn, &msg).await {
            log::warn!("ignoring a PrepareForSleep signal that logind did not send");
            continue;
        }
        let Ok(going) = msg.body().deserialize::<bool>() else {
            continue;
        };
        if going {
            log::info!("system going to sleep: closing the sensor");
            ctx.canceller.start_sleep();
            let (tx, rx) = zruntime::mpmc::bounded(std::num::NonZeroUsize::MIN);
            ctx.send(Command::Sleep { reply: tx });
            if timeout(ctx.opts.sleep_timeout, rx.recv()).await.is_none() {
                log::warn!("the sensor did not close before sleep");
            }
            // Releasing the inhibitor lets the suspend proceed.
            inhibitor = None;
        } else {
            log::info!("system woke up: reopening the sensor");
            ctx.send(Command::Wake);
            if inhibitor.is_none() {
                inhibitor = take_inhibitor(&conn).await;
            }
        }
    }
    drop(inhibitor);
}

/// Runs the service until `shutdown` completes. The sensor thread is started
/// first; the D-Bus objects exist from the start, whatever the sensor does.
pub async fn run<H: Hardware>(
    bus: Bus,
    hw: H,
    setup: Setup,
    deps: Deps,
    opts: Options,
    shutdown: impl Future<Output = ()>,
) -> Result<(), String> {
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (ev_tx, ev_rx) = zruntime::mpmc::unbounded();
    let canceller = Canceller::new();
    let sink: Sink = Arc::new(move |e| {
        let _ = ev_tx.try_send(e);
    });
    let worker = Worker::new(
        hw,
        setup.blobs.map(Arc::new),
        setup.calibration,
        cmd_rx,
        cmd_tx.clone(),
        sink,
        canceller.clone(),
        opts.timing.clone(),
    );
    let thread = std::thread::Builder::new()
        .name("sensor".into())
        .spawn(move || worker.run())
        .map_err(|e| format!("cannot start the sensor thread: {e}"))?;
    let ctx = Arc::new(Ctx {
        machine: Mutex::new(Machine::new()),
        changed: zruntime::Event::new(),
        commands: cmd_tx,
        canceller,
        deps,
        opts,
        watchers: Mutex::new(HashMap::new()),
    });

    let stop_worker = |ctx: Arc<Ctx>| async move {
        ctx.canceller.start_shutdown();
        let (tx, rx) = zruntime::mpmc::bounded(std::num::NonZeroUsize::MIN);
        ctx.send(Command::Shutdown { reply: tx });
        if timeout(Duration::from_secs(20), rx.recv()).await.is_none() {
            log::warn!("the sensor thread did not stop in time");
        }
    };

    let built = async {
        let b = match &bus {
            Bus::System => zbus::connection::Builder::system(),
            Bus::Session => zbus::connection::Builder::session(),
            Bus::Address(a) => zbus::connection::Builder::address(a.as_str()),
        };
        b.serve_at(MANAGER_PATH, Manager { ctx: ctx.clone() })
            .serve_at(DEVICE_PATH, Device { ctx: ctx.clone() })
            .name(BUS_NAME)
            .build()
            .await
    }
    .await;
    let conn = match built {
        Ok(c) => c,
        Err(e) => {
            stop_worker(ctx.clone()).await;
            return Err(format!("cannot serve {BUS_NAME}: {e}"));
        }
    };
    log::info!("serving {BUS_NAME} on {bus:?}");

    let forwarder = zruntime::spawn(forward(ctx.clone(), conn.clone(), ev_rx));
    let sleeper = zruntime::spawn(watch_sleep(ctx.clone(), conn.clone()));

    shutdown.await;
    log::info!("stopping");
    // Clients see the name go away first, then the sensor is closed.
    let _ = conn.release_name(BUS_NAME).await;
    stop_worker(ctx.clone()).await;
    drop(sleeper);
    drop(forwarder);
    ctx.watchers.lock().expect("watcher lock").clear();
    let joined = timeout(
        Duration::from_secs(20),
        zruntime::unblock(move || thread.join().is_ok()),
    )
    .await;
    if joined != Some(true) {
        log::warn!("the sensor thread did not end cleanly");
    }
    Ok(())
}

/// Completes on SIGTERM (systemd stopping the service) or SIGINT.
pub async fn termination() {
    use zruntime::signal::{Signal, Signals};
    let signals = zruntime::SharedRuntime::current()
        .and_then(|rt| Signals::new(&rt, [Signal::Terminate, Signal::Interrupt]));
    match signals {
        Ok(mut s) => match s.recv().await {
            Ok(sig) => log::info!("received {sig:?}"),
            Err(e) => {
                log::error!("waiting for SIGTERM failed: {e}");
                std::future::pending::<()>().await
            }
        },
        Err(e) => {
            log::error!("cannot handle SIGTERM: {e}");
            std::future::pending::<()>().await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::DeviceState;

    fn ctx() -> Arc<Ctx> {
        let (commands, _) = mpsc::channel();
        Arc::new(Ctx {
            machine: Mutex::new(Machine::new()),
            changed: zruntime::Event::new(),
            commands,
            canceller: Canceller::new(),
            deps: Deps {
                authority: Arc::new(polkit::Polkit),
                users: Arc::new(crate::users::SystemUsers),
                sids: SidMap::default(),
            },
            opts: Options::default(),
            watchers: Mutex::new(HashMap::new()),
        })
    }

    #[test]
    fn debug_output() {
        let ctx = ctx();
        assert_eq!(
            format!("{:?}", ctx.deps),
            format!("Deps {{ sids: {:?}, .. }}", SidMap::default())
        );
        assert_eq!(format!("{:?}", Manager { ctx: ctx.clone() }), "Manager");
        let dev = Device { ctx: ctx.clone() };
        assert_eq!(format!("{dev:?}"), "Device { state: Some(Opening), .. }");
        ctx.m().device = DeviceState::Ready;
        assert_eq!(format!("{dev:?}"), "Device { state: Some(Ready), .. }");
        // Never waits for the state lock.
        let held = ctx.m();
        assert_eq!(format!("{dev:?}"), "Device { state: None, .. }");
        drop(held);
    }
}
