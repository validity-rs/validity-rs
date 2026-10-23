//! The sensor thread. It alone talks to the sensor: the D-Bus side sends it
//! [`Command`]s and reads its [`Event`]s, and cancels runs through the shared
//! [`Canceller`].
//!
//! It never panics or exits on a sensor error. Every failure moves the device to
//! an explicit state ([`DeviceState`]) and, when it makes sense, to a bounded
//! number of reconnection attempts with backoff and one USB port reset; a sensor
//! that stays broken is parked in `Failed` and tried again after a cooldown, on
//! resume, or when USB devices change. The USB device is found again on every
//! attempt, so a sensor that came back at another address after a suspend
//! (systemd's hwdb sets `ID_PERSIST=0` for these readers) is picked up.

use std::collections::VecDeque;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use validity_proto::Error as ProtoError;
use validity_proto::db;
use validity_proto::init;
use validity_proto::scanner::{EnrollProgress, Identified, Scanner};
use validity_proto::sid::Sid;
use validity_proto::vendor::Blobs;

use crate::errors::{self, Failure};
use crate::machine::{ActionKind, DeviceState, Event, OpId, UserPrints};
use crate::sensor::{
    self, Canceller, Guarded, Hardware, ImageOutcome, OpenFailure, Progress, SessionError, Sink,
    UsbId,
};

/// File in the state directory recording when this daemon last rebooted the
/// sensor (milliseconds since the epoch), so that a new instance started
/// within the reappear window waits for it instead of calling it absent.
pub const REBOOT_MARKER: &str = "sensor-rebooted";

/// Polling for an absent sensor when hotplug notifications work.
const ABSENT_POLL_WITH_HOTPLUG: Duration = Duration::from_secs(60);

/// A one-shot reply channel (capacity 1) the D-Bus side awaits.
pub type Reply<T> = zruntime::mpmc::Sender<T>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteError {
    NotEnrolled,
    Unavailable(String),
    Failed(String),
}

#[derive(Debug)]
pub enum Command {
    Verify {
        op: OpId,
        sid: Sid,
        finger: Option<u16>,
    },
    Enroll {
        op: OpId,
        sid: Sid,
        finger: u16,
        replace: bool,
    },
    Delete {
        sid: Sid,
        finger: Option<u16>,
        reply: Reply<Result<(), DeleteError>>,
    },
    /// USB devices came or went.
    Hotplug,
    /// The system is about to sleep: close the session (the caller already
    /// interrupted any run through the canceller).
    Sleep { reply: Reply<()> },
    /// The system woke up: open the sensor again.
    Wake,
    /// Close the session and end the thread.
    Shutdown { reply: Reply<()> },
}

/// Delays and bounds. The defaults are for real hardware; tests shorten them.
#[derive(Debug, Clone)]
pub struct Timing {
    /// Delay before each attempt of a connection cycle (its length is the
    /// number of attempts). The port reset happens after the second failure.
    pub attempts: Vec<Duration>,
    /// Re-checks for a sensor while none is plugged in: first and longest delay.
    pub absent_first: Duration,
    pub absent_max: Duration,
    /// After a failed cycle, the next one starts this much later.
    pub failed_cooldown: Duration,
    /// Consecutive failed captures before the sensor is considered stuck.
    pub max_capture_failures: u32,
    /// After the sensor reboots (every session ends with one), after a resume,
    /// a USB reset or a lost session, the device is off the bus for a moment
    /// (about 0.5 s measured on a T480) and comes back at a new address. For
    /// this long, "not on the bus" means "not back yet": the device stays
    /// listed (opening), never reported gone.
    pub reappear: Duration,
    /// How often the bus is looked at meanwhile.
    pub reappear_poll: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            attempts: [0, 250, 500, 1000, 2000]
                .into_iter()
                .map(Duration::from_millis)
                .collect(),
            absent_first: Duration::from_millis(250),
            absent_max: Duration::from_secs(5),
            failed_cooldown: Duration::from_secs(300),
            max_capture_failures: 10,
            reappear: Duration::from_secs(5),
            reappear_poll: Duration::from_millis(100),
        }
    }
}

struct Live<S> {
    s: Guarded<S>,
    scanner: Scanner,
}

/// A run interrupted by a suspend, finished or reported after resume.
enum Pending {
    Verify {
        op: OpId,
        sid: Sid,
        finger: Option<u16>,
    },
    Enroll {
        op: OpId,
    },
}

pub struct Worker<H: Hardware> {
    hw: H,
    blobs: Result<Arc<Blobs>, String>,
    calibration: PathBuf,
    rx: Receiver<Command>,
    tx: Sender<Command>,
    sink: Sink,
    canceller: Arc<Canceller>,
    timing: Timing,
    live: Option<Live<H::Session>>,
    state: DeviceState,
    id: Option<UsbId>,
    pending: Option<Pending>,
    deferred: VecDeque<Command>,
    absent_delay: Duration,
    /// USB hotplug notifications work: absent-sensor polling is only a safety net.
    hotplug: bool,
    /// Until then the sensor is expected back on the bus (see [`Timing::reappear`]).
    expect_back_until: Option<Instant>,
}

/// What looking for the sensor found.
enum Probe {
    Found(UsbId),
    Absent,
    Failed(String),
    /// Sleep, wake or shutdown came first.
    Interrupted,
}

impl<H: Hardware> std::fmt::Debug for Worker<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker")
            .field("state", &self.state)
            .field("id", &self.id)
            .field("live", &self.live.is_some())
            .finish_non_exhaustive()
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

enum Flow {
    Continue,
    Exit,
}

impl<H: Hardware> Worker<H> {
    /// `tx` is a sender of the channel `rx` belongs to (for hotplug
    /// notifications).
    #[allow(
        clippy::too_many_arguments,
        reason = "the thread's wiring: each argument has a different owner in service::run"
    )]
    pub fn new(
        hw: H,
        blobs: Result<Arc<Blobs>, String>,
        calibration: PathBuf,
        rx: Receiver<Command>,
        tx: Sender<Command>,
        sink: Sink,
        canceller: Arc<Canceller>,
        timing: Timing,
    ) -> Self {
        let absent_delay = timing.absent_first;
        Worker {
            hw,
            blobs,
            calibration,
            rx,
            tx,
            sink,
            canceller,
            timing,
            live: None,
            state: DeviceState::Opening,
            id: None,
            pending: None,
            deferred: VecDeque::new(),
            absent_delay,
            hotplug: false,
            expect_back_until: None,
        }
    }

    fn emit(&self, ev: Event) {
        (self.sink)(ev);
    }

    fn set_state(&mut self, state: DeviceState) {
        if state != self.state {
            match &state {
                DeviceState::Ready => log::info!("sensor ready"),
                DeviceState::Absent => log::info!("no supported fingerprint sensor on the USB bus"),
                DeviceState::NeedsSetup(why) => log::warn!("sensor needs setup: {why}"),
                DeviceState::Failed(why) => log::warn!(
                    "sensor unavailable: {why}; next attempt in {}s, on resume or on USB changes",
                    self.timing.failed_cooldown.as_secs()
                ),
                DeviceState::Opening => log::info!("opening the sensor"),
                DeviceState::Suspended => log::info!("sensor closed for suspend"),
            }
        }
        self.state = state.clone();
        self.emit(Event::Device {
            state,
            name: Some(sensor::device_name(self.id)),
        });
    }

    pub fn run(mut self) {
        let tx = self.tx.clone();
        self.hotplug = self.hw.watch(Box::new(move || {
            let _ = tx.send(Command::Hotplug);
        }));
        if !self.hotplug {
            log::info!("no USB hotplug notifications: polling for the sensor instead");
        }
        // A previous instance may have rebooted the sensor just now.
        self.expect_back_after_restart();
        self.connect();
        loop {
            let cmd = match self.deferred.pop_front() {
                Some(c) => c,
                None => {
                    let wait = match &self.state {
                        DeviceState::Absent => Some(self.absent_delay),
                        DeviceState::Failed(_) => Some(self.timing.failed_cooldown),
                        _ => None,
                    };
                    let r = match wait {
                        None => self.rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
                        Some(t) => self.rx.recv_timeout(t),
                    };
                    match r {
                        Ok(c) => c,
                        Err(RecvTimeoutError::Timeout) => {
                            if self.state == DeviceState::Absent {
                                // With hotplug notifications, polling only
                                // covers a missed event.
                                let cap = if self.hotplug {
                                    ABSENT_POLL_WITH_HOTPLUG
                                } else {
                                    self.timing.absent_max
                                };
                                self.absent_delay = (self.absent_delay * 2).min(cap);
                            }
                            self.connect();
                            continue;
                        }
                        Err(RecvTimeoutError::Disconnected) => {
                            self.close("the daemon is stopping");
                            return;
                        }
                    }
                }
            };
            if let Flow::Exit = self.handle(cmd) {
                return;
            }
        }
    }

    fn handle(&mut self, cmd: Command) -> Flow {
        match cmd {
            Command::Verify { op, sid, finger } => self.verify(op, sid, finger),
            Command::Enroll {
                op,
                sid,
                finger,
                replace,
            } => self.enroll(op, sid, finger, replace),
            Command::Delete { sid, finger, reply } => {
                let r = self.delete(&sid, finger);
                let _ = reply.try_send(r);
            }
            Command::Hotplug => self.hotplug(),
            Command::Sleep { reply } => {
                self.close("suspend");
                self.set_state(DeviceState::Suspended);
                let _ = reply.try_send(());
            }
            Command::Wake => {
                self.canceller.end_sleep();
                // Powered off during sleep: it re-enumerates on resume.
                self.expect_back();
                self.absent_delay = self.timing.absent_first;
                // A session that survived (the sleep notice came too late, or
                // never) may still be dead: the sensor loses power in S3.
                self.check_alive();
                self.connect();
                self.resume_pending();
            }
            Command::Shutdown { reply } => {
                self.close("the daemon is stopping");
                let _ = reply.try_send(());
                return Flow::Exit;
            }
        }
        Flow::Continue
    }

    /// Ends the session; the sensor is rebooted, as the reference does on exit,
    /// so that it starts clean next time (it otherwise keeps its TLS session).
    fn close(&mut self, why: &str) {
        if let Some(mut live) = self.live.take() {
            live.s.set_op(0);
            match init::close(&mut live.s) {
                Ok(()) => log::info!("sensor session closed ({why})"),
                Err(e) => log::info!("sensor session dropped ({why}): {e}"),
            }
            drop(live.s.into_inner());
            // The reboot takes it off the bus for a moment, for this process
            // and for the next one if this is a restart.
            self.expect_back();
            if let Err(e) = std::fs::write(self.reboot_marker(), now_ms().to_string()) {
                log::debug!("cannot record the sensor reboot: {e}");
            }
        }
    }

    fn reboot_marker(&self) -> PathBuf {
        self.calibration.with_file_name(REBOOT_MARKER)
    }

    /// At start: if a previous instance rebooted the sensor less than
    /// [`Timing::reappear`] ago, expect it back for the rest of that window.
    fn expect_back_after_restart(&mut self) {
        let marker = self.reboot_marker();
        let Some(at) = std::fs::read_to_string(&marker)
            .ok()
            .and_then(|t| t.trim().parse::<u128>().ok())
        else {
            return;
        };
        let _ = std::fs::remove_file(&marker);
        let elapsed = Duration::from_millis(now_ms().saturating_sub(at) as u64);
        if let Some(left) = self.timing.reappear.checked_sub(elapsed) {
            log::info!("the sensor was rebooted {elapsed:?} ago: waiting for it");
            self.expect_back_until = Some(Instant::now() + left);
        }
    }

    /// The sensor is expected to leave the bus and come back.
    fn expect_back(&mut self) {
        self.expect_back_until = Some(Instant::now() + self.timing.reappear);
    }

    /// Looks for the sensor; while it is expected back, waits for it (keeping
    /// the device listed as opening) instead of reporting it absent.
    fn probe(&mut self) -> Probe {
        loop {
            match self.hw.probe() {
                Ok(Some(id)) => return Probe::Found(id),
                Ok(None) => {
                    if !self.expect_back_until.is_some_and(|t| Instant::now() < t) {
                        self.expect_back_until = None;
                        return Probe::Absent;
                    }
                    if self.state != DeviceState::Opening {
                        self.set_state(DeviceState::Opening);
                    }
                    if self.wait_or_command(self.timing.reappear_poll).is_break() {
                        return Probe::Interrupted;
                    }
                }
                Err(e) => return Probe::Failed(e),
            }
        }
    }

    /// Drops a session that failed; `reset` asks for a USB port reset first.
    fn drop_session(&mut self, reset: bool) {
        if let Some(live) = self.live.take() {
            // Lost (re-enumerating?) or about to be reset: it may come back.
            self.expect_back();
            let s = live.s.into_inner();
            if reset {
                match self.hw.reset(s) {
                    Ok(()) => log::info!("sensor USB port reset"),
                    Err(e) => log::warn!("sensor USB port reset failed: {e}"),
                }
            }
        }
    }

    /// Drops the session if the sensor no longer answers (a cheap command).
    fn check_alive(&mut self) {
        let Some(live) = &mut self.live else { return };
        if let Err(e) = validity_proto::cmd::RomInfo::get(&mut live.s) {
            log::info!("sensor lost: {e}");
            self.drop_session(false);
        }
    }

    fn hotplug(&mut self) {
        // One check for a burst of USB events (a dock, a hub).
        while let Ok(c) = self.rx.try_recv() {
            if !matches!(c, Command::Hotplug) {
                self.deferred.push_back(c);
            }
        }
        match self.state {
            DeviceState::Ready => {
                self.check_alive();
                self.connect();
            }
            DeviceState::Absent | DeviceState::Failed(_) | DeviceState::NeedsSetup(_) => {
                self.absent_delay = self.timing.absent_first;
                self.connect();
            }
            DeviceState::Opening | DeviceState::Suspended => {}
        }
    }

    /// Waits `d` (a backoff delay of a connection cycle). Sleep, wake and
    /// shutdown abort the cycle (they are handled next); requests are answered
    /// "unavailable" right away; USB events do not shorten the delay (the cycle
    /// looks for the sensor anyway).
    fn wait_or_command(&mut self, d: Duration) -> ControlFlow<()> {
        let end = Instant::now() + d;
        loop {
            let now = Instant::now();
            if now >= end {
                return ControlFlow::Continue(());
            }
            match self.rx.recv_timeout(end - now) {
                Err(RecvTimeoutError::Timeout) => return ControlFlow::Continue(()),
                Err(RecvTimeoutError::Disconnected) => return ControlFlow::Break(()),
                Ok(c @ (Command::Sleep { .. } | Command::Shutdown { .. } | Command::Wake)) => {
                    self.deferred.push_back(c);
                    return ControlFlow::Break(());
                }
                Ok(Command::Hotplug) => {}
                Ok(c) => self.unavailable(c),
            }
        }
    }

    fn unavailable(&mut self, c: Command) {
        match c {
            Command::Verify { op, .. } => {
                self.status(op, ActionKind::Verify, "verify-disconnected", true);
                self.emit(Event::OpEnded { op });
            }
            Command::Enroll { op, .. } => {
                self.status(op, ActionKind::Enroll, "enroll-disconnected", true);
                self.emit(Event::OpEnded { op });
            }
            Command::Delete { reply, .. } => {
                let _ = reply.try_send(Err(DeleteError::Unavailable(
                    "the sensor is not available".into(),
                )));
            }
            other => self.deferred.push_back(other),
        }
    }

    /// One connection cycle: bounded attempts with backoff, one USB port reset.
    fn connect(&mut self) {
        if self.live.is_some() {
            return;
        }
        let mut reset_done = false;
        let mut last = String::new();
        let attempts = self.timing.attempts.clone();
        for (n, delay) in attempts.iter().enumerate() {
            if self.wait_or_command(*delay).is_break() {
                // Sleep or shutdown: handled by the main loop.
                return;
            }
            // Probed before saying "opening": an absent sensor stays absent
            // (no state flapping, no log line per poll).
            let id = match self.probe() {
                Probe::Found(id) => id,
                Probe::Absent => {
                    self.id = None;
                    self.set_state(DeviceState::Absent);
                    return;
                }
                Probe::Interrupted => return,
                Probe::Failed(e) => {
                    last = format!("USB enumeration failed: {e}");
                    log::debug!("attempt {}: {last}", n + 1);
                    continue;
                }
            };
            if self.state != DeviceState::Opening {
                self.id = Some(id);
                self.set_state(DeviceState::Opening);
            }
            self.id = Some(id);
            // Setup problems are reported for a sensor that is there; without
            // one the device is simply absent.
            let blobs = match &self.blobs {
                Ok(b) => b.clone(),
                Err(e) => {
                    let e = e.clone();
                    self.set_state(DeviceState::NeedsSetup(e));
                    return;
                }
            };
            if id != sensor::VALIDATED {
                self.set_state(DeviceState::NeedsSetup(format!(
                    "{:04x}:{:04x} is not supported yet (only {:04x}:{:04x} is validated)",
                    id.0,
                    id.1,
                    sensor::VALIDATED.0,
                    sensor::VALIDATED.1
                )));
                return;
            }
            let opened = match self.hw.open() {
                Ok(o) => o,
                Err(OpenFailure::Setup(m)) => {
                    self.set_state(DeviceState::NeedsSetup(m));
                    return;
                }
                Err(OpenFailure::Io(m)) => {
                    last = format!("cannot open the USB device: {m}");
                    log::debug!("attempt {}: {last}", n + 1);
                    continue;
                }
            };
            self.id = Some(opened.id);
            let mut s = Guarded::new(
                opened.session,
                opened.cancel,
                self.canceller.clone(),
                self.sink.clone(),
            );
            match sensor::open_session(&mut s, &blobs, &self.calibration) {
                Ok(scanner) => {
                    log::info!(
                        "sensor opened: {} (attempt {})",
                        scanner.device.name.trim_end(),
                        n + 1
                    );
                    self.live = Some(Live { s, scanner });
                    if let Err(e) = self.refresh_prints() {
                        last = format!("reading the fingerprint database failed: {e}");
                        self.drop_session(false);
                        continue;
                    }
                    self.absent_delay = self.timing.absent_first;
                    self.expect_back_until = None;
                    self.set_state(DeviceState::Ready);
                    return;
                }
                Err(SessionError::Setup(m)) => {
                    drop(s.into_inner());
                    self.set_state(DeviceState::NeedsSetup(m));
                    return;
                }
                Err(SessionError::Sensor(e)) => {
                    last = format!("opening the sensor failed: {e}");
                    log::info!("attempt {}: {last}", n + 1);
                    let inner = s.into_inner();
                    if !reset_done && n >= 1 {
                        reset_done = true;
                        match self.hw.reset(inner) {
                            Ok(()) => log::info!("sensor USB port reset"),
                            Err(e) => log::warn!("sensor USB port reset failed: {e}"),
                        }
                        self.expect_back();
                    }
                }
            }
        }
        self.set_state(DeviceState::Failed(last));
    }

    /// Reads the database and publishes it.
    fn refresh_prints(&mut self) -> Result<(), ProtoError> {
        let Some(live) = &mut self.live else {
            return Ok(());
        };
        match db::list_users(&mut live.s) {
            Ok(users) => {
                let prints = users
                    .into_iter()
                    .map(|u| UserPrints {
                        sid: u.identity,
                        fingers: u.fingers.iter().map(|f| f.subtype).collect(),
                    })
                    .collect();
                self.emit(Event::Prints(prints));
                Ok(())
            }
            Err(e) => {
                log::warn!("reading the fingerprint database failed: {e}");
                self.lost(&e);
                Err(e)
            }
        }
    }

    /// A sensor error mid-session: drop the session if it is unusable.
    fn lost(&mut self, e: &ProtoError) {
        if errors::classify(e) == Failure::Lost {
            self.drop_session(false);
            if !errors::is_disconnect(e) {
                log::info!("sensor not responding ({e}), reconnecting");
            }
        }
    }

    fn status(&self, op: OpId, kind: ActionKind, result: &'static str, done: bool) {
        log::debug!("run {op}: {result}{}", if done { " (done)" } else { "" });
        self.emit(Event::Status {
            op,
            kind,
            result,
            done,
        });
    }

    /// The database user of `sid`, if any.
    fn lookup(&mut self, sid: &Sid) -> Result<Option<db::User>, ProtoError> {
        let live = self.live.as_mut().expect("checked by the caller");
        db::lookup_user(&mut live.s, sid)
    }

    /// Identification with retries reported as `retry` statuses; `Err(None)`
    /// when the sensor looks stuck.
    fn identify(
        &mut self,
        op: OpId,
        kind: ActionKind,
        retry: &'static str,
    ) -> Result<Identified, (ProtoError, bool)> {
        let max = self.timing.max_capture_failures;
        let sink = self.sink.clone();
        let live = self.live.as_mut().expect("checked by the caller");
        live.s.set_op(op);
        let mut failures = 0;
        let r = live.scanner.identify(&mut live.s, |_e| {
            failures += 1;
            sink(Event::Status {
                op,
                kind,
                result: retry,
                done: false,
            });
            if failures >= max {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        live.s.set_op(0);
        r.map_err(|e| (e, failures >= max))
    }

    /// After a failed run: reconnect when the session is unusable, reset when
    /// the sensor looks stuck.
    fn after_failure(&mut self, e: &ProtoError, stuck: bool) {
        if stuck {
            log::warn!("sensor stuck after repeated capture failures ({e}): resetting it");
            self.drop_session(true);
            self.connect();
        } else if errors::classify(e) == Failure::Lost {
            self.lost(e);
            self.connect();
        }
    }

    fn verify(&mut self, op: OpId, sid: Sid, finger: Option<u16>) {
        if self.canceller.should_stop(op) {
            if self.canceller.sleeping() && !self.canceller.cancelled(op) {
                self.pending = Some(Pending::Verify { op, sid, finger });
            } else {
                self.emit(Event::OpEnded { op });
            }
            return;
        }
        if self.live.is_none() {
            return self.unavailable(Command::Verify { op, sid, finger });
        }
        let user = match self.lookup(&sid) {
            Ok(Some(u)) => u,
            Ok(None) => {
                // The cache said otherwise: the database changed under us.
                let _ = self.refresh_prints();
                self.status(op, ActionKind::Verify, "verify-no-match", true);
                self.emit(Event::OpEnded { op });
                return;
            }
            Err(e) => {
                log::warn!("verify: user lookup failed: {e}");
                let r =
                    errors::verify_failure(errors::classify(&e)).unwrap_or("verify-unknown-error");
                self.status(op, ActionKind::Verify, r, true);
                self.emit(Event::OpEnded { op });
                self.after_failure(&e, false);
                return;
            }
        };
        match self.identify(op, ActionKind::Verify, "verify-retry-scan") {
            Ok(id) => {
                let r = sensor::judge(&id, user.dbid, finger);
                if let Identified::Match {
                    user: u, subtype, ..
                } = &id
                    && r == "verify-no-match"
                {
                    log::info!(
                        "the finger matched database record {u} finger {subtype}, not the \
                         claimed user's{}: reporting no match",
                        if finger.is_some() {
                            " requested finger"
                        } else {
                            ""
                        }
                    );
                }
                self.status(op, ActionKind::Verify, r, true);
                self.emit(Event::OpEnded { op });
            }
            Err((ProtoError::Cancelled, _)) => {
                if self.canceller.sleeping() && !self.canceller.cancelled(op) {
                    log::info!("verification interrupted by suspend, resumed after wake-up");
                    self.pending = Some(Pending::Verify { op, sid, finger });
                } else {
                    self.emit(Event::OpEnded { op });
                }
            }
            Err((e, stuck)) => {
                log::warn!("verification failed: {e}");
                let r = if stuck {
                    "verify-unknown-error"
                } else {
                    errors::verify_failure(errors::classify(&e)).unwrap_or("verify-unknown-error")
                };
                self.status(op, ActionKind::Verify, r, true);
                self.emit(Event::OpEnded { op });
                self.after_failure(&e, stuck);
            }
        }
    }

    fn enroll(&mut self, op: OpId, sid: Sid, finger: u16, replace: bool) {
        if self.canceller.should_stop(op) {
            if self.canceller.sleeping() && !self.canceller.cancelled(op) {
                self.pending = Some(Pending::Enroll { op });
            } else {
                self.emit(Event::OpEnded { op });
            }
            return;
        }
        if self.live.is_none() {
            return self.unavailable(Command::Enroll {
                op,
                sid,
                finger,
                replace,
            });
        }
        let fail = |w: &mut Self, e: &ProtoError, stuck: bool| {
            let f = errors::classify(e);
            if f == Failure::Cancelled {
                if w.canceller.sleeping() && !w.canceller.cancelled(op) {
                    w.pending = Some(Pending::Enroll { op });
                    return;
                }
            } else {
                log::warn!("enrolment failed: {e}");
                let r = if stuck {
                    "enroll-unknown-error"
                } else {
                    errors::enroll_failure(f).unwrap_or("enroll-unknown-error")
                };
                w.status(op, ActionKind::Enroll, r, true);
            }
            w.emit(Event::OpEnded { op });
            w.after_failure(e, stuck);
        };
        // fprintd deletes the finger's old print before enrolling it again (the
        // sensor refuses a second record for it, status 0x04c3).
        if replace {
            match self.delete(&sid, Some(finger)) {
                Ok(()) | Err(DeleteError::NotEnrolled) => {}
                Err(e) => {
                    log::warn!("enrolment: deleting the previous print failed: {e:?}");
                    self.status(op, ActionKind::Enroll, "enroll-failed", true);
                    self.emit(Event::OpEnded { op });
                    return;
                }
            }
        }
        // Stage 1: the finger must not be enrolled already, for anyone.
        match self.identify(op, ActionKind::Enroll, "enroll-retry-scan") {
            Ok(Identified::Match { user, subtype, .. }) => {
                log::info!(
                    "enrolment refused: the finger is already enrolled (database record {user}, finger {subtype})"
                );
                self.status(op, ActionKind::Enroll, "enroll-duplicate", true);
                self.emit(Event::OpEnded { op });
                return;
            }
            Ok(Identified::NoMatch(_)) => {
                self.status(op, ActionKind::Enroll, "enroll-stage-passed", false);
            }
            Err((e, stuck)) => return fail(self, &e, stuck),
        }
        let blobs = self
            .blobs
            .clone()
            .expect("a live session implies the blobs");
        let max = self.timing.max_capture_failures;
        let sink = self.sink.clone();
        let live = self.live.as_mut().expect("checked above");
        live.s.set_op(op);
        let mut progress = Progress::after_duplicate_check();
        let mut failures = 0;
        let emit = |result| {
            sink(Event::Status {
                op,
                kind: ActionKind::Enroll,
                result,
                done: false,
            })
        };
        let r = live
            .scanner
            .enroll(&mut live.s, &blobs, &sid, finger, |p| match p {
                EnrollProgress::Image(h) => {
                    failures = 0;
                    match progress.image(h) {
                        ImageOutcome::StagePassed => emit("enroll-stage-passed"),
                        ImageOutcome::Redundant => emit("enroll-remove-and-retry"),
                        ImageOutcome::Last => {}
                    }
                    ControlFlow::Continue(())
                }
                EnrollProgress::Retry(_) => {
                    failures += 1;
                    emit("enroll-retry-scan");
                    if failures >= max {
                        ControlFlow::Break(())
                    } else {
                        ControlFlow::Continue(())
                    }
                }
            });
        live.s.set_op(0);
        match r {
            Ok(record) => {
                log::info!("finger enrolled (database record {record})");
                let _ = self.refresh_prints();
                self.status(op, ActionKind::Enroll, "enroll-completed", true);
                self.emit(Event::OpEnded { op });
            }
            Err(e) => {
                // Records may have been written before the failure.
                if errors::classify(&e) != Failure::Lost {
                    let _ = self.refresh_prints();
                }
                fail(self, &e, failures >= max)
            }
        }
    }

    fn delete(&mut self, sid: &Sid, finger: Option<u16>) -> Result<(), DeleteError> {
        if self.live.is_none() {
            return Err(DeleteError::Unavailable(
                "the sensor is not available".into(),
            ));
        }
        let fail = |w: &mut Self, e: ProtoError| {
            log::warn!("deleting prints failed: {e}");
            w.after_failure(&e, false);
            DeleteError::Failed(e.to_string())
        };
        let user = match self.lookup(sid) {
            Ok(Some(u)) => u,
            Ok(None) => return Err(DeleteError::NotEnrolled),
            Err(e) => return Err(fail(self, e)),
        };
        let live = self.live.as_mut().expect("checked above");
        let r = match finger {
            // The user record and, with it, all its fingers.
            None => db::del_record(&mut live.s, user.dbid),
            Some(f) => {
                let records: Vec<u16> = user
                    .fingers
                    .iter()
                    .filter(|r| r.subtype == f)
                    .map(|r| r.dbid)
                    .collect();
                if records.is_empty() {
                    return Err(DeleteError::NotEnrolled);
                }
                records
                    .into_iter()
                    .try_for_each(|r| db::del_record(&mut live.s, r))
            }
        };
        let refreshed = self.refresh_prints();
        match (r, refreshed) {
            (Err(e), _) => Err(fail(self, e)),
            (Ok(()), Err(e)) => Err(DeleteError::Failed(e.to_string())),
            (Ok(()), Ok(())) => {
                log::info!(
                    "deleted {} for a user",
                    if finger.is_some() {
                        "one finger"
                    } else {
                        "all fingers"
                    }
                );
                Ok(())
            }
        }
    }

    /// After resume: finish or report the run a suspend interrupted.
    fn resume_pending(&mut self) {
        let Some(p) = self.pending.take() else { return };
        match p {
            Pending::Verify { op, sid, finger } => {
                if self.canceller.cancelled(op) {
                    self.emit(Event::OpEnded { op });
                } else if self.live.is_some() {
                    self.verify(op, sid, finger);
                } else {
                    self.status(op, ActionKind::Verify, "verify-disconnected", true);
                    self.emit(Event::OpEnded { op });
                }
            }
            // Enrolment progress lives in the sensor session, which is gone.
            Pending::Enroll { op } => {
                if !self.canceller.cancelled(op) {
                    self.status(op, ActionKind::Enroll, "enroll-disconnected", true);
                }
                self.emit(Event::OpEnded { op });
            }
        }
    }
}
