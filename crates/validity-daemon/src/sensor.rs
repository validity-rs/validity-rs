//! The sensor side: where a sensor comes from ([`Hardware`]), how the daemon
//! opens it (never pairing, never writing firmware), the session wrapper that
//! makes cancellation reliable and reports the finger state, and the pure
//! decisions on identification results.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use validity_proto::Error as ProtoError;
use validity_proto::calibration::CalibrationFile;
use validity_proto::channel;
use validity_proto::scanner::{Identified, Scanner};
use validity_proto::session::{CancelHandle, Sensor, Wait};
use validity_proto::tls;
use validity_proto::vendor::Blobs;
use validity_proto::{cmd, db, flash};

use crate::machine::{Event, OpId};

/// USB vendor and product id.
pub type UsbId = (u16, u16);

/// The one device validated end to end (the vendor blobs are this device's).
pub const VALIDATED: UsbId = (0x06cb, 0x009a);

/// Why a sensor could not be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenFailure {
    /// Needs an administrator: retrying will not help.
    Setup(String),
    /// Possibly transient (USB, permissions after a re-enumeration...).
    Io(String),
}

/// An opened session, the handle that cancels its blocking waits, and the device.
#[derive(Debug)]
pub struct Opened<S> {
    pub session: S,
    pub cancel: CancelHandle,
    pub id: UsbId,
}

/// Where sensors come from: the USB bus in production, an emulator in tests.
pub trait Hardware: Send + 'static {
    type Session: Sensor + Send + 'static;

    /// The supported sensor on the bus, if any. Cheap: no I/O to the device.
    fn probe(&mut self) -> Result<Option<UsbId>, String>;

    /// Opens the sensor found by `probe` (USB handle and interface only).
    fn open(&mut self) -> Result<Opened<Self::Session>, OpenFailure>;

    /// USB port reset of a stuck sensor. The session is consumed: reopen after.
    fn reset(&mut self, session: Self::Session) -> Result<(), String>;

    /// Calls `notify` (from any thread) whenever USB devices come or go.
    /// Returns false when no such notification exists; the caller polls then.
    fn watch(&mut self, notify: Box<dyn Fn() + Send + Sync>) -> bool;
}

/// Name for the `name` property.
pub fn device_name(id: Option<UsbId>) -> String {
    match id {
        Some((v, p)) => format!("Synaptics/Validity fingerprint sensor ({v:04x}:{p:04x})"),
        None => crate::machine::DEFAULT_NAME.to_string(),
    }
}

/// Why opening a session failed.
#[derive(Debug)]
pub enum SessionError {
    Setup(String),
    Sensor(ProtoError),
}

impl From<ProtoError> for SessionError {
    fn from(e: ProtoError) -> Self {
        SessionError::Sensor(e)
    }
}

/// Opens a paired sensor: the steps of `validity_proto::init::open` minus every
/// destructive one. A blank flash is not partitioned or paired, missing firmware
/// is not uploaded: both need the administrator (and pairing erases the
/// sensor), so they end in [`SessionError::Setup`]. Calibration is loaded from
/// `calibration` and saved there when the sensor had to be calibrated.
pub fn open_session(
    s: &mut impl Sensor,
    blobs: &Blobs,
    calibration: &Path,
) -> Result<Scanner, SessionError> {
    let info = flash::get_flash_info(s)?;
    if info.partitions.is_empty() {
        return Err(SessionError::Setup(
            "the sensor flash is blank: the sensor is not paired with this computer".into(),
        ));
    }
    cmd::send_init(s, blobs)?;
    let tls_flash = cmd::read_tls_flash(s)?;
    match s.open_channel(&tls_flash) {
        Ok(()) => {}
        Err(ProtoError::Channel(channel::Error::Tls(tls::Error::PairedElsewhere))) => {
            return Err(SessionError::Setup(
                "the sensor is paired with another computer (or this computer's DMI \
                 product name or serial changed)"
                    .into(),
            ));
        }
        Err(ProtoError::Channel(channel::Error::BadEcdhSignature)) => {
            return Err(SessionError::Setup(
                "the sensor key is not signed by a known firmware key".into(),
            ));
        }
        Err(e) => return Err(e.into()),
    }
    if flash::get_fw_info(s, 2)?.is_none() {
        return Err(SessionError::Setup(
            "no firmware extension on the sensor".into(),
        ));
    }
    let stored = match CalibrationFile::load(calibration) {
        Ok(f) => Some(f),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            log::warn!("ignoring calibration file {}: {e}", calibration.display());
            None
        }
    };
    let scanner = Scanner::open(s, blobs, stored.as_ref())?;
    if scanner.calibrated {
        match scanner.calibration_file().save(calibration) {
            Ok(()) => log::info!("calibration saved to {}", calibration.display()),
            Err(e) => log::warn!(
                "could not save calibration to {}: {e} (the sensor will be \
                 calibrated again next time)",
                calibration.display()
            ),
        }
    }
    db::init_db(s, blobs)?;
    Ok(scanner)
}

/// Operation-scoped cancellation shared by the D-Bus side and the sensor thread.
///
/// The session's [`CancelHandle`] only ends a blocking wait; `Scanner::identify`
/// and `Scanner::enroll` clear it when they start, so a cancellation that
/// arrives just before would be lost. Here a cancellation names the run it is
/// for, and [`Guarded`] re-arms the handle for as long as that run goes on.
#[derive(Debug, Default)]
pub struct Canceller {
    /// Runs with an id up to this one are cancelled.
    cancelled: AtomicU64,
    /// A suspend is starting: interrupt whatever runs.
    sleeping: AtomicBool,
    /// The daemon is stopping.
    shutdown: AtomicBool,
    handle: Mutex<Option<CancelHandle>>,
}

impl Canceller {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn poke(&self) {
        if let Some(h) = &*self.handle.lock().expect("canceller lock") {
            h.cancel();
        }
    }

    /// Cancels run `op` (and any earlier one).
    pub fn cancel(&self, op: OpId) {
        self.cancelled.fetch_max(op, Ordering::SeqCst);
        self.poke();
    }

    pub fn start_sleep(&self) {
        self.sleeping.store(true, Ordering::SeqCst);
        self.poke();
    }

    pub fn end_sleep(&self) {
        self.sleeping.store(false, Ordering::SeqCst);
    }

    pub fn sleeping(&self) -> bool {
        self.sleeping.load(Ordering::SeqCst)
    }

    pub fn start_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.poke();
    }

    pub fn shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Whether the client cancelled `op`.
    pub fn cancelled(&self, op: OpId) -> bool {
        self.cancelled.load(Ordering::SeqCst) >= op
    }

    /// Whether run `op` must end now, for any reason.
    pub fn should_stop(&self, op: OpId) -> bool {
        op != 0 && (self.cancelled(op) || self.sleeping() || self.shutting_down())
    }

    pub fn set_handle(&self, h: Option<CancelHandle>) {
        *self.handle.lock().expect("canceller lock") = h;
    }
}

/// Reports events of the sensor thread (to the D-Bus side in the daemon).
pub type Sink = Arc<dyn Fn(Event) + Send + Sync>;

/// The session as the daemon drives it: cancellation that cannot be lost, a
/// pause that ends early on cancellation, and finger-needed / finger-present
/// from the capture interrupts.
pub struct Guarded<S> {
    inner: S,
    cancel: CancelHandle,
    canceller: Arc<Canceller>,
    op: OpId,
    in_capture: bool,
    finger: (bool, bool),
    sink: Sink,
}

/// Capture program (`0x02`) and capture stop (`0x04`).
const CMD_CAPTURE: u8 = 0x02;
const CMD_CAPTURE_STOP: u8 = 0x04;
/// Pause slice: how soon a cancellation ends a pause.
const PAUSE_SLICE: Duration = Duration::from_millis(50);

impl<S> std::fmt::Debug for Guarded<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guarded")
            .field("op", &self.op)
            .field("in_capture", &self.in_capture)
            .field("finger", &self.finger)
            .finish_non_exhaustive()
    }
}

impl<S: Sensor> Guarded<S> {
    pub fn new(inner: S, cancel: CancelHandle, canceller: Arc<Canceller>, sink: Sink) -> Self {
        canceller.set_handle(Some(cancel.clone()));
        Guarded {
            inner,
            cancel,
            canceller,
            op: 0,
            in_capture: false,
            finger: (false, false),
            sink,
        }
    }

    /// The run the following calls belong to (0: none).
    pub fn set_op(&mut self, op: OpId) {
        self.op = op;
        if op == 0 {
            self.in_capture = false;
            self.set_finger(false, false);
        }
    }

    pub fn into_inner(self) -> S {
        self.canceller.set_handle(None);
        self.inner
    }

    fn set_finger(&mut self, present: bool, needed: bool) {
        if self.finger != (present, needed) {
            self.finger = (present, needed);
            (self.sink)(Event::Finger { present, needed });
        }
    }

    /// Finger-needed / finger-present from a capture interrupt.
    fn track(&mut self, r: &Result<Vec<u8>, ProtoError>) {
        if self.in_capture
            && let Ok(b) = r
        {
            // The capture interrupts as `Scanner::capture` reads them: 0 =
            // capture armed, 2 = finger detected, 3 with bit 2 of byte 2 = done.
            match (b.first(), b.get(2)) {
                (Some(0), _) => self.set_finger(false, true),
                (Some(2), _) => self.set_finger(true, true),
                (Some(3), Some(x)) if x & 4 != 0 => self.set_finger(true, false),
                _ => {}
            }
        }
    }
}

impl<S: Sensor> Sensor for Guarded<S> {
    fn cmd(&mut self, payload: &[u8]) -> Result<Vec<u8>, ProtoError> {
        if self.inner.is_open() {
            match payload.first() {
                Some(&CMD_CAPTURE) => self.in_capture = true,
                Some(&CMD_CAPTURE_STOP) => {
                    self.in_capture = false;
                    self.set_finger(false, false);
                }
                _ => {}
            }
        }
        self.inner.cmd(payload)
    }

    fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    fn open_channel(&mut self, tls_flash: &[u8]) -> Result<(), ProtoError> {
        self.inner.open_channel(tls_flash)
    }

    fn wait_int(&mut self) -> Result<Vec<u8>, ProtoError> {
        let r = self.inner.wait_int();
        self.track(&r);
        r
    }

    /// The inner sensor's bounded wait (its deadlines apply unchanged).
    fn wait_for(&mut self, what: Wait) -> Result<Vec<u8>, ProtoError> {
        let r = self.inner.wait_for(what);
        self.track(&r);
        r
    }

    fn read_82(&mut self) -> Result<Vec<u8>, ProtoError> {
        self.inner.read_82()
    }

    fn clear_cancel(&mut self) {
        self.inner.clear_cancel();
        if self.canceller.should_stop(self.op) {
            self.cancel.cancel();
        }
    }

    /// The inner sensor's pause, in slices, ending early on cancellation. Each
    /// slice counts as spent whether or not the inner pause sleeps, so a sensor
    /// whose pause is a no-op does not make this spin.
    fn pause(&mut self, d: Duration) {
        let mut left = d;
        while !left.is_zero() && !self.canceller.should_stop(self.op) {
            let slice = left.min(PAUSE_SLICE);
            self.inner.pause(slice);
            left -= slice;
        }
    }
}

/// Enrolment images the 009a needs: its progress record (tag 1 of the update
/// reply) starts with a bitmask of accepted images, which reached 0x1f (five
/// images) when the template was complete in every enrolment of the phase 0
/// sessions; redundant images left it unchanged.
pub const ENROLL_IMAGES: u32 = 5;

/// Enrolment stages announced to clients: a duplicate check (one touch, as
/// fprintd does for match-on-chip devices) and the images.
pub const ENROLL_STAGES: i32 = ENROLL_IMAGES as i32 + 1;

/// The accepted-image mask of an enrolment progress record (see
/// [`ENROLL_IMAGES`]); `None` when absent or too short.
pub fn progress_mask(header: Option<&[u8]>) -> Option<u16> {
    match header? {
        [a, b, _, _, ..] => Some(u16::from_le_bytes([*a, *b])),
        _ => None,
    }
}

/// What an accepted enrolment image means for the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageOutcome {
    /// One more stage done (not the last: completion is reported on its own).
    StagePassed,
    /// The image added nothing (same area again): lift and place differently.
    Redundant,
    /// The last stage: `enroll-completed` follows.
    Last,
}

/// Tracks enrolment progress across images.
#[derive(Debug, Default)]
pub struct Progress {
    mask: u16,
    /// Stages reported so far, including the duplicate check.
    pub stages: i32,
}

impl Progress {
    pub fn after_duplicate_check() -> Self {
        Progress { mask: 0, stages: 1 }
    }

    pub fn image(&mut self, header: Option<&[u8]>) -> ImageOutcome {
        match progress_mask(header) {
            Some(m) if m.count_ones() <= self.mask.count_ones() => ImageOutcome::Redundant,
            Some(m) => {
                self.mask = m;
                self.stages = 1 + m.count_ones() as i32;
                if self.stages >= ENROLL_STAGES {
                    ImageOutcome::Last
                } else {
                    ImageOutcome::StagePassed
                }
            }
            // No progress record: count the image as a stage, never claiming the
            // last one before the sensor says the template is complete.
            None => {
                if self.stages + 1 >= ENROLL_STAGES {
                    ImageOutcome::Redundant
                } else {
                    self.stages += 1;
                    ImageOutcome::StagePassed
                }
            }
        }
    }
}

/// The verify result for an identification. The sensor matches against every
/// enrolled print of every user (Windows accounts included): a match counts
/// only if the record belongs to the claimed user (and is the requested finger,
/// when one was named).
pub fn judge(id: &Identified, claimed_user: u16, finger: Option<u16>) -> &'static str {
    match id {
        Identified::Match { user, subtype, .. }
            if *user == u32::from(claimed_user) && finger.is_none_or(|f| f == *subtype) =>
        {
            "verify-match"
        }
        _ => "verify-no-match",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;

    #[test]
    fn verify_accepts_only_the_claimed_users_record() {
        let m = |user, subtype| Identified::Match {
            user,
            subtype,
            hash: vec![1],
        };
        assert_eq!(judge(&m(0x11, 7), 0x11, None), "verify-match");
        assert_eq!(judge(&m(0x11, 7), 0x11, Some(7)), "verify-match");
        // Another finger of the same user when a finger was named.
        assert_eq!(judge(&m(0x11, 8), 0x11, Some(7)), "verify-no-match");
        // Another user's record (another Linux user, or Windows).
        assert_eq!(judge(&m(0x12, 7), 0x11, None), "verify-no-match");
        assert_eq!(judge(&m(0x1_0011, 7), 0x11, None), "verify-no-match");
        assert_eq!(
            judge(&Identified::NoMatch(vec![4, 0]), 0x11, None),
            "verify-no-match"
        );
    }

    #[test]
    fn enrolment_progress() {
        // The 009a's masks: 01 03 03 07 0f 1f (one redundant image).
        let h = |m: u16| {
            let mut v = m.to_le_bytes().to_vec();
            v.extend([0x14, 0, 9, 9]);
            v
        };
        let mut p = Progress::after_duplicate_check();
        assert_eq!(p.image(Some(&h(0x01))), ImageOutcome::StagePassed);
        assert_eq!(p.image(Some(&h(0x03))), ImageOutcome::StagePassed);
        assert_eq!(p.image(Some(&h(0x03))), ImageOutcome::Redundant);
        assert_eq!(p.image(Some(&h(0x07))), ImageOutcome::StagePassed);
        assert_eq!(p.image(Some(&h(0x0f))), ImageOutcome::StagePassed);
        assert_eq!(p.stages, 5);
        assert_eq!(p.image(Some(&h(0x1f))), ImageOutcome::Last);
        assert_eq!(p.stages, ENROLL_STAGES);

        // Without progress records: never more stage-passed than stages - 1.
        let mut p = Progress::after_duplicate_check();
        let outcomes: Vec<_> = (0..7).map(|_| p.image(None)).collect();
        assert_eq!(
            outcomes,
            [
                ImageOutcome::StagePassed,
                ImageOutcome::StagePassed,
                ImageOutcome::StagePassed,
                ImageOutcome::StagePassed,
                ImageOutcome::Redundant,
                ImageOutcome::Redundant,
                ImageOutcome::Redundant,
            ]
        );
        assert_eq!(progress_mask(Some(&[1, 0, 0])), None);
        assert_eq!(progress_mask(Some(&[3, 0, 0x28, 0])), Some(3));
    }

    /// Records calls; interrupts and replies are scripted.
    struct Probe {
        ints: VecDeque<Vec<u8>>,
        cancel: CancelHandle,
        cleared: usize,
        paused: Duration,
        waits: Vec<Wait>,
    }

    impl Sensor for Probe {
        fn cmd(&mut self, _p: &[u8]) -> Result<Vec<u8>, ProtoError> {
            Ok(vec![0, 0])
        }
        fn is_open(&self) -> bool {
            true
        }
        fn open_channel(&mut self, _: &[u8]) -> Result<(), ProtoError> {
            Ok(())
        }
        fn wait_int(&mut self) -> Result<Vec<u8>, ProtoError> {
            if self.cancel.take() {
                return Err(ProtoError::Cancelled);
            }
            Ok(self.ints.pop_front().unwrap_or_default())
        }
        fn wait_for(&mut self, what: Wait) -> Result<Vec<u8>, ProtoError> {
            self.waits.push(what);
            if what == Wait::Finger && self.ints.is_empty() {
                return Err(ProtoError::Timeout {
                    waiting_for: what,
                    after: Duration::from_secs(30),
                });
            }
            self.wait_int()
        }
        fn read_82(&mut self) -> Result<Vec<u8>, ProtoError> {
            Ok(vec![])
        }
        fn clear_cancel(&mut self) {
            self.cleared += 1;
            self.cancel.take();
        }
        fn pause(&mut self, d: Duration) {
            self.paused += d;
        }
    }

    fn guarded(ints: Vec<Vec<u8>>) -> (Guarded<Probe>, Arc<Canceller>, Arc<StdMutex<Vec<Event>>>) {
        let cancel = CancelHandle::default();
        let canceller = Canceller::new();
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let s2 = seen.clone();
        let g = Guarded::new(
            Probe {
                ints: ints.into(),
                cancel: cancel.clone(),
                cleared: 0,
                paused: Duration::ZERO,
                waits: Vec::new(),
            },
            cancel,
            canceller.clone(),
            Arc::new(move |e| s2.lock().unwrap().push(e)),
        );
        (g, canceller, seen)
    }

    #[test]
    fn a_cancellation_before_the_run_clears_its_handle_is_kept() {
        let (mut g, c, _) = guarded(vec![vec![9]]);
        g.set_op(5);
        // Stop arrives before identify() starts and clears the handle.
        c.cancel(5);
        g.clear_cancel();
        assert_eq!(g.inner.cleared, 1);
        assert!(matches!(g.wait_int(), Err(ProtoError::Cancelled)));
        // A later run is not affected by the earlier cancellation.
        g.set_op(6);
        g.clear_cancel();
        assert_eq!(g.wait_int().unwrap(), [9]);
        // Sleep interrupts any run; shutdown too.
        c.start_sleep();
        g.clear_cancel();
        assert!(matches!(g.wait_int(), Err(ProtoError::Cancelled)));
        c.end_sleep();
        assert!(!c.should_stop(6));
        c.start_shutdown();
        assert!(c.should_stop(6));
        // No run, nothing to stop.
        assert!(!c.should_stop(0));
    }

    #[test]
    fn pause_ends_early_when_cancelled() {
        let (mut g, c, _) = guarded(vec![]);
        g.set_op(1);
        g.pause(Duration::from_millis(120));
        assert_eq!(g.inner.paused, Duration::from_millis(120));
        c.cancel(1);
        g.pause(Duration::from_secs(5));
        assert_eq!(g.inner.paused, Duration::from_millis(120));
    }

    #[test]
    fn bounded_waits_reach_the_session_unchanged() {
        let (mut g, _, seen) = guarded(vec![vec![0, 1, 2, 3, 4], vec![2, 0, 0, 0, 0]]);
        g.set_op(1);
        g.cmd(&[CMD_CAPTURE, 1, 2]).unwrap();
        assert_eq!(g.wait_for(Wait::CaptureStart).unwrap()[0], 0);
        assert_eq!(g.wait_for(Wait::Finger).unwrap()[0], 2);
        // The session's deadline error comes through as it is.
        assert!(matches!(
            g.wait_for(Wait::Finger),
            Err(ProtoError::Timeout {
                waiting_for: Wait::Finger,
                ..
            })
        ));
        assert_eq!(
            g.inner.waits,
            [Wait::CaptureStart, Wait::Finger, Wait::Finger]
        );
        let fin = |present, needed| Event::Finger { present, needed };
        assert_eq!(*seen.lock().unwrap(), [fin(false, true), fin(true, true)]);
    }

    #[test]
    fn finger_state_follows_capture_interrupts() {
        let (mut g, _, seen) = guarded(vec![
            vec![0, 7, 7, 7, 7],
            vec![0, 1, 2, 3, 4],
            vec![1, 9, 9, 9, 9],
            vec![2, 9, 9, 9, 9],
            vec![3, 0, 1, 0, 0],
            vec![3, 0, 6, 0, 0],
        ]);
        g.set_op(1);
        // Outside a capture, interrupts mean nothing for the finger.
        g.cmd(&[0x68]).unwrap();
        g.wait_int().unwrap();
        assert!(seen.lock().unwrap().is_empty());
        g.cmd(&[CMD_CAPTURE, 1, 2]).unwrap();
        for _ in 0..5 {
            g.wait_int().unwrap();
        }
        g.cmd(&[CMD_CAPTURE_STOP]).unwrap();
        let fin = |present, needed| Event::Finger { present, needed };
        assert_eq!(
            *seen.lock().unwrap(),
            [
                fin(false, true),
                fin(true, true),
                fin(true, false),
                fin(false, false)
            ]
        );
    }
}
