//! The application-level view of a sensor: python-validity's `tls.cmd` / `tls.app`
//! plus the interrupt and bulk reads that capture needs. Everything above this layer
//! (flash, database, capture, enrolment) is written against [`Sensor`], so the same
//! code drives real hardware ([`UsbSession`]) and recorded sessions
//! ([`crate::replay::ReplaySensor`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use p256::ecdsa::VerifyingKey;

use crate::channel::{self, Channel, TlsFlash, firmware_key};
use crate::cmd::{Error, status_word};
use crate::hex;
use crate::tls::{self, PskKeys};
use crate::transport::{Entropy, Transport, TransportError};
#[cfg(feature = "usb")]
use crate::usb::UsbSensor;

pub trait Sensor {
    /// `tls.cmd`: in the clear before the channel is open, encrypted afterwards.
    fn cmd(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error>;

    /// Whether the encrypted channel is open.
    fn is_open(&self) -> bool;

    /// `tls.app`: an application command that must go over the open channel.
    fn app(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.is_open() {
            return Err(channel::Error::Tls(tls::Error::NotSecure).into());
        }
        self.cmd(payload)
    }

    /// Opens the encrypted channel with the pairing material of a TLS flash image
    /// (partition 1 as read from, or about to be written to, the sensor).
    fn open_channel(&mut self, tls_flash: &[u8]) -> Result<(), Error>;

    /// `usb.wait_int`: blocks until the sensor raises an interrupt.
    /// Returns [`Error::Cancelled`] once [`CancelHandle::cancel`] was called.
    ///
    /// On a [`UsbSession`] this is [`Sensor::wait_for`]`(`[`Wait::Interrupt`]`)`:
    /// bounded by [`Deadlines::interrupt`].
    fn wait_int(&mut self) -> Result<Vec<u8>, Error>;

    /// Waits for the interrupt that ends `what`, bounded by its deadline
    /// ([`Deadlines`]): [`Error::Timeout`] when it does not come in time,
    /// [`Error::Cancelled`] once [`CancelHandle::cancel`] was called.
    ///
    /// Consecutive waits for the same `what`, with no command in between, share
    /// one deadline counted from the first of them: a phase stays bounded however
    /// many other interrupts the sensor raises meanwhile.
    ///
    /// The default (replays, test doubles) is [`Sensor::wait_int`]: those
    /// sensors answer from a finite script and have no deadline of their own.
    fn wait_for(&mut self, what: Wait) -> Result<Vec<u8>, Error> {
        let _ = what;
        self.wait_int()
    }

    /// `usb.read_82`: one bulk read of image data on endpoint 0x82. On a
    /// [`UsbSession`] it fails with [`Error::Timeout`] ([`Wait::Image`]) after
    /// [`Deadlines::image`].
    fn read_82(&mut self) -> Result<Vec<u8>, Error>;

    /// Clears a pending cancellation; called when a cancellable operation starts.
    fn clear_cancel(&mut self) {}

    /// Back-off between retries of a failed capture (a no-op when replaying).
    fn pause(&mut self, _d: Duration) {}
}

/// A bare transport is a sensor whose channel is never open: commands go in the
/// clear and there is no interrupt endpoint. Used before pairing material exists.
impl<T: Transport> Sensor for T {
    fn cmd(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(Transport::cmd(self, payload)?)
    }

    fn is_open(&self) -> bool {
        false
    }

    fn open_channel(&mut self, _tls_flash: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported("a bare transport has no channel"))
    }

    fn wait_int(&mut self) -> Result<Vec<u8>, Error> {
        Err(Error::Unsupported(
            "a bare transport has no interrupt endpoint",
        ))
    }

    fn read_82(&mut self) -> Result<Vec<u8>, Error> {
        Err(Error::Unsupported("a bare transport has no image endpoint"))
    }
}

/// What a real session needs from the USB device beyond command exchanges.
pub trait UsbLink: Transport {
    /// One interrupt packet, or `Ok(None)` after `timeout`.
    fn interrupt(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError>;
    /// One bulk read on endpoint 0x82 (up to 1 MiB).
    fn bulk_82(&mut self, timeout: Duration) -> Result<Vec<u8>, TransportError>;
}

#[cfg(feature = "usb")]
impl UsbLink for UsbSensor {
    fn interrupt(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        self.wait_int(timeout)
    }

    fn bulk_82(&mut self, timeout: Duration) -> Result<Vec<u8>, TransportError> {
        self.read_82(timeout)
    }
}

/// Cancels a blocking [`Sensor::wait_int`] from another thread.
#[derive(Debug, Clone, Default)]
pub struct CancelHandle(Arc<AtomicBool>);

impl CancelHandle {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Consumes a pending cancellation: true once per [`CancelHandle::cancel`].
    ///
    /// For [`Sensor`] implementations other than [`UsbSession`] (test doubles,
    /// emulators) that honour the same handle in their `wait_int`.
    pub fn take(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }

    fn clear(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// What a wait on the sensor is waiting for; it selects the wait's deadline
/// in [`Deadlines`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Wait {
    /// The sensor acknowledging a capture program (interrupt 0): the scan is
    /// armed and the LED pattern runs.
    CaptureStart,
    /// A finger on the sensor once the scan is armed (interrupt 2). The only
    /// wait that depends on the user.
    Finger,
    /// The capture completing once the finger is down (interrupts 3).
    Capture,
    /// The on-chip match result (the interrupt after command `5e`).
    Match,
    /// An enrolment step: the interrupts after the enrolment update commands
    /// (`68`, `6b`) and after storing the new finger record.
    Enrollment,
    /// Image data on endpoint 0x82 (calibration).
    Image,
    /// Any other interrupt ([`Sensor::wait_int`]).
    Interrupt,
}

impl Wait {
    /// Whether this is the wait for the user's finger; every other wait is a
    /// wait for the sensor, which a working sensor always ends quickly.
    pub fn is_finger(self) -> bool {
        self == Wait::Finger
    }
}

impl core::fmt::Display for Wait {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Wait::CaptureStart => "the capture to start",
            Wait::Finger => "a finger",
            Wait::Capture => "the capture to complete",
            Wait::Match => "the match result",
            Wait::Enrollment => "the enrolment update",
            Wait::Image => "image data",
            Wait::Interrupt => "an interrupt",
        })
    }
}

/// How long each wait on the sensor may last before it fails with
/// [`Error::Timeout`]. Only [`Deadlines::finger`] waits for the user; every
/// other deadline bounds a wait for the sensor, and passing it means the sensor
/// stopped answering (a session should then be closed, the sensor rebooted and
/// reopened).
///
/// The defaults ([`Deadlines::DEFAULT`]) come from the phase 0 sessions
/// (python-validity on a 06cb:009a: pairings, two enrolments, identifications),
/// with a wide margin over the longest delay observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadlines {
    /// Placing the finger once the scan is armed (default 30 s, pam_fprintd's
    /// default verification timeout).
    pub finger: Duration,
    /// Capture program sent to scan armed (default 2 s).
    pub capture_start: Duration,
    /// Finger detected to capture complete (default 5 s).
    pub capture: Duration,
    /// Match command to its result (default 10 s).
    pub matching: Duration,
    /// Each enrolment step (default 5 s).
    pub enrollment: Duration,
    /// One bulk read of image data (default 5 s).
    pub image: Duration,
    /// Any other interrupt (default 5 s).
    pub interrupt: Duration,
}

// How the defaults were derived. Longest delay observed in the phase 0 logs
// (14 python-validity session logs on a 06cb:009a) and the number of samples:
//   capture start, capture command reply to interrupt 0:   6 ms   (53)
//   capture, interrupt 2 to the interrupt 3 that ends it:  856 ms (52)
//   match, command 5e reply to its interrupt:               829 ms (32)
//   enrolment, commands 68 / 6b / new record to interrupt:  431 ms (34)
//   image data, capture command reply to the bulk read:     103 ms (4)
//   other interrupts:                                        6 ms   (18)
// Sensor deadlines are at least 5x the longest delay (2 s for a 6 ms one); the
// match got 10 s (12x) because it scans every enrolled finger and only 2 were
// enrolled. The finger wait (median 12 ms, 90th percentile 808 ms, longest
// 62.9 s, one user pause) is a user choice: 30 s, pam_fprintd's default.
impl Deadlines {
    pub const DEFAULT: Deadlines = Deadlines {
        finger: Duration::from_secs(30),
        capture_start: Duration::from_secs(2),
        capture: Duration::from_secs(5),
        matching: Duration::from_secs(10),
        enrollment: Duration::from_secs(5),
        image: Duration::from_secs(5),
        interrupt: Duration::from_secs(5),
    };

    /// The deadline of `what`.
    pub fn get(&self, what: Wait) -> Duration {
        match what {
            Wait::CaptureStart => self.capture_start,
            Wait::Finger => self.finger,
            Wait::Capture => self.capture,
            Wait::Match => self.matching,
            Wait::Enrollment => self.enrollment,
            Wait::Image => self.image,
            Wait::Interrupt => self.interrupt,
        }
    }
}

impl Default for Deadlines {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The monotonic clock deadlines are measured with ([`Instant::now`] unless a
/// test injects its own through [`UsbSession::with_clock`]).
type Clock = Box<dyn Fn() -> Instant + Send + Sync>;

/// Interrupt polling period: a cancellation is noticed within this delay.
const INT_POLL: Duration = Duration::from_millis(100);

/// A live session: the USB link, the channel once open, and the randomness source.
///
/// Every wait is bounded ([`Deadlines`]). At `trace` level the session logs one
/// line per command and reply (opcode, length and status word, never the
/// content), one per interrupt and one per wait with its deadline.
pub struct UsbSession<L: UsbLink, E: Entropy> {
    link: L,
    channel: Option<Channel>,
    rng: E,
    psk: PskKeys,
    fw_key: VerifyingKey,
    cancel: CancelHandle,
    deadlines: Deadlines,
    clock: Clock,
    /// The wait in progress and when it started (reset by every command).
    phase: Option<(Wait, Instant)>,
    /// For the timeout report: opcode of the last command, last interrupt.
    last_cmd: Option<u8>,
    last_int: Option<Vec<u8>>,
}

impl<L: UsbLink, E: Entropy> core::fmt::Debug for UsbSession<L, E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UsbSession")
            .field("open", &self.is_open())
            .field("deadlines", &self.deadlines)
            .finish_non_exhaustive()
    }
}

impl<L: UsbLink, E: Entropy> UsbSession<L, E> {
    /// `psk` are the host's pre-shared keys ([`PskKeys::from_hw`] of the DMI product
    /// name and serial), which seal the host key in the TLS flash.
    pub fn new(link: L, rng: E, psk: PskKeys) -> Self {
        UsbSession {
            link,
            channel: None,
            rng,
            psk,
            fw_key: firmware_key(),
            cancel: CancelHandle::default(),
            deadlines: Deadlines::DEFAULT,
            clock: Box::new(Instant::now),
            phase: None,
            last_cmd: None,
            last_int: None,
        }
    }

    /// Replaces the wait deadlines (default [`Deadlines::DEFAULT`]).
    pub fn with_deadlines(mut self, deadlines: Deadlines) -> Self {
        self.deadlines = deadlines;
        self
    }

    pub fn deadlines(&self) -> &Deadlines {
        &self.deadlines
    }

    /// Replaces the clock the deadlines are measured with (tests: a fake clock
    /// that the fake link advances, so that a 30 s deadline passes at once).
    pub fn with_clock(mut self, clock: impl Fn() -> Instant + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Replaces the firmware key that must have signed the sensor's ECDH key
    /// (hardcoded per firmware revision in the vendor driver; tests use their own).
    pub fn with_firmware_key(mut self, key: VerifyingKey) -> Self {
        self.fw_key = key;
        self
    }

    pub fn cancel_handle(&self) -> CancelHandle {
        self.cancel.clone()
    }

    pub fn psk(&self) -> &PskKeys {
        &self.psk
    }

    /// Gives the link back, e.g. to reset the device.
    pub fn into_link(self) -> L {
        self.link
    }

    /// The error for a wait on `what` that passed its deadline `after`, logged
    /// with the last command and interrupt (warn level).
    fn timed_out(&mut self, what: Wait, after: Duration) -> Error {
        self.phase = None;
        let cmd = self
            .last_cmd
            .map_or_else(|| "none".to_string(), |c| format!("{c:02x}"));
        let int = self
            .last_int
            .as_deref()
            .map_or_else(|| "none".to_string(), hex::encode);
        log::warn!(
            "timed out after {after:?} waiting for {what} (last command {cmd}, last interrupt {int})"
        );
        Error::Timeout {
            waiting_for: what,
            after,
        }
    }
}

/// The opcode of a command, for the trace.
fn opcode(payload: &[u8]) -> String {
    payload
        .first()
        .map_or_else(|| "--".to_string(), |c| format!("{c:02x}"))
}

impl<L: UsbLink, E: Entropy> Sensor for UsbSession<L, E> {
    /// Sends a command. At `trace` level, logs `>app> OP (N bytes)` and
    /// `<app< OP (N bytes, status SSSS)` for a command over the channel
    /// (`>plain>` / `<plain<` before it is open): the opcode, the lengths and the
    /// status word only, never the content, which holds keys, templates and
    /// flash data.
    fn cmd(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        self.phase = None;
        self.last_cmd = payload.first().copied();
        let (kind, op) = (
            if self.channel.is_some() {
                "app"
            } else {
                "plain"
            },
            opcode(payload),
        );
        log::trace!(">{kind}> {op} ({} bytes)", payload.len());
        let r = match &mut self.channel {
            Some(ch) => ch
                .app(&mut self.link, &mut self.rng, payload)
                .map_err(Error::from),
            None => self.link.cmd(payload).map_err(Error::from),
        };
        match &r {
            Ok(rsp) => log::trace!(
                "<{kind}< {op} ({} bytes, status {})",
                rsp.len(),
                status_word(rsp).map_or_else(|_| "none".to_string(), |s| format!("{s:04x}"))
            ),
            Err(e) => log::trace!("<{kind}< {op} failed: {e}"),
        }
        r
    }

    fn is_open(&self) -> bool {
        self.channel.as_ref().is_some_and(Channel::is_open)
    }

    fn open_channel(&mut self, tls_flash: &[u8]) -> Result<(), Error> {
        self.channel = None;
        self.phase = None;
        let flash = TlsFlash::parse(tls_flash, &self.psk, &self.fw_key)?;
        let mut ch = Channel::new(flash);
        log::trace!("channel: handshake");
        ch.open(&mut self.link, &mut self.rng)?;
        log::trace!("channel: open");
        self.channel = Some(ch);
        Ok(())
    }

    fn wait_int(&mut self) -> Result<Vec<u8>, Error> {
        self.wait_for(Wait::Interrupt)
    }

    // python-validity clears its cancel flag every time it starts waiting, so a
    // cancellation that arrives while a command is in flight is lost and the wait
    // never ends. Here the flag is only cleared when an operation starts
    // (`clear_cancel`) or when the cancellation is delivered. python-validity
    // also waits without a deadline; here every wait has one.
    //
    // Trace: `wait: WHAT (deadline D)` when a wait starts, `<int< HEX` per
    // interrupt (5-byte event records: type, then flags; no payload).
    fn wait_for(&mut self, what: Wait) -> Result<Vec<u8>, Error> {
        let limit = self.deadlines.get(what);
        let start = match self.phase {
            Some((w, t)) if w == what => t,
            _ => {
                log::trace!("wait: {what} (deadline {limit:?})");
                (self.clock)()
            }
        };
        self.phase = Some((what, start));
        loop {
            let left = limit.saturating_sub((self.clock)().saturating_duration_since(start));
            if left.is_zero() {
                return Err(self.timed_out(what, limit));
            }
            if let Some(b) = self.link.interrupt(left.min(INT_POLL))? {
                log::trace!("<int< {}", hex::encode(&b));
                self.last_int = Some(b.clone());
                return Ok(b);
            }
            if self.cancel.take() {
                self.phase = None;
                return Err(Error::Cancelled);
            }
        }
    }

    fn read_82(&mut self) -> Result<Vec<u8>, Error> {
        self.phase = None;
        let limit = self.deadlines.image;
        log::trace!("wait: {} (deadline {limit:?})", Wait::Image);
        match self.link.bulk_82(limit) {
            Ok(b) => {
                log::trace!("<82< {} bytes", b.len());
                Ok(b)
            }
            Err(TransportError::Timeout) => Err(self.timed_out(Wait::Image, limit)),
            Err(e) => Err(e.into()),
        }
    }

    fn clear_cancel(&mut self) {
        self.cancel.clear();
    }

    fn pause(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Link {
        replies: VecDeque<Vec<u8>>,
        ints: VecDeque<Option<Vec<u8>>>,
        cancel_after_polls: Option<(usize, CancelHandle)>,
    }

    impl Transport for Link {
        fn cmd(&mut self, _out: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.replies.pop_front().ok_or(TransportError::Disconnected)
        }
    }

    impl UsbLink for Link {
        fn interrupt(&mut self, _t: Duration) -> Result<Option<Vec<u8>>, TransportError> {
            if let Some((n, h)) = &mut self.cancel_after_polls {
                if *n == 0 {
                    h.cancel();
                } else {
                    *n -= 1;
                }
            }
            Ok(self.ints.pop_front().unwrap_or(None))
        }
        fn bulk_82(&mut self, _t: Duration) -> Result<Vec<u8>, TransportError> {
            Ok(vec![7; 3])
        }
    }

    struct Zero;
    impl Entropy for Zero {
        fn fill(&mut self, b: &mut [u8]) {
            b.fill(0);
        }
    }

    fn session(link: Link) -> UsbSession<Link, Zero> {
        UsbSession::new(link, Zero, PskKeys::from_hw("Synthetic", "0"))
    }

    #[test]
    fn plain_until_open_and_app_refused() {
        let mut s = session(Link {
            replies: VecDeque::from([vec![0, 0, 1]]),
            ints: VecDeque::new(),
            cancel_after_polls: None,
        });
        assert!(!s.is_open());
        assert_eq!(s.cmd(&[1]).unwrap(), [0, 0, 1]);
        assert!(matches!(
            s.app(&[1]),
            Err(Error::Channel(channel::Error::Tls(tls::Error::NotSecure)))
        ));
        assert!(s.open_channel(&[0xff; 64]).is_err());
        assert!(!s.is_open());
        assert_eq!(s.read_82().unwrap(), [7, 7, 7]);
    }

    #[test]
    fn wait_int_polls_until_data_or_cancel() {
        let mut s = session(Link {
            replies: VecDeque::new(),
            ints: VecDeque::from([None, None, Some(vec![2, 0])]),
            cancel_after_polls: None,
        });
        assert_eq!(s.wait_int().unwrap(), [2, 0]);

        let h = CancelHandle::default();
        let mut s = session(Link {
            replies: VecDeque::new(),
            ints: VecDeque::new(),
            cancel_after_polls: Some((3, h.clone())),
        });
        s.cancel = h;
        assert!(matches!(s.wait_int(), Err(Error::Cancelled)));
        // Delivered once: the flag is consumed.
        assert!(!s.cancel.take());

        // A cancellation requested before the wait is not lost.
        let mut s = session(Link {
            replies: VecDeque::new(),
            ints: VecDeque::from([None]),
            cancel_after_polls: None,
        });
        s.cancel_handle().cancel();
        assert!(matches!(s.wait_int(), Err(Error::Cancelled)));
        s.cancel_handle().cancel();
        s.clear_cancel();
        s.link.ints = VecDeque::from([Some(vec![3])]);
        assert_eq!(s.wait_int().unwrap(), [3]);
    }

    /// A link whose polls each last their whole timeout on a shared fake clock,
    /// raising the scripted interrupts in between.
    struct Timed {
        ints: VecDeque<Vec<u8>>,
        passed: Arc<std::sync::Mutex<Duration>>,
        polls: Vec<Duration>,
    }

    impl Transport for Timed {
        fn cmd(&mut self, _out: &[u8]) -> Result<Vec<u8>, TransportError> {
            Ok(vec![0, 0])
        }
    }

    impl UsbLink for Timed {
        fn interrupt(&mut self, t: Duration) -> Result<Option<Vec<u8>>, TransportError> {
            self.polls.push(t);
            *self.passed.lock().unwrap() += t;
            Ok(self.ints.pop_front())
        }
        fn bulk_82(&mut self, _t: Duration) -> Result<Vec<u8>, TransportError> {
            Err(TransportError::Disconnected)
        }
    }

    fn timed(ints: Vec<Vec<u8>>, d: Deadlines) -> UsbSession<Timed, Zero> {
        let passed = Arc::new(std::sync::Mutex::new(Duration::ZERO));
        let origin = Instant::now();
        let p = passed.clone();
        UsbSession::new(
            Timed {
                ints: ints.into(),
                passed,
                polls: Vec::new(),
            },
            Zero,
            PskKeys::from_hw("Synthetic", "0"),
        )
        .with_deadlines(d)
        .with_clock(move || origin + *p.lock().unwrap())
    }

    fn passed(s: &UsbSession<Timed, Zero>) -> Duration {
        *s.link.passed.lock().unwrap()
    }

    #[test]
    fn waits_end_at_their_deadline() {
        let d = Deadlines {
            finger: Duration::from_millis(350),
            interrupt: Duration::from_millis(250),
            ..Deadlines::DEFAULT
        };
        // The plain wait is bounded too; polls never overshoot the deadline.
        let mut s = timed(vec![], d);
        assert!(matches!(
            s.wait_int(),
            Err(Error::Timeout { waiting_for: Wait::Interrupt, after }) if after == d.interrupt
        ));
        assert_eq!(passed(&s), d.interrupt);
        assert_eq!(
            s.link.polls,
            [100, 100, 50].map(Duration::from_millis).to_vec()
        );

        // Consecutive waits for the finger share one deadline, however many
        // interrupts arrive in between...
        let mut s = timed(vec![vec![1], vec![1], vec![1]], d);
        for _ in 0..3 {
            assert_eq!(s.wait_for(Wait::Finger).unwrap(), [1]);
        }
        assert!(matches!(
            s.wait_for(Wait::Finger),
            Err(Error::Timeout {
                waiting_for: Wait::Finger,
                ..
            })
        ));
        assert_eq!(passed(&s), d.finger);

        // ...but a command, or another wait, starts a new one.
        let mut s = timed(vec![vec![1], vec![1], vec![1]], d);
        for _ in 0..3 {
            assert_eq!(s.wait_for(Wait::Finger).unwrap(), [1]);
        }
        s.cmd(&[0x39]).unwrap();
        assert!(s.wait_for(Wait::Finger).is_err());
        assert_eq!(passed(&s), Duration::from_millis(300) + d.finger);
        let mut s = timed(vec![vec![1], vec![1], vec![1]], d);
        for _ in 0..3 {
            assert_eq!(s.wait_for(Wait::Finger).unwrap(), [1]);
        }
        assert!(s.wait_for(Wait::Interrupt).is_err());
        assert_eq!(passed(&s), Duration::from_millis(300) + d.interrupt);

        // A cancellation still ends a wait, and wins over a passed deadline.
        let mut s = timed(vec![], d);
        s.cancel_handle().cancel();
        assert!(matches!(s.wait_for(Wait::Finger), Err(Error::Cancelled)));
        let mut s = timed(
            vec![],
            Deadlines {
                finger: Duration::from_millis(100),
                ..d
            },
        );
        s.cancel_handle().cancel();
        assert!(matches!(s.wait_for(Wait::Finger), Err(Error::Cancelled)));

        // A zero deadline fails at once, without polling.
        let mut s = timed(
            vec![vec![9]],
            Deadlines {
                capture_start: Duration::ZERO,
                ..d
            },
        );
        assert!(matches!(
            s.wait_for(Wait::CaptureStart),
            Err(Error::Timeout {
                waiting_for: Wait::CaptureStart,
                ..
            })
        ));
        assert!(s.link.polls.is_empty());
        assert_eq!(s.deadlines().capture_start, Duration::ZERO);

        // Other image read errors are not timeouts.
        assert!(matches!(
            s.read_82(),
            Err(Error::Transport(TransportError::Disconnected))
        ));
    }

    #[test]
    fn timeouts_say_what_was_awaited() {
        let e = Error::Timeout {
            waiting_for: Wait::Finger,
            after: Duration::from_secs(30),
        };
        assert_eq!(e.to_string(), "timed out after 30s waiting for a finger");
        let all = [
            Wait::CaptureStart,
            Wait::Finger,
            Wait::Capture,
            Wait::Match,
            Wait::Enrollment,
            Wait::Image,
            Wait::Interrupt,
        ];
        let names: std::collections::BTreeSet<String> =
            all.iter().map(ToString::to_string).collect();
        assert_eq!(names.len(), all.len());
        assert_eq!(all.iter().filter(|w| w.is_finger()).count(), 1);
    }
}
