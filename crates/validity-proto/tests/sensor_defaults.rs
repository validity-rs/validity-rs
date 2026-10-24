//! The parts of the sensor layer that the protocol tests drive only indirectly:
//! a bare transport seen as a [`Sensor`], the session-ending commands, clearing
//! a stale cancellation, the retry pause and the OS random source. Written from
//! the survivors of a mutation-testing run. All data is synthetic.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use validity_proto::Error;
use validity_proto::cmd::REBOOT;
use validity_proto::init::close;
use validity_proto::scanner::factory_reset;
use validity_proto::session::{Sensor, UsbLink, UsbSession};
use validity_proto::tls::PskKeys;
use validity_proto::transport::{Entropy, OsEntropy, Transport, TransportError};
use validity_proto::vendor::Blobs;

/// A transport that records every command and answers each with status 0000.
#[derive(Default)]
struct Recorder(Vec<Vec<u8>>);

impl Transport for Recorder {
    fn cmd(&mut self, out: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.0.push(out.to_vec());
        Ok(vec![0, 0])
    }
}

#[test]
fn a_bare_transport_is_a_sensor_without_channel_or_endpoints() {
    let mut t = Recorder::default();
    assert!(!Sensor::is_open(&t));
    assert_eq!(Sensor::cmd(&mut t, &[0x3e]).unwrap(), [0, 0]);
    assert!(matches!(
        t.open_channel(&[0; 64]),
        Err(Error::Unsupported("a bare transport has no channel"))
    ));
    assert!(matches!(
        Sensor::wait_int(&mut t),
        Err(Error::Unsupported(
            "a bare transport has no interrupt endpoint"
        ))
    ));
    assert!(matches!(
        t.read_82(),
        Err(Error::Unsupported("a bare transport has no image endpoint"))
    ));
    // `app` needs the channel: refused before anything is sent.
    assert!(t.app(&[1]).is_err());
    assert_eq!(t.0, [vec![0x3e]]);
}

#[test]
fn close_reboots_the_sensor() {
    let mut t = Recorder::default();
    close(&mut t).unwrap();
    assert_eq!(t.0, [REBOOT.to_vec()]);
}

#[test]
fn factory_reset_erases_then_reboots() {
    let blobs = Blobs {
        init_hardcoded: vec![6, 1, 1],
        init_hardcoded_clean_slate: vec![6, 2, 2],
        reset_blob: vec![6, 3, 3],
        db_write_enable: vec![6, 4, 4],
        partition_signature: vec![0x5a; 256],
    };
    let mut t = Recorder::default();
    factory_reset(&mut t, &blobs).unwrap();
    let mut erase = vec![0x10];
    erase.extend_from_slice(&[0; 0x61]);
    assert_eq!(t.0, [vec![6, 3, 3], erase, REBOOT.to_vec()]);
}

/// A link whose interrupt endpoint answers from a script (`None`: nothing yet).
struct Link(VecDeque<Option<Vec<u8>>>);

impl Transport for Link {
    fn cmd(&mut self, _out: &[u8]) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::Disconnected)
    }
}

impl UsbLink for Link {
    fn interrupt(&mut self, _timeout: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(self.0.pop_front().flatten())
    }
    fn bulk_82(&mut self, _timeout: Duration) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::Timeout)
    }
}

struct Zero;

impl Entropy for Zero {
    fn fill(&mut self, b: &mut [u8]) {
        b.fill(0);
    }
}

fn session(ints: Vec<Option<Vec<u8>>>) -> UsbSession<Link, Zero> {
    UsbSession::new(Link(ints.into()), Zero, PskKeys::from_hw("Synthetic", "0"))
}

#[test]
fn a_stale_cancellation_is_delivered_until_cleared() {
    // Not cleared: the pending cancellation ends the next wait.
    let mut s = session(vec![None, Some(vec![2, 0])]);
    s.cancel_handle().cancel();
    assert!(matches!(s.wait_int(), Err(Error::Cancelled)));

    // Cleared when the operation starts: the wait goes on to the interrupt.
    let mut s = session(vec![None, Some(vec![2, 0])]);
    let h = s.cancel_handle();
    h.cancel();
    s.clear_cancel();
    assert_eq!(s.wait_int().unwrap(), [2, 0]);
    // Cleared means consumed: nothing is left for a later wait either.
    assert!(!h.take());
}

#[test]
fn a_session_pauses_for_real() {
    let mut s = session(vec![]);
    let t = Instant::now();
    s.pause(Duration::from_millis(200));
    assert!(t.elapsed() >= Duration::from_millis(200));
}

#[test]
fn os_entropy_fills_the_buffer() {
    // Two 256-bit draws: all-zero, or equal, has probability 2^-256.
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    OsEntropy.fill(&mut a);
    OsEntropy.fill(&mut b);
    assert_ne!(a, [0; 32]);
    assert_ne!(a, b);
}

/// Without a sensor, the USB layer enumerates nothing it does not support and
/// gives up opening once its deadline passed. On a machine where a supported
/// sensor is plugged in, only the enumeration is checked: opening it here would
/// take it from the daemon.
#[cfg(feature = "usb")]
#[test]
fn usb_without_a_sensor() {
    use std::sync::mpsc;
    use validity_proto::usb::{UsbSensor, find_supported, is_supported};

    let found = find_supported();
    if let Ok(ids) = &found {
        for &(v, p) in ids {
            assert!(is_supported(v, p), "{v:04x}:{p:04x} is not supported");
        }
    }
    if found.as_ref().is_ok_and(|ids| !ids.is_empty()) {
        eprintln!("a supported sensor is plugged in: open_wait not exercised");
        return;
    }
    let timeout = Duration::from_millis(300);
    let (tx, rx) = mpsc::channel();
    // In a thread, so that a wait that never ends fails the test instead of
    // hanging it.
    std::thread::spawn(move || {
        let t = Instant::now();
        let r = UsbSensor::open_wait(timeout).map(|_| ());
        let _ = tx.send((r, t.elapsed()));
    });
    let (r, took) = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("open_wait ends once its deadline passed");
    assert!(r.is_err(), "no sensor, yet open_wait succeeded");
    assert!(
        took >= timeout,
        "gave up after {took:?}, before {timeout:?}"
    );
}
