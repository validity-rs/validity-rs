//! Every wait on the sensor is bounded (issue #2). A fake sensor behind a real
//! `UsbSession` (channel included) that never raises the interrupt an operation
//! waits for must make enrolment, identification and calibration fail with
//! `Error::Timeout` once the deadline has passed, and not before. Time is a fake
//! clock that the fake link advances by each poll's timeout, so a 30 s deadline
//! passes in microseconds.
//!
//! The trace (`log::trace!`) must never contain a command or reply payload.

use std::collections::VecDeque;
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use validity_proto::Error;
use validity_proto::pairing::{ECDH_BLOCK_LEN, encrypt_key, make_tls_flash};
use validity_proto::scanner::{EnrollProgress, Identified, RomInfo, Scanner};
use validity_proto::session::{Deadlines, Sensor, UsbLink, UsbSession, Wait};
use validity_proto::sid::Sid;
use validity_proto::tables::{SensorCaptureProg, SensorTypeInfo, dev_info_lookup};
use validity_proto::tls::{self, PskKeys, SessionKeys};
use validity_proto::transport::{Entropy, Transport, TransportError};
use validity_proto::vendor::Blobs;

// ------------------------------------------------------------ trace capture

/// Every log record of this test binary, as `LEVEL message`.
fn records() -> &'static Mutex<Vec<String>> {
    static LOG: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    LOG.get_or_init(|| {
        struct Capture;
        impl log::Log for Capture {
            fn enabled(&self, _: &log::Metadata<'_>) -> bool {
                true
            }
            fn log(&self, r: &log::Record<'_>) {
                records()
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", r.level(), r.args()));
            }
            fn flush(&self) {}
        }
        log::set_logger(&Capture).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        Mutex::new(Vec::new())
    })
}

// ------------------------------------------------------------ keys and flash

fn key(tag: &str) -> SecretKey {
    (0u32..)
        .find_map(|i| SecretKey::from_slice(&Sha256::digest(format!("{tag}-{i}"))).ok())
        .unwrap()
}

struct Det(u64);
impl Entropy for Det {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.0 >> 56) as u8;
        }
    }
}

fn le(b: &[u8]) -> Vec<u8> {
    b.iter().rev().copied().collect()
}

/// Sensor ECDH key block (flash block 6) signed by `fw`.
fn ecdh_block(sensor: &PublicKey, fw: &SigningKey) -> Vec<u8> {
    let p = sensor.to_sec1_point(false);
    let mut k = vec![0u8; 0x90];
    k[0x08..0x28].copy_from_slice(&le(&p.as_bytes()[1..33]));
    k[0x4c..0x6c].copy_from_slice(&le(&p.as_bytes()[33..65]));
    let sig: DerSignature = fw.sign(&k);
    k.extend_from_slice(&(sig.as_bytes().len() as u32).to_le_bytes());
    k.extend_from_slice(sig.as_bytes());
    k.resize(ECDH_BLOCK_LEN, 0);
    k
}

// ------------------------------------------------------------ the fake sensor

/// What the fake sensor does; every "never" is the interrupt it withholds.
#[derive(Clone, Copy, Default)]
struct Behaviour {
    /// Raises interrupt 0 after a capture program.
    capture_start: bool,
    /// A finger arrives once the scan is armed (interrupts 2, then 3 done).
    finger: bool,
    /// While waiting for the finger, raises an unrelated interrupt at every
    /// poll (the finger phase must stay bounded all the same).
    noise: bool,
    /// Raises the interrupt after a match command.
    match_result: bool,
    /// Raises the interrupts of the enrolment steps.
    enrollment: bool,
}

const SERVER_RANDOM: [u8; 32] = [0x5a; 32];

/// The fake clock: an origin plus the time the fake link let pass.
#[derive(Clone)]
struct Clock {
    origin: Instant,
    passed: Arc<Mutex<Duration>>,
}

impl Clock {
    fn new() -> Self {
        Clock {
            origin: Instant::now(),
            passed: Arc::default(),
        }
    }
    fn advance(&self, d: Duration) {
        *self.passed.lock().unwrap() += d;
    }
    fn elapsed(&self) -> Duration {
        *self.passed.lock().unwrap()
    }
}

/// What the test inspects after the run.
#[derive(Default)]
struct Seen {
    /// Plaintext application commands, in order.
    commands: Vec<Vec<u8>>,
    /// Plaintext replies, in order (commands in the clear included).
    replies: Vec<Vec<u8>>,
    /// Timeouts asked of the image endpoint.
    bulk_timeouts: Vec<Duration>,
}

struct FakeLink {
    behaviour: Behaviour,
    clock: Clock,
    seen: Arc<Mutex<Seen>>,
    ints: VecDeque<Vec<u8>>,
    armed: bool,
    sensor: SecretKey,
    transcript: Sha256,
    client_random: [u8; 32],
    keys: Option<SessionKeys>,
    handshakes: u8,
    /// Reply to commands in the clear.
    plain_reply: Vec<u8>,
}

impl FakeLink {
    fn server_keys(&self) -> SessionKeys {
        let k = self.keys.clone().unwrap();
        SessionKeys {
            sign: k.validation,
            validation: k.sign,
            encryption: k.decryption,
            decryption: k.encryption,
            ..k
        }
    }

    /// The server side of the handshake (as in `tests/session.rs`).
    fn handshake(&mut self, out: &[u8]) -> Vec<u8> {
        self.handshakes += 1;
        let recs = tls::split_records(&out[4..]).unwrap();
        if self.handshakes == 1 {
            let hello = recs[0].1;
            self.client_random = hello[6..38].try_into().unwrap();
            self.transcript.update(hello);
            let mut sh = vec![3, 3];
            sh.extend_from_slice(&SERVER_RANDOM);
            sh.extend_from_slice(&[0, 0xc0, 0x05, 0]);
            let mut hs = tls::handshake_msg(0x02, &sh);
            hs.extend(tls::handshake_msg(0x0d, &[0x01, 0x40, 0, 0]));
            hs.extend(tls::handshake_msg(0x0e, &[]));
            self.transcript.update(&hs);
            return tls::record(tls::CONTENT_HANDSHAKE, &hs);
        }
        let hs = recs[0].1;
        self.transcript.update(hs);
        let cert_len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
        let kex = &hs[4 + cert_len..];
        let eph = PublicKey::from_sec1_bytes(&kex[4..4 + kex[3] as usize]).unwrap();
        self.keys = Some(SessionKeys::derive(
            &self.sensor,
            &eph,
            &self.client_random,
            &SERVER_RANDOM,
        ));
        let h: [u8; 32] = self.transcript.clone().finalize().into();
        let k = self.keys.as_ref().unwrap();
        let sfin = tls::handshake_msg(0x14, &k.verify_data(b"server finished", &h));
        let mut rsp = tls::record(tls::CONTENT_CHANGE_CIPHER_SPEC, &[1]);
        rsp.extend(tls::record(
            tls::CONTENT_HANDSHAKE,
            &tls::seal(&self.server_keys(), tls::CONTENT_HANDSHAKE, &sfin, &[9; 16]),
        ));
        rsp
    }

    /// The sensor's answer to an application command.
    fn app(&mut self, c: &[u8]) -> Vec<u8> {
        let b = self.behaviour;
        match c[0] {
            // Capture program: finger captures (no line count) raise interrupts.
            0x02 => {
                if c[3..5] == [0, 0] {
                    self.armed = true;
                    if b.capture_start {
                        self.ints.push_back(vec![0, 0, 0, 0, 0]);
                    }
                    if b.capture_start && b.finger {
                        self.ints.push_back(vec![2, 0, 0, 0, 0]);
                        self.ints.push_back(vec![3, 0, 0x06, 0, 0]);
                    }
                }
                vec![0, 0]
            }
            0x04 => {
                self.armed = false;
                vec![0, 0]
            }
            // Capture result: geometry, no scan error.
            0x51 => vec![
                0, 0, 12, 0, 0, 0, 0x60, 0, 0x50, 0, 0x20, 1, 4, 0, 0, 0, 0, 0,
            ],
            0x5e => {
                if b.match_result {
                    self.ints.push_back(vec![4, 0, 0, 0, 0]);
                }
                vec![0, 0]
            }
            0x68 => {
                if b.enrollment {
                    self.ints.push_back(vec![3, 0, 0, 0, 0]);
                }
                vec![0, 0, 0x78, 0x56, 0x34, 0x12]
            }
            // Glow, match cleanup, enrolment start / end, anything else.
            _ => vec![0, 0],
        }
    }
}

impl Transport for FakeLink {
    fn cmd(&mut self, out: &[u8]) -> Result<Vec<u8>, TransportError> {
        if out.starts_with(&[0x44, 0, 0, 0]) {
            return Ok(self.handshake(out));
        }
        if out.first() == Some(&tls::CONTENT_APP_DATA) {
            let recs = tls::split_records(out).unwrap();
            let c = tls::open(&self.server_keys(), tls::CONTENT_APP_DATA, recs[0].1).unwrap();
            let reply = self.app(&c);
            let mut seen = self.seen.lock().unwrap();
            seen.commands.push(c);
            seen.replies.push(reply.clone());
            return Ok(tls::record(
                tls::CONTENT_APP_DATA,
                &tls::seal(&self.server_keys(), tls::CONTENT_APP_DATA, &reply, &[3; 16]),
            ));
        }
        self.seen
            .lock()
            .unwrap()
            .replies
            .push(self.plain_reply.clone());
        Ok(self.plain_reply.clone())
    }
}

impl UsbLink for FakeLink {
    fn interrupt(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        if let Some(b) = self.ints.pop_front() {
            self.clock.advance(Duration::from_millis(1));
            return Ok(Some(b));
        }
        // Nothing comes: the poll lasts its whole timeout.
        self.clock.advance(timeout);
        if self.behaviour.noise && self.armed {
            return Ok(Some(vec![1, 0, 0, 0, 0]));
        }
        Ok(None)
    }

    fn bulk_82(&mut self, timeout: Duration) -> Result<Vec<u8>, TransportError> {
        // Image data never comes.
        self.seen.lock().unwrap().bulk_timeouts.push(timeout);
        self.clock.advance(timeout);
        Err(TransportError::Timeout)
    }
}

type Session = UsbSession<FakeLink, Det>;

struct Rig {
    s: Session,
    clock: Clock,
    seen: Arc<Mutex<Seen>>,
    wall: Instant,
}

impl Rig {
    /// A session with the channel open over a fake sensor that behaves as `b`.
    fn new(b: Behaviour) -> Self {
        Self::with(b, Deadlines::default(), vec![0, 0, 0x77], |_| {})
    }

    /// `before_open` runs on the session before the channel is opened.
    fn with(
        b: Behaviour,
        deadlines: Deadlines,
        plain_reply: Vec<u8>,
        before_open: impl FnOnce(&mut Session),
    ) -> Self {
        records();
        let psk = PskKeys::from_hw("Synthetic Laptop", "SN-DEADLINES");
        let fw = SigningKey::from(&key("fw"));
        let sensor = key("sensor");
        let image = make_tls_flash(
            &encrypt_key(&key("host"), &psk, &[1; 16]),
            &(0..184u8).collect::<Vec<_>>(),
            &ecdh_block(&sensor.public_key(), &fw),
        )
        .unwrap();
        let clock = Clock::new();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let link = FakeLink {
            behaviour: b,
            clock: clock.clone(),
            seen: seen.clone(),
            ints: VecDeque::new(),
            armed: false,
            sensor,
            transcript: Sha256::new(),
            client_random: [0; 32],
            keys: None,
            handshakes: 0,
            plain_reply,
        };
        let c = clock.clone();
        let mut s = UsbSession::new(link, Det(7), psk)
            .with_firmware_key(VerifyingKey::from(&fw))
            .with_deadlines(deadlines)
            .with_clock(move || c.origin + c.elapsed());
        before_open(&mut s);
        s.open_channel(&image).unwrap();
        assert!(s.is_open());
        Rig {
            s,
            clock,
            seen,
            wall: Instant::now(),
        }
    }

    /// Opcodes of the application commands sent.
    fn opcodes(&self) -> Vec<u8> {
        self.seen
            .lock()
            .unwrap()
            .commands
            .iter()
            .map(|c| c[0])
            .collect()
    }

    /// The fake time passed, and no real waiting was done.
    fn elapsed(&self) -> Duration {
        assert!(
            self.wall.elapsed() < Duration::from_secs(5),
            "the test waited for real: {:?}",
            self.wall.elapsed()
        );
        self.clock.elapsed()
    }
}

fn scanner() -> Scanner {
    let device = dev_info_lookup(0x190, 0x59).unwrap();
    let type_info = SensorTypeInfo::get(device.sensor_type).unwrap();
    let rom = RomInfo {
        timestamp: 0,
        build: 0x56,
        major: 6,
        minor: 8,
        product: 0x30,
        u1: 0,
    };
    let program = SensorCaptureProg::get(&rom, 0x199, 0x18, 0x19).unwrap();
    Scanner {
        device,
        type_info,
        rom,
        key_calibration_line: 0x38,
        calibration_frames: 3,
        calibration_iterations: 3,
        program,
        lines_per_frame: 224,
        bytes_per_line: 0x78,
        factory_calibration_values: (0..112).map(|i| 0x70 + (i % 9) as u8).collect(),
        factory_calib_data: None,
        calib_data: vec![],
        calibrated: false,
    }
}

fn blobs() -> Blobs {
    Blobs {
        init_hardcoded: vec![6, 1, 1],
        init_hardcoded_clean_slate: vec![6, 2, 2],
        reset_blob: vec![6, 3, 3],
        db_write_enable: vec![6, 4, 4],
        partition_signature: vec![0x5a; 256],
    }
}

fn sid() -> Sid {
    "S-1-5-21-111111111-1111111111-1111111111-1000"
        .parse()
        .unwrap()
}

fn timeout(e: &Error) -> (Wait, Duration) {
    match e {
        Error::Timeout { waiting_for, after } => (*waiting_for, *after),
        other => panic!("expected a timeout, got {other:?}"),
    }
}

const D: Deadlines = Deadlines::DEFAULT;
const GLOW: u8 = 0x39;
const CAPTURE: u8 = 0x02;
const STOP: u8 = 0x04;

// ------------------------------------------------------------ the tests

#[test]
fn default_deadlines() {
    assert_eq!(D.finger, Duration::from_secs(30));
    for w in [
        Wait::CaptureStart,
        Wait::Capture,
        Wait::Match,
        Wait::Enrollment,
        Wait::Image,
        Wait::Interrupt,
    ] {
        assert!(!w.is_finger());
        assert!(D.get(w) <= Duration::from_secs(10), "{w}");
        assert!(D.get(w) >= Duration::from_secs(2), "{w}");
    }
    assert!(Wait::Finger.is_finger());
    assert_eq!(D.get(Wait::Finger), D.finger);
    assert_eq!(Deadlines::default(), D);
}

#[test]
fn identify_fails_when_the_scan_never_starts() {
    let mut r = Rig::new(Behaviour::default());
    let mut retries = 0;
    let e = scanner()
        .identify(&mut r.s, |_| {
            retries += 1;
            ControlFlow::Continue(())
        })
        .unwrap_err();
    // A silent sensor is not retried: it would never answer either.
    assert_eq!(timeout(&e), (Wait::CaptureStart, D.capture_start));
    assert_eq!(retries, 0);
    assert_eq!(r.elapsed(), D.capture_start);
    assert_eq!(r.opcodes(), [GLOW, CAPTURE, STOP]);
}

#[test]
fn identify_gives_up_on_the_finger_after_its_deadline() {
    let mut r = Rig::new(Behaviour {
        capture_start: true,
        ..Default::default()
    });
    let mut seen = Vec::new();
    let e = scanner()
        .identify(&mut r.s, |e| {
            seen.push(timeout(e));
            ControlFlow::Break(())
        })
        .unwrap_err();
    assert_eq!(seen, [(Wait::Finger, D.finger)]);
    assert_eq!(timeout(&e), (Wait::Finger, D.finger));
    let t = r.elapsed();
    assert!(
        t >= D.finger && t < D.finger + Duration::from_millis(10),
        "{t:?}"
    );
    // The capture is stopped and the LED pattern ended.
    assert_eq!(r.opcodes(), [GLOW, CAPTURE, STOP, GLOW]);
    assert_eq!(r.seen.lock().unwrap().commands[3][0..3], [0x39, 0xf4, 0x01]);
}

#[test]
fn the_finger_deadline_is_configurable_and_bounds_the_whole_phase() {
    // Unrelated interrupts all along the finger wait do not restart it.
    let mut r = Rig::with(
        Behaviour {
            capture_start: true,
            noise: true,
            ..Default::default()
        },
        Deadlines {
            finger: Duration::from_secs(3),
            ..D
        },
        vec![0, 0],
        |_| {},
    );
    let e = scanner()
        .identify(&mut r.s, |_| ControlFlow::Break(()))
        .unwrap_err();
    assert_eq!(timeout(&e), (Wait::Finger, Duration::from_secs(3)));
    // The phase starts after the capture start interrupt (1 ms in).
    assert_eq!(r.elapsed(), Duration::from_millis(3001));
}

#[test]
fn identify_fails_when_the_match_never_answers() {
    let mut r = Rig::new(Behaviour {
        capture_start: true,
        finger: true,
        ..Default::default()
    });
    let e = scanner()
        .identify(&mut r.s, |_| ControlFlow::Continue(()))
        .unwrap_err();
    assert_eq!(timeout(&e), (Wait::Match, D.matching));
    assert!(r.elapsed() >= D.matching && r.elapsed() < D.matching + Duration::from_secs(1));
    // The match is cleaned up (0x62) as on every other failure.
    assert_eq!(r.opcodes().last(), Some(&0x62));
}

#[test]
fn a_match_that_answers_is_not_affected() {
    let mut r = Rig::new(Behaviour {
        capture_start: true,
        finger: true,
        match_result: true,
        ..Default::default()
    });
    let id = scanner()
        .identify(&mut r.s, |_| ControlFlow::Continue(()))
        .unwrap();
    assert_eq!(id, Identified::NoMatch(vec![4, 0, 0, 0, 0]));
    assert!(r.elapsed() < Duration::from_millis(100));
}

#[test]
fn enroll_fails_when_the_scan_never_starts() {
    let mut r = Rig::new(Behaviour::default());
    let mut progress = 0;
    let e = scanner()
        .enroll(&mut r.s, &blobs(), &sid(), 7, |_| {
            progress += 1;
            ControlFlow::Continue(())
        })
        .unwrap_err();
    assert_eq!(timeout(&e), (Wait::CaptureStart, D.capture_start));
    assert_eq!(progress, 0);
    assert_eq!(r.elapsed(), D.capture_start);
    // Enrolment opened, scan armed and stopped, enrolment closed.
    assert_eq!(r.opcodes(), [0x69, GLOW, CAPTURE, STOP, 0x69]);
}

#[test]
fn enroll_reports_the_missing_finger_and_stops_when_asked() {
    let mut r = Rig::new(Behaviour {
        capture_start: true,
        ..Default::default()
    });
    let mut seen = Vec::new();
    let e = scanner()
        .enroll(&mut r.s, &blobs(), &sid(), 7, |p| {
            match p {
                EnrollProgress::Retry(e) => seen.push(timeout(e)),
                EnrollProgress::Image(_) => panic!("no image without a finger"),
            }
            ControlFlow::Break(())
        })
        .unwrap_err();
    assert_eq!(seen, [(Wait::Finger, D.finger)]);
    assert_eq!(timeout(&e), (Wait::Finger, D.finger));
    let t = r.elapsed();
    assert!(
        t >= D.finger && t < D.finger + Duration::from_millis(10),
        "{t:?}"
    );
    assert_eq!(r.opcodes(), [0x69, GLOW, CAPTURE, STOP, 0x69, GLOW]);
}

#[test]
fn enroll_fails_when_an_enrolment_step_never_answers() {
    let mut r = Rig::new(Behaviour {
        capture_start: true,
        finger: true,
        ..Default::default()
    });
    let mut progress = 0;
    let e = scanner()
        .enroll(&mut r.s, &blobs(), &sid(), 7, |_| {
            progress += 1;
            ControlFlow::Continue(())
        })
        .unwrap_err();
    assert_eq!(timeout(&e), (Wait::Enrollment, D.enrollment));
    assert_eq!(progress, 0);
    let t = r.elapsed();
    assert!(
        t >= D.enrollment && t < D.enrollment + Duration::from_millis(10),
        "{t:?}"
    );
}

#[test]
fn calibration_fails_when_no_image_comes() {
    let mut r = Rig::new(Behaviour::default());
    let mut sc = scanner();
    let e = sc.calibrate(&mut r.s, &blobs(), None).unwrap_err();
    assert_eq!(timeout(&e), (Wait::Image, D.image));
    assert_eq!(r.seen.lock().unwrap().bulk_timeouts, [D.image]);
    assert_eq!(r.elapsed(), D.image);
    assert!(!sc.calibrated);
}

#[test]
fn trace_logs_opcodes_lengths_and_interrupts_never_payloads() {
    // A flash read in the clear (how the TLS keys are read) and over the
    // channel, then a whole identification.
    let secret_reply = [0x00, 0x00, 0xc0, 0xff, 0xee, 0x15, 0xba, 0xd0];
    let secret = [0xd3, 0xad, 0xbe, 0xef, 0x13, 0x37, 0x42, 0x99];
    let mut cmd = vec![0x40];
    cmd.extend(secret);
    let mut r = Rig::with(
        Behaviour {
            capture_start: true,
            finger: true,
            match_result: true,
            ..Default::default()
        },
        Deadlines {
            capture_start: Duration::from_millis(1500),
            ..D
        },
        secret_reply.to_vec(),
        |s| assert_eq!(s.cmd(&cmd).unwrap(), secret_reply),
    );
    r.s.cmd(&cmd).unwrap();
    scanner()
        .identify(&mut r.s, |_| ControlFlow::Continue(()))
        .unwrap();
    // A timeout: logged with the last command and interrupt.
    let mut silent = Rig::with(
        Behaviour::default(),
        Deadlines {
            capture_start: Duration::from_millis(1500),
            ..D
        },
        vec![0, 0],
        |_| {},
    );
    scanner()
        .identify(&mut silent.s, |_| ControlFlow::Continue(()))
        .unwrap_err();

    let log = records().lock().unwrap().clone();
    let has = |want: &str| log.iter().any(|l| l.contains(want));
    assert!(has("TRACE >plain> 40 (9 bytes)"), "{log:#?}");
    assert!(has("TRACE <plain< 40 (8 bytes, status 0000)"), "{log:#?}");
    assert!(has("TRACE channel: open"), "{log:#?}");
    assert!(has("TRACE >app> 40 (9 bytes)"), "{log:#?}");
    assert!(has("TRACE <app< 5e (2 bytes, status 0000)"), "{log:#?}");
    assert!(has("TRACE <app< 51 (18 bytes, status 0000)"), "{log:#?}");
    assert!(has("TRACE <int< 0300060000"), "{log:#?}");
    assert!(has("TRACE wait: a finger (deadline 30s)"), "{log:#?}");
    assert!(
        has(
            "WARN timed out after 1.5s waiting for the capture to start \
             (last command 02, last interrupt none)"
        ),
        "{log:#?}"
    );

    // No payload, of any command or reply this test saw, in any form.
    let seen = r.seen.lock().unwrap();
    let mut payloads: Vec<Vec<u8>> = vec![secret.to_vec(), secret_reply[2..].to_vec()];
    payloads.extend(seen.commands.iter().map(|c| c[1..].to_vec()));
    payloads.extend(seen.replies.iter().map(|c| c[2..].to_vec()));
    let mut checked = 0;
    for p in payloads.iter().filter(|p| p.len() >= 4) {
        let windows: Vec<&[u8]> = p.windows(4).collect();
        for w in windows {
            // Skip runs that are not distinctive (zeros, repeated bytes).
            if w.iter().all(|&b| b == w[0]) {
                continue;
            }
            let forms = [
                w.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                w.iter().map(|b| format!("{b:02X}")).collect::<String>(),
                w.iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" "),
                format!("{}, {}, {}, {}", w[0], w[1], w[2], w[3]),
            ];
            for f in &forms {
                for l in &log {
                    // Interrupt lines carry the interrupt, which is not a payload.
                    if l.contains("<int< ") || l.contains("last interrupt") {
                        continue;
                    }
                    assert!(!l.contains(f.as_str()), "payload bytes {f} in {l:?}");
                }
            }
            checked += 1;
        }
    }
    assert!(checked > 100, "only {checked} byte sequences checked");
}
