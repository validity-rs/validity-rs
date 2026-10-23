//! Replays recorded python-validity sessions against the Rust implementation and
//! checks that every command we send is byte-identical to the recorded one, except
//! for the ranges listed by the masks in `validity_proto::replay`.
//!
//! The recordings hold device secrets and are never part of this repository. Set:
//! - `VALIDITY_TRACES`: directory of `*.log` files written by the capture script
//!   (`<timestamp>-<step>.log`, step = `reset`, `pair`, `list`, `enroll-<finger>`
//!   or `identify-<n>-<label>`; files starting with `INVALID-` or `recover-` are
//!   ignored);
//! - `VALIDITY_DLL`: the vendor `synaWudfBioUsb.dll` (command blobs);
//! - `VALIDITY_FWEXT`: the vendor `.xpfwext` (needed by sessions that upload it).
//!
//! Without `VALIDITY_TRACES` the test prints "skipped". Output never includes
//! recorded bytes except on a mismatch.

use std::ops::ControlFlow;
use std::path::Path;

use validity_proto::Error;
use validity_proto::calibration::CalibrationFile;
use validity_proto::db;
use validity_proto::fwext::Fwext;
use validity_proto::init::{self, Opened, Setup};
use validity_proto::replay::{
    self, Event, ReplaySensor, Trace, calibration_from_capture, identity_from_lookup,
};
use validity_proto::scanner::{EnrollProgress, Identified, Scanner, factory_reset};
use validity_proto::tables::{SensorTypeInfo, dev_info_lookup, finger_id};
use validity_proto::tls::PskKeys;
use validity_proto::transport::Entropy;
use validity_proto::vendor::Blobs;

/// Deterministic entropy: the random fields it feeds are masked anyway.
struct Counter(u64);
impl Entropy for Counter {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 56) as u8;
        }
    }
}

fn app_txs(t: &Trace) -> impl Iterator<Item = (&Vec<u8>, Option<&Vec<u8>>)> {
    t.events.iter().filter_map(|e| match e {
        Event::App { tx, rx } => Some((tx, rx.as_ref())),
        _ => None,
    })
}

/// Geometry of the recorded sensor, from its `0x75` reply (if the session got there).
fn sensor_type(t: &Trace) -> Option<&'static SensorTypeInfo> {
    let id = app_txs(t)
        .find(|(tx, _)| tx.as_slice() == [0x75])
        .and_then(|(_, rx)| rx)
        .filter(|id| id.len() == 10)?;
    let (minor, major) = (
        u16::from_le_bytes([id[6], id[7]]),
        u16::from_le_bytes([id[8], id[9]]),
    );
    SensorTypeInfo::get(dev_info_lookup(major, minor)?.sensor_type)
}

/// The calibration file the recorded session had, rebuilt from its own first
/// capture program (zeros if it captured nothing). `None` for sessions that
/// calibrated (python-validity had no file) or never identified the sensor.
fn stored_calibration(t: &Trace) -> Result<Option<CalibrationFile>, Error> {
    if t.events.iter().any(|e| matches!(e, Event::Bulk82(_))) {
        return Ok(None);
    }
    let Some(ti) = sensor_type(t) else {
        return Ok(None);
    };
    let (lines, bpl) = (
        ti.lines_per_calibration_data as usize,
        ti.bytes_per_line as usize,
    );
    let data = match app_txs(t).find(|(tx, _)| tx.first() == Some(&0x02)) {
        Some((tx, _)) => calibration_from_capture(tx, lines, bpl)?,
        None => vec![0; lines * bpl],
    };
    Ok(Some(CalibrationFile {
        sensor_type: ti.sensor_type,
        bytes_per_line: bpl as u16,
        lines: lines as u16,
        data,
    }))
}

struct Outcome {
    summary: String,
}

fn check_results(want: &[String], prefix: &str, got: &[String]) -> Result<(), Error> {
    let want: Vec<&String> = want.iter().filter(|r| r.starts_with(prefix)).collect();
    let got: Vec<&String> = got.iter().collect();
    if want != got {
        return Err(Error::Replay(format!(
            "results differ:\n  recorded {want:?}\n  ours     {got:?}"
        )));
    }
    Ok(())
}

fn run_step(
    step: &str,
    t: &Trace,
    s: &mut ReplaySensor,
    blobs: &Blobs,
    fwext: Option<&Fwext>,
) -> Result<String, Error> {
    if step == "reset" {
        factory_reset(s, blobs)?;
        return Ok("factory reset, sensor rebooted".into());
    }
    let log_has = |m: &str| t.results.iter().any(|r| r.starts_with(m));
    let calibration = stored_calibration(t)?;
    let psk = PskKeys::from_hw("replay", "replay");
    let setup = Setup {
        blobs,
        psk: &psk,
        fwext,
        calibration: calibration.as_ref(),
    };
    let scanner: Scanner = match init::open(s, &setup, &mut Counter(1))? {
        Opened::Rebooted(why) => {
            // Either the script logged the reboot, or the recording ends with it
            // (checked by `finish`: every recorded event must have been consumed).
            if log_has("open: sensor rebooted") {
                return Ok(format!("open: rebooted after {why:?}, as recorded"));
            }
            if log_has("open:") || s.remaining() != 0 {
                return Err(Error::Replay(format!(
                    "we rebooted ({why:?}), the recording did not"
                )));
            }
            return Ok(format!(
                "open: rebooted after {why:?}; the recording ends with the same reboot"
            ));
        }
        Opened::Ready(sc) => *sc,
    };
    if !log_has("open: ok") {
        return Err(Error::Replay("we opened, the recording did not".into()));
    }
    let mut detail = format!(
        "open: ok ({}, calibrated in session: {})",
        scanner.device.name.trim_end(),
        scanner.calibrated
    );
    if let Some(finger) = step.strip_prefix("enroll-") {
        let subtype = finger_id(finger).ok_or(Error::Replay(format!("finger {finger}")))?;
        let identity = app_txs(t)
            .find(|(tx, _)| tx.first() == Some(&0x4a) && tx.len() > 7)
            .ok_or(Error::Replay("no user lookup in the recording".into()))
            .and_then(|(tx, _)| identity_from_lookup(tx))?;
        let (mut images, mut retries) = (0, 0);
        let recid = scanner.enroll(s, blobs, &identity, subtype, |p| {
            match p {
                EnrollProgress::Image(_) => images += 1,
                EnrollProgress::Retry(_) => retries += 1,
            }
            ControlFlow::Continue(())
        })?;
        check_results(
            &t.results,
            "enroll",
            &[format!("enroll {finger}: recid={recid}")],
        )?;
        detail += &format!(
            "; enroll {finger}: {images} images, {retries} failed captures, record {recid}"
        );
    } else if let Some(rest) = step.strip_prefix("identify-") {
        let (n, label) = rest.split_once('-').ok_or(Error::Replay("step".into()))?;
        let n: usize = n.parse().map_err(|_| Error::Replay("step".into()))?;
        let mut got = Vec::new();
        let mut matched = 0;
        for i in 1..=n {
            let r = scanner.identify(s, |_| ControlFlow::Continue(()))?;
            got.push(match r {
                Identified::Match { user, subtype, .. } => {
                    matched += 1;
                    format!("identify {label} #{i}: match user={user} finger={subtype}")
                }
                Identified::NoMatch(int) => format!(
                    "identify {label} #{i}: no match (Exception('Finger not recognized: {}'))",
                    validity_proto::hex::encode(&int)
                ),
            });
        }
        got.push(format!("identify {label}: {matched}/{n} matched"));
        check_results(&t.results, "identify", &got)?;
        detail +=
            &format!("; identify x{n}: {matched} matched, results identical to the recording");
    } else if step == "list" {
        let users = db::list_users(s)?;
        let fingers: usize = users.iter().map(|u| u.fingers.len()).sum();
        detail += &format!("; list: {} users, {fingers} fingers", users.len());
    }
    init::close(s)?;
    Ok(detail)
}

fn replay_log(
    name: &str,
    text: &str,
    blobs: &Blobs,
    fwext: Option<&Fwext>,
) -> Result<Outcome, Error> {
    let trace = replay::parse_log(text)?;
    let step = name
        .split_once("Z-")
        .map(|(_, s)| s.trim_end_matches(".log"))
        .ok_or(Error::Replay("unexpected file name".into()))?;
    let mut s = ReplaySensor::new(&trace);
    if trace
        .events
        .iter()
        .any(|e| matches!(e, Event::Plain { tx, .. } if tx.first() == Some(&0x4f)))
    {
        s = s
            .with_mask(replay::mask_pairing_cert())
            .with_mask(replay::mask_sealed_key());
    }
    if trace.events.iter().any(|e| matches!(e, Event::Bulk82(_))) {
        s = s
            .with_mask(replay::mask_calibration_program(
                sensor_type(&trace).map_or(0, |t| t.line_width as usize),
            ))
            .with_mask(replay::mask_clean_slate());
    }
    let r = run_step(step, &trace, &mut s, blobs, fwext);
    let detail = match r {
        Ok(d) => d,
        // A recording that stops on an error (sensor gone) replays if we stop at
        // the same point.
        Err(e)
            if !matches!(e, Error::Replay(_)) && s.remaining() == 0 && trace.results.is_empty() =>
        {
            format!("recording aborted; we stopped at the same point: {e}")
        }
        Err(e) => return Err(e),
    };
    let st = s.finish()?;
    let masked: usize = st.masked.values().sum();
    let mut summary = format!(
        "{name}: {} events; {} commands byte-exact, {masked} masked; {} handshakes checked; {} interrupts; {} bulk reads; {} bytes compared, {} masked\n    {detail}",
        trace.events.len(),
        st.exact,
        st.handshakes,
        st.interrupts,
        st.bulk_reads,
        st.bytes_compared,
        st.bytes_masked,
    );
    for (m, n) in &st.masked {
        summary += &format!("\n    masked x{n}: {m}");
    }
    Ok(Outcome { summary })
}

#[test]
fn replay_recorded_sessions() {
    let Ok(dir) = std::env::var("VALIDITY_TRACES") else {
        println!("VALIDITY_TRACES not set, skipped");
        return;
    };
    let dll = std::env::var("VALIDITY_DLL")
        .expect("VALIDITY_DLL must point at synaWudfBioUsb.dll when VALIDITY_TRACES is set");
    let blobs = Blobs::from_dll(&std::fs::read(dll).unwrap()).unwrap();
    let fwext = std::env::var("VALIDITY_FWEXT")
        .ok()
        .map(|p| Fwext::parse(&std::fs::read(p).unwrap()).unwrap());

    let mut logs: Vec<_> = std::fs::read_dir(Path::new(&dir))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "log"))
        .collect();
    logs.sort();
    let mut failures = Vec::new();
    let mut replayed = 0;
    for p in logs {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("INVALID-") || name.starts_with("recover-") {
            println!("{name}: ignored");
            continue;
        }
        let text = std::fs::read_to_string(&p).unwrap();
        match replay_log(&name, &text, &blobs, fwext.as_ref()) {
            Ok(o) => {
                replayed += 1;
                println!("{}", o.summary);
            }
            Err(e) => {
                println!("{name}: FAILED: {e}");
                failures.push(name);
            }
        }
    }
    println!("{replayed} sessions replayed, {} failed", failures.len());
    assert!(failures.is_empty(), "failed: {failures:?}");
    assert!(replayed > 0, "no session found in {dir}");
}
