//! Hardware session: opens the sensor the way the daemon will, then lists the
//! on-chip database or identifies fingers.
//!
//! Usage (root): session <synaWudfBioUsb.dll> <calibration-file> list
//!               session <synaWudfBioUsb.dll> <calibration-file> identify <n>
//!               session <synaWudfBioUsb.dll> <calibration-file> enroll <uid> <finger-subtype>
//!
//! The calibration file is read when present and written after a calibration.

use std::ops::ControlFlow;
use std::path::Path;
use std::time::Instant;

use validity_proto::calibration::CalibrationFile;
use validity_proto::db;
use validity_proto::init::{self, Opened, Setup};
use validity_proto::scanner::{EnrollProgress, Identified};
use validity_proto::session::UsbSession;
use validity_proto::sid::Sid;
use validity_proto::tls::PskKeys;
use validity_proto::transport::OsEntropy;
use validity_proto::usb::UsbSensor;
use validity_proto::vendor::Blobs;

fn dmi(field: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/dmi/id/{field}"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|e| panic!("reading DMI {field} (needs root): {e}"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger_lite();
    let args: Vec<String> = std::env::args().collect();
    let usage =
        "usage: session <dll> <calibration-file> list | identify <n> | enroll <uid> <subtype>";
    let (dll, calib_path, cmd) = match args.as_slice() {
        [_, dll, calib, cmd, ..] => (dll, Path::new(calib), cmd.as_str()),
        _ => return Err(usage.into()),
    };
    let blobs = Blobs::from_dll(&std::fs::read(dll)?)?;
    let psk = PskKeys::from_hw(&dmi("product_name"), &dmi("product_serial"));
    let stored = CalibrationFile::load(calib_path).ok();
    println!(
        "calibration file: {}",
        if stored.is_some() { "loaded" } else { "none" }
    );

    let t0 = Instant::now();
    let mut s = UsbSession::new(
        UsbSensor::open_wait(std::time::Duration::from_secs(5))?,
        OsEntropy,
        psk.clone(),
    );
    let setup = Setup {
        blobs: &blobs,
        psk: &psk,
        fwext: None,
        calibration: stored.as_ref(),
    };
    let scanner = match init::open(&mut s, &setup, &mut OsEntropy)? {
        Opened::Ready(sc) => *sc,
        Opened::Rebooted(why) => {
            println!("sensor rebooted ({why:?}); run again");
            return Ok(());
        }
    };
    println!(
        "open: ok in {:?} ({}, calibrated in session: {})",
        t0.elapsed(),
        scanner.device.name.trim_end(),
        scanner.calibrated
    );
    if scanner.calibrated {
        scanner.calibration_file().save(calib_path)?;
        println!("calibration file: saved");
    }

    match cmd {
        "list" => {
            for u in db::list_users(&mut s)? {
                println!(
                    "user {} {}: {} finger(s)",
                    u.dbid,
                    u.identity,
                    u.fingers.len()
                );
                for f in &u.fingers {
                    println!("  record {} finger subtype {}", f.dbid, f.subtype);
                }
            }
        }
        "identify" => {
            let n: usize = args.get(4).ok_or(usage)?.parse()?;
            let mut matched = 0;
            for i in 1..=n {
                println!(">>> [{i}/{n}] place a finger");
                match scanner.identify(&mut s, |e| {
                    println!("  capture error: {e}, try again");
                    ControlFlow::Continue(())
                })? {
                    Identified::Match { user, subtype, .. } => {
                        matched += 1;
                        println!("RESULT #{i}: match user={user} finger={subtype}");
                    }
                    Identified::NoMatch(_) => println!("RESULT #{i}: no match"),
                }
            }
            println!("RESULT: {matched}/{n} matched");
        }
        "enroll" => {
            let uid: u32 = args.get(4).ok_or(usage)?.parse()?;
            let subtype: u16 = args.get(5).ok_or(usage)?.parse()?;
            // Same SID scheme as python-validity's dbus-service.
            let sid: Sid = format!("S-1-5-21-111111111-1111111111-1111111111-{uid}").parse()?;
            let mut images = 0;
            println!(">>> place the finger repeatedly until done");
            let recid = scanner.enroll(&mut s, &blobs, &sid, subtype, |p| {
                match p {
                    EnrollProgress::Image(_) => {
                        images += 1;
                        println!("  image {images} accepted, lift and place again");
                    }
                    EnrollProgress::Retry(e) => println!("  try again: {e}"),
                }
                ControlFlow::Continue(())
            })?;
            println!("RESULT: enrolled finger {subtype} as record {recid} after {images} images");
        }
        _ => return Err(usage.into()),
    }
    init::close(&mut s)?;
    println!("close: sensor rebooted");
    Ok(())
}

/// Minimal logger: `VALIDITY_LOG=info|debug|trace` prints to stderr.
fn env_logger_lite() {
    struct L(log::LevelFilter);
    impl log::Log for L {
        fn enabled(&self, m: &log::Metadata<'_>) -> bool {
            m.level() <= self.0
        }
        fn log(&self, r: &log::Record<'_>) {
            if self.enabled(r.metadata()) {
                eprintln!("{} {}", r.level(), r.args());
            }
        }
        fn flush(&self) {}
    }
    let level = std::env::var("VALIDITY_LOG")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(log::LevelFilter::Warn);
    let _ = log::set_logger(Box::leak(Box::new(L(level))));
    log::set_max_level(level);
}
