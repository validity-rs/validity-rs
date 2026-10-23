//! The daemon with the emulated sensor, for the container end-to-end test
//! (`ci/e2e/`): the production service on the system bus, fprintd's clients
//! and pam_fprintd in front of it. Built by tests, never installed.
//!
//! Usage: fake_daemon [--address ADDRESS] [--allow-all] [--state-dir DIR]
//!
//! The emulated sensor is controlled through `org.validityrs.FakeSensor` at
//! `/org/validityrs/FakeSensor` on the same bus:
//!   Touch(u finger)     queue a good image of finger `finger`
//!   ScanError()         queue a failed capture
//!   Unplug() / Plug()   the sensor leaves / comes back to the USB bus
//!   PendingTouches() -> u

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use validity_daemon::fake::{FakeSensor, Touch, blobs};
use validity_daemon::polkit::{Authority, Check, Polkit};
use validity_daemon::service::{self, Bus, Deps, Options, Setup};
use validity_daemon::users::{SidMap, SystemUsers};
use zbus::Connection;

struct AllowAll;

impl Authority for AllowAll {
    fn check<'a>(&'a self, _: &'a Connection, _: &'a str, _: &'a str) -> Check<'a> {
        Box::pin(async { Ok(true) }) as Pin<Box<dyn Future<Output = _> + Send>>
    }
}

struct Control(FakeSensor);

#[zbus::interface(name = "org.validityrs.FakeSensor")]
impl Control {
    fn touch(&self, finger: u32) {
        self.0.touch([Touch::Finger(finger)]);
    }
    fn scan_error(&self) {
        self.0.touch([Touch::ScanError]);
    }
    fn unplug(&self) {
        self.0.unplug();
    }
    fn plug(&self) {
        self.0.plug();
    }
    fn pending_touches(&self) -> u32 {
        self.0.pending_touches() as u32
    }
}

fn main() -> Result<(), String> {
    let mut bus = Bus::System;
    let mut allow_all = false;
    let mut state = PathBuf::from("/var/lib/validity-e2e");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--address" => bus = Bus::Address(args.next().ok_or("--address ADDRESS")?),
            "--allow-all" => allow_all = true,
            "--state-dir" => state = PathBuf::from(args.next().ok_or("--state-dir DIR")?),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    validity_daemon::logging::init(log::LevelFilter::Debug);
    std::fs::create_dir_all(&state).map_err(|e| e.to_string())?;
    let fake = FakeSensor::new();
    let authority: Arc<dyn Authority> = if allow_all {
        Arc::new(AllowAll)
    } else {
        Arc::new(Polkit)
    };
    zbus::block_on(async {
        let ctl = match &bus {
            Bus::Address(a) => zbus::connection::Builder::address(a.as_str()),
            Bus::Session => zbus::connection::Builder::session(),
            Bus::System => zbus::connection::Builder::system(),
        }
        .name("org.validityrs.FakeSensor")
        .serve_at("/org/validityrs/FakeSensor", Control(fake.clone()))
        .build()
        .await
        .map_err(|e| format!("control object: {e}"))?;
        let r = service::run(
            bus,
            fake.hardware(),
            Setup {
                blobs: Ok(blobs()),
                calibration: state.join("calibration.bin"),
            },
            Deps {
                authority,
                users: Arc::new(SystemUsers),
                sids: SidMap::default(),
            },
            Options::default(),
            service::termination(),
        )
        .await;
        drop(ctl);
        r
    })
}
