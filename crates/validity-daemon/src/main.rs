//! validity-daemon: see the library documentation and `--help`.

use std::process::ExitCode;
use std::sync::Arc;

use validity_daemon::config::{self, Cli};
use validity_daemon::logging;
use validity_daemon::polkit::Polkit;
use validity_daemon::service::{self, Deps, Options, Setup};
use validity_daemon::usb::{UsbHardware, host_keys, load_blobs};
use validity_daemon::users::{SidMap, SystemUsers};
use validity_proto::session::Deadlines;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = match config::parse(&args) {
        Ok(Cli::Run(c)) => c,
        Ok(Cli::Help) => {
            print!("{}", config::USAGE);
            return ExitCode::SUCCESS;
        }
        Ok(Cli::Version) => {
            println!("validity-daemon {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("validity-daemon: {e}");
            return ExitCode::from(2);
        }
    };
    logging::init(config.log_level);
    log::info!("validity-daemon {} starting", env!("CARGO_PKG_VERSION"));
    if let Err(e) = std::fs::create_dir_all(&config.state_dir) {
        log::warn!("state directory {}: {e}", config.state_dir.display());
    }
    let blobs = load_blobs(&config.vendor_dll);
    if let Err(e) = &blobs {
        log::warn!("{e}");
    }
    let hw = UsbHardware::new(
        host_keys(std::path::Path::new("/sys/class/dmi/id")),
        Deadlines {
            finger: config.finger_timeout,
            ..Deadlines::DEFAULT
        },
    );
    let setup = Setup {
        blobs,
        calibration: config.calibration_path(),
    };
    let deps = Deps {
        authority: Arc::new(Polkit),
        users: Arc::new(SystemUsers),
        sids: SidMap::new(config.sid_overrides.clone()),
    };
    let opts = Options {
        ready_timeout: config.ready_timeout,
        ..Options::default()
    };
    match zbus::block_on(service::run(
        config.bus,
        hw,
        setup,
        deps,
        opts,
        service::termination(),
    )) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e}");
            ExitCode::FAILURE
        }
    }
}
