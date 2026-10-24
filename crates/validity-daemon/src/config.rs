//! Configuration: `/etc/validity/validity.toml` (optional) and the command line,
//! which wins.
//!
//! ```toml
//! # Synaptics driver DLL from the vendor package, installed by `validity-vendor
//! # install` (checked against its SHA-256 at start; the daemon never downloads
//! # anything). Default: <state_dir>/vendor/synaWudfBioUsb.dll.
//! vendor_dll = "/var/lib/validity/vendor/synaWudfBioUsb.dll"
//! # Calibration and other state.
//! state_dir = "/var/lib/validity"
//! # error, warn, info or debug.
//! log_level = "info"
//! # How long Claim / ListEnrolledFingers wait for a sensor that is coming up
//! # (start, resume) before failing; an absent or broken sensor fails at once.
//! ready_timeout_ms = 3000
//! # How long a scan waits for the finger: a verification then ends with
//! # verify-no-match, an enrolment asks for the finger again. Every other wait
//! # on the sensor has a fixed deadline; passing one reboots the sensor.
//! finger_timeout_ms = 30000
//!
//! # SIDs for users enrolled under another identity (by default a user is
//! # S-1-5-21-111111111-1111111111-1111111111-<uid>, as with python-validity).
//! [users]
//! alice = "S-1-5-21-111111111-1111111111-1111111111-1000"
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use log::LevelFilter;
use serde::Deserialize;
use validity_proto::session::Deadlines;
use validity_proto::sid::Sid;

pub const DEFAULT_CONFIG: &str = "/etc/validity/validity.toml";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/validity";
pub const DLL_NAME: &str = "synaWudfBioUsb.dll";
/// Where `validity-vendor` installs the vendor files, inside the state directory.
pub const VENDOR_SUBDIR: &str = "vendor";
pub const CALIBRATION_FILE: &str = "calibration.bin";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    vendor_dll: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    log_level: Option<String>,
    ready_timeout_ms: Option<u64>,
    finger_timeout_ms: Option<u64>,
    #[serde(default)]
    users: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bus {
    System,
    Session,
    Address(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub vendor_dll: PathBuf,
    pub state_dir: PathBuf,
    pub log_level: LevelFilter,
    pub ready_timeout: Duration,
    /// How long a scan waits for the finger (`finger_timeout_ms`); the other
    /// deadlines of [`Deadlines`] are fixed.
    pub finger_timeout: Duration,
    pub sid_overrides: BTreeMap<String, Sid>,
    pub bus: Bus,
    /// Serve an emulated sensor instead of the USB one (`--fake-sensor`, hidden:
    /// for the package tests, which have no sensor).
    pub fake_sensor: bool,
}

impl Config {
    pub fn calibration_path(&self) -> PathBuf {
        self.state_dir.join(CALIBRATION_FILE)
    }
}

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
pub enum Cli {
    Run(Config),
    Help,
    Version,
}

pub const USAGE: &str = "\
Usage: validity-daemon [OPTIONS]

fprintd-compatible D-Bus service (net.reactivated.Fprint) for Synaptics/Validity
match-on-chip fingerprint sensors.

Options:
  --config PATH            configuration file (default /etc/validity/validity.toml,
                           used only if present)
  --vendor-dll PATH        Synaptics driver DLL with the sensor command blobs
  --state-dir PATH         state directory (default /var/lib/validity)
  --log-level LEVEL        error, warn, info (default) or debug
  --trace-sensor-traffic   log every sensor command, reply and interrupt (opcode,
                           length and status only, never the content)
  --session                serve on the session bus (development)
  --address ADDRESS        serve on the bus at ADDRESS (tests)
  -h, --help               this text
  -V, --version            version
";

fn level(s: &str) -> Result<LevelFilter, String> {
    match s {
        "error" => Ok(LevelFilter::Error),
        "warn" => Ok(LevelFilter::Warn),
        "info" => Ok(LevelFilter::Info),
        "debug" => Ok(LevelFilter::Debug),
        other => Err(format!(
            "log level {other:?}: expected error, warn, info or debug"
        )),
    }
}

/// Parses the configuration file text.
fn parse_file(text: &str, path: &Path) -> Result<File, String> {
    toml::from_str(text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Parses the command line (without the program name), reading the
/// configuration file it names (or the default one, if present).
pub fn parse(args: &[String]) -> Result<Cli, String> {
    let mut config_path: Option<PathBuf> = None;
    let mut dll = None;
    let mut state = None;
    let mut lvl = None;
    let mut trace = false;
    let mut bus = Bus::System;
    let mut fake_sensor = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match a.as_str() {
            "-h" | "--help" => return Ok(Cli::Help),
            "-V" | "--version" => return Ok(Cli::Version),
            "--config" => config_path = Some(PathBuf::from(value("--config")?)),
            "--vendor-dll" => dll = Some(PathBuf::from(value("--vendor-dll")?)),
            "--state-dir" => state = Some(PathBuf::from(value("--state-dir")?)),
            "--log-level" => lvl = Some(level(&value("--log-level")?)?),
            "--trace-sensor-traffic" => trace = true,
            "--session" => bus = Bus::Session,
            "--address" => bus = Bus::Address(value("--address")?),
            // Not in USAGE: tests only (docs/packaging.md).
            "--fake-sensor" => fake_sensor = true,
            other => return Err(format!("unknown argument {other:?}\n\n{USAGE}")),
        }
    }
    let file = match &config_path {
        Some(p) => parse_file(
            &std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?,
            p,
        )?,
        None => {
            let p = Path::new(DEFAULT_CONFIG);
            match std::fs::read_to_string(p) {
                Ok(t) => parse_file(&t, p)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => File::default(),
                Err(e) => return Err(format!("{}: {e}", p.display())),
            }
        }
    };
    let state_dir = state
        .or(file.state_dir)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    let vendor_dll = dll
        .or(file.vendor_dll)
        .unwrap_or_else(|| state_dir.join(VENDOR_SUBDIR).join(DLL_NAME));
    let log_level = match (trace, lvl) {
        (true, _) => LevelFilter::Trace,
        (false, Some(l)) => l,
        (false, None) => match &file.log_level {
            Some(s) => level(s)?,
            None => LevelFilter::Info,
        },
    };
    let mut sid_overrides = BTreeMap::new();
    for (user, sid) in file.users {
        let s: Sid = sid.parse().map_err(|e| format!("[users] {user}: {e}"))?;
        sid_overrides.insert(user, s);
    }
    Ok(Cli::Run(Config {
        vendor_dll,
        state_dir,
        log_level,
        ready_timeout: Duration::from_millis(file.ready_timeout_ms.unwrap_or(3000)),
        finger_timeout: file
            .finger_timeout_ms
            .map_or(Deadlines::DEFAULT.finger, Duration::from_millis),
        sid_overrides,
        bus,
        fake_sensor,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn tmp(name: &str, text: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "validity-config-{}-{name}.toml",
            std::process::id()
        ));
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn file_and_command_line() {
        let p = tmp(
            "full",
            r#"
vendor_dll = "/opt/v/syna.dll"
state_dir = "/srv/validity"
log_level = "debug"
ready_timeout_ms = 1500
finger_timeout_ms = 12000
[users]
alice = "S-1-5-21-7-8-9-500"
"#,
        );
        let Cli::Run(c) = parse(&args(&["--config", p.to_str().unwrap()])).unwrap() else {
            panic!()
        };
        assert_eq!(c.vendor_dll, Path::new("/opt/v/syna.dll"));
        assert_eq!(c.state_dir, Path::new("/srv/validity"));
        assert_eq!(
            c.calibration_path(),
            Path::new("/srv/validity/calibration.bin")
        );
        assert_eq!(c.log_level, LevelFilter::Debug);
        assert_eq!(c.ready_timeout, Duration::from_millis(1500));
        assert_eq!(c.finger_timeout, Duration::from_secs(12));
        assert_eq!(c.sid_overrides["alice"].to_string(), "S-1-5-21-7-8-9-500");
        assert_eq!(c.bus, Bus::System);

        let Cli::Run(c) = parse(&args(&[
            "--config",
            p.to_str().unwrap(),
            "--state-dir",
            "/x",
            "--log-level",
            "warn",
            "--address",
            "unix:path=/tmp/b",
        ]))
        .unwrap() else {
            panic!()
        };
        assert_eq!(c.state_dir, Path::new("/x"));
        // The file's DLL path still wins over the state directory default.
        assert_eq!(c.vendor_dll, Path::new("/opt/v/syna.dll"));
        assert_eq!(c.log_level, LevelFilter::Warn);
        assert_eq!(c.bus, Bus::Address("unix:path=/tmp/b".into()));

        // Tracing only from the command line.
        let Cli::Run(c) = parse(&args(&[
            "--config",
            p.to_str().unwrap(),
            "--trace-sensor-traffic",
        ]))
        .unwrap() else {
            panic!()
        };
        assert_eq!(c.log_level, LevelFilter::Trace);
    }

    #[test]
    fn defaults_and_errors() {
        let empty = tmp("empty", "");
        let Cli::Run(c) =
            parse(&args(&["--config", empty.to_str().unwrap(), "--session"])).unwrap()
        else {
            panic!()
        };
        assert_eq!(c.state_dir, Path::new(DEFAULT_STATE_DIR));
        assert_eq!(
            c.vendor_dll,
            Path::new("/var/lib/validity/vendor/synaWudfBioUsb.dll")
        );
        assert!(!c.fake_sensor);
        let Cli::Run(fake) = parse(&args(&[
            "--config",
            empty.to_str().unwrap(),
            "--fake-sensor",
            "--state-dir",
            "/s",
        ]))
        .unwrap() else {
            panic!()
        };
        assert!(fake.fake_sensor);
        assert_eq!(fake.vendor_dll, Path::new("/s/vendor/synaWudfBioUsb.dll"));
        assert!(!USAGE.contains("fake"));
        assert_eq!(c.log_level, LevelFilter::Info);
        assert_eq!(c.ready_timeout, Duration::from_secs(3));
        assert_eq!(c.finger_timeout, Deadlines::DEFAULT.finger);
        assert_eq!(c.finger_timeout, Duration::from_secs(30));
        assert_eq!(c.bus, Bus::Session);

        assert_eq!(parse(&args(&["--help"])).unwrap(), Cli::Help);
        assert_eq!(parse(&args(&["-V"])).unwrap(), Cli::Version);
        assert!(
            parse(&args(&["--bogus"]))
                .unwrap_err()
                .contains("unknown argument")
        );
        assert!(
            parse(&args(&["--state-dir"]))
                .unwrap_err()
                .contains("needs a value")
        );
        assert!(parse(&args(&["--log-level", "trace"])).is_err());
        let p = tmp("trace", "log_level = \"trace\"\n");
        assert!(parse(&args(&["--config", p.to_str().unwrap()])).is_err());
        let p = tmp("unknown", "colour = \"blue\"\n");
        assert!(
            parse(&args(&["--config", p.to_str().unwrap()]))
                .unwrap_err()
                .contains("colour")
        );
        let p = tmp("badsid", "[users]\nbob = \"X-1\"\n");
        assert!(
            parse(&args(&["--config", p.to_str().unwrap()]))
                .unwrap_err()
                .contains("bob")
        );
        assert!(parse(&args(&["--config", "/nonexistent/v.toml"])).is_err());
    }
}
