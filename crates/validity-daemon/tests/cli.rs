//! The `validity-daemon` binary itself: its command line, its log lines and
//! its lifetime (serving until SIGTERM). The sensor is the emulated one
//! (`--fake-sensor`), so no USB device is touched; the bus is a private
//! `dbus-daemon` (a requirement, as for tests/dbus.rs).

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_validity-daemon");

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let p =
            std::env::temp_dir().join(format!("validity-daemon-cli-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The daemon's command, with an empty configuration file and a state
/// directory of its own, logging in the terminal format.
fn daemon(dir: &TempDir, args: &[&str]) -> Command {
    let config = dir.0.join("validity.toml");
    std::fs::write(&config, "").unwrap();
    let mut c = Command::new(BIN);
    c.arg("--config")
        .arg(&config)
        .arg("--state-dir")
        .arg(dir.0.join("state"))
        .args(args)
        .env_remove("JOURNAL_STREAM")
        .stdin(Stdio::null());
    c
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn version_help_and_usage_errors() {
    let out = Command::new(BIN).arg("--version").output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        text(&out.stdout),
        format!("validity-daemon {}\n", env!("CARGO_PKG_VERSION"))
    );

    let out = Command::new(BIN).arg("-h").output().unwrap();
    assert!(out.status.success());
    assert_eq!(text(&out.stdout), validity_daemon::config::USAGE);

    let out = Command::new(BIN).arg("--bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(
        text(&out.stderr).starts_with("validity-daemon: unknown argument \"--bogus\""),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_bus_it_cannot_reach_is_a_logged_failure() {
    let dir = TempDir::new("nobus");
    let address = format!("unix:path={}", dir.0.join("no-such-socket").display());
    let out: Output = daemon(&dir, &["--fake-sensor", "--address", &address])
        .output()
        .unwrap();
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(
        lines.first().copied(),
        Some(
            format!(
                "INFO  validity_daemon: validity-daemon {} starting",
                env!("CARGO_PKG_VERSION")
            )
            .as_str()
        ),
        "{err}"
    );
    assert!(
        lines.contains(
            &"WARN  validity_daemon: --fake-sensor: serving an emulated sensor, for tests only"
        ),
        "{err}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("ERROR validity_daemon: cannot serve net.reactivated.Fprint: ")),
        "{err}"
    );
    // Info and above only: nothing at debug level, from any module.
    assert!(!lines.iter().any(|l| l.starts_with("DEBUG")), "{err}");
}

/// A private `dbus-daemon`, killed on drop.
struct PrivateBus {
    child: Child,
    address: String,
}

impl PrivateBus {
    fn start(dir: &TempDir) -> Self {
        let config = dir.0.join("bus.conf");
        std::fs::write(
            &config,
            format!(
                r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>validity-test</type>
  <listen>unix:path={}/socket</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#,
                dir.0.display()
            ),
        )
        .unwrap();
        let mut child = Command::new("dbus-daemon")
            .arg(format!("--config-file={}", config.display()))
            .arg("--nofork")
            .arg("--print-address=1")
            .stdout(Stdio::piped())
            .spawn()
            .expect("dbus-daemon must be installed to run these tests");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let address = line.trim().to_string();
        assert!(address.starts_with("unix:"), "dbus-daemon said {line:?}");
        PrivateBus { child, address }
    }
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Kills the daemon if the test fails before it ended.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn devices(conn: &zbus::Connection) -> zbus::Result<Vec<zbus::OwnedObjectPath>> {
    zbus::block_on(async {
        conn.call_method(
            Some("net.reactivated.Fprint"),
            "/net/reactivated/Fprint/Manager",
            Some("net.reactivated.Fprint.Manager"),
            "GetDevices",
            &(),
        )
        .await?
        .body()
        .deserialize()
    })
}

#[test]
fn serves_until_sigterm_then_stops_cleanly() {
    let dir = TempDir::new("serve");
    let bus = PrivateBus::start(&dir);
    let mut d = Daemon(
        daemon(&dir, &["--fake-sensor", "--address", &bus.address])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let conn =
        zbus::block_on(zbus::connection::Builder::address(bus.address.as_str()).build()).unwrap();

    // The emulated sensor is listed once the daemon owns its name.
    let end = Instant::now() + Duration::from_secs(20);
    let listed = loop {
        match devices(&conn) {
            Ok(v) if !v.is_empty() => break v,
            _ if Instant::now() < end => std::thread::sleep(Duration::from_millis(50)),
            other => panic!("the daemon never served its device: {other:?}"),
        }
    };
    assert_eq!(listed[0].as_str(), "/net/reactivated/Fprint/Device/0");

    // Still serving a while later: only a signal ends it.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        d.0.try_wait().unwrap().is_none(),
        "the daemon stopped on its own"
    );
    assert!(devices(&conn).is_ok());

    let pid = d.0.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    let end = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(s) = d.0.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < end, "the daemon did not stop on SIGTERM");
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut err = String::new();
    d.0.stderr.take().unwrap().read_to_string(&mut err).unwrap();
    assert!(status.success(), "{status:?}\n{err}");
    let lines: Vec<&str> = err.lines().collect();
    for want in [
        "INFO  service: received Terminate",
        "INFO  service: stopping",
    ] {
        assert!(lines.contains(&want), "no {want:?} in\n{err}");
    }
    assert!(!err.contains("did not end cleanly"), "{err}");
    assert!(!err.contains("ERROR"), "{err}");
}
