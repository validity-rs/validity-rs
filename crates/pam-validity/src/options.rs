//! The module's arguments, from the PAM configuration line.
//!
//! `max-tries=N` and `timeout=N` are pam_fprintd's (same defaults); `confirm`
//! and `bus=` are this module's. An argument that is unknown or whose value
//! is not valid is ignored, leaving the default: a typo never locks anyone
//! out, since the stack falls back to the password whatever the module does.

use std::time::Duration;

/// Attempts when none is given (pam_fprintd's default).
pub const DEFAULT_MAX_TRIES: u32 = 3;
/// Seconds to wait for a finger per attempt when none is given (pam_fprintd's default).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest `timeout=` accepted, in seconds; longer values are ignored.
pub const MAX_TIMEOUT_SECS: u64 = 3600;
/// The system bus, as the D-Bus specification fixes it. Deliberately not
/// `DBUS_SYSTEM_BUS_ADDRESS`: the module runs inside setuid programs (su),
/// whose caller chooses the environment, and a bus of the caller's would
/// answer "verify-match" to anything.
pub const SYSTEM_BUS: &str = "unix:path=/var/run/dbus/system_bus_socket";

/// What the configuration line asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// `max-tries=N` (N >= 1): fingers refused before the module fails.
    pub max_tries: u32,
    /// `timeout=N` (1 <= N <= 3600 seconds): wait for a finger, per attempt.
    pub timeout: Duration,
    /// `confirm`: after a match, say "`<user>` recognized, press Enter." (for
    /// LightDM, where the finger answers an empty password).
    pub confirm: bool,
    /// `bus=ADDRESS`: the D-Bus address to use instead of the system bus
    /// (tests, and setups with a bus of their own). The PAM configuration
    /// is root's, so this is as trusted as the module line itself.
    pub bus: String,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            max_tries: DEFAULT_MAX_TRIES,
            timeout: DEFAULT_TIMEOUT,
            confirm: false,
            bus: SYSTEM_BUS.to_string(),
        }
    }
}

impl Options {
    /// Parses the module's arguments.
    pub fn parse<'a>(args: impl IntoIterator<Item = &'a str>) -> Self {
        let mut o = Options::default();
        for arg in args {
            match arg.split_once('=') {
                Some(("max-tries", v)) => {
                    if let Ok(n) = v.parse::<u32>()
                        && n >= 1
                    {
                        o.max_tries = n;
                    }
                }
                Some(("timeout", v)) => {
                    if let Ok(n) = v.parse::<u64>()
                        && (1..=MAX_TIMEOUT_SECS).contains(&n)
                    {
                        o.timeout = Duration::from_secs(n);
                    }
                }
                Some(("bus", v)) if !v.is_empty() => o.bus = v.to_string(),
                None if arg == "confirm" => o.confirm = true,
                _ => {}
            }
        }
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_pam_fprintd_s() {
        let o = Options::parse([]);
        assert_eq!(o, Options::default());
        assert_eq!(o.max_tries, 3);
        assert_eq!(o.timeout, Duration::from_secs(30));
        assert!(!o.confirm);
        assert_eq!(o.bus, "unix:path=/var/run/dbus/system_bus_socket");
    }

    #[test]
    fn the_profile_s_lines() {
        let o = Options::parse(["max-tries=1", "timeout=30", "confirm"]);
        assert_eq!(o.max_tries, 1);
        assert_eq!(o.timeout, Duration::from_secs(30));
        assert!(o.confirm);
        let o = Options::parse(["max-tries=1", "timeout=10"]);
        assert_eq!(
            (o.max_tries, o.timeout, o.confirm),
            (1, Duration::from_secs(10), false)
        );
    }

    #[test]
    fn bounds() {
        assert_eq!(Options::parse(["max-tries=1"]).max_tries, 1);
        assert_eq!(Options::parse(["max-tries=7"]).max_tries, 7);
        assert_eq!(
            Options::parse(["timeout=1"]).timeout,
            Duration::from_secs(1)
        );
        assert_eq!(
            Options::parse(["timeout=3600"]).timeout,
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn invalid_values_keep_the_default() {
        for arg in [
            "max-tries=0",
            "max-tries=-1",
            "max-tries=",
            "max-tries=x",
            "timeout=0",
            "timeout=3601",
            "timeout=-5",
            "timeout=",
            "timeout=1.5",
            "bus=",
            "confirm=yes",
            "Confirm",
            "debug",
            "",
            "=",
        ] {
            assert_eq!(Options::parse([arg]), Options::default(), "{arg:?}");
        }
    }

    #[test]
    fn bus_and_last_one_wins() {
        let o = Options::parse([
            "bus=unix:path=/tmp/x",
            "max-tries=2",
            "max-tries=5",
            "max-tries=0",
        ]);
        assert_eq!(o.bus, "unix:path=/tmp/x");
        assert_eq!(o.max_tries, 5);
    }
}
