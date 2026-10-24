//! Logging to stderr, which systemd hands to the journal. Under systemd
//! (`JOURNAL_STREAM` set) each line starts with its syslog priority (`<3>`...),
//! which journald turns into the entry's priority; on a terminal the level is
//! spelled out.
//!
//! Sensor traffic (validity-proto's `trace` records: one line per command,
//! reply and interrupt with the opcode, length and status word, never the
//! content) is only ever logged when asked for on the command line, never
//! through the configuration file.

use log::{Level, LevelFilter, Log, Metadata, Record};

struct Logger {
    level: LevelFilter,
    journal: bool,
}

impl Log for Logger {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        m.level() <= self.level
            // Other crates (zbus...) stay at info at most.
            && (m.target().starts_with("validity") || m.level() <= Level::Info)
    }

    fn log(&self, r: &Record<'_>) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let line = format_line(self.journal, r.level(), r.target(), &r.args().to_string());
        eprintln!("{line}");
    }

    fn flush(&self) {}
}

fn priority(l: Level) -> u8 {
    match l {
        Level::Error => 3,
        Level::Warn => 4,
        Level::Info => 6,
        Level::Debug | Level::Trace => 7,
    }
}

/// One log line, without the newline.
pub fn format_line(journal: bool, level: Level, target: &str, msg: &str) -> String {
    let module = target.rsplit("::").next().unwrap_or(target);
    if journal {
        format!("<{}>{module}: {msg}", priority(level))
    } else {
        format!("{level:<5} {module}: {msg}")
    }
}

/// Installs the logger once; later calls are ignored.
pub fn init(level: LevelFilter) {
    let journal = std::env::var_os("JOURNAL_STREAM").is_some();
    let logger: &'static Logger = Box::leak(Box::new(Logger { level, journal }));
    if log::set_logger(logger).is_ok() {
        log::set_max_level(level);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_priorities() {
        assert_eq!(
            format_line(true, Level::Warn, "validity_daemon::worker", "x"),
            "<4>worker: x"
        );
        assert_eq!(
            format_line(true, Level::Error, "validity_daemon", "x"),
            "<3>validity_daemon: x"
        );
        assert_eq!(
            format_line(false, Level::Info, "validity_proto::scanner", "y"),
            "INFO  scanner: y"
        );
        assert_eq!(priority(Level::Debug), 7);
        assert_eq!(priority(Level::Info), 6);
    }

    #[test]
    fn levels_and_targets() {
        let enabled = |max: LevelFilter, level: Level, target: &str| {
            Logger {
                level: max,
                journal: false,
            }
            .enabled(&Metadata::builder().level(level).target(target).build())
        };
        // Up to the configured level, for the daemon and the protocol.
        assert!(enabled(
            LevelFilter::Info,
            Level::Info,
            "validity_daemon::worker"
        ));
        assert!(enabled(LevelFilter::Info, Level::Warn, "validity_proto"));
        assert!(!enabled(LevelFilter::Info, Level::Debug, "validity_daemon"));
        assert!(enabled(
            LevelFilter::Trace,
            Level::Trace,
            "validity_proto::session"
        ));
        assert!(!enabled(LevelFilter::Warn, Level::Info, "validity_proto"));
        // Other crates: at most info, and never above the configured level.
        assert!(enabled(LevelFilter::Trace, Level::Info, "zbus::connection"));
        assert!(!enabled(
            LevelFilter::Trace,
            Level::Debug,
            "zbus::connection"
        ));
        assert!(!enabled(LevelFilter::Warn, Level::Info, "zbus"));
        assert!(enabled(LevelFilter::Warn, Level::Error, "zbus"));
    }
}
