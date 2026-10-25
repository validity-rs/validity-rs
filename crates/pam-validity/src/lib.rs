//! `pam_validity.so`: fingerprint authentication through the
//! `net.reactivated.Fprint` D-Bus service (validity-daemon, or fprintd),
//! with no prompt.
//!
//! It does what pam_fprintd does for the `auth` stack, without its
//! messages, which were no use on LightDM: slick-greeter showed nothing
//! after Enter, then the prompt and the result together once the finger
//! was read, and in English on a French greeter (gettext follows
//! `setlocale`, which LightDM's PAM process never calls). The only thing it
//! ever says is "Access granted" (`PAM_TEXT_INFO`), after a match, with the
//! `confirm` option, and not under `PAM_SILENT`.
//!
//! ```text
//! auth  [success=end default=die]  pam_validity.so max-tries=1 timeout=30 confirm
//! ```
//!
//! Results: `PAM_SUCCESS` only on a `verify-match` from the daemon;
//! `PAM_AUTH_ERR` for a refused finger; `PAM_AUTHINFO_UNAVAIL` for
//! everything that is not an answer (no daemon, no device, no enrolled
//! finger, a D-Bus error, no finger in time, no user, a panic), so that the
//! stack falls back to the password.
//!
//! - [`options`]: the arguments.
//! - [`verify`]: the D-Bus side.
//! - `ffi` (not in static builds, which cannot make a shared object): the
//!   PAM entry points, the module's only unsafe code.

pub mod options;
pub mod verify;

#[cfg(not(target_feature = "crt-static"))]
mod ffi;

use options::Options;

/// How an authentication ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The daemon said `verify-match`: `PAM_SUCCESS`.
    Match,
    /// A finger was refused: `PAM_AUTH_ERR`.
    NoMatch,
    /// No answer to be had: `PAM_AUTHINFO_UNAVAIL`.
    Unavailable,
}

/// Linux-PAM's return codes, as `<security/_pam_types.h>` defines them.
pub mod code {
    /// `PAM_SUCCESS`.
    pub const SUCCESS: i32 = 0;
    /// `PAM_AUTH_ERR`.
    pub const AUTH_ERR: i32 = 7;
    /// `PAM_AUTHINFO_UNAVAIL`.
    pub const AUTHINFO_UNAVAIL: i32 = 9;
}

impl Outcome {
    /// The PAM return code.
    pub fn code(self) -> i32 {
        match self {
            Outcome::Match => code::SUCCESS,
            Outcome::NoMatch => code::AUTH_ERR,
            Outcome::Unavailable => code::AUTHINFO_UNAVAIL,
        }
    }
}

/// Where the confirmation goes: the application's conversation function.
pub trait Talk {
    /// Shows one line of information (`PAM_TEXT_INFO`).
    fn info(&mut self, text: &str);
}

/// Authenticates `user` with the module's arguments `args`; with `confirm`,
/// says [`options::CONFIRMATION`] through `talk` after a match. Blocks for
/// the length of the verification.
pub fn authenticate<'a>(
    user: &str,
    args: impl IntoIterator<Item = &'a str>,
    talk: &mut dyn Talk,
) -> Outcome {
    let opts = Options::parse(args);
    let outcome = zbus::block_on(verify::verify(user, &opts));
    if outcome == Outcome::Match && opts.confirm {
        talk.info(options::CONFIRMATION);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        assert_eq!(Outcome::Match.code(), 0);
        assert_eq!(Outcome::NoMatch.code(), 7);
        assert_eq!(Outcome::Unavailable.code(), 9);
    }

    struct Said(Vec<String>);
    impl Talk for Said {
        fn info(&mut self, text: &str) {
            self.0.push(text.to_string());
        }
    }

    #[test]
    fn no_bus_no_answer_no_word() {
        let mut said = Said(Vec::new());
        let dir = std::env::temp_dir().join(format!("pam-validity-nobus-{}", std::process::id()));
        let bus = format!("bus=unix:path={}/none", dir.display());
        let start = std::time::Instant::now();
        assert_eq!(
            authenticate("root", [bus.as_str(), "confirm"], &mut said),
            Outcome::Unavailable
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        assert!(said.0.is_empty());
    }
}
