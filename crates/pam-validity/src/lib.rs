//! `pam_validity.so`: fingerprint authentication through the
//! `net.reactivated.Fprint` D-Bus service (validity-daemon, or fprintd),
//! with its messages in the language of the session.
//!
//! It does what pam_fprintd does for the `auth` stack, with two
//! differences: the messages follow the environment's locale variables
//! rather than the application's `setlocale` (which LightDM's PAM process
//! never calls, so pam_fprintd spoke English to a French greeter), and the
//! `confirm` option says "`<user>` recognized, press Enter." after a match.
//! English and French are built in; any other locale gets English. Never
//! two languages at once.
//!
//! ```text
//! auth  [success=end default=die]  pam_validity.so max-tries=1 timeout=30 confirm
//! ```
//!
//! Results: `PAM_SUCCESS` only on a `verify-match` from the daemon;
//! `PAM_AUTH_ERR` for a refused finger; `PAM_AUTHINFO_UNAVAIL` for
//! everything that is not an answer (no daemon, no device, no enrolled
//! finger, a D-Bus error, no finger in time, no user or conversation, a
//! panic), so that the stack falls back to the password. The module only
//! speaks (`PAM_TEXT_INFO`) once a device is verifying, and not at all
//! under `PAM_SILENT`.
//!
//! - [`options`]: the arguments.
//! - [`text`]: the language and the messages.
//! - [`verify`]: the D-Bus side.
//! - `ffi` (not in static builds, which cannot make a shared object): the
//!   PAM entry points, the module's only unsafe code.

pub mod options;
pub mod text;
pub mod verify;

#[cfg(not(target_feature = "crt-static"))]
mod ffi;

use options::Options;
use text::Lang;

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

/// Where the messages go: the application's conversation function.
pub trait Talk {
    /// Shows one line of information (`PAM_TEXT_INFO`).
    fn info(&mut self, text: &str);
}

/// Authenticates `user` with the module's arguments `args`, speaking
/// `lang` through `talk`. Blocks for the length of the verification.
pub fn authenticate<'a>(
    user: &str,
    args: impl IntoIterator<Item = &'a str>,
    lang: Lang,
    talk: &mut dyn Talk,
) -> Outcome {
    let opts = Options::parse(args);
    zbus::block_on(verify::verify(user, &opts, lang, talk))
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

    struct Quiet(Vec<String>);
    impl Talk for Quiet {
        fn info(&mut self, text: &str) {
            self.0.push(text.to_string());
        }
    }

    #[test]
    fn no_bus_no_answer_no_word() {
        let mut talk = Quiet(Vec::new());
        let dir = std::env::temp_dir().join(format!("pam-validity-nobus-{}", std::process::id()));
        let bus = format!("bus=unix:path={}/none", dir.display());
        let start = std::time::Instant::now();
        assert_eq!(
            authenticate("root", [bus.as_str(), "confirm"], Lang::En, &mut talk),
            Outcome::Unavailable
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        assert!(talk.0.is_empty());
    }
}
