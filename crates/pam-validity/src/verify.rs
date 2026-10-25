//! One verification through `net.reactivated.Fprint`, as pam_fprintd does
//! it: the default device, the user's enrolled fingers, `Claim`,
//! `VerifyStart("any")`, the `VerifyStatus` signals, `VerifyStop`, `Release`.
//!
//! Every D-Bus call is bounded ([`CALL_TIMEOUT`]) and the wait for a finger
//! by the `timeout` option, so the module always returns, and quickly when
//! there is no daemon, no device or no enrolled finger: the stack then asks
//! for the password, as it would without the module.

use std::pin::Pin;
use std::time::{Duration, Instant};

use futures_core::Stream;
use zbus::OwnedObjectPath;
use zbus::proxy::CacheProperties;

use crate::options::Options;
use crate::text::{self, Lang};
use crate::{Outcome, Talk};

/// The longest any one D-Bus call (or the connection) may take.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);

#[zbus::proxy(
    interface = "net.reactivated.Fprint.Manager",
    default_service = "net.reactivated.Fprint",
    default_path = "/net/reactivated/Fprint/Manager"
)]
trait Manager {
    fn get_default_device(&self) -> zbus::Result<OwnedObjectPath>;
}

#[zbus::proxy(
    interface = "net.reactivated.Fprint.Device",
    default_service = "net.reactivated.Fprint"
)]
trait Device {
    fn list_enrolled_fingers(&self, username: &str) -> zbus::Result<Vec<String>>;
    fn claim(&self, username: &str) -> zbus::Result<()>;
    fn release(&self) -> zbus::Result<()>;
    fn verify_start(&self, finger_name: &str) -> zbus::Result<()>;
    fn verify_stop(&self) -> zbus::Result<()>;
    #[zbus(signal)]
    fn verify_status(&self, result: String, done: bool) -> zbus::Result<()>;
}

/// How one attempt ended.
#[derive(Debug, PartialEq, Eq)]
enum Attempt {
    Match,
    NoMatch,
    /// The daemon cannot verify (disconnected, error, no answer in time).
    Unavailable,
    /// A final status this module does not know: a failure, never a match.
    Unknown,
}

/// The attempt's end for a final `VerifyStatus` result (fprintd's names).
fn attempt_of(result: &str) -> Attempt {
    match result {
        "verify-match" => Attempt::Match,
        "verify-no-match" => Attempt::NoMatch,
        "verify-disconnected" | "verify-unknown-error" => Attempt::Unavailable,
        _ => Attempt::Unknown,
    }
}

/// Runs `fut` for at most `limit`; `None` on error or time-out.
async fn bounded<T>(
    rt: &zruntime::SharedRuntime,
    limit: Duration,
    fut: impl Future<Output = zbus::Result<T>>,
) -> Option<T> {
    rt.timeout(limit, fut).await.ok()?.ok()
}

/// Verifies `user`'s finger. Talks only once a device has started
/// verifying: the prompt (each attempt), then the confirmation after a
/// match if `opts.confirm`.
pub async fn verify(user: &str, opts: &Options, lang: Lang, talk: &mut dyn Talk) -> Outcome {
    let Ok(rt) = zruntime::SharedRuntime::current() else {
        return Outcome::Unavailable;
    };
    let builder = zbus::connection::Builder::address(opts.bus.as_str());
    let Some(conn) = bounded(&rt, CALL_TIMEOUT, builder.build()).await else {
        return Outcome::Unavailable;
    };
    let manager = ManagerProxy::builder(&conn)
        .cache_properties(CacheProperties::No)
        .build();
    let Some(manager) = bounded(&rt, CALL_TIMEOUT, manager).await else {
        return Outcome::Unavailable;
    };
    let Some(path) = bounded(&rt, CALL_TIMEOUT, manager.get_default_device()).await else {
        return Outcome::Unavailable;
    };
    let device = DeviceProxy::builder(&conn)
        .path(path)
        .cache_properties(CacheProperties::No)
        .build();
    let Some(device) = bounded(&rt, CALL_TIMEOUT, device).await else {
        return Outcome::Unavailable;
    };
    let fingers = bounded(&rt, CALL_TIMEOUT, device.list_enrolled_fingers(user)).await;
    let Some(fingers) = fingers.filter(|f| !f.is_empty()) else {
        return Outcome::Unavailable;
    };
    if bounded(&rt, CALL_TIMEOUT, device.claim(user))
        .await
        .is_none()
    {
        return Outcome::Unavailable;
    }
    let outcome = attempts(&rt, &device, opts, &text::prompt(lang, &fingers), talk).await;
    let _ = bounded(&rt, CALL_TIMEOUT, device.release()).await;
    if outcome == Outcome::Match && opts.confirm {
        talk.info(&text::confirm(lang, user));
    }
    outcome
}

/// Up to `opts.max_tries` attempts on the claimed device.
async fn attempts(
    rt: &zruntime::SharedRuntime,
    device: &DeviceProxy<'_>,
    opts: &Options,
    prompt: &str,
    talk: &mut dyn Talk,
) -> Outcome {
    // Subscribed before VerifyStart, so that no status can be missed. The
    // stream only takes signals from the owner of net.reactivated.Fprint.
    let Some(mut statuses) = bounded(rt, CALL_TIMEOUT, device.receive_verify_status()).await else {
        return Outcome::Unavailable;
    };
    let mut tries = 0;
    loop {
        tries += 1;
        if bounded(rt, CALL_TIMEOUT, device.verify_start("any"))
            .await
            .is_none()
        {
            return Outcome::Unavailable;
        }
        talk.info(prompt);
        let attempt = wait(rt, &mut statuses, Instant::now() + opts.timeout).await;
        let _ = bounded(rt, CALL_TIMEOUT, device.verify_stop()).await;
        match attempt {
            Attempt::Match => return Outcome::Match,
            Attempt::NoMatch if tries < opts.max_tries => continue,
            Attempt::NoMatch | Attempt::Unknown => return Outcome::NoMatch,
            Attempt::Unavailable => return Outcome::Unavailable,
        }
    }
}

/// Waits for the attempt's final status until `deadline`. Statuses that
/// are not final (a scan to retry) leave the attempt running.
async fn wait(
    rt: &zruntime::SharedRuntime,
    statuses: &mut VerifyStatusStream,
    deadline: Instant,
) -> Attempt {
    loop {
        let next = std::future::poll_fn(|cx| Pin::new(&mut *statuses).poll_next(cx));
        let signal = match rt.timeout_at(deadline, next).await {
            Ok(Some(signal)) => signal,
            // Timed out, or the connection is gone.
            Ok(None) | Err(_) => return Attempt::Unavailable,
        };
        let Ok(args) = signal.args() else { continue };
        if args.result == "verify-match" {
            return Attempt::Match;
        }
        if args.done {
            return attempt_of(&args.result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_statuses() {
        assert_eq!(attempt_of("verify-match"), Attempt::Match);
        assert_eq!(attempt_of("verify-no-match"), Attempt::NoMatch);
        assert_eq!(attempt_of("verify-disconnected"), Attempt::Unavailable);
        assert_eq!(attempt_of("verify-unknown-error"), Attempt::Unavailable);
        for other in [
            "verify-retry-scan",
            "verify-swipe-too-short",
            "",
            "verify-match ",
            "VERIFY-MATCH",
        ] {
            assert_eq!(attempt_of(other), Attempt::Unknown, "{other:?}");
        }
    }
}
