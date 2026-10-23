//! Authorisation, as fprintd does it: polkit's `CheckAuthorization` for the
//! calling bus name (polkit looks up the caller's credentials itself), with user
//! interaction allowed, for the actions `net.reactivated.fprint.device.*`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use zbus::{Connection, Variant};

use crate::errors::FprintError;

/// Verify fingers against saved prints (and list them).
pub const VERIFY: &str = "net.reactivated.fprint.device.verify";
/// Enroll or delete prints.
pub const ENROLL: &str = "net.reactivated.fprint.device.enroll";
/// Act for another user than the caller.
pub const SETUSERNAME: &str = "net.reactivated.fprint.device.setusername";

pub type Check<'a> = Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>>;

/// Decides whether the connection `sender` may perform `action`.
pub trait Authority: Send + Sync + 'static {
    fn check<'a>(&'a self, conn: &'a Connection, sender: &'a str, action: &'a str) -> Check<'a>;
}

/// The system's polkit daemon.
#[derive(Debug, Clone, Copy, Default)]
pub struct Polkit;

const ALLOW_USER_INTERACTION: u32 = 1;

impl Authority for Polkit {
    fn check<'a>(&'a self, conn: &'a Connection, sender: &'a str, action: &'a str) -> Check<'a> {
        Box::pin(async move {
            let subject = (
                "system-bus-name",
                HashMap::from([("name", Variant::new(sender))]),
            );
            let details: HashMap<&str, &str> = HashMap::new();
            let reply = conn
                .call_method(
                    Some("org.freedesktop.PolicyKit1"),
                    "/org/freedesktop/PolicyKit1/Authority",
                    Some("org.freedesktop.PolicyKit1.Authority"),
                    "CheckAuthorization",
                    &(subject, action, details, ALLOW_USER_INTERACTION, ""),
                )
                .await
                .map_err(|e| e.to_string())?;
            let (authorized, _challenge, _details): (bool, bool, HashMap<String, String>) =
                reply.body().deserialize().map_err(|e| e.to_string())?;
            Ok(authorized)
        })
    }
}

/// fprintd's rule: authorised if any one of `actions` is. Errors become
/// `PermissionDenied`.
pub async fn require_any(
    authority: &dyn Authority,
    conn: &Connection,
    sender: &str,
    actions: &[&str],
) -> Result<(), FprintError> {
    let mut last = String::new();
    for action in actions {
        match authority.check(conn, sender, action).await {
            Ok(true) => return Ok(()),
            Ok(false) => last = format!("Not Authorized: {action}"),
            Err(e) => last = format!("Not Authorized: {e}"),
        }
    }
    log::warn!("authorization denied to {sender}: {last}");
    Err(FprintError::PermissionDenied(last))
}
