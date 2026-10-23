//! Users and fingers: usernames, UIDs, the SIDs the sensor database stores, and
//! the fprintd finger names.
//!
//! The sensor keeps Windows identities. Like python-validity's `dbus-service`, a
//! Linux user maps to `S-1-5-21-111111111-1111111111-1111111111-<uid>`, unless the
//! configuration names another SID for that user.

use std::collections::BTreeMap;

use validity_proto::sid::Sid;
use validity_proto::tables;

/// Domain part of the SIDs given to Linux users (python-validity's choice, kept so
/// that prints enrolled with it stay usable).
pub const SID_PREFIX: &str = "S-1-5-21-111111111-1111111111-1111111111";

/// The SID of a Linux user without an override.
pub fn sid_for_uid(uid: u32) -> Sid {
    format!("{SID_PREFIX}-{uid}")
        .parse()
        .expect("prefix and uid form a valid SID")
}

/// Whether `sid` is one this daemon hands out (as opposed to, say, a Windows
/// account sharing the sensor). Used for diagnostics only.
pub fn is_linux_sid(sid: &Sid) -> bool {
    let prefix: Sid = SID_PREFIX.parse().expect("valid constant");
    sid.revision == prefix.revision
        && sid.auth == prefix.auth
        && sid.subauth.len() == prefix.subauth.len() + 1
        && sid.subauth.starts_with(&prefix.subauth)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uid: u32,
}

/// The account database. The system one asks NSS; tests use their own.
pub trait UserDb: Send + Sync + 'static {
    fn by_uid(&self, uid: u32) -> Option<User>;
    fn by_name(&self, name: &str) -> Option<User>;
}

/// NSS through `getpwuid_r` / `getpwnam_r` (local files, LDAP, systemd-homed...).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemUsers;

fn from_nss(u: Option<nix::unistd::User>) -> Option<User> {
    u.map(|u| User {
        name: u.name,
        uid: u.uid.as_raw(),
    })
}

impl UserDb for SystemUsers {
    fn by_uid(&self, uid: u32) -> Option<User> {
        from_nss(nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).ok()?)
    }

    fn by_name(&self, name: &str) -> Option<User> {
        from_nss(nix::unistd::User::from_name(name).ok()?)
    }
}

/// Username to SID, honouring the per-user overrides of the configuration.
#[derive(Debug, Clone, Default)]
pub struct SidMap {
    overrides: BTreeMap<String, Sid>,
}

impl SidMap {
    pub fn new(overrides: BTreeMap<String, Sid>) -> Self {
        SidMap { overrides }
    }

    pub fn sid(&self, user: &User) -> Sid {
        self.overrides
            .get(&user.name)
            .cloned()
            .unwrap_or_else(|| sid_for_uid(user.uid))
    }
}

/// fprintd finger names, in the order fprintd lists them (sensor subtypes 1..=10).
pub const FINGER_NAMES: [&str; 10] = [
    "left-thumb",
    "left-index-finger",
    "left-middle-finger",
    "left-ring-finger",
    "left-little-finger",
    "right-thumb",
    "right-index-finger",
    "right-middle-finger",
    "right-ring-finger",
    "right-little-finger",
];

/// The sensor subtype of an fprintd finger name; `None` for "any" and anything
/// that is not one of the ten fingers.
pub fn finger_subtype(name: &str) -> Option<u16> {
    if !FINGER_NAMES.contains(&name) {
        return None;
    }
    tables::finger_id(name)
}

/// The fprintd name of a sensor subtype; `None` for the Windows-only positions.
pub fn finger_name(subtype: u16) -> Option<&'static str> {
    let n = tables::finger_name(subtype)?;
    FINGER_NAMES.contains(&n).then_some(n)
}

/// fprintd's order: left thumb first.
pub fn sort_fingers(subtypes: &mut [u16]) {
    subtypes.sort_by_key(|s| {
        finger_name(*s)
            .and_then(|n| FINGER_NAMES.iter().position(|x| *x == n))
            .unwrap_or(usize::MAX)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_mapping_matches_python_validity() {
        let s = sid_for_uid(1000);
        assert_eq!(
            s.to_string(),
            "S-1-5-21-111111111-1111111111-1111111111-1000"
        );
        assert_eq!(s.subauth, [21, 111111111, 1111111111, 1111111111, 1000]);
        // The binary form the sensor stores: revision, count, authority, subauths.
        let b = s.to_bytes();
        assert_eq!(&b[..8], [1, 5, 0, 0, 0, 0, 0, 5]);
        assert_eq!(&b[b.len() - 4..], 1000u32.to_le_bytes());
        assert_eq!(sid_for_uid(0).to_string(), format!("{SID_PREFIX}-0"));
        assert_eq!(
            sid_for_uid(u32::MAX).to_string(),
            format!("{SID_PREFIX}-4294967295")
        );
        assert!(is_linux_sid(&sid_for_uid(1234)));
        assert!(!is_linux_sid(&"S-1-5-21-1-2-3-1000".parse().unwrap()));
        assert!(!is_linux_sid(&SID_PREFIX.parse().unwrap()));
    }

    #[test]
    fn overrides_win() {
        let alice = User {
            name: "alice".into(),
            uid: 1000,
        };
        let bob = User {
            name: "bob".into(),
            uid: 1001,
        };
        let map = SidMap::new(BTreeMap::from([(
            "alice".to_string(),
            "S-1-5-21-7-8-9-500".parse().unwrap(),
        )]));
        assert_eq!(map.sid(&alice).to_string(), "S-1-5-21-7-8-9-500");
        assert_eq!(map.sid(&bob), sid_for_uid(1001));
        assert_eq!(SidMap::default().sid(&alice), sid_for_uid(1000));
    }

    #[test]
    fn fingers() {
        assert_eq!(finger_subtype("right-thumb"), Some(1));
        assert_eq!(finger_subtype("left-little-finger"), Some(10));
        assert_eq!(finger_subtype("any"), None);
        assert_eq!(finger_subtype(""), None);
        assert_eq!(finger_subtype("WINBIO_ANSI_381_POS_UNKNOWN"), None);
        assert_eq!(finger_name(7), Some("left-index-finger"));
        assert_eq!(finger_name(0xf5), None);
        assert_eq!(finger_name(0), None);
        for n in FINGER_NAMES {
            assert_eq!(finger_name(finger_subtype(n).unwrap()), Some(n));
        }
        let mut v = vec![2, 0xf5, 6, 7, 1];
        sort_fingers(&mut v);
        assert_eq!(v, [6, 7, 1, 2, 0xf5]);
    }

    #[test]
    fn system_users_resolve_root() {
        // uid 0 exists everywhere this runs (hosts, CI runners, containers).
        let root = SystemUsers.by_uid(0).expect("uid 0 resolves");
        assert_eq!(root.uid, 0);
        assert_eq!(SystemUsers.by_name(&root.name), Some(root));
        assert_eq!(SystemUsers.by_name("no such user \u{1}"), None);
        assert_eq!(SystemUsers.by_name("nul\0inside"), None);
    }
}
