//! Installs the vendor files that `validity-daemon` and the pairing tools need,
//! which cannot be redistributed: the Synaptics driver DLL (it holds the sensor
//! command blobs) and the sensor firmware extension. Both come from Lenovo's
//! driver package `nz3gf07w.exe`, an Inno Setup installer.
//!
//! [`install`] downloads the package (or takes a local copy), checks its SHA-256,
//! extracts the two files, checks theirs, and switches them into place in one
//! atomic step:
//!
//! ```text
//! /var/lib/validity/vendor -> vendor.<stamp>        (symbolic link, replaced by rename(2))
//! /var/lib/validity/vendor.<stamp>/synaWudfBioUsb.dll
//! /var/lib/validity/vendor.<stamp>/6_07f_lenovo_mis_qm.xpfwext
//! ```
//!
//! Either the link points at a complete, verified set, or it is left as it was:
//! a failure at any step (offline, wrong hash, crash) never leaves a partial
//! install. Running it again when the files are in place and intact does
//! nothing, without touching the network. It never runs at build time: the
//! packages call it after installation, and an administrator can run it by hand.
//!
//! The download goes through `curl` (proxies, the system's certificate store);
//! integrity rests on the pinned SHA-256 alone, whatever the transport.

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// Where the files are installed by default (the daemon's state directory).
pub const DEFAULT_DIR: &str = "/var/lib/validity";
/// The link, inside the directory, that points at the installed set.
pub const LINK: &str = "vendor";
/// Lock file inside the directory: one installer at a time.
const LOCK: &str = ".vendor.lock";
/// Prefix of the versioned directories the link points at.
const SET_PREFIX: &str = "vendor.";
/// The downloaded package, inside the staging directory.
const DOWNLOAD: &str = ".download";
/// Refuses a download larger than this (the real package is 7244088 bytes).
const MAX_DOWNLOAD: u64 = 64 << 20;

/// One file to take out of the package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member<'a> {
    /// The file's destination as recorded in the installer, exactly.
    pub entry: &'a str,
    /// The name it is installed under.
    pub name: &'a str,
    /// Its SHA-256, lowercase hex.
    pub sha256: &'a str,
}

/// A vendor package: where to get it, what it must hash to, what to take out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Package<'a> {
    pub url: &'a str,
    /// Its SHA-256, lowercase hex.
    pub sha256: &'a str,
    pub members: &'a [Member<'a>],
}

/// Lenovo's Synaptics driver package for the ThinkPad T480 family (06cb:009a).
/// The hashes are those recorded in `docs/phase-0.md`; the DLL's is also
/// `validity_proto::vendor::DLL_SHA256`.
pub const LENOVO: Package<'static> = Package {
    url: "https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe",
    sha256: "c0f8fa6fe1279d4519cc8a381862455948231c45388234b5cf22aa26da6270ef",
    members: &[
        Member {
            entry: "{code:GetExtractPath|}\\WBF_Drivers\\synaWudfBioUsb.dll",
            name: "synaWudfBioUsb.dll",
            sha256: "aed9f4246bbaca28776c05c169c734cae9763322b03dc00e4319320e1aa2294d",
        },
        Member {
            entry: "{code:GetExtractPath|}\\WBF_Drivers\\6_07f_lenovo_mis_qm.xpfwext",
            name: "6_07f_lenovo_mis_qm.xpfwext",
            sha256: "ed2b1b5818c4072dd5c1a66e5d556888e81e3806ab0fc653164bea823ccfa2b1",
        },
    ],
};

/// Where the package comes from.
#[derive(Debug, Clone, Copy)]
pub enum Source<'a> {
    /// Downloaded from this URL (`http` or `https`).
    Url(&'a str),
    /// A copy already on disk (downloaded on another machine, for example).
    Archive(&'a Path),
}

#[derive(Debug)]
pub enum Error {
    /// The download failed. `network` is true when the server could not be
    /// reached at all (no network, no DNS, connection refused, timeout).
    Download {
        url: String,
        detail: String,
        network: bool,
    },
    /// `curl` is not installed.
    NoCurl,
    ArchiveHash {
        expected: String,
        actual: String,
    },
    /// The package is not a readable Inno Setup installer.
    Archive(String),
    MissingMember(String),
    MemberHash {
        name: String,
        expected: String,
        actual: String,
    },
    /// `<dir>/vendor` exists but is not a link this tool made.
    Foreign(PathBuf),
    Io {
        what: String,
        err: io::Error,
    },
}

impl Error {
    fn io(what: impl Into<String>) -> impl FnOnce(io::Error) -> Error {
        let what = what.into();
        move |err| Error::Io { what, err }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Download {
                url,
                detail,
                network: true,
            } => write!(f, "cannot reach {url} (offline?): {detail}"),
            Error::Download { url, detail, .. } => write!(f, "cannot download {url}: {detail}"),
            Error::NoCurl => write!(f, "curl is not installed; it is needed for the download"),
            Error::ArchiveHash { expected, actual } => write!(
                f,
                "the downloaded package has SHA-256 {actual}, expected {expected}: refusing it"
            ),
            Error::Archive(e) => {
                write!(f, "the package is not a readable Inno Setup installer: {e}")
            }
            Error::MissingMember(n) => write!(f, "{n} is not in the package"),
            Error::MemberHash {
                name,
                expected,
                actual,
            } => write!(
                f,
                "{name} from the package has SHA-256 {actual}, expected {expected}: refusing it"
            ),
            Error::Foreign(p) => write!(
                f,
                "{} exists and is not a link made by validity-vendor; move it away and retry",
                p.display()
            ),
            Error::Io { what, err } => write!(f, "{what}: {err}"),
        }
    }
}

impl std::error::Error for Error {}

/// What [`install`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The files were already there and intact: nothing was done.
    AlreadyInstalled(PathBuf),
    /// The files were installed (or repaired) in this directory.
    Installed(PathBuf),
}

/// The state of an installation directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Every file is present and has its expected SHA-256.
    Installed(PathBuf),
    /// No installed set.
    Missing,
    /// A set is installed but this file is absent or altered.
    Damaged(String),
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Checks the set installed in `dir` (`<dir>/vendor`).
pub fn check(pkg: &Package<'_>, dir: &Path) -> Result<Status, Error> {
    let link = dir.join(LINK);
    let target = match fs::read_link(&link) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Status::Missing),
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => return Err(Error::Foreign(link)),
        Err(e) => return Err(Error::io(format!("reading {}", link.display()))(e)),
    };
    if !is_set_name(&target) {
        return Err(Error::Foreign(link));
    }
    for m in pkg.members {
        match fs::read(link.join(m.name)) {
            Ok(data) if sha256_hex(&data) == m.sha256 => {}
            Ok(_) => return Ok(Status::Damaged(m.name.to_string())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Status::Damaged(m.name.to_string()));
            }
            Err(e) => {
                return Err(Error::io(format!(
                    "reading {}",
                    link.join(m.name).display()
                ))(e));
            }
        }
    }
    Ok(Status::Installed(link))
}

/// A relative, single-component `vendor.<stamp>` link target.
fn is_set_name(target: &Path) -> bool {
    let mut parts = target.components();
    match (parts.next(), parts.next()) {
        (Some(std::path::Component::Normal(n)), None) => n
            .to_str()
            .is_some_and(|s| s.starts_with(SET_PREFIX) && s.len() > SET_PREFIX.len()),
        _ => false,
    }
}

/// Installs `pkg` into `dir` from `source`, unless an intact set is already
/// there. See the crate documentation for the layout and the guarantees.
pub fn install(pkg: &Package<'_>, dir: &Path, source: Source<'_>) -> Result<Outcome, Error> {
    if let Status::Installed(p) = check(pkg, dir)? {
        return Ok(Outcome::AlreadyInstalled(p));
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(Error::io(format!("creating {}", dir.display())))?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(LOCK))
        .map_err(Error::io(format!("opening the lock in {}", dir.display())))?;
    lock.lock()
        .map_err(Error::io(format!("locking {}", dir.join(LOCK).display())))?;
    // Another installer may have finished while this one waited for the lock.
    if let Status::Installed(p) = check(pkg, dir)? {
        return Ok(Outcome::AlreadyInstalled(p));
    }
    let name = stamp();
    let staging = dir.join(&name);
    let result = stage(pkg, &staging, source).and_then(|()| switch(dir, &name));
    match result {
        Ok(()) => {
            remove_other_sets(dir, &name);
            Ok(Outcome::Installed(dir.join(LINK)))
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            Err(e)
        }
    }
}

/// `vendor.<seconds><nanoseconds>-<pid>`: unique per run.
fn stamp() -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "{SET_PREFIX}{}{:09}-{}",
        t.as_secs(),
        t.subsec_nanos(),
        std::process::id()
    )
}

/// Fills `staging` with the verified members.
fn stage(pkg: &Package<'_>, staging: &Path, source: Source<'_>) -> Result<(), Error> {
    fs::DirBuilder::new()
        .mode(0o755)
        .create(staging)
        .map_err(Error::io(format!("creating {}", staging.display())))?;
    // The directory mode is subject to the umask; the set must be readable.
    fs::set_permissions(staging, fs::Permissions::from_mode(0o755)).map_err(Error::io(format!(
        "setting the mode of {}",
        staging.display()
    )))?;
    let archive = match source {
        Source::Url(url) => {
            let dest = staging.join(DOWNLOAD);
            download(url, &dest)?;
            dest
        }
        Source::Archive(p) => p.to_path_buf(),
    };
    let data = fs::read(&archive).map_err(Error::io(format!("reading {}", archive.display())))?;
    let actual = sha256_hex(&data);
    if actual != pkg.sha256 {
        return Err(Error::ArchiveHash {
            expected: pkg.sha256.to_string(),
            actual,
        });
    }
    for (m, content) in extract(pkg, data)? {
        write_synced(&staging.join(m.name), &content)?;
    }
    if matches!(source, Source::Url(_)) {
        fs::remove_file(&archive).map_err(Error::io(format!("removing {}", archive.display())))?;
    }
    sync_dir(staging)
}

/// Takes the members out of the installer, each checked against its hash.
fn extract<'p>(pkg: &Package<'p>, data: Vec<u8>) -> Result<Vec<(Member<'p>, Vec<u8>)>, Error> {
    let mut inno =
        inno::Inno::new(io::Cursor::new(data)).map_err(|e| Error::Archive(e.to_string()))?;
    let wanted = |dest: Option<&str>| pkg.members.iter().any(|m| Some(m.entry) == dest);
    let mut found: Vec<(Member<'p>, Vec<u8>)> = Vec::new();
    let mut mismatch: Option<Error> = None;
    for entry in inno.filtered_files(|e| wanted(e.file().destination())) {
        let (e, content) = entry.map_err(|e| Error::Archive(e.to_string()))?;
        let Some(m) = pkg
            .members
            .iter()
            .find(|m| Some(m.entry) == e.file().destination())
        else {
            continue;
        };
        if found.iter().any(|(f, _)| f.name == m.name) {
            continue;
        }
        let actual = sha256_hex(&content);
        if actual == m.sha256 {
            found.push((*m, content));
        } else {
            mismatch.get_or_insert(Error::MemberHash {
                name: m.name.to_string(),
                expected: m.sha256.to_string(),
                actual,
            });
        }
    }
    for m in pkg.members {
        if !found.iter().any(|(f, _)| f.name == m.name) {
            return Err(match mismatch {
                Some(e @ Error::MemberHash { .. }) => e,
                _ => Error::MissingMember(m.name.to_string()),
            });
        }
    }
    Ok(found)
}

fn write_synced(path: &Path, content: &[u8]) -> Result<(), Error> {
    let what = || format!("writing {}", path.display());
    let mut f = fs::File::create(path).map_err(Error::io(what()))?;
    f.write_all(content).map_err(Error::io(what()))?;
    f.set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(Error::io(what()))?;
    f.sync_all().map_err(Error::io(what()))
}

fn sync_dir(dir: &Path) -> Result<(), Error> {
    fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(Error::io(format!("syncing {}", dir.display())))
}

/// Points `<dir>/vendor` at `<dir>/<name>` in one rename(2).
fn switch(dir: &Path, name: &str) -> Result<(), Error> {
    let link = dir.join(LINK);
    match fs::symlink_metadata(&link) {
        Ok(m) if !m.file_type().is_symlink() => return Err(Error::Foreign(link)),
        _ => {}
    }
    let tmp = dir.join(format!(".{LINK}.new"));
    let _ = fs::remove_file(&tmp);
    std::os::unix::fs::symlink(name, &tmp)
        .map_err(Error::io(format!("creating {}", tmp.display())))?;
    if let Err(e) = fs::rename(&tmp, &link) {
        let _ = fs::remove_file(&tmp);
        return Err(Error::io(format!("replacing {}", link.display()))(e));
    }
    sync_dir(dir)
}

/// Removes the sets the link no longer points at (older installs, and staging
/// directories left by an interrupted run). Failures are harmless leftovers.
fn remove_other_sets(dir: &Path, keep: &str) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let n = e.file_name();
        let Some(n) = n.to_str() else { continue };
        if n.starts_with(SET_PREFIX) && n != keep && e.file_type().is_ok_and(|t| t.is_dir()) {
            let _ = fs::remove_dir_all(e.path());
        }
    }
}

/// curl exit codes for "the server could not be reached": proxy and host
/// resolution, connection, timeout, TLS connection, receive failure.
const CURL_NETWORK: [i32; 7] = [5, 6, 7, 28, 35, 52, 56];

/// Downloads `url` to `dest` with curl.
fn download(url: &str, dest: &Path) -> Result<(), Error> {
    let out = Command::new("curl")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            // Only HTTP(S); a redirect may only lead to HTTPS.
            "--proto",
            "=http,https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "20",
            "--max-time",
            "600",
            "--retry",
            "3",
            "--max-filesize",
            &MAX_DOWNLOAD.to_string(),
            "--output",
        ])
        .arg(dest)
        .arg(url)
        .output();
    let out = match out {
        Ok(o) => o,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Error::NoCurl),
        Err(e) => return Err(Error::io("running curl")(e)),
    };
    if out.status.success() {
        return Ok(());
    }
    let code = out.status.code();
    Err(Error::Download {
        url: url.to_string(),
        detail: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        network: code.is_some_and(|c| CURL_NETWORK.contains(&c)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_names() {
        assert!(is_set_name(Path::new("vendor.1-2")));
        assert!(!is_set_name(Path::new("vendor.")));
        assert!(!is_set_name(Path::new("other")));
        assert!(!is_set_name(Path::new("/var/lib/validity/vendor.1")));
        assert!(!is_set_name(Path::new("../vendor.1")));
        assert!(!is_set_name(Path::new("vendor.1/x")));
        assert!(stamp().starts_with(SET_PREFIX));
        assert_ne!(stamp(), stamp());
    }

    #[test]
    fn lenovo_package_matches_the_protocol_crate() {
        // The daemon checks the DLL, and the pairing the firmware extension,
        // against these hashes too.
        assert_eq!(LENOVO.members[0].name, "synaWudfBioUsb.dll");
        assert_eq!(LENOVO.members[0].sha256, validity_proto::vendor::DLL_SHA256);
        assert_eq!(
            LENOVO.members[1].sha256,
            validity_proto::fwext::FWEXT_MIS_QM_SHA256
        );
        assert!(LENOVO.url.starts_with("https://"));
        for h in [
            LENOVO.sha256,
            LENOVO.members[0].sha256,
            LENOVO.members[1].sha256,
        ] {
            assert_eq!(h.len(), 64);
            assert!(
                h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
        }
    }

    #[test]
    fn digest() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
