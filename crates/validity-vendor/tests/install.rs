//! The installer against a synthetic Inno Setup package served by a local HTTP
//! mirror: download, hash checks, extraction, atomic switch, idempotence,
//! failures (offline, HTTP error, wrong hashes, not an installer) and the CLI.
//! The real package is only used by `tests/real.rs`, on request.

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use support::http::{Mirror, unreachable_url};
use support::inno::installer;
use validity_vendor::{
    Error, LENOVO, LINK, Member, Outcome, Package, Source, Status, check, install, sha256_hex,
};

const DLL_ENTRY: &str = "{code:GetExtractPath|}\\WBF_Drivers\\synaWudfBioUsb.dll";
const FWEXT_ENTRY: &str = "{code:GetExtractPath|}\\WBF_Drivers\\6_07f_lenovo_mis_qm.xpfwext";

/// Deterministic filler (no real vendor byte anywhere).
fn content(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

struct Fixture {
    exe: Vec<u8>,
    dll: Vec<u8>,
    fwext: Vec<u8>,
    hashes: [String; 3],
}

impl Fixture {
    fn new() -> Fixture {
        let dll = content(1, 300_000);
        let fwext = content(2, 70_001);
        let decoys: Vec<(String, Vec<u8>)> = (0..80)
            .map(|i| (format!("{{app}}\\decoy\\file{i}.bin"), content(100 + i, 97)))
            .collect();
        let mut files: Vec<(&str, &[u8])> = decoys
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        files.insert(40, (DLL_ENTRY, &dll));
        files.push((FWEXT_ENTRY, &fwext));
        // Lenovo's package lists some files twice; the extractor must cope.
        files.push(("{code:GetExtractPath|}\\DPInst.exe", b"decoy"));
        files.push(("{code:GetExtractPath|}\\DPInst.exe", b"decoy"));
        let exe = installer(&files);
        let hashes = [sha256_hex(&exe), sha256_hex(&dll), sha256_hex(&fwext)];
        Fixture {
            exe,
            dll,
            fwext,
            hashes,
        }
    }

    fn members(&self) -> [Member<'_>; 2] {
        [
            Member {
                entry: DLL_ENTRY,
                name: "synaWudfBioUsb.dll",
                sha256: &self.hashes[1],
            },
            Member {
                entry: FWEXT_ENTRY,
                name: "6_07f_lenovo_mis_qm.xpfwext",
                sha256: &self.hashes[2],
            },
        ]
    }
}

fn package<'a>(url: &'a str, sha256: &'a str, members: &'a [Member<'a>]) -> Package<'a> {
    Package {
        url,
        sha256,
        members,
    }
}

/// A fresh, empty directory under the system temporary directory.
fn tempdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("validity-vendor-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// The directory's entries, sorted, without the lock file.
fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .map(|r| {
            r.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n != ".vendor.lock")
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

#[test]
fn installs_from_a_mirror_then_does_nothing() {
    let f = Fixture::new();
    let m = Mirror::start();
    m.put("/nz3gf07w.exe", f.exe.clone());
    let url = m.url("/nz3gf07w.exe");
    let members = f.members();
    let pkg = package(&url, &f.hashes[0], &members);
    let dir = tempdir("install");

    assert_eq!(check(&pkg, &dir).unwrap(), Status::Missing);
    let out = install(&pkg, &dir, Source::Url(&url)).unwrap();
    assert_eq!(out, Outcome::Installed(dir.join(LINK)));
    assert_eq!(m.hits(), 1);
    assert_eq!(
        fs::read(dir.join("vendor/synaWudfBioUsb.dll")).unwrap(),
        f.dll
    );
    assert_eq!(
        fs::read(dir.join("vendor/6_07f_lenovo_mis_qm.xpfwext")).unwrap(),
        f.fwext
    );
    // A link to one versioned set, which holds the two files and nothing else.
    let set = fs::read_link(dir.join(LINK)).unwrap();
    assert!(set.to_str().unwrap().starts_with("vendor."), "{set:?}");
    assert_eq!(
        listing(&dir),
        vec![LINK.to_string(), set.to_string_lossy().into_owned()]
    );
    assert_eq!(
        listing(&dir.join(&set)),
        vec!["6_07f_lenovo_mis_qm.xpfwext", "synaWudfBioUsb.dll"]
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(dir.join("vendor/synaWudfBioUsb.dll"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644);
    assert_eq!(
        check(&pkg, &dir).unwrap(),
        Status::Installed(dir.join(LINK))
    );

    // Idempotent: nothing downloaded, nothing changed.
    let again = install(&pkg, &dir, Source::Url(&url)).unwrap();
    assert_eq!(again, Outcome::AlreadyInstalled(dir.join(LINK)));
    assert_eq!(m.hits(), 1);
    assert_eq!(fs::read_link(dir.join(LINK)).unwrap(), set);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn repairs_a_damaged_install_and_drops_the_old_set() {
    let f = Fixture::new();
    let m = Mirror::start();
    m.put("/p.exe", f.exe.clone());
    let url = m.url("/p.exe");
    let members = f.members();
    let pkg = package(&url, &f.hashes[0], &members);
    let dir = tempdir("repair");
    install(&pkg, &dir, Source::Url(&url)).unwrap();
    let old = fs::read_link(dir.join(LINK)).unwrap();

    fs::write(dir.join("vendor/6_07f_lenovo_mis_qm.xpfwext"), b"altered").unwrap();
    assert_eq!(
        check(&pkg, &dir).unwrap(),
        Status::Damaged("6_07f_lenovo_mis_qm.xpfwext".into())
    );
    assert_eq!(
        install(&pkg, &dir, Source::Url(&url)).unwrap(),
        Outcome::Installed(dir.join(LINK))
    );
    assert_eq!(m.hits(), 2);
    let new = fs::read_link(dir.join(LINK)).unwrap();
    assert_ne!(new, old);
    assert!(!dir.join(&old).exists(), "the old set is removed");
    assert_eq!(
        check(&pkg, &dir).unwrap(),
        Status::Installed(dir.join(LINK))
    );

    fs::remove_file(dir.join("vendor/synaWudfBioUsb.dll")).unwrap();
    assert_eq!(
        check(&pkg, &dir).unwrap(),
        Status::Damaged("synaWudfBioUsb.dll".into())
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_failed_repair_leaves_the_previous_set_in_place() {
    let f = Fixture::new();
    let m = Mirror::start();
    m.put("/p.exe", f.exe.clone());
    let url = m.url("/p.exe");
    let members = f.members();
    let pkg = package(&url, &f.hashes[0], &members);
    let dir = tempdir("atomic");
    install(&pkg, &dir, Source::Url(&url)).unwrap();
    let set = fs::read_link(dir.join(LINK)).unwrap();
    fs::write(dir.join("vendor/synaWudfBioUsb.dll"), b"altered").unwrap();

    // The mirror now serves a tampered package: refused, nothing switched.
    let mut bad = f.exe.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    m.put("/p.exe", bad);
    let e = install(&pkg, &dir, Source::Url(&url)).unwrap_err();
    assert!(matches!(e, Error::ArchiveHash { .. }), "{e}");
    assert_eq!(fs::read_link(dir.join(LINK)).unwrap(), set);
    assert_eq!(
        listing(&dir),
        vec![LINK.to_string(), set.to_string_lossy().into_owned()]
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn refuses_a_package_with_the_wrong_hash() {
    let f = Fixture::new();
    let m = Mirror::start();
    m.put("/p.exe", f.exe.clone());
    let url = m.url("/p.exe");
    let members = f.members();
    let wrong = "0".repeat(64);
    let pkg = package(&url, &wrong, &members);
    let dir = tempdir("archive-hash");
    match install(&pkg, &dir, Source::Url(&url)) {
        Err(Error::ArchiveHash { expected, actual }) => {
            assert_eq!(expected, wrong);
            assert_eq!(actual, f.hashes[0]);
        }
        other => panic!("{other:?}"),
    }
    assert!(listing(&dir).is_empty(), "{:?}", listing(&dir));
    assert_eq!(check(&pkg, &dir).unwrap(), Status::Missing);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn refuses_a_member_with_the_wrong_hash() {
    let f = Fixture::new();
    let m = Mirror::start();
    m.put("/p.exe", f.exe.clone());
    let url = m.url("/p.exe");
    let wrong = "f".repeat(64);
    let mut members = f.members();
    members[1].sha256 = &wrong;
    let pkg = package(&url, &f.hashes[0], &members);
    let dir = tempdir("member-hash");
    match install(&pkg, &dir, Source::Url(&url)) {
        Err(Error::MemberHash { name, actual, .. }) => {
            assert_eq!(name, "6_07f_lenovo_mis_qm.xpfwext");
            assert_eq!(actual, f.hashes[2]);
        }
        other => panic!("{other:?}"),
    }
    assert!(listing(&dir).is_empty(), "{:?}", listing(&dir));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn reports_a_missing_member() {
    let f = Fixture::new();
    let mut members = f.members().to_vec();
    members.push(Member {
        entry: "{code:GetExtractPath|}\\WBF_Drivers\\absent.dll",
        name: "absent.dll",
        sha256: &f.hashes[1],
    });
    let pkg = package("http://unused", &f.hashes[0], &members);
    let dir = tempdir("missing");
    let archive = dir.join("p.exe");
    fs::write(&archive, &f.exe).unwrap();
    let target = tempdir("missing-target");
    let e = install(&pkg, &target, Source::Archive(&archive)).unwrap_err();
    assert!(
        matches!(&e, Error::MissingMember(n) if n == "absent.dll"),
        "{e}"
    );
    assert!(listing(&target).is_empty());
    fs::remove_dir_all(&dir).unwrap();
    fs::remove_dir_all(&target).unwrap();
}

#[test]
fn installs_from_a_local_copy_without_network() {
    let f = Fixture::new();
    let members = f.members();
    let pkg = package("http://127.0.0.1:9/never-used", &f.hashes[0], &members);
    let src = tempdir("archive-src");
    let archive = src.join("nz3gf07w.exe");
    fs::write(&archive, &f.exe).unwrap();
    let dir = tempdir("archive");
    assert_eq!(
        install(&pkg, &dir, Source::Archive(&archive)).unwrap(),
        Outcome::Installed(dir.join(LINK))
    );
    assert_eq!(
        fs::read(dir.join("vendor/synaWudfBioUsb.dll")).unwrap(),
        f.dll
    );
    // The local copy is the caller's: left alone.
    assert_eq!(fs::read(&archive).unwrap(), f.exe);
    fs::remove_dir_all(&src).unwrap();
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn offline_and_http_errors_are_download_errors() {
    let f = Fixture::new();
    let members = f.members();
    let url = unreachable_url();
    let pkg = package(&url, &f.hashes[0], &members);
    let dir = tempdir("offline");
    match install(&pkg, &dir, Source::Url(&url)) {
        Err(e @ Error::Download { network: true, .. }) => {
            assert!(e.to_string().contains("offline"), "{e}");
        }
        other => panic!("{other:?}"),
    }
    assert!(listing(&dir).is_empty(), "{:?}", listing(&dir));

    let m = Mirror::start();
    let url = m.url("/absent.exe");
    match install(&pkg, &dir, Source::Url(&url)) {
        Err(Error::Download {
            network: false,
            detail,
            ..
        }) => {
            assert!(detail.contains("404"), "{detail}");
        }
        other => panic!("{other:?}"),
    }
    assert!(listing(&dir).is_empty(), "{:?}", listing(&dir));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn refuses_what_is_not_an_installer() {
    let junk = content(7, 5000);
    let hash = sha256_hex(&junk);
    let pkg = package("http://unused", &hash, &[]);
    let src = tempdir("junk-src");
    let archive = src.join("junk.exe");
    fs::write(&archive, &junk).unwrap();
    let dir = tempdir("junk");
    let e = install(&pkg, &dir, Source::Archive(&archive)).unwrap_err();
    assert!(matches!(e, Error::Archive(_)), "{e}");
    assert!(listing(&dir).is_empty());
    fs::remove_dir_all(&src).unwrap();
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_foreign_vendor_entry_is_left_alone() {
    let f = Fixture::new();
    let members = f.members();
    let pkg = package("http://unused", &f.hashes[0], &members);
    let dir = tempdir("foreign");
    fs::create_dir(dir.join(LINK)).unwrap();
    assert!(matches!(check(&pkg, &dir), Err(Error::Foreign(_))));
    let archive = dir.join("p.exe");
    fs::write(&archive, &f.exe).unwrap();
    assert!(matches!(
        install(&pkg, &dir, Source::Archive(&archive)),
        Err(Error::Foreign(_))
    ));
    assert!(dir.join(LINK).is_dir());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn stale_sets_from_an_interrupted_run_are_cleaned_up() {
    let f = Fixture::new();
    let members = f.members();
    let pkg = package("http://unused", &f.hashes[0], &members);
    let dir = tempdir("stale");
    fs::create_dir(dir.join("vendor.123-1")).unwrap();
    fs::write(dir.join("vendor.123-1/.download"), b"partial").unwrap();
    let src = tempdir("stale-src");
    let archive = src.join("p.exe");
    fs::write(&archive, &f.exe).unwrap();
    install(&pkg, &dir, Source::Archive(&archive)).unwrap();
    let set = fs::read_link(dir.join(LINK)).unwrap();
    assert_eq!(
        listing(&dir),
        vec![LINK.to_string(), set.to_string_lossy().into_owned()]
    );
    fs::remove_dir_all(&src).unwrap();
    fs::remove_dir_all(&dir).unwrap();
}

/// The binary, with the real (Lenovo) package description.
fn cli(args: &[&str], env_url: Option<&str>) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_validity-vendor"));
    c.args(args).env_remove("VALIDITY_VENDOR_URL");
    if let Some(u) = env_url {
        c.env("VALIDITY_VENDOR_URL", u);
    }
    let o = c.output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn cli_offline_is_explained_and_harmless() {
    let dir = tempdir("cli-offline");
    let d = dir.to_str().unwrap();
    let url = unreachable_url();
    let (code, _, err) = cli(&["install", "--dir", d], Some(&url));
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("offline"), "{err}");
    assert!(err.contains("password login is"), "{err}");
    assert!(err.contains("--archive"), "{err}");
    assert!(listing(&dir).is_empty());
    // --url wins over the environment.
    let (code, _, err) = cli(
        &["install", "--dir", d, "--url", &unreachable_url()],
        Some("http://x.invalid/"),
    );
    assert_eq!(code, 3, "{err}");
    assert!(!err.contains("x.invalid"), "{err}");

    let (code, _, err) = cli(&["check", "--dir", d], None);
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("not installed"), "{err}");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cli_refuses_a_mirror_serving_something_else() {
    // The CLI always checks against Lenovo's hash: a mirror cannot substitute.
    let f = Fixture::new();
    let m = Mirror::start();
    m.put("/nz3gf07w.exe", f.exe.clone());
    let dir = tempdir("cli-hash");
    let (code, _, err) = cli(
        &[
            "install",
            "--dir",
            dir.to_str().unwrap(),
            "--url",
            &m.url("/nz3gf07w.exe"),
        ],
        None,
    );
    assert_eq!(code, 1, "{err}");
    assert!(
        err.contains(LENOVO.sha256) && err.contains(&f.hashes[0]),
        "{err}"
    );
    assert!(listing(&dir).is_empty());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cli_usage() {
    let (code, out, _) = cli(&["--help"], None);
    assert_eq!(code, 0);
    assert!(out.contains("validity-vendor install"));
    let (code, out, _) = cli(&["-V"], None);
    assert_eq!(code, 0);
    assert!(out.starts_with("validity-vendor "));
    for bad in [
        &[][..],
        &["frobnicate"],
        &["install", "--bogus"],
        &["install", "--dir"],
        &["check", "--url", "http://x"],
        &["install", "--url", "u", "--archive", "a"],
    ] {
        let (code, _, err) = cli(bad, None);
        assert_eq!(code, 2, "{bad:?}: {err}");
    }
}

/// innoextract, when installed, reads the synthetic package the same way: an
/// independent check that the test fixture is a well-formed Inno Setup 5.5.7
/// installer, not merely one this crate's reader accepts.
#[test]
fn innoextract_agrees_on_the_synthetic_package() {
    if Command::new("innoextract")
        .arg("--version")
        .output()
        .is_err()
    {
        println!("innoextract not installed, skipped");
        return;
    }
    let f = Fixture::new();
    let dir = tempdir("innoextract");
    let exe = dir.join("p.exe");
    fs::write(&exe, &f.exe).unwrap();
    let out = Command::new("innoextract")
        .args(["--silent", "--output-dir"])
        .arg(&dir)
        .arg(&exe)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let base = dir.join("code$GetExtractPath$/WBF_Drivers");
    assert_eq!(fs::read(base.join("synaWudfBioUsb.dll")).unwrap(), f.dll);
    assert_eq!(
        fs::read(base.join("6_07f_lenovo_mis_qm.xpfwext")).unwrap(),
        f.fwext
    );
    fs::remove_dir_all(&dir).unwrap();
}
