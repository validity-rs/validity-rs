//! The real package, on request only (it may not be redistributed, so it is
//! never committed nor fetched by default):
//!
//! - `VALIDITY_VENDOR_ARCHIVE=<nz3gf07w.exe>`: installs from that copy;
//! - `VALIDITY_VENDOR_ONLINE=1`: downloads it from Lenovo.
//!
//! Either checks Lenovo's SHA-256s end to end. Without them: "skipped".

use std::fs;

use validity_vendor::{LENOVO, Outcome, Source, Status, check, install};

fn run(source: Source<'_>, name: &str) {
    let dir = std::env::temp_dir().join(format!(
        "validity-vendor-real-{}-{name}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    let out = install(&LENOVO, &dir, source).unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(out, Outcome::Installed(_)), "{out:?}");
    assert_eq!(
        check(&LENOVO, &dir).unwrap(),
        Status::Installed(dir.join("vendor"))
    );
    for m in LENOVO.members {
        let data = fs::read(dir.join("vendor").join(m.name)).unwrap();
        assert_eq!(validity_vendor::sha256_hex(&data), m.sha256, "{}", m.name);
        println!("{} {} ({} bytes)", m.sha256, m.name, data.len());
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn real_package_from_a_local_copy() {
    let Ok(path) = std::env::var("VALIDITY_VENDOR_ARCHIVE") else {
        println!("VALIDITY_VENDOR_ARCHIVE not set, skipped");
        return;
    };
    run(Source::Archive(std::path::Path::new(&path)), "archive");
}

#[test]
fn real_package_from_lenovo() {
    if std::env::var("VALIDITY_VENDOR_ONLINE").as_deref() != Ok("1") {
        println!("VALIDITY_VENDOR_ONLINE not set, skipped");
        return;
    }
    run(Source::Url(LENOVO.url), "online");
}
