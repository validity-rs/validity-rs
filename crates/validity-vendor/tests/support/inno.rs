//! Writes a minimal, synthetic Inno Setup 5.5.7 (Unicode) installer: the format
//! of Lenovo's package, holding test files instead of vendor ones. Every byte is
//! made here; no part of a real installer is used.
//!
//! Layout (as Inno Setup's loader and readers expect it):
//!
//! ```text
//! 0x00  "MZ", zeros
//! 0x30  "Inno", offset of the loader table, its bitwise NOT
//! 0x40  loader table (5.1.5 signature, revision 1, CRC32)
//!       setup-0: the 64-byte version string, then two block streams:
//!         primary   header, file entries, wizard images
//!         secondary file locations
//!       setup-1: one stored data chunk ("zlb\x1a" + the files back to back)
//! ```
//!
//! Streams and the chunk are stored (no compression), which the format allows
//! and keeps this writer short. Fields are written in the order the 5.5.7
//! readers consume them (innoextract's `setup/header.cpp`, `file_entry.cpp`,
//! `data_entry.cpp`); `innoextract` itself is the independent check
//! (`tests/install.rs`).

use sha1::{Digest, Sha1};

const VERSION: &[u8] = b"Inno Setup Setup Data (5.5.7) (u)";
const LOADER_SIGNATURE: &[u8; 12] = b"rDlPtS\xCD\xE6\xD7{\x0B*";
const BLOCK: usize = 4096;

#[derive(Default)]
struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    fn zeros(&mut self, n: usize) {
        self.0.resize(self.0.len() + n, 0);
    }
    /// A length-prefixed byte string (ANSI fields, images).
    fn raw(&mut self, b: &[u8]) {
        self.u32(u32::try_from(b.len()).unwrap());
        self.bytes(b);
    }
    /// A length-prefixed UTF-16LE string (the Unicode build's strings).
    fn wide(&mut self, s: &str) {
        let units: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        self.raw(&units);
    }
    /// Windows version range: begin and end, each Windows and NT versions
    /// (build u16, minor u8, major u8) and the NT service pack (u8, u8).
    fn windows_range(&mut self) {
        self.zeros(2 * (4 + 4 + 2));
    }
}

/// A block stream: CRC32 of (size, compressed flag), then the payload in 4 KiB
/// blocks, each preceded by its CRC32. The size counts the block CRCs.
fn stream(payload: &[u8]) -> Vec<u8> {
    let mut body = W::default();
    for block in payload.chunks(BLOCK) {
        body.u32(crc32fast::hash(block));
        body.bytes(block);
    }
    let mut head = W::default();
    head.u32(u32::try_from(body.0.len()).unwrap());
    head.u8(0); // stored
    let mut out = W::default();
    out.u32(crc32fast::hash(&head.0));
    out.bytes(&head.0);
    out.bytes(&body.0);
    out.0
}

/// The primary header of a 5.5.7 Unicode installer with `files` file entries
/// (and as many file locations), nothing else.
fn header(w: &mut W, files: u32) {
    // AppName ... SetupMutex: 28 strings (5.5.7 has every one of them).
    let strings = [
        "Synthetic", // AppName
        "Synthetic 1.0",
        "SyntheticId",
        "", // copyright
        "validity-rs tests",
        "",
        "",
        "",
        "",
        "1.0",
        "{tmp}\\synthetic",
        "",
        "setup", // base file name
        "{app}",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "yes",
        "",
        "",
    ];
    for s in strings {
        w.wide(s);
    }
    // LicenseText, InfoBeforeText, InfoAfterText, CompiledCodeText (ANSI).
    for _ in 0..4 {
        w.raw(b"");
    }
    // Entry counts: languages, custom messages, permissions, types, components,
    // tasks, directories, files, file locations, icons, ini, registry,
    // install delete, uninstall delete, run, uninstall run.
    for count in [0, 0, 0, 0, 0, 0, 0, files, files, 0, 0, 0, 0, 0, 0, 0] {
        w.u32(count);
    }
    w.windows_range();
    w.u32(0); // BackColor
    w.u32(0); // BackColor2
    w.u8(0); // WizardImageAlphaFormat
    w.zeros(20); // password hash (SHA-1)
    w.zeros(8); // password salt
    w.u64(0); // ExtraDiskSpaceRequired
    w.u32(1); // SlicesPerDisk
    w.u8(0); // UninstallLogMode
    w.u8(0); // DirExistsWarning
    w.u8(0); // PrivilegesRequired
    w.u8(0); // ShowLanguageDialog
    w.u8(0); // LanguageDetectionMethod
    w.u8(0); // CompressMethod: stored
    w.u8(0); // ArchitecturesAllowed
    w.u8(0); // ArchitecturesInstallIn64BitMode
    w.u8(0); // DisableDirPage
    w.u8(0); // DisableProgramGroupPage
    w.u64(0); // UninstallDisplaySize
    // Options: 47 flags in 5.5.7 (Unicode), all clear.
    w.zeros(47_usize.div_ceil(8));
}

fn file_entry(w: &mut W, destination: &str, location: u32, size: u64) {
    w.wide(""); // source
    w.wide(destination);
    w.wide(""); // font name
    w.wide(""); // strong assembly name
    for _ in 0..6 {
        // components, tasks, languages, check, after install, before install
        w.wide("");
    }
    w.windows_range();
    w.u32(location);
    w.u32(0); // attributes
    w.u64(size); // external size
    w.u16(0xffff); // permission index: -1, none
    // Options: 32 flags in 5.5.7, all clear.
    w.zeros(4);
    w.u8(0); // file type: user file
}

fn file_location(w: &mut W, offset_in_chunk: u64, data: &[u8], chunk_size: u64) {
    w.u32(0); // first slice
    w.u32(0); // last slice
    w.u32(0); // chunk start, relative to setup-1
    w.u64(offset_in_chunk);
    w.u64(data.len() as u64);
    w.u64(chunk_size);
    w.bytes(&Sha1::digest(data));
    w.u64(0); // file time
    w.u32(0); // file version (most significant)
    w.u32(0); // file version (least significant)
    // Options: 11 flags in 5.5.7, all clear (not compressed, not encrypted).
    w.zeros(2);
}

/// An installer holding `files` (destination as recorded, content), in order.
pub fn installer(files: &[(&str, &[u8])]) -> Vec<u8> {
    let n = u32::try_from(files.len()).unwrap();
    let chunk: Vec<u8> = files.iter().flat_map(|(_, d)| d.iter().copied()).collect();

    let mut primary = W::default();
    header(&mut primary, n);
    for (i, (dest, data)) in files.iter().enumerate() {
        file_entry(
            &mut primary,
            dest,
            u32::try_from(i).unwrap(),
            data.len() as u64,
        );
    }
    primary.raw(b""); // wizard image
    primary.raw(b""); // small wizard image

    let mut secondary = W::default();
    let mut offset = 0;
    for (_, data) in files {
        file_location(&mut secondary, offset, data, chunk.len() as u64);
        offset += data.len() as u64;
    }

    let mut setup0 = W::default();
    let mut version = VERSION.to_vec();
    version.resize(64, 0);
    setup0.bytes(&version);
    setup0.bytes(&stream(&primary.0));
    setup0.bytes(&stream(&secondary.0));

    let table_offset: u32 = 0x40;
    let table_len = 12 + 4 * 7 + 4;
    let header_offset = table_offset + table_len;
    let data_offset = header_offset + u32::try_from(setup0.0.len()).unwrap();

    let mut out = W::default();
    out.bytes(b"MZ");
    out.zeros(0x30 - 2);
    out.bytes(b"Inno");
    out.u32(table_offset);
    out.u32(!table_offset);
    out.zeros(table_offset as usize - out.0.len());

    let mut table = W::default();
    table.bytes(LOADER_SIGNATURE);
    table.u32(1); // revision
    let total = data_offset + 4 + u32::try_from(chunk.len()).unwrap();
    table.u32(total); // minimum setup.exe size
    table.u32(0); // offset of setup.e32 (none here)
    table.u32(0); // its uncompressed size
    table.u32(0); // its CRC32
    table.u32(header_offset);
    table.u32(data_offset);
    let crc = crc32fast::hash(&table.0);
    table.u32(crc);
    assert_eq!(table.0.len(), table_len as usize);
    out.bytes(&table.0);

    out.bytes(&setup0.0);
    assert_eq!(out.0.len(), data_offset as usize);
    out.bytes(b"zlb\x1a");
    out.bytes(&chunk);
    out.0
}
