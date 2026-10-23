//! Exact-boundary tests for the table lookups, SIDs, calibration arithmetic and
//! file, timeslot decoding, pairing images and the firmware-extension upload,
//! written from the survivors of a mutation-testing run. All data is synthetic.

use std::collections::VecDeque;

use validity_proto::Error;
use validity_proto::calibration::{CalibrationFile, Geometry};
use validity_proto::fwext::{Fwext, FwextUpload, upload_fwext};
use validity_proto::pairing::{
    ECDH_BLOCK_LEN, TLS_FLASH_LEN, curve_block, make_tls_flash, parse_ecdh_reply, tls_flash_blocks,
};
use validity_proto::scanner::RomInfo;
use validity_proto::session::Sensor;
use validity_proto::sid::Sid;
use validity_proto::tables::{CAPTURE_PROGRAMS, FIRMWARE_FILES, SensorCaptureProg, firmware_file};
use validity_proto::timeslot::{Insn, decode_insn};
use validity_proto::vendor::Blobs;

// ---------------------------------------------------------------- tables

const ANY: u32 = 0xffff;

/// python-validity's `SensorCaptureProg.get` and `metric`, transcribed from
/// `table_types.py`: filter on major, sensor type, a0 and a1 (0xffff matches
/// anything), score each of major, minor, build and u1 as 2 (exact), 1 (wildcard)
/// or 0 in two-bit fields, most significant first, and keep the first entry with
/// the highest non-zero score.
fn reference_get(rom: &RomInfo, sensor_type: u16, a0: u32, a1: u32) -> Option<usize> {
    let fuzzy = |want: u32, have: u32| {
        if want == have {
            2
        } else if want == ANY {
            1
        } else {
            0
        }
    };
    let mut maximum = 0;
    let mut found = None;
    for (k, i) in CAPTURE_PROGRAMS.iter().enumerate() {
        if (i.major != ANY && i.major != rom.major as u32)
            || (i.dev_type != ANY && i.dev_type != sensor_type as u32)
            || (i.a0 != ANY && i.a0 != a0)
            || (i.a1 != ANY && i.a1 != a1)
        {
            continue;
        }
        let mut m = fuzzy(i.major, rom.major as u32);
        m = m * 4 + fuzzy(i.minor, rom.minor as u32);
        m = m * 4 + fuzzy(i.build, rom.build);
        m = m * 4 + fuzzy(i.u1, rom.u1 as u32);
        if m > maximum {
            found = Some(k);
            maximum = m;
        }
    }
    found
}

/// Every value a field takes in the table, plus `extra` (values it never takes,
/// and the wildcard itself where the input can hold it).
fn values(f: impl Fn(&SensorCaptureProg) -> u32, extra: &[u32]) -> Vec<u32> {
    let mut v: Vec<u32> = CAPTURE_PROGRAMS.iter().map(f).collect();
    v.extend(extra);
    v.sort_unstable();
    v.dedup();
    v
}

#[test]
fn capture_program_selection_matches_the_reference() {
    // Major, minor and u1 are bytes in the ROM info: they never equal the wildcard.
    let byte = |v: Vec<u32>| v.into_iter().filter(|&x| x <= 0xff).collect::<Vec<_>>();
    let majors = byte(values(|p| p.major, &[0x7e]));
    let minors = byte(values(|p| p.minor, &[0x7f]));
    let u1s = byte(values(|p| p.u1, &[0x7d]));
    let builds = values(|p| p.build, &[0x7fff, ANY]);
    let types = values(|p| p.dev_type, &[0x7ffe, ANY]);
    let (a0s, a1s) = (
        values(|p| p.a0, &[0x7ffd, ANY]),
        values(|p| p.a1, &[0x7ffc, ANY]),
    );
    let (mut checked, mut found, mut distinct) = (0, 0, std::collections::BTreeSet::new());
    for &major in &majors {
        for &minor in &minors {
            for &build in &builds {
                for &u1 in &u1s {
                    let rom = RomInfo {
                        timestamp: 0,
                        build,
                        major: major as u8,
                        minor: minor as u8,
                        product: 0x30,
                        u1: u1 as u8,
                    };
                    for &t in &types {
                        for &a0 in &a0s {
                            for &a1 in &a1s {
                                let want = reference_get(&rom, t as u16, a0, a1);
                                let got = SensorCaptureProg::get(&rom, t as u16, a0, a1);
                                assert_eq!(
                                    got,
                                    want.map(|k| CAPTURE_PROGRAMS[k].program()),
                                    "rom {rom:?}, type {t:#x}, a0 {a0:#x}, a1 {a1:#x}: want entry {want:?}"
                                );
                                checked += 1;
                                if let Some(k) = want {
                                    found += 1;
                                    distinct.insert(k);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // The grid is not vacuous: it reaches many entries.
    assert!(checked > 10_000 && found > 1_000, "{checked} {found}");
    assert!(distinct.len() > CAPTURE_PROGRAMS.len() / 2, "{distinct:?}");
}

#[test]
fn capture_program_wildcards_and_exact_matches() {
    let rom = |major, minor, build, u1| RomInfo {
        timestamp: 0,
        build,
        major,
        minor,
        product: 0x30,
        u1,
    };
    // The 0x199 program of ROM 6.8 build 0x56 (what 06cb:009a reports).
    let p = SensorCaptureProg::get(&rom(6, 8, 0x56, 0), 0x199, 0x18, 0x19).unwrap();
    // An unknown build of the same ROM still gets a program.
    assert_eq!(
        SensorCaptureProg::get(&rom(6, 8, 0x7fff, 0), 0x199, 0x18, 0x19),
        Some(p.clone())
    );
    // Other majors are filtered out, not merely scored low.
    for t in [0x199, 0xdb] {
        assert_eq!(
            SensorCaptureProg::get(&rom(0x7e, 8, 0x56, 0), t, 0x18, 0x19),
            None
        );
    }
}

#[test]
fn firmware_file_needs_both_ids() {
    assert_eq!(
        firmware_file(0x06cb, 0x009a).unwrap().fwext_name,
        "6_07f_lenovo_mis_qm.xpfwext"
    );
    assert_eq!(firmware_file(0x138a, 0x0090), Some(&FIRMWARE_FILES[0]));
    // Right vendor, wrong product; right product, wrong vendor.
    assert_eq!(firmware_file(0x06cb, 0x0090), None);
    assert_eq!(firmware_file(0x138a, 0x009a), None);
    assert_eq!(firmware_file(0x1234, 0x009a), None);
}

// ---------------------------------------------------------------- SIDs

#[test]
fn sid_binary_length_checks() {
    // Too short to hold the header: an error, not a panic.
    for b in [&[][..], &[1], &[1, 0, 0, 0, 0, 0, 0]] {
        assert!(matches!(Sid::from_bytes(b), Err(Error::Malformed("SID"))));
    }
    // Exactly the header: a SID without subauthorities.
    assert_eq!(
        Sid::from_bytes(&[1, 0, 0, 0, 0, 0, 0, 5]).unwrap(),
        "S-1-5".parse().unwrap()
    );
}

#[test]
fn sid_authority_is_big_endian() {
    let s = Sid::from_bytes(&[1, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]).unwrap();
    assert_eq!(s.auth, 0x0102_0304_0506);
    assert_eq!(s.to_string(), format!("S-1-{}", 0x0102_0304_0506u64));
}

#[test]
fn sid_subauthority_count_limit() {
    // The binary form counts subauthorities in one byte: 255 is the maximum.
    let max = format!("S-1-5{}", "-7".repeat(255));
    let s: Sid = max.parse().unwrap();
    assert_eq!(s.subauth.len(), 255);
    assert_eq!(Sid::from_bytes(&s.to_bytes()).unwrap(), s);
    let over = format!("S-1-5{}", "-7".repeat(256));
    assert!(matches!(over.parse::<Sid>(), Err(Error::Protocol(_))));
    let way_over = format!("S-1-5{}", "-7".repeat(300));
    assert!(matches!(way_over.parse::<Sid>(), Err(Error::Protocol(_))));
}

// ---------------------------------------------------------------- calibration

fn protocol_message(r: Result<Vec<u8>, Error>) -> String {
    match r {
        Err(Error::Protocol(m)) => m,
        other => panic!("expected a protocol error, got {other:?}"),
    }
}

#[test]
fn average_rejects_empty_geometry() {
    // No bytes per frame, but a calibration line count.
    let g = Geometry {
        lines_per_frame: 0,
        bytes_per_line: 10,
        lines_per_calibration_data: 4,
        calibration_frames: 3,
    };
    assert_eq!(protocol_message(g.average(&[])), "empty sensor geometry");
    // Frame bytes, but no calibration lines.
    let g = Geometry {
        lines_per_frame: 4,
        bytes_per_line: 2,
        lines_per_calibration_data: 0,
        calibration_frames: 3,
    };
    assert_eq!(
        protocol_message(g.average(&[0; 64])),
        "empty sensor geometry"
    );
}

#[test]
fn average_of_a_single_non_interleaved_frame() {
    // One frame, one line per calibration line: the frame itself.
    let g = Geometry {
        lines_per_frame: 2,
        bytes_per_line: 2,
        lines_per_calibration_data: 2,
        calibration_frames: 1,
    };
    assert_eq!(g.average(&[1, 2, 3, 4]).unwrap(), [1, 2, 3, 4]);
    // Two frames: both are skipped, nothing is left.
    let g = Geometry {
        calibration_frames: 2,
        ..g
    };
    assert_eq!(
        protocol_message(g.average(&[1, 2, 3, 4, 5, 6, 7, 8])),
        "no calibration frame left to average"
    );
    // Three frames: the third alone.
    let g = Geometry {
        calibration_frames: 3,
        ..g
    };
    assert_eq!(
        g.average(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]).unwrap(),
        [9, 10, 11, 12]
    );
}

fn file_error(b: &[u8]) -> String {
    match CalibrationFile::from_bytes(b) {
        Err(Error::Protocol(m)) => m,
        other => panic!("expected a protocol error, got {other:?}"),
    }
}

#[test]
fn calibration_file_header_length() {
    // An empty calibration is exactly a header (52 bytes) and is valid.
    let empty = CalibrationFile {
        sensor_type: 0x199,
        bytes_per_line: 0,
        lines: 0,
        data: vec![],
    };
    let b = empty.to_bytes();
    assert_eq!(b.len(), 52);
    assert_eq!(CalibrationFile::from_bytes(&b).unwrap(), empty);
    // One byte short of a header, with a valid magic: rejected as such.
    assert_eq!(file_error(&b[..51]), "calibration file: bad magic");
    assert_eq!(file_error(&b[..20]), "calibration file: bad magic");
    assert_eq!(file_error(&b[..8]), "calibration file: bad magic");
    assert_eq!(file_error(&b[..3]), "calibration file: bad magic");
    // A full header with a wrong magic.
    let mut bad = b.clone();
    bad[0] ^= 1;
    assert_eq!(file_error(&bad), "calibration file: bad magic");
}

// ---------------------------------------------------------------- timeslot

#[test]
fn only_end_of_table_return_and_end_of_data_terminate() {
    for op in 0u8..=0xff {
        let Ok((insn, _)) = decode_insn(&[op, 0x12, 0x34]) else {
            continue;
        };
        assert_eq!(
            insn.is_terminator(),
            matches!(op, 1 | 2 | 4),
            "{op:#04x}: {insn}"
        );
    }
    assert!(Insn::EndOfTable.is_terminator());
    assert!(Insn::Return.is_terminator());
    assert!(Insn::EndOfData.is_terminator());
}

#[test]
fn decoded_operands() {
    assert_eq!(
        decode_insn(&[0x09, 0x34]).unwrap(),
        (Insn::EnableSo(0x134), 2)
    );
    assert_eq!(
        decode_insn(&[0x0b, 0xff]).unwrap(),
        (Insn::DisableSo(0x1ff), 2)
    );
    assert_eq!(
        decode_insn(&[0x4f, 0xcd, 0xab]).unwrap(),
        (
            Insn::RegWrite {
                addr: 0x8000_203c,
                value: 0xabcd
            },
            3
        )
    );
}

// ---------------------------------------------------------------- pairing

fn ecdh_reply(rest: &[u8]) -> Vec<u8> {
    let mut r = vec![0, 0];
    r.extend(((4 + rest.len()) as u32).to_le_bytes());
    r.extend(rest);
    r
}

#[test]
fn ecdh_reply_block_length() {
    let block: Vec<u8> = (0..ECDH_BLOCK_LEN).map(|i| i as u8 | 1).collect();
    // Exactly one block, no zero padding.
    assert_eq!(parse_ecdh_reply(&ecdh_reply(&block)).unwrap(), block);
    // Zero padding before the block.
    let mut padded = vec![0; 7];
    padded.extend(&block);
    assert_eq!(parse_ecdh_reply(&ecdh_reply(&padded)).unwrap(), block);
    // One byte short.
    assert!(matches!(
        parse_ecdh_reply(&ecdh_reply(&block[1..])),
        Err(Error::Malformed("ECDH reply length"))
    ));
    assert!(matches!(
        parse_ecdh_reply(&ecdh_reply(&[])),
        Err(Error::Malformed("ECDH reply length"))
    ));
}

#[test]
fn tls_flash_image_fills_its_partition_exactly() {
    let (cert, ecdh) = (vec![0x33; 10], vec![0x66; ECDH_BLOCK_LEN]);
    // Seven blocks of 36 header bytes; bodies 1, key, cert, curve, 256, 256, ECDH.
    let fixed = 7 * 36 + 1 + cert.len() + curve_block().len() + 2 * 0x100 + ecdh.len();
    let key = vec![0x44; TLS_FLASH_LEN - fixed];
    let img = make_tls_flash(&key, &cert, &ecdh).unwrap();
    assert_eq!(img.len(), TLS_FLASH_LEN);
    // No room left for the end marker: the image ends with the ECDH block.
    assert_eq!(img[TLS_FLASH_LEN - ECDH_BLOCK_LEN..], ecdh[..]);
    let blocks = tls_flash_blocks(&img).unwrap();
    assert_eq!(blocks.len(), 7);
    assert_eq!(blocks[1], (4, &key[..]));
    // One byte more does not fit.
    let key = vec![0x44; TLS_FLASH_LEN - fixed + 1];
    assert!(matches!(
        make_tls_flash(&key, &cert, &ecdh),
        Err(Error::Protocol(_))
    ));
    // One byte less leaves one 0xff.
    let key = vec![0x44; TLS_FLASH_LEN - fixed - 1];
    let img = make_tls_flash(&key, &cert, &ecdh).unwrap();
    assert_eq!(img.len(), TLS_FLASH_LEN);
    assert_eq!(img[TLS_FLASH_LEN - 1], 0xff);
}

// ---------------------------------------------------------------- fwext

/// Every command must match the script exactly.
struct Script(VecDeque<(Vec<u8>, Vec<u8>)>);

impl Script {
    fn done(&self) {
        assert!(self.0.is_empty(), "{} commands left", self.0.len());
    }
}

impl Sensor for Script {
    fn cmd(&mut self, p: &[u8]) -> Result<Vec<u8>, Error> {
        let (tx, rx) = self.0.pop_front().expect("a scripted command");
        assert_eq!(hex::encode(p), hex::encode(tx));
        Ok(rx)
    }
    fn is_open(&self) -> bool {
        true
    }
    fn open_channel(&mut self, _: &[u8]) -> Result<(), Error> {
        unreachable!()
    }
    fn wait_int(&mut self) -> Result<Vec<u8>, Error> {
        unreachable!()
    }
    fn read_82(&mut self) -> Result<Vec<u8>, Error> {
        unreachable!()
    }
}

fn blobs() -> Blobs {
    Blobs {
        init_hardcoded: vec![6, 1, 1],
        init_hardcoded_clean_slate: vec![6, 2, 2],
        reset_blob: vec![6, 3, 3],
        db_write_enable: vec![6, 4, 4],
        partition_signature: vec![0x5a; 256],
    }
}

const OK: [u8; 2] = [0, 0];

/// Up to and including the register read that returns `reg`.
fn upload_start(reg: u32) -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (vec![0x43, 2], vec![0xb0, 0x04]),
        (vec![8, 0x5c, 0x20, 0, 0x80, 7, 0, 0, 0, 4], OK.to_vec()),
        (
            vec![7, 0x80, 0x20, 0, 0x80, 4],
            [&OK[..], &reg.to_le_bytes()].concat(),
        ),
    ]
}

fn fwext() -> Fwext {
    Fwext {
        payload: vec![0xab; 5],
        signature: vec![0xcd; 0x100],
    }
}

#[test]
fn fwext_upload_accepts_register_values_2_and_3() {
    for reg in [2, 3] {
        let mut steps = upload_start(reg);
        let mut sig = vec![0x42, 2, 0, 0, 1];
        sig.extend([0xcd; 0x100]);
        let mut info = OK.to_vec();
        info.extend([1, 0, 7, 0, 0, 0, 0x78, 0x56, 0x34, 0x12]);
        steps.extend([
            (vec![0x75], vec![0, 0, 0, 0, 0, 0, 0x59, 0, 0x90, 1]),
            (vec![6, 4, 4], OK.to_vec()),
            (
                vec![
                    0x41, 2, 1, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0xab, 0xab, 0xab, 0xab, 0xab,
                ],
                OK.to_vec(),
            ),
            (vec![0x1a], OK.to_vec()),
            (sig, OK.to_vec()),
            (vec![0x43, 2], info),
            (vec![5, 2, 0], OK.to_vec()),
        ]);
        let mut s = Script(steps.into());
        match upload_fwext(&mut s, &blobs(), Some(&fwext())).unwrap() {
            FwextUpload::Uploaded(fwi) => {
                assert_eq!((fwi.major, fwi.minor, fwi.buildtime), (1, 7, 0x1234_5678));
            }
            FwextUpload::Present(_) => panic!("uploaded expected"),
        }
        s.done();
    }
}

#[test]
fn fwext_upload_stops_on_other_register_values() {
    for reg in [0, 1, 4, 0x8000_0003] {
        let mut s = Script(upload_start(reg).into());
        match upload_fwext(&mut s, &blobs(), Some(&fwext())) {
            Err(Error::Protocol(m)) => assert_eq!(m, format!("unexpected register value {reg:#x}")),
            other => panic!("register {reg:#x}: {other:?}"),
        }
        s.done();
    }
}
