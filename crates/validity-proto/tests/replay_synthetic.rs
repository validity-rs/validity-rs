//! The replay machinery on synthetic logs, written from the survivors of a
//! mutation-testing run: the log parser, `ReplaySensor` (ordering, comparison,
//! statistics, error messages and the handshake checks) and the masks. The logs
//! below are made up in python-validity's debug-log format, and the handshakes
//! sign their sensor key with a test firmware key
//! (`ReplaySensor::with_firmware_key`); nothing comes from a real recording.

use std::ops::Range;

use p256::SecretKey;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point;

use validity_proto::Error;
use validity_proto::db::identity_to_bytes;
use validity_proto::flash::write_flash_cmd;
use validity_proto::pairing::{
    CERT_LEN, ECDH_BLOCK_LEN, FLASH_LAYOUT, make_tls_flash, partition_flash_cmd,
};
use validity_proto::replay::{
    Event, Mask, ReplaySensor, Trace, calibration_from_capture, identity_from_lookup,
    mask_calibration_program, mask_clean_slate, mask_pairing_cert, mask_sealed_key, parse_log,
};
use validity_proto::session::Sensor;
use validity_proto::sid::Sid;
use validity_proto::tables::flash_ic_lookup;
use validity_proto::timeslot::{self, Chunk, merge_chunks};
use validity_proto::tls;

/// Prefixes each line with a `logging` timestamp.
fn log(lines: &[&str]) -> String {
    lines
        .iter()
        .enumerate()
        .map(|(k, l)| format!("2026-01-01 00:00:00,{k:03} {l}\n"))
        .collect()
}

fn replay_msg<T: std::fmt::Debug>(r: Result<T, Error>) -> String {
    match r {
        Err(Error::Replay(m)) => m,
        other => panic!("expected a replay error, got {other:?}"),
    }
}

// ---------------------------------------------------------------- parser

#[test]
fn only_real_timestamps_are_stripped() {
    // The timestamp is `YYYY-MM-DD HH:MM:SS,mmm `; a line that only looks like one
    // is not a log message and is ignored.
    for fake in [
        "2026x01-01 00:00:00,000 >cmd> 3e",
        "2026-01-01x00:00:00,000 >cmd> 3e",
        "2026-01-01 00:00:00x000 >cmd> 3e",
        "2026-01-01 00:00:00,000x>cmd> 3e",
    ] {
        assert_eq!(parse_log(fake).unwrap(), Trace::default(), "{fake}");
    }
    let t = parse_log("2026-01-01 00:00:00,000 >cmd> 3e").unwrap();
    assert_eq!(
        t.events,
        [Event::Plain {
            tx: vec![0x3e],
            rx: None
        }]
    );
    // The `LEVEL:logger:` form.
    let t = parse_log("INFO:validity:RESULT done\nWARNING:x:<int< 05").unwrap();
    assert_eq!(t.results, ["done"]);
    assert_eq!(t.events, [Event::Interrupt(vec![5])]);
}

#[test]
fn parse_errors_name_the_line() {
    let l = log(&["step", ">cmd> 3e", "<cmd< 00zz"]);
    assert_eq!(replay_msg(parse_log(&l)), "log line 3: bad hex");
    let l = log(&[">cmd> 3e", "<cmd< 0000", "<cmd< 0000"]);
    assert_eq!(
        replay_msg(parse_log(&l)),
        "log line 3: reply without command"
    );
}

#[test]
fn a_command_gets_one_reply() {
    // Application command: the second raw reply has no command left to answer.
    let l = log(&[
        ">tls> 17: 4302",
        ">cmd> 1703030001",
        "<cmd< 1703030002",
        "<tls< 17: 0000",
        "<cmd< 1703030003",
    ]);
    assert_eq!(
        replay_msg(parse_log(&l)),
        "log line 5: reply without command"
    );
    // Handshake.
    let l = log(&[">cmd> 44000000", "<cmd< 16", "<cmd< 17"]);
    assert_eq!(
        replay_msg(parse_log(&l)),
        "log line 3: reply without command"
    );
    // One reply each is fine.
    let l = log(&[
        ">tls> 17: 4302",
        ">cmd> 1703030001",
        "<cmd< 1703030002",
        "<tls< 17: 0000",
        "<tls< 17: 01",
    ]);
    assert_eq!(
        parse_log(&l).unwrap().events,
        [Event::App {
            tx: vec![0x43, 2],
            rx: Some(vec![0, 0, 1])
        }]
    );
}

// ---------------------------------------------------------------- sensor

/// Plain 3e (reply 0000aa), a handshake, an interrupt, two bulk reads, an
/// unanswered plain command.
fn trace() -> Trace {
    parse_log(&log(&[
        ">cmd> 3e",
        "<cmd< 0000aa",
        ">cmd> 440000001603030102030405060708090a0b",
        "<cmd< 16",
        "<int< 0201",
        "<130< 6 bytes",
        "<130< Error: timeout",
        ">cmd> 0102030405060708090a0b0c0d",
    ]))
    .unwrap()
}

#[test]
fn remaining_counts_unconsumed_events() {
    let mut r = ReplaySensor::new(&trace());
    assert_eq!(r.remaining(), 6);
    assert!(!r.is_open());
    r.cmd(&[0x3e]).unwrap();
    assert_eq!(r.remaining(), 5);
    // A failed call does not consume the event.
    assert!(r.wait_int().is_err());
    assert_eq!(r.remaining(), 5);
}

#[test]
fn every_event_kind_is_described() {
    let t = trace();
    let next = |n: usize| {
        let mut short = t.clone();
        short.events.drain(..n);
        replay_msg(ReplaySensor::new(&short).finish())
    };
    assert_eq!(
        next(0),
        "event 0: session ended early; next: plain command 3e (1 bytes)"
    );
    assert_eq!(
        next(1),
        "event 0: session ended early; next: handshake 440000001603030102030405… (18 bytes)"
    );
    assert_eq!(
        next(2),
        "event 0: session ended early; next: interrupt 0201"
    );
    assert_eq!(
        next(3),
        "event 0: session ended early; next: bulk read Some(6)"
    );
    assert_eq!(
        next(4),
        "event 0: session ended early; next: bulk read None"
    );
    assert_eq!(
        next(5),
        "event 0: session ended early; next: plain command 0102030405060708090a0b0c… (13 bytes)"
    );
    let app = Trace {
        events: vec![Event::App {
            tx: vec![0x43, 2],
            rx: None,
        }],
        results: vec![],
    };
    assert_eq!(
        replay_msg(ReplaySensor::new(&app).finish()),
        "event 0: session ended early; next: application command 4302 (2 bytes)"
    );
    // An application command while the channel is closed.
    let mut r = ReplaySensor::new(&app);
    assert_eq!(
        replay_msg(r.cmd(&[0x43, 2])),
        "event 0: recording has application command 4302 (2 bytes), we did a plain command 4302"
    );
}

#[test]
fn out_of_order_calls_report_the_recorded_event() {
    let mut r = ReplaySensor::new(&trace());
    r.cmd(&[0x3e]).unwrap();
    let m = replay_msg(r.wait_int());
    assert_eq!(
        m,
        "event 1: recording has handshake 440000001603030102030405… (18 bytes), we did an interrupt wait"
    );
    // The divergence sticks, and the position did not move.
    assert_eq!(replay_msg(r.cmd(&[0x3e])), m);
    assert_eq!(replay_msg(r.finish()), m);
    assert_eq!(r.remaining(), 5);

    let mut r = ReplaySensor::new(&trace());
    assert_eq!(
        replay_msg(r.read_82()),
        "event 0: recording has plain command 3e (1 bytes), we did a bulk read"
    );
}

#[test]
fn statistics() {
    let t = parse_log(&log(&[
        ">cmd> 3e",
        "<cmd< 0000",
        "<int< 0201",
        "<int< 03",
        "<130< 6 bytes",
        "<130< 7 bytes",
        ">cmd> 0102",
        "<cmd< 0000",
    ]))
    .unwrap();
    let mut r = ReplaySensor::new(&t);
    r.cmd(&[0x3e]).unwrap();
    assert_eq!(r.wait_int().unwrap(), [2, 1]);
    assert_eq!(r.wait_int().unwrap(), [3]);
    assert_eq!(r.read_82().unwrap().len(), 6);
    assert_eq!(r.read_82().unwrap().len(), 7);
    r.cmd(&[1, 2]).unwrap();
    let st = r.finish().unwrap();
    assert_eq!(st.exact, 2);
    assert_eq!(st.interrupts, 2);
    assert_eq!(st.bulk_reads, 2);
    assert_eq!(st.bytes_compared, 3);
    assert_eq!(st.bytes_masked, 0);
    assert_eq!(st.handshakes, 0);
    assert!(st.masked.is_empty());
}

#[test]
fn masked_bytes_are_counted() {
    // Clean slate at address 4: every image byte is masked.
    let mut rec = vec![0x41, 6, 1, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 7, 8, 9];
    let mut ours = rec.clone();
    ours[14] = 0;
    let t = Trace {
        events: vec![
            Event::Plain {
                tx: vec![0x3e],
                rx: Some(vec![0, 0]),
            },
            Event::Plain {
                tx: rec.clone(),
                rx: Some(vec![0, 0]),
            },
        ],
        results: vec![],
    };
    let mut r = ReplaySensor::new(&t).with_mask(mask_clean_slate());
    r.cmd(&[0x3e]).unwrap();
    r.cmd(&ours).unwrap();
    let st = r.finish().unwrap();
    assert_eq!(st.exact, 1);
    assert_eq!(st.bytes_compared, 1 + rec.len());
    assert_eq!(st.bytes_masked, 3);
    assert_eq!(st.masked.values().copied().collect::<Vec<_>>(), [1]);

    // Outside the masked bytes: reported at the first differing byte.
    rec[2] = 1;
    let t = Trace {
        events: vec![Event::Plain {
            tx: rec.clone(),
            rx: Some(vec![0, 0]),
        }],
        results: vec![],
    };
    let mut ours = rec.clone();
    ours[3] = 9;
    ours[14] = 0;
    let mut r = ReplaySensor::new(&t).with_mask(mask_clean_slate());
    assert_eq!(
        replay_msg(r.cmd(&ours)),
        "event 0: command differs from the recording at byte 3 \
         (recorded 16 bytes, ours 16): recorded 00000400000003000000070809…, ours 09000400000003000000070009…"
    );
    assert_eq!(r.remaining(), 1);
}

#[test]
fn bulk_reads_are_deterministic_noise() {
    // The stand-in image: an LCG (x = x * 1103515245 + 12345 from 0x12345678),
    // byte = bits 16-23.
    let t = parse_log(&log(&["<130< 8 bytes"])).unwrap();
    let mut r = ReplaySensor::new(&t);
    let img = r.read_82().unwrap();
    let mut x = 0x1234_5678u32;
    let want: Vec<u8> = (0..8)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (x >> 16) as u8
        })
        .collect();
    assert_eq!(img, want);
    assert!(img.iter().any(|&b| b != 0));
}

/// A sensor ECDH key block (TLS flash block 6) holding a valid point, signed by
/// `signer`.
fn ecdh_block(signer: &SigningKey) -> Vec<u8> {
    let le = |b: &[u8]| b.iter().rev().copied().collect::<Vec<u8>>();
    let sensor = SecretKey::from_slice(&[7; 32]).unwrap().public_key();
    let p = sensor.to_sec1_point(false);
    let mut k = vec![0u8; 0x90];
    k[0x08..0x28].copy_from_slice(&le(&p.as_bytes()[1..33]));
    k[0x4c..0x6c].copy_from_slice(&le(&p.as_bytes()[33..65]));
    let sig: DerSignature = signer.sign(&k);
    k.extend((sig.as_bytes().len() as u32).to_le_bytes());
    k.extend(sig.as_bytes());
    k.resize(ECDH_BLOCK_LEN, 0);
    k
}

/// The firmware key of the synthetic recordings (stands in for the vendor's).
fn test_fw() -> SigningKey {
    SigningKey::from_slice(&[0x5f; 32]).unwrap()
}

/// A TLS partition image whose ECDH block is not signed by the firmware key
/// (neither the vendor's nor the test one).
fn unsigned_tls_flash() -> Vec<u8> {
    let not_fw = SigningKey::from_slice(&[9; 32]).unwrap();
    make_tls_flash(&[4; 0x70], &[3; CERT_LEN], &ecdh_block(&not_fw)).unwrap()
}

#[test]
fn handshake_checks_the_tls_image_first() {
    let t = parse_log(&log(&[">cmd> 44000000", "<cmd< 16"])).unwrap();
    // The certificate block (3) is required.
    let mut img = unsigned_tls_flash();
    let blocks: Vec<(u16, Vec<u8>)> = validity_proto::pairing::tls_flash_blocks(&img)
        .unwrap()
        .into_iter()
        .map(|(i, b)| (i, b.to_vec()))
        .collect();
    let without_cert: Vec<u8> = blocks
        .iter()
        .filter(|(i, _)| *i != 3)
        .flat_map(|(i, b)| tls::flash_block(*i, b))
        .collect();
    let mut r = ReplaySensor::new(&t);
    assert_eq!(
        replay_msg(r.open_channel(&without_cert)),
        "TLS flash image without block 3"
    );
    // Block 6 (the sensor key) must verify under the firmware key: the block is
    // found, its key parses, and its signature is rejected.
    let mut r = ReplaySensor::new(&t);
    let e = r.open_channel(&img).unwrap_err();
    assert!(
        matches!(
            e,
            Error::Channel(validity_proto::channel::Error::BadEcdhSignature)
        ),
        "{e:?}"
    );
    assert!(!r.is_open());
    assert_eq!(r.remaining(), 1);
    // A block 6 too short to hold a key is a length error, not a signature error.
    img = blocks
        .iter()
        .flat_map(|(i, b)| {
            if *i == 6 {
                tls::flash_block(6, &b[..0x93])
            } else {
                tls::flash_block(*i, b)
            }
        })
        .collect();
    let short = ReplaySensor::new(&t).open_channel(&img).unwrap_err();
    assert_ne!(format!("{short}"), format!("{e}"));
}

// ---------------------------------------------------------------- masks

fn ranges(m: &Mask, tx: &[u8]) -> Option<Vec<Range<usize>>> {
    (m.ranges)(tx)
}

fn one(r: Range<usize>) -> Vec<Range<usize>> {
    vec![r]
}

#[test]
fn pairing_cert_mask() {
    let m = mask_pairing_cert();
    let ic = flash_ic_lookup(0xef, 0x40, 0x100000).unwrap();
    let a = partition_flash_cmd(ic, &FLASH_LAYOUT, &[1; 256], &[2; CERT_LEN]);
    // The certificate is the block before the 4 + 420 byte curve block.
    let body = a.len() - (4 + 420) - CERT_LEN;
    assert_eq!(a[body - 4..body - 2], 5u16.to_le_bytes());
    assert_eq!(
        ranges(&m, &a).unwrap(),
        [
            body + 8..body + 40,
            body + 76..body + 108,
            body + 184..body + CERT_LEN
        ]
    );
    // Not a pairing command.
    assert_eq!(ranges(&m, &[0x4e, 0, 0, 0, 0, 5, 0, 0xbc, 1]), None);
    // A block 5 of another length, a block of certificate length with another id.
    let blk = |id: u16, len: usize| {
        let mut b = id.to_le_bytes().to_vec();
        b.extend((len as u16).to_le_bytes());
        b.extend(vec![0; len]);
        b
    };
    let cmd = |blocks: &[Vec<u8>]| [vec![0x4f, 0, 0, 0, 0], blocks.concat()].concat();
    assert_eq!(ranges(&m, &cmd(&[blk(5, 4)])), None);
    assert_eq!(ranges(&m, &cmd(&[blk(3, CERT_LEN)])), None);
    assert_eq!(
        ranges(&m, &cmd(&[blk(1, 0), blk(5, CERT_LEN)])).unwrap()[0],
        21..53
    );
    // Trailing bytes too short for a block header.
    assert_eq!(ranges(&m, &cmd(&[blk(1, 0), vec![5, 0, 0xbc]])), None);
    assert_eq!(ranges(&m, &[0x4f, 0, 0, 0, 0, 5, 0, 0xbc]), None);
}

#[test]
fn sealed_key_mask() {
    let m = mask_sealed_key();
    let img = unsigned_tls_flash();
    let tx = write_flash_cmd(1, 0, &img);
    // Block 0 (one byte) comes first, then block 4: its hash and body are masked.
    let at = 13 + 36 + 1;
    assert_eq!(img[at - 13..at - 11], 4u16.to_le_bytes());
    assert_eq!(ranges(&m, &tx).unwrap(), one(at + 4..at + 36 + 0x70));
    // Other partitions, other addresses, other commands.
    assert_eq!(ranges(&m, &write_flash_cmd(2, 0, &img)), None);
    assert_eq!(ranges(&m, &write_flash_cmd(1, 0x1000, &img)), None);
    assert_eq!(
        ranges(&m, &[0x40, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        None
    );
    // The end marker stops the scan before a later block 4.
    let mut img2 = tls::flash_block(1, &[0; 3]);
    img2.extend([0xff; 36]);
    img2.extend(tls::flash_block(4, &[9; 5]));
    assert_eq!(ranges(&m, &write_flash_cmd(1, 0, &img2)), None);
    // Without the marker, a block 4 after another block is found.
    let mut img3 = tls::flash_block(1, &[0; 3]);
    img3.extend(tls::flash_block(4, &[9; 5]));
    assert_eq!(
        ranges(&m, &write_flash_cmd(1, 0, &img3)).unwrap(),
        one(13 + 39 + 4..13 + 39 + 36 + 5)
    );
    // No block 4; a last block cut short; less than a block header.
    let img4 = tls::flash_block(1, &[0; 4]);
    assert_eq!(ranges(&m, &write_flash_cmd(1, 0, &img4)), None);
    assert_eq!(
        ranges(
            &m,
            &write_flash_cmd(1, 0, &tls::flash_block(4, &[1; 8])[..35])
        ),
        None
    );
    assert_eq!(ranges(&m, &write_flash_cmd(1, 0, &[4, 0, 0, 0])), None);
}

#[test]
fn calibration_program_mask() {
    let m = mask_calibration_program(8);
    let mut lu = 2u32.to_le_bytes().to_vec();
    lu.extend([0xaa; 16]); // two line headers
    lu.extend([0xbb; 12]); // line data
    let chunks = [
        Chunk::new(0x17, [1, 2, 3]),
        Chunk::new(timeslot::CHUNK_TIMESLOT_TABLE_2D, [0x11; 20]),
        Chunk::new(timeslot::CHUNK_LINE_UPDATE, lu),
        Chunk::new(timeslot::CHUNK_TIMESLOT_TABLE_2D, [0x22; 5]),
        Chunk::new(timeslot::CHUNK_LINE_UPDATE, [7, 7]),
    ];
    let mut tx = vec![0x02, 0x78, 0, 0, 0];
    tx.extend(merge_chunks(&chunks));
    // Chunk bodies start at 5 + 4 + 3 + 4 = 16, then 16 + 20 + 4 = 40, then
    // 40 + 32 + 4 = 76; a short line update (2 bytes, no count) adds nothing.
    assert_eq!(
        ranges(&m, &tx).unwrap(),
        [16..24, 40 + 4 + 16..40 + 32, 76..81]
    );
    // A line update with no line data.
    let mut tx2 = vec![0x02, 0, 0, 0, 0];
    tx2.extend(merge_chunks(&[Chunk::new(
        timeslot::CHUNK_LINE_UPDATE,
        [0, 0, 0, 0],
    )]));
    assert_eq!(ranges(&m, &tx2).unwrap(), one(13..13));
    // Header boundaries: a capture command has at least 5 bytes.
    assert_eq!(ranges(&m, &[0x02]), None);
    assert_eq!(ranges(&m, &[0x02, 0, 0, 0]), None);
    assert_eq!(ranges(&m, &[0x02, 0, 0, 0, 0]).unwrap(), []);
    assert_eq!(ranges(&m, &[0x02, 0, 0, 0, 0, 0x34, 0, 0]).unwrap(), []);
    assert_eq!(ranges(&m, &[0x03, 0, 0, 0, 0, 0, 0, 0, 0]), None);
}

#[test]
fn clean_slate_mask() {
    let m = mask_clean_slate();
    let mut at0 = vec![0x41, 6, 1, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0];
    at0.extend([0; 0x50]);
    assert_eq!(
        ranges(&m, &at0).unwrap(),
        [13 + 4..13 + 0x24, 13 + 0x46..13 + 0x50]
    );
    let later = [0x41, 6, 1, 0, 0, 0, 0x10, 0, 0, 2, 0, 0, 0, 1, 2];
    assert_eq!(ranges(&m, &later).unwrap(), one(13..15));
    // Exactly a header, no data.
    let header = [0x41, 6, 1, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0];
    assert_eq!(ranges(&m, &header).unwrap(), one(13..13));
    // One byte short of a header.
    assert_eq!(ranges(&m, &header[..12]), None);
    // Another partition.
    let mut p1 = later.to_vec();
    p1[1] = 1;
    assert_eq!(ranges(&m, &p1), None);
}

// ---------------------------------------------------------------- helpers

#[test]
fn calibration_lines_with_a_count_of_one_are_direct() {
    // A line update entry is in the transform chunk only when its count field
    // (bits 20-23) is above 1; count 1 carries its data in the line update.
    let (lines, bpl) = (2, 16);
    let mut lu = 1u32.to_le_bytes().to_vec();
    lu.extend(0xffff_ffffu32.to_le_bytes());
    lu.extend((4u32 | 1 << 20 | 0x85 << 24).to_le_bytes());
    lu.extend([1, 2, 3, 4, 5, 6, 7, 8]);
    let mut c = vec![2, 0, 0, 0, 0];
    c.extend(merge_chunks(&[Chunk::new(timeslot::CHUNK_LINE_UPDATE, lu)]));
    let mut want = vec![0; lines * bpl];
    want[12..16].copy_from_slice(&[1, 2, 3, 4]);
    want[28..32].copy_from_slice(&[5, 6, 7, 8]);
    assert_eq!(calibration_from_capture(&c, lines, bpl).unwrap(), want);
}

#[test]
fn identity_lookup_needs_the_command_and_its_zero_word() {
    let sid: Sid = "S-1-5-21-9-8-7-1000".parse().unwrap();
    let lookup = |head: [u8; 3]| {
        let mut tx = head.to_vec();
        tx.extend([3, 0, 0x4c, 0]);
        tx.extend(identity_to_bytes(&sid));
        tx
    };
    assert_eq!(identity_from_lookup(&lookup([0x4a, 0, 0])).unwrap(), sid);
    for head in [[0x4b, 0, 0], [0x4a, 1, 0], [0x4a, 0, 1]] {
        assert!(matches!(
            identity_from_lookup(&lookup(head)),
            Err(Error::Malformed("not a user lookup"))
        ));
    }
}

// ---------------------------------------------------------------- handshakes

const CERT: [u8; CERT_LEN] = [0x3c; CERT_LEN];

/// TLS image with the test firmware key's signature on the sensor key.
fn signed_tls_flash() -> Vec<u8> {
    make_tls_flash(&[4; 0x70], &CERT, &ecdh_block(&test_fw())).unwrap()
}

/// `44000000 || record(ClientHello)`, as our channel would send it.
fn client_hello() -> Vec<u8> {
    let mut h = vec![0x44, 0, 0, 0];
    h.extend(tls::record(
        tls::CONTENT_HANDSHAKE,
        &tls::client_hello(&[0x21; 32]),
    ));
    h
}

/// The Certificate message carrying `cert`.
fn cert_msg(cert: &[u8]) -> Vec<u8> {
    let l = (cert.len() as u16).to_be_bytes();
    let mut body = vec![0, l[0], l[1], 0, l[0], l[1], 0xac, 0x16];
    body.extend(cert);
    tls::handshake_msg(0x0b, &body)
}

fn be24(n: usize) -> [u8; 3] {
    [(n >> 16) as u8, (n >> 8) as u8, n as u8]
}

/// The second client handshake message, field by field, so each check can be
/// broken on its own.
#[derive(Clone)]
struct Second {
    record: [u8; 3],
    cert: Vec<u8>,
    kex_type: u8,
    /// Length field of the ClientKeyExchange, whose body is that many bytes
    /// starting with `point`.
    kex_len: usize,
    point: u8,
    verify_type: u8,
    /// Length field of the CertificateVerify, and its actual body length.
    verify_len: usize,
    verify_body: usize,
    /// ChangeCipherSpec and the encrypted Finished record.
    rest: Vec<u8>,
}

impl Second {
    fn ok() -> Self {
        let mut rest = vec![tls::CONTENT_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1];
        rest.extend([tls::CONTENT_HANDSHAKE, 3, 3, 0, 80]);
        rest.extend([0x99; 80]);
        Second {
            record: [tls::CONTENT_HANDSHAKE, 3, 3],
            cert: CERT.to_vec(),
            kex_type: 0x10,
            kex_len: 65,
            point: 4,
            verify_type: 0x0f,
            verify_len: 72,
            verify_body: 72,
            rest,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut hs = cert_msg(&self.cert);
        hs.push(self.kex_type);
        hs.extend(be24(self.kex_len));
        hs.push(self.point);
        hs.extend(vec![0x77; self.kex_len - 1]);
        hs.push(self.verify_type);
        hs.extend(be24(self.verify_len));
        hs.extend(vec![0x88; self.verify_body]);
        let mut b = vec![0x44, 0, 0, 0];
        b.extend(self.record);
        b.extend((hs.len() as u16).to_be_bytes());
        b.extend(hs);
        b.extend(&self.rest);
        b
    }
}

/// A recording of the two handshake exchanges and one application command.
fn handshake_trace(second: &Second) -> Trace {
    Trace {
        events: vec![
            Event::Handshake {
                tx: client_hello(),
                rx: Some(vec![0x16, 3, 3]),
            },
            Event::Handshake {
                tx: second.bytes(),
                rx: Some(vec![0x14, 3, 3]),
            },
            Event::App {
                tx: vec![0x01],
                rx: Some(vec![0, 0, 9]),
            },
        ],
        results: vec![],
    }
}

fn replay(second: &Second) -> ReplaySensor {
    ReplaySensor::new(&handshake_trace(second)).with_firmware_key(*test_fw().verifying_key())
}

#[test]
fn a_synthetic_handshake_is_accepted() {
    let mut r = replay(&Second::ok());
    assert!(!r.is_open());
    r.open_channel(&signed_tls_flash()).unwrap();
    assert!(r.is_open());
    assert_eq!(r.remaining(), 1);
    // Over the open channel, application commands follow.
    assert_eq!(r.app(&[0x01]).unwrap(), [0, 0, 9]);
    let st = r.finish().unwrap();
    assert_eq!(st.handshakes, 1);
    // The ClientHello is compared whole, then the application command; of the
    // second message, the record header and the certificate.
    assert_eq!(st.exact, 2);
    assert_eq!(
        st.bytes_compared,
        client_hello().len() + 9 + cert_msg(&CERT).len() + 1
    );
}

#[test]
fn the_vendor_key_is_the_default() {
    // The same recording without the test key: the sensor key does not verify.
    let mut r = ReplaySensor::new(&handshake_trace(&Second::ok()));
    assert!(matches!(
        r.open_channel(&signed_tls_flash()),
        Err(Error::Channel(
            validity_proto::channel::Error::BadEcdhSignature
        ))
    ));
    assert_eq!(r.remaining(), 3);
    // And a key signed by neither is refused under the test key too.
    let mut r = replay(&Second::ok());
    assert!(matches!(
        r.open_channel(&unsigned_tls_flash()),
        Err(Error::Channel(
            validity_proto::channel::Error::BadEcdhSignature
        ))
    ));
}

#[test]
fn the_client_hello_is_rebuilt_from_its_random() {
    let mut t = handshake_trace(&Second::ok());
    // Another cipher suite list: same random, different bytes.
    let Event::Handshake { tx, .. } = &mut t.events[0] else {
        unreachable!()
    };
    let last = tx.len() - 2;
    tx[last] ^= 1;
    let mut r = ReplaySensor::new(&t).with_firmware_key(*test_fw().verifying_key());
    let m = replay_msg(r.open_channel(&signed_tls_flash()));
    assert!(m.starts_with("event 0: command differs"), "{m}");
    // Too short to hold a random.
    let Event::Handshake { tx, .. } = &mut t.events[0] else {
        unreachable!()
    };
    tx.truncate(46);
    let mut r = ReplaySensor::new(&t).with_firmware_key(*test_fw().verifying_key());
    assert!(matches!(
        r.open_channel(&signed_tls_flash()),
        Err(Error::Malformed("short ClientHello"))
    ));
}

/// Opens with `second`; `Ok` or the reason it was refused.
fn open_with(second: &Second) -> Result<(), String> {
    let mut r = replay(second);
    match r.open_channel(&signed_tls_flash()) {
        Ok(()) => {
            assert!(r.is_open());
            Ok(())
        }
        Err(e) => {
            let m = replay_msg::<()>(Err(e));
            // The second message is not consumed, and the divergence sticks.
            assert_eq!(r.remaining(), 2);
            assert!(!r.is_open());
            assert_eq!(replay_msg(r.finish()), m);
            assert_eq!(r.stats.handshakes, 0);
            Err(m)
        }
    }
}

const REFUSED: &str = "event 1: second handshake message does not carry our certificate";

#[test]
fn the_second_message_must_carry_our_certificate() {
    let ok = Second::ok();
    assert_eq!(open_with(&ok), Ok(()));
    let refused = |f: &dyn Fn(&mut Second)| {
        let mut s = ok.clone();
        f(&mut s);
        assert_eq!(open_with(&s), Err(REFUSED.to_string()));
    };
    // Another certificate, or a certificate of another length.
    refused(&|s| s.cert[100] ^= 1);
    refused(&|s| s.cert.push(0));
    // The record is not a TLS 1.2 handshake record.
    refused(&|s| s.record = [tls::CONTENT_APP_DATA, 3, 3]);
    refused(&|s| s.record = [tls::CONTENT_HANDSHAKE, 3, 1]);
    refused(&|s| s.record = [tls::CONTENT_HANDSHAKE, 2, 3]);
}

#[test]
fn the_key_exchange_is_an_uncompressed_point() {
    let ok = Second::ok();
    let with = |f: &dyn Fn(&mut Second)| {
        let mut s = ok.clone();
        f(&mut s);
        open_with(&s)
    };
    // python-validity drops leading zero bytes of the coordinates: up to 65 bytes.
    assert_eq!(with(&|s| s.kex_len = 64), Ok(()));
    assert_eq!(with(&|s| s.kex_len = 60), Ok(()));
    assert_eq!(with(&|s| s.kex_len = 66), Err(REFUSED.into()));
    assert_eq!(with(&|s| s.kex_type = 0x11), Err(REFUSED.into()));
    assert_eq!(with(&|s| s.point = 2), Err(REFUSED.into()));
}

#[test]
fn the_certificate_verify_fills_the_record() {
    let ok = Second::ok();
    let with = |f: &dyn Fn(&mut Second)| {
        let mut s = ok.clone();
        f(&mut s);
        open_with(&s)
    };
    assert_eq!(with(&|s| s.verify_len = s.verify_body), Ok(()));
    assert_eq!(with(&|s| s.verify_type = 0x0e), Err(REFUSED.into()));
    // A byte more, or less, than its length says.
    assert_eq!(with(&|s| s.verify_body += 1), Err(REFUSED.into()));
    assert_eq!(with(&|s| s.verify_body -= 1), Err(REFUSED.into()));
    // Other lengths are fine when consistent.
    assert_eq!(
        with(&|s| {
            s.verify_len = 70;
            s.verify_body = 70;
        }),
        Ok(())
    );
}

#[test]
fn the_finished_record_follows_a_change_cipher_spec() {
    let ok = Second::ok();
    let with = |f: &dyn Fn(&mut Second)| {
        let mut s = ok.clone();
        f(&mut s);
        open_with(&s)
    };
    // ChangeCipherSpec, then 80 bytes of encrypted Finished: 91 bytes.
    assert_eq!(ok.rest.len(), 91);
    assert_eq!(
        with(&|s| s.rest[0] = tls::CONTENT_HANDSHAKE),
        Err(REFUSED.into())
    );
    assert_eq!(with(&|s| s.rest[5] = 0), Err(REFUSED.into()));
    assert_eq!(
        with(&|s| s.rest[6] = tls::CONTENT_APP_DATA),
        Err(REFUSED.into())
    );
    assert_eq!(with(&|s| s.rest.push(0)), Err(REFUSED.into()));
    assert_eq!(
        with(&|s| {
            s.rest.pop();
        }),
        Err(REFUSED.into())
    );
    assert_eq!(with(&|s| s.rest.clear()), Err(REFUSED.into()));
}

#[test]
fn a_handshake_is_expected_where_the_recording_has_one() {
    let mut t = handshake_trace(&Second::ok());
    t.events[1] = Event::Interrupt(vec![1]);
    let mut r = ReplaySensor::new(&t).with_firmware_key(*test_fw().verifying_key());
    assert_eq!(
        replay_msg(r.open_channel(&signed_tls_flash())),
        "event 1: recording has interrupt 01, we did a handshake"
    );
    assert_eq!(r.remaining(), 2);
}
