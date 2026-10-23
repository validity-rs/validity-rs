//! Protocol functions checked byte-exact against python-validity on synthetic
//! inputs (`tools/oracle/gen_proto_vectors.py` -> `vectors/proto.json`).

use std::collections::BTreeMap;

use p256::SecretKey;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use validity_proto::calibration;
use validity_proto::db;
use validity_proto::flash::{parse_flash_info, parse_fw_info};
use validity_proto::hex;
use validity_proto::pairing;
use validity_proto::scanner::{
    CaptureMode, Identified, RomInfo, Scanner, parse_enrollment_update, parse_factory_bits,
    patch_timeslot_again, patch_timeslot_table,
};
use validity_proto::sid::Sid;
use validity_proto::tables::{SensorCaptureProg, SensorTypeInfo, dev_info_lookup, flash_ic_lookup};
use validity_proto::timeslot::{self, Insn, decode_insn, find_nth_insn, find_nth_regwrite};
use validity_proto::tls::{self, PskKeys};
use validity_proto::vendor::Blobs;
use validity_proto::{Error, Sensor};

fn v() -> Value {
    serde_json::from_str(include_str!("vectors/proto.json")).unwrap()
}

fn b(x: &Value) -> Vec<u8> {
    hex::decode(x.as_str().unwrap()).unwrap()
}

fn u(x: &Value) -> u64 {
    x.as_u64().unwrap()
}

/// `{len, sha256, head}` of a large byte string.
fn check_big(want: &Value, got: &[u8], what: &str) {
    assert_eq!(got.len() as u64, u(&want["len"]), "{what}: length");
    assert_eq!(
        hex::encode(&got[..got.len().min(32)]),
        want["head"].as_str().unwrap(),
        "{what}: head"
    );
    assert_eq!(
        hex::encode(&Sha256::digest(got)),
        want["sha256"].as_str().unwrap(),
        "{what}: sha256"
    );
}

/// python's `det(tag, n)`: SHA-256 of `tag-i` blocks.
fn det(tag: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while out.len() < n {
        out.extend(Sha256::digest(format!("{tag}-{i}")));
        i += 1;
    }
    out.truncate(n);
    out
}

const WEN: [u8; 3] = [6, 4, 4];

fn blobs() -> Blobs {
    Blobs {
        init_hardcoded: vec![],
        init_hardcoded_clean_slate: vec![],
        reset_blob: vec![],
        db_write_enable: WEN.to_vec(),
        partition_signature: vec![],
    }
}

/// Mirrors the oracle's mock: records commands, answers like a blank sensor.
struct Mock {
    sent: Vec<Vec<u8>>,
    flash6: Vec<u8>,
    frames: usize,
    sensor_type: u16,
    frame_len: usize,
    replies: BTreeMap<u8, Vec<u8>>,
    ints: Vec<Vec<u8>>,
}

impl Mock {
    fn new(sensor_type: u16, frame_len: usize) -> Self {
        Mock {
            sent: vec![],
            flash6: vec![0xff; 0x8000],
            frames: 0,
            sensor_type,
            frame_len,
            replies: BTreeMap::new(),
            ints: vec![],
        }
    }
}

impl Sensor for Mock {
    fn cmd(&mut self, c: &[u8]) -> Result<Vec<u8>, Error> {
        self.sent.push(c.to_vec());
        let le = |o: usize| u32::from_le_bytes(c[o..o + 4].try_into().unwrap()) as usize;
        Ok(match c[0] {
            0x40 => {
                let (part, addr, size) = (c[1], le(5), le(9));
                let data = if part == 6 {
                    self.flash6[addr..addr + size].to_vec()
                } else {
                    vec![0xff; size]
                };
                let mut r = vec![0, 0];
                r.extend((data.len() as u32).to_le_bytes());
                r.extend([0, 0]);
                r.extend(data);
                r
            }
            0x41 => {
                let (part, addr, size) = (c[1], le(5), le(9));
                if part == 6 {
                    self.flash6[addr..addr + size].copy_from_slice(&c[13..13 + size]);
                }
                let mut r = vec![0, 0];
                r.extend((size as u32).to_le_bytes());
                r
            }
            k => self.replies.get(&k).cloned().unwrap_or(vec![0, 0]),
        })
    }
    fn is_open(&self) -> bool {
        true
    }
    fn open_channel(&mut self, _: &[u8]) -> Result<(), Error> {
        unreachable!()
    }
    fn wait_int(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.ints.remove(0))
    }
    fn read_82(&mut self) -> Result<Vec<u8>, Error> {
        self.frames += 1;
        Ok(det(
            &format!("frame{:x}-{}", self.sensor_type, self.frames),
            self.frame_len,
        ))
    }
}

fn scanner(c: &Value) -> Scanner {
    let device = dev_info_lookup(u(&c["major"]) as u16, u(&c["version"]) as u16).unwrap();
    let type_info = SensorTypeInfo::get(device.sensor_type).unwrap();
    let rom = RomInfo {
        timestamp: 0,
        build: 0x56,
        major: 6,
        minor: 8,
        product: 0x30,
        u1: 0,
    };
    let program = SensorCaptureProg::get(&rom, device.sensor_type, 0x18, 0x19).unwrap();
    let lines_2d = timeslot::split_chunks(&program)
        .unwrap()
        .iter()
        .find(|c| c.kind == timeslot::CHUNK_2D)
        .map(|c| u32::from_le_bytes(c.value[..4].try_into().unwrap()))
        .unwrap();
    Scanner {
        device,
        type_info,
        rom,
        key_calibration_line: u(&c["key_line"]) as usize,
        calibration_frames: u(&c["frames"]) as usize,
        calibration_iterations: u(&c["iterations"]) as usize,
        program,
        lines_per_frame: lines_2d as usize * type_info.repeat_multiplier as usize,
        bytes_per_line: type_info.bytes_per_line as usize,
        factory_calibration_values: b(&c["factory_values"]),
        factory_calib_data: c["factory_calib_data"]
            .as_str()
            .map(|x| hex::decode(x).unwrap()),
        calib_data: vec![],
        calibrated: false,
    }
}

#[test]
fn timeslot_decoding() {
    let v = v();
    for d in v["decode_insn"].as_array().unwrap() {
        let op = u(&d["op"]) as u8;
        let r = decode_insn(&[op, 0x5a, 0]);
        if d.get("error").is_some() {
            assert!(r.is_err(), "op {op:02x}");
            continue;
        }
        let (insn, len) = r.unwrap();
        let args: Vec<u64> = match insn {
            Insn::Macro(x) | Insn::EnableRx(x) | Insn::Interrupt(x) | Insn::Features(x) => {
                vec![x as u64]
            }
            Insn::IdleRx(x) | Insn::EnableSo(x) | Insn::DisableSo(x) => vec![x as u64],
            Insn::Call {
                rx_inc,
                addr,
                repeat,
            } => vec![rx_inc as u64, addr as u64, repeat as u64],
            Insn::RegWrite { addr, value } => vec![addr as u64, value as u64],
            Insn::Sample(a, b) => vec![a as u64, b as u64],
            Insn::SampleRepeat(a, b, r) => vec![a as u64, b as u64, r as u64],
            _ => vec![],
        };
        assert_eq!(insn.opcode() as u64, u(&d["opcode"]), "op {op:02x}");
        assert_eq!(len as u64, u(&d["len"]), "op {op:02x}");
        let want: Vec<u64> = d["args"].as_array().unwrap().iter().map(u).collect();
        assert_eq!(args, want, "op {op:02x}");
    }
}

#[test]
fn timeslot_patching() {
    let v = v();
    for t in v["patch_timeslot_table"].as_array().unwrap() {
        let out = patch_timeslot_table(
            &b(&t["in"]),
            t["inc"].as_bool().unwrap(),
            u(&t["mult"]) as u8,
        )
        .unwrap();
        assert_eq!(out, b(&t["out"]));
    }
    let a = &v["patch_timeslot_again"];
    assert_eq!(
        patch_timeslot_again(&b(&a["in"]), u(&a["value"]) as u8).unwrap(),
        b(&a["out"])
    );
    let f = &v["find"];
    let t = b(&f["table"]);
    assert_eq!(
        find_nth_insn(&t, 6, 1).unwrap(),
        Some(u(&f["enable_rx_1"]) as usize)
    );
    assert_eq!(
        find_nth_insn(&t, 6, 2).unwrap(),
        Some(u(&f["enable_rx_2"]) as usize)
    );
    assert_eq!(
        find_nth_regwrite(&t, 0x8000_203c, 2).unwrap(),
        Some(u(&f["write_203c_2"]) as usize)
    );
}

#[test]
fn calibration_arithmetic() {
    let v = v();
    for (x, want) in v["scale"].as_array().unwrap().iter().enumerate() {
        assert_eq!(calibration::scale(x as u8) as u64, u(want), "scale({x})");
    }
    for t in v["add"].as_array().unwrap() {
        let t = t.as_array().unwrap();
        assert_eq!(
            calibration::add(u(&t[0]) as u8, u(&t[1]) as u8) as u64,
            u(&t[2])
        );
    }
    for t in v["bitpack"].as_array().unwrap() {
        let (bits, min, out) = calibration::bitpack(&b(&t["in"])).unwrap();
        assert_eq!((bits as u64, min as u64), (u(&t["u"]), u(&t["min"])));
        assert_eq!(out, b(&t["out"]));
    }
}

/// A whole calibration on synthetic image data, then the capture programs built
/// from the result: every command and the calibration data match the reference.
#[test]
fn calibration_sessions_and_capture_programs() {
    let v = v();
    for c in v["calibration_sessions"].as_array().unwrap() {
        let mut sc = scanner(c);
        assert_eq!(sc.lines_per_frame as u64, u(&c["lines_per_frame"]));
        check_big(
            &c["identify_uncalibrated"],
            &sc.build_cmd_02(CaptureMode::Identify).unwrap(),
            "uncalibrated",
        );
        let mut m = Mock::new(sc.device.sensor_type, u(&c["frame_len"]) as usize);
        sc.calibrate(&mut m, &blobs(), None).unwrap();
        let sent = c["sent"].as_array().unwrap();
        assert_eq!(m.sent.len(), sent.len());
        for (i, (got, want)) in m.sent.iter().zip(sent).enumerate() {
            check_big(
                want,
                got,
                &format!("{:#x} command {i}", sc.device.sensor_type),
            );
        }
        check_big(&c["calib_data"], &sc.calib_data, "calibration data");
        assert!(sc.calibrated);
        check_big(
            &c["identify"],
            &sc.build_cmd_02(CaptureMode::Identify).unwrap(),
            "identify",
        );
        check_big(
            &c["enroll"],
            &sc.build_cmd_02(CaptureMode::Enroll).unwrap(),
            "enroll",
        );
        check_big(
            &c["calibrate"],
            &sc.build_cmd_02(CaptureMode::Calibrate).unwrap(),
            "calibrate",
        );

        // The clean slate written is accepted on the next session.
        assert!(sc.check_clean_slate(&mut m).unwrap());
    }
}

#[test]
fn pairing_material() {
    let v = v();
    let p = &v["pairing"];
    let psk = PskKeys::from_hw(
        p["product"].as_str().unwrap(),
        p["serial"].as_str().unwrap(),
    );
    let key = SecretKey::from_slice(&b(&p["d"])).unwrap();
    let iv: [u8; 16] = b(&p["iv"]).try_into().unwrap();
    assert_eq!(pairing::encrypt_key(&key, &psk, &iv), b(&p["priv_blob"]));

    // The reference signs with a random nonce: compare the message, and check that
    // its signature verifies under the same handshake key as ours.
    let theirs = b(&p["cert"]);
    let ours = pairing::make_cert(&key.public_key());
    assert_eq!(ours.len(), theirs.len());
    assert_eq!(&ours[..184], &theirs[..184]);
    let hs = VerifyingKey::from(&SigningKey::from_slice(&tls::hs_key()).unwrap());
    let l = u32::from_le_bytes(theirs[184..188].try_into().unwrap()) as usize;
    hs.verify(
        &theirs[..184],
        &DerSignature::from_bytes(&theirs[188..188 + l]).unwrap(),
    )
    .unwrap();
    assert!(theirs[188 + l..].iter().all(|&x| x == 0));

    let ic = flash_ic_lookup(0xef, 0x40, 0x100000).unwrap();
    assert_eq!(
        pairing::serialize_flash_params(ic).to_vec(),
        b(&p["flash_params"])
    );
    assert_eq!(
        pairing::partition_flash_cmd(
            ic,
            &pairing::FLASH_LAYOUT,
            &b(&p["partition_signature"]),
            &theirs
        ),
        b(&p["partition_cmd"])
    );
    assert_eq!(pairing::curve_block(), b(&p["crt_hardcoded"]));
    assert_eq!(
        pairing::make_tls_flash(
            &b(&p["priv_blob"]),
            &b(&p["host_cert"]),
            &b(&p["ecdh_blob"])
        )
        .unwrap(),
        b(&p["tls_flash"])
    );
}

#[test]
fn database_records() {
    let v = v();
    let d = &v["db"];
    let sid: Sid = d["sid"].as_str().unwrap().parse().unwrap();
    assert_eq!(sid.to_string(), d["sid"].as_str().unwrap());
    assert_eq!(sid.to_bytes(), b(&d["sid_bytes"]));
    assert_eq!(
        Sid::from_bytes(&b(&d["sid_bytes"])).unwrap().to_string(),
        d["sid_round_trip"].as_str().unwrap()
    );
    assert_eq!(db::identity_to_bytes(&sid), b(&d["identity"]));

    let st = db::parse_user_storage(&b(&d["storage_reply"]))
        .unwrap()
        .unwrap();
    assert_eq!(st.dbid as u64, u(&d["storage"]["dbid"]));
    assert_eq!(st.name, b(&d["storage"]["name"]));
    let users: Vec<(u64, u64)> = d["storage"]["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| (u(&x["dbid"]), u(&x["valueSize"])))
        .collect();
    assert_eq!(
        st.users
            .iter()
            .map(|x| (x.dbid as u64, x.value_size as u64))
            .collect::<Vec<_>>(),
        users
    );

    let user = db::parse_user(&b(&d["user_reply"])).unwrap();
    assert_eq!(user.dbid as u64, u(&d["user"]["dbid"]));
    assert_eq!(
        user.identity.to_string(),
        d["user"]["identity"].as_str().unwrap()
    );
    let fingers: Vec<[u64; 4]> = d["user"]["fingers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            [
                u(&f["dbid"]),
                u(&f["subtype"]),
                u(&f["storage"]),
                u(&f["valueSize"]),
            ]
        })
        .collect();
    assert_eq!(
        user.fingers
            .iter()
            .map(|f| [
                f.dbid as u64,
                f.subtype as u64,
                f.storage as u64,
                f.value_size as u64
            ])
            .collect::<Vec<_>>(),
        fingers
    );

    assert_eq!(
        db::make_finger_data(7, &det("template", 300), &det("tid", 32)),
        b(&d["finger_data"])
    );

    // Record creation: the same command sequence as the reference.
    let mut m = Mock::new(0, 0);
    m.replies.insert(0x45, [vec![0, 0], vec![0; 24]].concat());
    m.replies.insert(0x47, vec![0, 0, 0x31, 0]);
    m.replies.insert(0x4b, b(&d["storage_reply"]));
    let bl = blobs();
    assert_eq!(db::new_user(&mut m, &bl, &sid).unwrap(), 0x31);
    db::new_finger(&mut m, &bl, 0x11, b"tinfo").unwrap();
    db::new_data(&mut m, &bl, 0x22, b"data").unwrap();
    db::new_user_storage(&mut m, &bl).unwrap();
    let want: Vec<Vec<u8>> = d["commands"].as_array().unwrap().iter().map(b).collect();
    assert_eq!(m.sent, want);
}

#[test]
fn sensor_replies() {
    let v = v();
    let fb = parse_factory_bits(&b(&v["factory_bits"]["reply"])).unwrap();
    let want: BTreeMap<u16, Vec<u8>> = v["factory_bits"]["bits"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, x)| (k.parse().unwrap(), b(x)))
        .collect();
    assert_eq!(fb, want);

    let e = &v["enrollment_update"];
    let r = b(&e["reply"]);
    let up = parse_enrollment_update(&r).unwrap();
    assert_eq!(up.header, Some(b(&e["header"])));
    assert_eq!(up.template, Some(b(&e["template"])));
    assert_eq!(up.tid, Some(b(&e["tid"])));

    let c = &v["calibration_sessions"][0];
    let sc = scanner(c);
    let mut m = Mock::new(0, 0);
    m.replies.insert(0x60, b(&v["match"]["reply"]));
    m.ints.push(vec![3, 2, 2, 2, 2]);
    let r = sc.match_finger(&mut m).unwrap();
    assert_eq!(
        r,
        Identified::Match {
            user: u(&v["match"]["user"]) as u32,
            subtype: u(&v["match"]["subtype"]) as u16,
            hash: b(&v["match"]["hash"]),
        }
    );
    assert_eq!(
        m.sent,
        [
            vec![0x5e, 2, 0xff, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
            vec![0x60, 0, 0, 0, 0],
            vec![0x62, 0, 0, 0, 0]
        ]
    );

    let f = &v["flash_info"];
    let info = parse_flash_info(&b(&f["reply"])).unwrap();
    assert_eq!(info.ic.name, f["ic"].as_str().unwrap());
    assert_eq!(
        (info.blocks as u64, info.blocksize as u64),
        (u(&f["blocks"]), u(&f["blocksize"]))
    );
    let parts: Vec<Vec<u64>> = f["partitions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_array().unwrap().iter().map(u).collect())
        .collect();
    assert_eq!(
        info.partitions
            .iter()
            .map(|p| vec![
                p.id as u64,
                p.kind as u64,
                p.access_lvl as u64,
                p.offset as u64,
                p.size as u64
            ])
            .collect::<Vec<_>>(),
        parts
    );

    let w = &v["fw_info"];
    let fw = parse_fw_info(&b(&w["reply"])).unwrap().unwrap();
    assert_eq!(
        (fw.major as u64, fw.minor as u64, fw.buildtime as u64),
        (u(&w["major"]), u(&w["minor"]), u(&w["buildtime"]))
    );
    let mods: Vec<Vec<u64>> = w["modules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_array().unwrap().iter().map(u).collect())
        .collect();
    assert_eq!(
        fw.modules
            .iter()
            .map(|m| vec![
                m.kind as u64,
                m.subtype as u64,
                m.major as u64,
                m.minor as u64,
                m.size as u64
            ])
            .collect::<Vec<_>>(),
        mods
    );
}
