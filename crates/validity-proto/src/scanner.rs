//! Sensor identification, capture programs, calibration, enrolment and
//! identification (python-validity `sensor.py`).

use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::calibration::{self, CalibrationFile, Geometry};
use crate::cmd::{Error, Reader, checked, status};
use crate::db;
use crate::flash::{
    erase_flash, read_flash, read_flash_all, with_cleanups, write_enable, write_flash_all,
};
use crate::session::{Deadlines, Sensor, Wait};
use crate::sid::Sid;
use crate::tables::{DeviceInfo, SensorCaptureProg, SensorTypeInfo, dev_info_lookup};
use crate::timeslot::{self, Chunk, Insn, decode_insn, find_nth_insn, find_nth_regwrite};
use crate::vendor::Blobs;

/// `0x39`: LED pattern while waiting for a finger.
pub const GLOW_START_SCAN: &str = "3920bf0200ffff0000019900200000000099990000000000000000000000000020000000000000000000000000ffff000000990020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
/// `0x39`: LED pattern at the end of a scan.
pub const GLOW_END_SCAN: &str = "39f4010000f401000001ff002000000000ffff0000000000000000000000000020000000000000000000000000f401000000ff0020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

fn unhex(s: &str) -> Vec<u8> {
    crate::hex::decode(s).expect("valid constant")
}

pub fn glow_start_scan(s: &mut impl Sensor) -> Result<(), Error> {
    status(&s.app(&unhex(GLOW_START_SCAN))?).map(|_| ())
}

pub fn glow_end_scan(s: &mut impl Sensor) -> Result<(), Error> {
    status(&s.app(&unhex(GLOW_END_SCAN))?).map(|_| ())
}

/// Capture program status.
pub fn get_prg_status(s: &mut impl Sensor) -> Result<Vec<u8>, Error> {
    s.app(&[0x51, 0, 0, 0, 0])
}

/// Capture result: status, `len (le32)`, then x, y, w1, w2 (le16) and an error (le32).
pub fn get_prg_status2(s: &mut impl Sensor) -> Result<Vec<u8>, Error> {
    s.app(&[0x51, 0, 0x20, 0, 0])
}

/// Polling period of [`wait_till_finished`].
const PRG_STATUS_POLL: Duration = Duration::from_millis(200);

/// Polls the capture program until it is idle (0) or done (7), for at most
/// the default capture deadline ([`Deadlines::capture`]); then fails with
/// [`Error::Timeout`] ([`Wait::Capture`]). python-validity polls forever.
pub fn wait_till_finished(s: &mut impl Sensor) -> Result<(), Error> {
    let limit = Deadlines::DEFAULT.capture;
    let polls = limit.as_millis() / PRG_STATUS_POLL.as_millis();
    for i in 0..=polls {
        let st = get_prg_status(s)?;
        if matches!(st.first(), Some(0 | 7)) {
            return Ok(());
        }
        if i < polls {
            s.pause(PRG_STATUS_POLL);
        }
    }
    log::warn!("timed out after {limit:?} waiting for the capture program to finish");
    Err(Error::Timeout {
        waiting_for: Wait::Capture,
        after: limit,
    })
}

pub fn read_hw_reg32(s: &mut impl Sensor, addr: u32) -> Result<u32, Error> {
    let mut c = vec![7];
    c.extend_from_slice(&addr.to_le_bytes());
    c.push(4);
    let rsp = s.cmd(&c)?;
    let mut r = Reader::new(status(&rsp)?, "register value");
    let v = r.u32()?;
    r.end()?;
    Ok(v)
}

pub fn write_hw_reg32(s: &mut impl Sensor, addr: u32, val: u32) -> Result<(), Error> {
    let mut c = vec![8];
    c.extend_from_slice(&addr.to_le_bytes());
    c.extend_from_slice(&val.to_le_bytes());
    c.push(4);
    checked(s, &c).map(|_| ())
}

/// Reboots the sensor; it disconnects and the session is over.
pub fn reboot(s: &mut impl Sensor) -> Result<(), Error> {
    checked(s, &crate::cmd::REBOOT).map(|_| ())
}

/// Erases the pairing and the database (in the clear), then reboots.
pub fn factory_reset(s: &mut impl Sensor, blobs: &Blobs) -> Result<(), Error> {
    checked(s, &blobs.reset_blob)?;
    let mut c = vec![0x10];
    c.extend_from_slice(&[0; 0x61]);
    checked(s, &c)?;
    reboot(s)
}

pub use crate::cmd::RomInfo;

/// Sensor model (`cmd 0x75`).
pub fn identify_sensor(s: &mut impl Sensor) -> Result<&'static DeviceInfo, Error> {
    let rsp = s.cmd(&[0x75])?;
    let mut r = Reader::new(status(&rsp)?, "sensor id");
    let (zeroes, minor, major) = (r.u32()?, r.u16()?, r.u16()?);
    r.end()?;
    if zeroes != 0 {
        return Err(Error::Protocol(format!(
            "unexpected sensor id prefix {zeroes:x}"
        )));
    }
    dev_info_lookup(major, minor)
        .ok_or_else(|| Error::Protocol(format!("unknown sensor {major:04x}:{minor:04x}")))
}

/// Factory calibration entries of `tag`, by subtag (`cmd 0x6f`).
pub fn parse_factory_bits(rsp: &[u8]) -> Result<BTreeMap<u16, Vec<u8>>, Error> {
    let mut r = Reader::new(status(rsp)?, "factory bits");
    let _unknown = r.u32()?;
    let entries = r.u32()?;
    let mut out = BTreeMap::new();
    for _ in 0..entries {
        let (_ptr, len, _tag, subtag, _flags) = (r.u32()?, r.u16()?, r.u16()?, r.u16()?, r.u16()?);
        out.insert(subtag, r.bytes(len as usize)?.to_vec());
    }
    r.end()?;
    Ok(out)
}

pub fn get_factory_bits(s: &mut impl Sensor, tag: u16) -> Result<BTreeMap<u16, Vec<u8>>, Error> {
    let mut c = vec![0x6f];
    c.extend_from_slice(&tag.to_le_bytes());
    c.extend_from_slice(&[0; 6]);
    parse_factory_bits(&s.cmd(&c)?)
}

/// Sensor types whose capture programs carry the type-1 line update.
pub const LINE_UPDATE_TYPE1_DEVICES: [u16; 13] = [
    0xb5, 0x885, 0xb3, 0x143b, 0x1055, 0xe1, 0x8b1, 0xea, 0xe4, 0xed, 0x1825, 0x1ff5, 0x199,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    Calibrate,
    Identify,
    Enroll,
}

/// Rewrites Call instructions at the head of a timeslot table: repeat counts above
/// one are multiplied, and the address optionally incremented. This is the DLL's
/// logic as transcribed by the reference. Byte overflow (which makes the reference
/// raise) is an error.
pub fn patch_timeslot_table(b: &[u8], inc_address: bool, mult: u8) -> Result<Vec<u8>, Error> {
    let mut b = b.to_vec();
    let overflow = || Error::Protocol("timeslot patch overflows a byte".into());
    let mut i = 0;
    while i + 3 < b.len() {
        if b[i] & 0xf8 == 0x10 {
            if b[i + 2] > 1 {
                b[i + 2] = b[i + 2].checked_mul(mult).ok_or_else(overflow)?;
                if inc_address {
                    b[i + 1] = b[i + 1].checked_add(1).ok_or_else(overflow)?;
                }
            }
            i += 3;
        } else if b[i] == 0 {
            i += 1;
        } else if b[i] == 7 {
            i += 2;
        } else {
            break;
        }
    }
    Ok(b)
}

/// Finds the last Call of the table, then the last write to register 0x8000203c in
/// the called routine, and replaces its low value byte with `value`.
pub fn patch_timeslot_again(b: &[u8], value: u8) -> Result<Vec<u8>, Error> {
    let mut b = b.to_vec();
    let mut target = None;
    let mut pc = 0;
    while pc < b.len() {
        let (insn, len) = decode_insn(&b[pc..])?;
        if insn.is_terminator() {
            break;
        }
        if let Insn::Call { addr, .. } = insn {
            target = Some(addr as usize);
        }
        pc += len;
    }
    let Some(mut pc) = target else {
        return Ok(b);
    };
    let mut hit = None;
    while pc < b.len() {
        let (insn, len) = decode_insn(&b[pc..])?;
        if insn.is_terminator() {
            break;
        }
        if let Insn::RegWrite {
            addr: 0x8000_203c, ..
        } = insn
        {
            hit = Some(pc);
        }
        pc += len;
    }
    if let Some(at) = hit {
        b[at + 1] = value;
    }
    Ok(b)
}

/// One line-update entry.
struct Line {
    mask: u32,
    flags: u32,
    data: Vec<u8>,
    v0: u8,
    v1: u8,
    v2: u16,
}

impl Line {
    fn new(mask: u32, flags: u32, data: Vec<u8>) -> Self {
        Line {
            mask,
            flags,
            data,
            v0: 0,
            v1: 0,
            v2: 0,
        }
    }

    /// Lines with a count field above 1 go to the transform chunk.
    fn transformed(&self) -> bool {
        (self.flags & 0x00f0_0000) >> 20 > 1
    }
}

fn pad4(lines: &mut [Line]) {
    for l in lines {
        let n = l.data.len() % 4;
        if n > 0 {
            l.data.resize(l.data.len() + 4 - n, 0);
        }
    }
}

fn line_update_chunk(lines: &[Line], data_of: impl Fn(&Line) -> bool) -> Vec<u8> {
    let mut b = (lines.len() as u32).to_le_bytes().to_vec();
    for l in lines {
        b.extend_from_slice(&l.mask.to_le_bytes());
        b.extend_from_slice(&l.flags.to_le_bytes());
    }
    for l in lines.iter().filter(|l| data_of(l)) {
        b.extend_from_slice(&l.data);
    }
    b
}

fn insn_pc(found: Option<usize>, what: &str) -> Result<u32, Error> {
    found
        .map(|pc| pc as u32)
        .ok_or_else(|| Error::Protocol(format!("capture program has no {what}")))
}

/// Mode-specific chunks of type-1 programs.
const T1_IDENTIFY_DETECT: &str =
    "fbb20f0000000f00300000008700020067000a00018000000a0200000b1900008813b80b01091000";
const T1_IDENTIFY_RECON: &str = "0200180002000000700070004d010000a0008c003c32321e3c0a0202";
const T1_ENROLL_DETECT: &str =
    "fbb20f0000000f00300000008700020067000a00018000000a0200000b19000050c360ea01091000";
const T1_ENROLL_RECON: &str = "0200180023000000700070004d010000a0008c003c32321e3c0a0202";
/// Mode-specific chunks of type-2 programs.
const T2_IDENTIFY_DETECT: &str =
    "fbb20f0000000f00300000006001020040010a00018000000a0200000b1900008813b80b01091000";
const T2_IDENTIFY_RECON: &str = "0200180002000000900090004d01000090017c013c323232640a0201";
const T2_ENROLL_DETECT: &str =
    "fbb20f0000000f00300000006001020040010a00018000000a0200000b19000050c360ea01091000";
const T2_ENROLL_RECON: &str = "0200180023000000900090004d01000090017c013c323232640a0201";

/// What a capture returned (`get_prg_status2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureInfo {
    pub x: u16,
    pub y: u16,
    pub w1: u16,
    pub w2: u16,
}

/// Progress reported during enrolment.
#[derive(Debug)]
pub enum EnrollProgress<'a> {
    /// An image was accepted; `header` is the sensor's progress record, if any.
    Image(Option<&'a [u8]>),
    /// A capture or update failed; enrolment retries unless the callback breaks.
    Retry(&'a Error),
}

/// Outcome of an identification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identified {
    Match {
        user: u32,
        subtype: u16,
        hash: Vec<u8>,
    },
    /// The sensor did not recognise the finger; the interrupt it raised.
    NoMatch(Vec<u8>),
}

/// Pause before retrying after a failed capture.
pub const RETRY_PAUSE: Duration = Duration::from_secs(1);

/// A wait for the sensor (not for the finger) that passed its deadline: the
/// sensor stopped answering, so retrying the capture is pointless.
fn sensor_timeout(e: &Error) -> bool {
    matches!(e, Error::Timeout { waiting_for, .. } if !waiting_for.is_finger())
}

/// No finger was placed before [`Deadlines::finger`].
fn finger_timeout(e: &Error) -> bool {
    matches!(e, Error::Timeout { waiting_for, .. } if waiting_for.is_finger())
}

/// An opened sensor: model, ROM, factory capture program, factory and host
/// calibration (python-validity's `Sensor`).
#[derive(Debug, Clone)]
pub struct Scanner {
    pub device: &'static DeviceInfo,
    pub type_info: &'static SensorTypeInfo,
    pub rom: RomInfo,
    pub key_calibration_line: usize,
    pub calibration_frames: usize,
    pub calibration_iterations: usize,
    pub program: Vec<u8>,
    pub lines_per_frame: usize,
    pub bytes_per_line: usize,
    pub factory_calibration_values: Vec<u8>,
    pub factory_calib_data: Option<Vec<u8>>,
    pub calib_data: Vec<u8>,
    /// Set when the sensor was calibrated in this session: save [`Scanner::calibration_file`].
    pub calibrated: bool,
}

impl Scanner {
    /// Identifies the sensor, loads its factory data and makes sure it is
    /// calibrated. `stored` is the calibration file saved by an earlier session.
    pub fn open(
        s: &mut impl Sensor,
        blobs: &Blobs,
        stored: Option<&CalibrationFile>,
    ) -> Result<Self, Error> {
        let mut sc = Self::probe(s)?;
        let stored = stored.filter(|f| {
            let ok = f.sensor_type == sc.device.sensor_type
                && f.lines == sc.type_info.lines_per_calibration_data
                && f.bytes_per_line as usize * f.lines as usize == f.data.len();
            if !ok {
                log::warn!("calibration file does not match this sensor, ignored");
            }
            ok
        });
        sc.calibrate(s, blobs, stored.map(|f| f.data.as_slice()))?;
        Ok(sc)
    }

    /// Everything `open` does before calibrating.
    pub fn probe(s: &mut impl Sensor) -> Result<Self, Error> {
        let device = identify_sensor(s)?;
        log::info!("opening sensor: {}", device.name.trim_end());
        let type_info = SensorTypeInfo::get(device.sensor_type).ok_or_else(|| {
            Error::Protocol(format!(
                "no geometry for sensor type {:#x}",
                device.sensor_type
            ))
        })?;
        // Hardcoded per type in the reference (0x48 for 0xdb is its guess).
        let (key_calibration_line, calibration_frames, calibration_iterations) =
            match device.sensor_type {
                0x199 => (0x38, 3, 3),
                0xdb => (0x48, 6, 0),
                t => {
                    return Err(Error::Protocol(format!(
                        "sensor {} (type {t:#x}) is not supported",
                        device.name.trim_end()
                    )));
                }
            };
        let rom = RomInfo::get(s)?;
        let program =
            SensorCaptureProg::get(&rom, device.sensor_type, 0x18, 0x19).ok_or_else(|| {
                Error::Protocol(format!(
                    "no capture program for ROM {rom:?} and sensor type {:#x}",
                    device.sensor_type
                ))
            })?;
        let lines_2d = timeslot::split_chunks(&program)?
            .into_iter()
            .find(|c| c.kind == timeslot::CHUNK_2D)
            .and_then(|c| {
                c.value
                    .get(..4)
                    .map(|v| u32::from_le_bytes(v.try_into().expect("4")))
            })
            .ok_or(Error::Malformed("capture program without 2D chunk"))?;
        let bits = get_factory_bits(s, 0x0e00)?;
        let factory_calibration_values = bits
            .get(&3)
            .and_then(|v| v.get(4..))
            .ok_or(Error::Malformed("factory bits without subtag 3"))?
            .to_vec();
        let factory_calib_data = bits.get(&7).and_then(|v| v.get(4..)).map(<[u8]>::to_vec);
        Ok(Scanner {
            device,
            type_info,
            rom,
            key_calibration_line,
            calibration_frames,
            calibration_iterations,
            program,
            lines_per_frame: lines_2d as usize * type_info.repeat_multiplier as usize,
            bytes_per_line: type_info.bytes_per_line as usize,
            factory_calibration_values,
            factory_calib_data,
            calib_data: Vec::new(),
            calibrated: false,
        })
    }

    pub fn geometry(&self) -> Geometry {
        Geometry {
            lines_per_frame: self.lines_per_frame,
            bytes_per_line: self.bytes_per_line,
            lines_per_calibration_data: self.type_info.lines_per_calibration_data as usize,
            calibration_frames: self.calibration_frames,
        }
    }

    /// The calibration to persist for the next session.
    pub fn calibration_file(&self) -> CalibrationFile {
        let lines = self.type_info.lines_per_calibration_data;
        CalibrationFile {
            sensor_type: self.device.sensor_type,
            bytes_per_line: (self.calib_data.len() / lines.max(1) as usize) as u16,
            lines,
            data: self.calib_data.clone(),
        }
    }

    fn key_line(&self) -> Result<Vec<u8>, Error> {
        calibration::key_line(
            &self.calib_data,
            self.type_info.lines_per_calibration_data as usize,
            self.key_calibration_line,
            self.type_info.line_width as usize,
        )
    }

    fn patched_table(&self, table: &[u8], mode: CaptureMode) -> Result<Vec<u8>, Error> {
        // The reference always increments the address (its TODO: find out when to).
        let t = patch_timeslot_table(table, true, self.type_info.repeat_multiplier)?;
        if mode == CaptureMode::Calibrate {
            return Ok(t);
        }
        let v = *self
            .factory_calibration_values
            .get(self.key_calibration_line)
            .ok_or(Error::Malformed("factory calibration values too short"))?;
        patch_timeslot_again(&t, v)
    }

    fn line_update_type_1(&self, mode: CaptureMode, chunks: &mut Vec<Chunk>) -> Result<(), Error> {
        let mut tst = None;
        for c in chunks.iter_mut() {
            if c.kind == timeslot::CHUNK_TIMESLOT_TABLE_2D {
                let t = self.patched_table(&c.value, mode)?;
                let w = (self.type_info.line_width as usize).min(t.len());
                let mut v = self.key_line()?;
                v.extend_from_slice(&t[w..]);
                c.value = v;
                tst = Some(t);
            }
        }
        let tst = tst.ok_or(Error::Malformed("capture program without timeslot table"))?;

        chunks.push(Chunk::new(timeslot::CHUNK_REPLY_CONFIG, []));
        match mode {
            CaptureMode::Identify => {
                chunks.push(Chunk::new(
                    timeslot::CHUNK_IDENTIFY_DETECT,
                    unhex(T1_IDENTIFY_DETECT),
                ));
                chunks.push(Chunk::new(
                    timeslot::CHUNK_IMAGE_RECONSTRUCTION,
                    unhex(T1_IDENTIFY_RECON),
                ));
            }
            CaptureMode::Enroll => {
                chunks.push(Chunk::new(
                    timeslot::CHUNK_FINGER_DETECT,
                    unhex(T1_ENROLL_DETECT),
                ));
                chunks.push(Chunk::new(
                    timeslot::CHUNK_IMAGE_RECONSTRUCTION,
                    unhex(T1_ENROLL_RECON),
                ));
            }
            CaptureMode::Calibrate => {}
        }
        chunks.push(Chunk::new(
            timeslot::CHUNK_LINE_UPDATE_INTERLEAVE,
            1u32.to_le_bytes(),
        ));

        let mut lines = Vec::new();
        // The reference starts this counter at 2 without knowing why.
        let mut cnt = 2u32;
        let pc = insn_pc(find_nth_insn(&tst, 6, 2)?, "second Enable Rx")?;
        let mut l = Line::new(
            0xff,
            (pc + 1) | (cnt << 20) | 0x0700_0000,
            self.type_info.calibration_blob(),
        );
        l.v0 = 0xf;
        lines.push(l);
        cnt += 1;

        let pc = insn_pc(
            find_nth_regwrite(&tst, 0x8000_203c, 1)?,
            "write to 0x8000203c",
        )?;
        let (u, m, packed) = calibration::bitpack(&self.factory_calibration_values)?;
        let mut l = Line::new(0xff, (pc + 1) | (cnt << 20) | 0x0700_0000, packed);
        l.v0 = (u - 1) | 8;
        l.v1 = m;
        lines.push(l);

        if !self.calib_data.is_empty() {
            let bpcl = self.calib_data.len() / self.type_info.lines_per_calibration_data as usize;
            for i in (0..112).step_by(4) {
                let mut data = Vec::with_capacity(112 * 4);
                for j in 0..112 {
                    let p = 8 + j * bpcl + i;
                    data.extend_from_slice(
                        self.calib_data
                            .get(p..p + 4)
                            .ok_or(Error::Protocol("calibration data too short".into()))?,
                    );
                }
                lines.push(Line::new(0xffff_ffff, i as u32 | (0x85 << 24), data));
            }
        }
        pad4(&mut lines);

        chunks.push(Chunk::new(
            timeslot::CHUNK_LINE_UPDATE,
            line_update_chunk(&lines, |l| !l.transformed()),
        ));
        let mut transform = Vec::new();
        for l in lines.iter().filter(|l| l.transformed()) {
            transform.push(l.v0);
            transform.push(l.v1);
            transform.extend_from_slice(&l.v2.to_le_bytes());
            transform.extend_from_slice(&l.data);
        }
        chunks.push(Chunk::new(timeslot::CHUNK_LINE_UPDATE_TRANSFORM, transform));
        Ok(())
    }

    fn line_update_type_2(&self, mode: CaptureMode, chunks: &mut Vec<Chunk>) -> Result<(), Error> {
        let mut tst = None;
        for c in chunks.iter_mut() {
            if c.kind == timeslot::CHUNK_TIMESLOT_TABLE_2D {
                c.value = self.patched_table(&c.value, mode)?;
                tst = Some(c.value.clone());
            }
        }
        let tst = tst.ok_or(Error::Malformed("capture program without timeslot table"))?;

        chunks.push(Chunk::new(timeslot::CHUNK_REPLY_CONFIG, []));
        match mode {
            CaptureMode::Identify => {
                chunks.push(Chunk::new(
                    timeslot::CHUNK_IDENTIFY_DETECT,
                    unhex(T2_IDENTIFY_DETECT),
                ));
                chunks.push(Chunk::new(
                    timeslot::CHUNK_IMAGE_RECONSTRUCTION,
                    unhex(T2_IDENTIFY_RECON),
                ));
            }
            CaptureMode::Enroll => {
                chunks.push(Chunk::new(
                    timeslot::CHUNK_FINGER_DETECT,
                    unhex(T2_ENROLL_DETECT),
                ));
                chunks.push(Chunk::new(
                    timeslot::CHUNK_IMAGE_RECONSTRUCTION,
                    unhex(T2_ENROLL_RECON),
                ));
            }
            CaptureMode::Calibrate => {}
        }

        let rx = insn_pc(find_nth_insn(&tst, 6, 2)?, "second Enable Rx")?;
        let fc = insn_pc(
            find_nth_regwrite(&tst, 0x8000_20fc, 1)?,
            "write to 0x800020fc",
        )?;
        let w3c = insn_pc(
            find_nth_regwrite(&tst, 0x8000_203c, 1)?,
            "write to 0x8000203c",
        )?;
        let factory = self
            .factory_calib_data
            .clone()
            .ok_or(Error::Malformed("factory bits without subtag 7"))?;
        let mut lines = vec![
            Line::new(
                0xff,
                (rx + 1) | 0x0300_0000,
                self.type_info.calibration_blob(),
            ),
            Line::new(0xff, (fc + 1) | 0x0300_0000, factory),
            Line::new(
                0xff,
                (w3c + 1) | 0x0300_0000,
                self.factory_calibration_values.clone(),
            ),
        ];
        pad4(&mut lines);
        chunks.push(Chunk::new(
            timeslot::CHUNK_LINE_UPDATE,
            line_update_chunk(&lines, |_| true),
        ));
        Ok(())
    }

    /// Capture command (`0x02`): the factory program patched for the mode, with the
    /// line updates carrying the calibration.
    pub fn build_cmd_02(&self, mode: CaptureMode) -> Result<Vec<u8>, Error> {
        let mut chunks = timeslot::split_chunks(&self.program)?;
        if self.rom.product != 0x30 {
            return Err(Error::Unsupported(
                "capture programs for ROM product other than 0x30",
            ));
        }
        if LINE_UPDATE_TYPE1_DEVICES.contains(&self.device.sensor_type) {
            self.line_update_type_1(mode, &mut chunks)?;
        } else {
            self.line_update_type_2(mode, &mut chunks)?;
        }
        // The reference's guess at the line count of a calibration capture.
        let req_lines = match mode {
            CaptureMode::Calibrate => self.calibration_frames * self.lines_per_frame + 1,
            _ => 0,
        };
        let mut c = vec![0x02];
        c.extend_from_slice(&(self.bytes_per_line as u16).to_le_bytes());
        c.extend_from_slice(&(req_lines as u16).to_le_bytes());
        c.extend(timeslot::merge_chunks(&chunks));
        Ok(c)
    }

    /// Whether partition 6 holds a valid clean slate.
    pub fn check_clean_slate(&self, s: &mut impl Sensor) -> Result<bool, Error> {
        let start = read_flash(s, 6, 0, calibration::CLEAN_SLATE_HDR as u32)?;
        let Some((len, hash)) = calibration::clean_slate_header(&start) else {
            return Ok(false);
        };
        let img = read_flash_all(s, 6, calibration::CLEAN_SLATE_HDR as u32, len as u32)?;
        if Sha256::digest(&img).as_slice() != hash {
            log::warn!("calibration flash hash mismatch");
            return Ok(false);
        }
        Ok(true)
    }

    /// Writes the clean slate to partition 6 unless it is already there.
    pub fn persist_clean_slate(
        &self,
        s: &mut impl Sensor,
        blobs: &Blobs,
        clean_slate: &[u8],
    ) -> Result<(), Error> {
        let hdr = calibration::CLEAN_SLATE_HDR;
        let start = read_flash(s, 6, 0, hdr as u32)?;
        if start.iter().any(|&b| b != 0xff) {
            if clean_slate.get(..hdr) == Some(&start[..]) {
                log::info!("calibration data already matches the data on the flash");
                return Ok(());
            }
            log::info!("calibration flash already written, erasing");
            erase_flash(s, blobs, 6)?;
        }
        write_flash_all(s, blobs, 6, 0, clean_slate)
    }

    /// Uses the stored calibration if the flash still holds the matching clean
    /// slate; otherwise calibrates (starting from the stored data, as the
    /// reference does) and writes a new clean slate.
    pub fn calibrate(
        &mut self,
        s: &mut impl Sensor,
        blobs: &Blobs,
        stored: Option<&[u8]>,
    ) -> Result<(), Error> {
        match stored {
            Some(d) => {
                self.calib_data = d.to_vec();
                if self.check_clean_slate(s)? {
                    return Ok(());
                }
                log::info!("no calibration data on the flash, calibrating");
            }
            None => {
                self.calib_data.clear();
                log::info!("no calibration data loaded, calibrating");
            }
        }
        let g = self.geometry();
        for i in 0..self.calibration_iterations {
            log::debug!("calibration iteration {i}");
            checked(s, &self.build_cmd_02(CaptureMode::Calibrate)?)?;
            let avg = g.average(&s.read_82()?)?;
            self.calib_data = calibration::process_calibration_results(
                &self.calib_data,
                &avg,
                self.bytes_per_line,
            )?;
        }
        log::debug!("requesting a blank image");
        checked(s, &self.build_cmd_02(CaptureMode::Calibrate)?)?;
        let blank = g.average(&s.read_82()?)?;
        self.persist_clean_slate(s, blobs, &calibration::clean_slate(&blank))?;
        self.calibrated = true;
        Ok(())
    }

    /// Runs one capture and returns its geometry. The capture is stopped afterwards
    /// in every case (the status of the stop command is not meaningful).
    pub fn capture(&self, s: &mut impl Sensor, mode: CaptureMode) -> Result<CaptureInfo, Error> {
        let r = self.capture_inner(s, mode);
        let stop = s.app(&[0x04]);
        let info = r?;
        stop?;
        Ok(info)
    }

    fn capture_inner(&self, s: &mut impl Sensor, mode: CaptureMode) -> Result<CaptureInfo, Error> {
        status(&s.app(&self.build_cmd_02(mode)?)?)?;
        let hexs = crate::hex::encode;
        let b = s.wait_for(Wait::CaptureStart)?;
        if b.first() != Some(&0) {
            return Err(Error::Protocol(format!(
                "capture start: unexpected interrupt {}",
                hexs(&b)
            )));
        }
        // Wait for the finger: the scan is armed (the LED pattern runs).
        while s.wait_for(Wait::Finger)?.first() != Some(&2) {}
        // Wait for the capture to complete.
        loop {
            let b = s.wait_for(Wait::Capture)?;
            if b.first() != Some(&3) || b.len() < 3 {
                return Err(Error::Protocol(format!(
                    "capture: unexpected interrupt {}",
                    hexs(&b)
                )));
            }
            if b[2] & 4 != 0 {
                break;
            }
        }
        let res = get_prg_status2(s)?;
        let mut r = Reader::new(status(&res)?, "capture result");
        let len = r.u32()? as usize;
        if len != r.buf.len() {
            return Err(Error::Malformed("capture result length"));
        }
        let info = CaptureInfo {
            x: r.u16()?,
            y: r.u16()?,
            w1: r.u16()?,
            w2: r.u16()?,
        };
        let error = r.u32()?;
        r.end()?;
        if error != 0 {
            return Err(Error::Protocol(format!("scanning problem: {error:04x}")));
        }
        Ok(info)
    }

    /// `0x68`: starts an enrolment update; returns the next key and consumes the
    /// interrupt that follows.
    fn enrollment_update_start(s: &mut impl Sensor, key: u32) -> Result<u32, Error> {
        let mut c = vec![0x68];
        c.extend_from_slice(&key.to_le_bytes());
        c.extend_from_slice(&[0; 4]);
        let rsp = s.app(&c)?;
        let mut r = Reader::new(status(&rsp)?, "enrollment key");
        let k = r.u32()?;
        r.end()?;
        s.wait_for(Wait::Enrollment)?;
        Ok(k)
    }

    fn create_enrollment(s: &mut impl Sensor) -> Result<(), Error> {
        status(&s.app(&[0x69, 1, 0, 0, 0])?).map(|_| ())
    }

    fn enrollment_update_end(s: &mut impl Sensor) -> Result<(), Error> {
        status(&s.app(&[0x69, 0, 0, 0, 0])?).map(|_| ())
    }

    /// `0x6b`: feeds the previous template; raises an interrupt.
    fn enrollment_update(
        s: &mut impl Sensor,
        blobs: &Blobs,
        prev: &[u8],
    ) -> Result<Vec<u8>, Error> {
        write_enable(s, blobs)?;
        let mut c = vec![0x6b];
        c.extend_from_slice(prev);
        with_cleanups(s, |cmd| {
            let rsp = cmd(&c)?;
            Ok(status(&rsp)?.to_vec())
        })
    }

    /// Adds the captured image to the enrolment.
    fn append_new_image(s: &mut impl Sensor, blobs: &Blobs, prev: &[u8]) -> Result<Update, Error> {
        Self::enrollment_update(s, blobs, prev)?;
        s.wait_for(Wait::Enrollment)?;
        let res = Self::enrollment_update(s, blobs, prev)?;
        parse_enrollment_update(&res)
    }

    /// Enrols a finger of `identity` (creating the user if needed) and returns the
    /// new finger record id. `progress` sees every accepted image and every failed
    /// attempt; returning `Break` from a failed attempt aborts the enrolment with
    /// that error. The reference retries forever, without the pause its comment
    /// asks for; here failures pause [`RETRY_PAUSE`] and can be aborted.
    ///
    /// No finger within [`Deadlines::finger`] is a failed attempt like any
    /// other (`Retry` with [`Error::Timeout`] for [`Wait::Finger`]): the scan
    /// is re-armed unless `progress` breaks. Any other timeout means the
    /// sensor stopped answering: it is returned at once, without retrying.
    pub fn enroll(
        &self,
        s: &mut impl Sensor,
        blobs: &Blobs,
        identity: &Sid,
        subtype: u16,
        mut progress: impl FnMut(EnrollProgress<'_>) -> ControlFlow<()>,
    ) -> Result<u16, Error> {
        s.clear_cancel();
        let mut key = 0u32;
        let mut template = Vec::new();
        Self::create_enrollment(s)?;
        let tid = loop {
            let r = self.enroll_step(s, blobs, &mut key, &mut template, &mut progress);
            if let Err(Error::Cancelled) = r {
                let g = glow_end_scan(s);
                let e = Self::enrollment_update_end(s);
                g?;
                e?;
                return Err(Error::Cancelled);
            }
            let end = Self::enrollment_update_end(s);
            match r {
                Ok(Some(tid)) => {
                    end?;
                    break tid;
                }
                Ok(None) => end?,
                // A lost device (or a diverged replay) is not retried; the
                // reference re-raises USB errors too. Neither is a sensor that
                // stopped answering.
                Err(e @ (Error::Transport(_) | Error::Replay(_))) => return Err(e),
                Err(e) if sensor_timeout(&e) => return Err(e),
                Err(e) => {
                    end?;
                    log::info!("enrolment attempt failed: {e}");
                    if progress(EnrollProgress::Retry(&e)).is_break() {
                        if finger_timeout(&e) {
                            glow_end_scan(s)?;
                        }
                        return Err(e);
                    }
                    s.pause(RETRY_PAUSE);
                }
            }
        };
        // The reference ends the enrolment a second time here.
        Self::enrollment_update_end(s)?;

        let finger = db::make_finger_data(subtype, &template, &tid);
        let user = match db::lookup_user(s, identity)? {
            Some(u) => u.dbid,
            None => db::new_user(s, blobs, identity)?,
        };
        let recid = db::new_finger(s, blobs, user, &finger)?;
        s.wait_for(Wait::Enrollment)?;
        glow_end_scan(s)?;
        Ok(recid)
    }

    /// One enrolment image; `Some(template id)` once the enrolment is complete.
    fn enroll_step(
        &self,
        s: &mut impl Sensor,
        blobs: &Blobs,
        key: &mut u32,
        template: &mut Vec<u8>,
        progress: &mut impl FnMut(EnrollProgress<'_>) -> ControlFlow<()>,
    ) -> Result<Option<Vec<u8>>, Error> {
        glow_start_scan(s)?;
        self.capture(s, CaptureMode::Enroll)?;
        *key = Self::enrollment_update_start(s, *key)?;
        let u = Self::append_new_image(s, blobs, template)?;
        // python-validity replaces the template by None when a reply lacks one,
        // which breaks every later attempt; such a reply is an error here and the
        // previous template is kept.
        *template = u
            .template
            .ok_or(Error::Malformed("enrolment update without template"))?;
        // The callback may not abort an accepted image: only failures are optional.
        let _ = progress(EnrollProgress::Image(u.header.as_deref()));
        Ok(u.tid.filter(|t| !t.is_empty()))
    }

    /// Asks the sensor to match the finger on it against every enrolled finger.
    pub fn match_finger(&self, s: &mut impl Sensor) -> Result<Identified, Error> {
        let r = Self::match_inner(s);
        // Cleanup; its status is irrelevant.
        let c = s.app(&[0x62, 0, 0, 0, 0]);
        let v = r?;
        c?;
        Ok(v)
    }

    fn match_inner(s: &mut impl Sensor) -> Result<Identified, Error> {
        // 0x5e 02 ff, storage 0 and user 0 (match any), 1, 0, 0.
        let c = [0x5e, 2, 0xff, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0];
        status(&s.app(&c)?)?;
        let b = s.wait_for(Wait::Match)?;
        if b.first() != Some(&3) {
            return Ok(Identified::NoMatch(b));
        }
        let rsp = s.app(&[0x60, 0, 0, 0, 0])?;
        let mut r = Reader::new(status(&rsp)?, "match result");
        let len = r.u16()? as usize;
        if len != r.buf.len() {
            return Err(Error::Malformed("match result length"));
        }
        let d = parse_dict(r.rest())?;
        let get = |k: u16| d.get(&k).ok_or(Error::Malformed("match result field"));
        let user = u32::from_le_bytes(
            get(1)?
                .as_slice()
                .try_into()
                .map_err(|_| Error::Malformed("match user"))?,
        );
        let subtype = u16::from_le_bytes(
            get(3)?
                .as_slice()
                .try_into()
                .map_err(|_| Error::Malformed("match subtype"))?,
        );
        Ok(Identified::Match {
            user,
            subtype,
            hash: get(4)?.clone(),
        })
    }

    /// Captures a finger (retrying failed captures; `on_retry` may abort) and
    /// matches it.
    ///
    /// No finger within [`Deadlines::finger`] is a failed capture
    /// ([`Error::Timeout`] for [`Wait::Finger`], passed to `on_retry`); any
    /// other timeout means the sensor stopped answering and is returned at
    /// once.
    pub fn identify(
        &self,
        s: &mut impl Sensor,
        mut on_retry: impl FnMut(&Error) -> ControlFlow<()>,
    ) -> Result<Identified, Error> {
        s.clear_cancel();
        loop {
            let r = glow_start_scan(s).and_then(|_| self.capture(s, CaptureMode::Identify));
            match r {
                Ok(_) => break,
                Err(e @ (Error::Transport(_) | Error::Replay(_))) => return Err(e),
                Err(e) if sensor_timeout(&e) => return Err(e),
                Err(Error::Cancelled) => {
                    glow_end_scan(s)?;
                    return Err(Error::Cancelled);
                }
                Err(e) => {
                    log::info!("capture failed: {e}");
                    if on_retry(&e).is_break() {
                        if finger_timeout(&e) {
                            glow_end_scan(s)?;
                        }
                        return Err(e);
                    }
                    s.pause(RETRY_PAUSE);
                }
            }
        }
        self.match_finger(s)
    }
}

/// Reply of the second enrolment update: `len (le16)` then records of
/// `tag (le16) || len (le16) || 0x34 more header bytes || value`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Update {
    /// Tag 1: progress record.
    pub header: Option<Vec<u8>>,
    /// Tag 0: the template so far, its 0x38-byte record header included.
    pub template: Option<Vec<u8>>,
    /// Tag 3: template id, present once the enrolment is complete.
    pub tid: Option<Vec<u8>>,
}

/// Record header size, hardcoded in the DLL.
const MAGIC_LEN: usize = 0x38;

pub fn parse_enrollment_update(res: &[u8]) -> Result<Update, Error> {
    let mut r = Reader::new(res, "enrollment update");
    let len = r.u16()? as usize;
    let mut res = r.rest();
    if len != res.len() {
        return Err(Error::Malformed("enrollment update length"));
    }
    let mut u = Update::default();
    while !res.is_empty() {
        let mut h = Reader::new(res, "enrollment record");
        let (tag, l) = (h.u16()?, h.u16()? as usize);
        let rec = res
            .get(..MAGIC_LEN + l)
            .ok_or(Error::Malformed("enrollment record"))?;
        match tag {
            0 => u.template = Some(rec.to_vec()),
            1 => u.header = Some(rec[MAGIC_LEN..].to_vec()),
            3 => u.tid = Some(rec[MAGIC_LEN..].to_vec()),
            t => log::warn!("ignoring unknown enrolment record tag {t:x}"),
        }
        res = &res[MAGIC_LEN + l..];
    }
    Ok(u)
}

/// `tag (le16) || len (le16) || value` records.
pub fn parse_dict(mut x: &[u8]) -> Result<BTreeMap<u16, Vec<u8>>, Error> {
    let mut out = BTreeMap::new();
    while !x.is_empty() {
        let mut r = Reader::new(x, "tagged value");
        let (t, l) = (r.u16()?, r.u16()? as usize);
        out.insert(t, r.bytes(l)?.to_vec());
        x = r.rest();
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Script, Step, blobs};
    use crate::transport::TransportError;

    fn sensor() -> Scanner {
        let device = dev_info_lookup(0x190, 0x59).unwrap();
        let type_info = SensorTypeInfo::get(device.sensor_type).unwrap();
        let rom = RomInfo {
            timestamp: 0,
            build: 0x56,
            major: 6,
            minor: 8,
            product: 0x30,
            u1: 0,
        };
        let program = SensorCaptureProg::get(&rom, 0x199, 0x18, 0x19).unwrap();
        Scanner {
            device,
            type_info,
            rom,
            key_calibration_line: 0x38,
            calibration_frames: 3,
            calibration_iterations: 3,
            program,
            lines_per_frame: 224,
            bytes_per_line: 0x78,
            factory_calibration_values: (0..112).map(|i| 0x70 + (i % 9) as u8).collect(),
            factory_calib_data: None,
            calib_data: vec![],
            calibrated: false,
        }
    }

    fn ok() -> Vec<u8> {
        vec![0, 0]
    }

    fn cmd(tx: &[u8], rx: Vec<u8>) -> Step {
        Step::Cmd(tx.to_vec(), rx)
    }

    /// A successful capture: program, start, finger, done, result, stop.
    fn capture_steps(sc: &Scanner, mode: CaptureMode) -> Vec<Step> {
        let mut res = vec![0, 0, 12, 0, 0, 0];
        res.extend([0x60, 0, 0x50, 0, 0x20, 1, 4, 0, 0, 0, 0, 0]);
        vec![
            cmd(&sc.build_cmd_02(mode).unwrap(), ok()),
            Step::Int(vec![0, 1, 2, 3, 4]),
            Step::Int(vec![1, 9, 9, 9, 9]),
            Step::Int(vec![2, 9, 9, 9, 9]),
            Step::Int(vec![3, 0, 1, 0, 0]),
            Step::Int(vec![3, 0, 6, 0, 0]),
            cmd(&[0x51, 0, 0x20, 0, 0], res),
            cmd(&[0x04], vec![0x34, 0x12]),
        ]
    }

    #[test]
    fn replies() {
        let mut r = vec![0, 0];
        r.extend([
            0x44, 0x33, 0x22, 0x11, 0x56, 0, 0, 0, 6, 8, 0xee, 0x30, 0xee, 0xee, 0xee, 5, 0x99,
        ]);
        let rom = RomInfo::parse(&r).unwrap();
        assert_eq!((rom.timestamp, rom.build), (0x11223344, 0x56));
        assert_eq!((rom.major, rom.minor, rom.product, rom.u1), (6, 8, 0x30, 5));
        assert!(RomInfo::parse(&r[..17]).is_err());

        let mut s = Script::new(vec![
            (vec![0x75], vec![0, 0, 0, 0, 0, 0, 0x59, 0, 0x90, 1]),
            (vec![0x75], vec![0, 0, 1, 0, 0, 0, 0x59, 0, 0x90, 1]),
            (vec![0x75], vec![0, 0, 0, 0, 0, 0, 0x59, 0, 0x90]),
            (vec![7, 0x80, 0x20, 0, 0x80, 4], vec![0, 0, 3, 0, 0, 0]),
            (vec![8, 0x5c, 0x20, 0, 0x80, 7, 0, 0, 0, 4], ok()),
        ]);
        assert_eq!(identify_sensor(&mut s).unwrap().sensor_type, 0x199);
        assert!(matches!(identify_sensor(&mut s), Err(Error::Protocol(_))));
        assert!(identify_sensor(&mut s).is_err());
        assert_eq!(read_hw_reg32(&mut s, 0x8000_2080).unwrap(), 3);
        write_hw_reg32(&mut s, 0x8000_205c, 7).unwrap();
        s.done();

        let d = parse_dict(&[1, 0, 2, 0, 9, 9, 3, 0, 0, 0]).unwrap();
        assert_eq!(d[&1], [9, 9]);
        assert!(d[&3].is_empty());
        assert!(parse_dict(&[1, 0, 2, 0, 9]).is_err());

        let mut u = vec![0u8; 2];
        u.extend([3, 0, 2, 0]);
        u.extend([0; 0x34]);
        u.extend([0xaa, 0xbb]);
        let n = (u.len() - 2) as u16;
        u[..2].copy_from_slice(&n.to_le_bytes());
        assert_eq!(
            parse_enrollment_update(&u).unwrap().tid,
            Some(vec![0xaa, 0xbb])
        );
        u.pop();
        assert!(parse_enrollment_update(&u).is_err());
    }

    #[test]
    fn wait_till_finished_is_bounded() {
        let status = |st: u8| cmd(&[0x51, 0, 0, 0, 0], vec![st, 0]);
        let mut s = Script::steps(vec![status(1), status(1), status(7)]).opened();
        wait_till_finished(&mut s).unwrap();
        s.done();
        // A program that never finishes: one poll every 200 ms for 5 s, then a timeout.
        let mut s = Script::steps((0..26).map(|_| status(1)).collect()).opened();
        assert!(matches!(
            wait_till_finished(&mut s),
            Err(Error::Timeout { waiting_for: Wait::Capture, after })
                if after == Deadlines::DEFAULT.capture
        ));
        s.done();
    }

    #[test]
    fn timeslot_patch_errors() {
        assert!(patch_timeslot_table(&[0x10, 0xff, 2, 0], true, 2).is_err());
        assert!(patch_timeslot_table(&[0x10, 1, 0x90, 0], false, 2).is_err());
        // No call: unchanged.
        let t = [0x06, 1, 0x4f, 1, 2, 1];
        assert_eq!(patch_timeslot_again(&t, 9).unwrap(), t);
    }

    #[test]
    fn programs_need_calibration_geometry() {
        let mut sc = sensor();
        sc.factory_calibration_values = vec![7; 112];
        assert!(sc.build_cmd_02(CaptureMode::Identify).is_err());
        let mut sc = sensor();
        sc.rom.product = 0x31;
        assert!(matches!(
            sc.build_cmd_02(CaptureMode::Identify),
            Err(Error::Unsupported(_))
        ));
        let mut sc = sensor();
        sc.calib_data = vec![0; 100];
        assert!(sc.build_cmd_02(CaptureMode::Enroll).is_err());
    }

    #[test]
    fn identify_retries_then_reports_no_match() {
        let sc = sensor();
        let glow = unhex(GLOW_START_SCAN);
        let mut steps = vec![
            cmd(&glow, ok()),
            cmd(&sc.build_cmd_02(CaptureMode::Identify).unwrap(), ok()),
            // Unexpected first interrupt: the capture fails, is stopped, retried.
            Step::Int(vec![2, 1, 1, 1, 1]),
            cmd(&[0x04], vec![0x34, 0x12]),
            cmd(&glow, ok()),
        ];
        steps.extend(capture_steps(&sc, CaptureMode::Identify));
        steps.push(cmd(
            &[0x5e, 2, 0xff, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
            vec![0, 0, 0, 0, 0, 0],
        ));
        steps.push(Step::Int(vec![4, 1, 1, 1, 1]));
        steps.push(cmd(&[0x62, 0, 0, 0, 0], ok()));
        let mut s = Script::steps(steps).opened();
        let mut retries = 0;
        let r = sc
            .identify(&mut s, |_| {
                retries += 1;
                ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(r, Identified::NoMatch(vec![4, 1, 1, 1, 1]));
        assert_eq!(retries, 1);
        s.done();
    }

    #[test]
    fn identify_abort_and_cancel() {
        let sc = sensor();
        let glow = unhex(GLOW_START_SCAN);
        let mut s = Script::steps(vec![cmd(&glow, vec![1, 0])]).opened();
        let r = sc.identify(&mut s, |_| ControlFlow::Break(()));
        assert!(matches!(r, Err(Error::Status(1))));
        s.done();

        struct Cancelling(Script);
        impl Sensor for Cancelling {
            fn cmd(&mut self, p: &[u8]) -> Result<Vec<u8>, Error> {
                self.0.cmd(p)
            }
            fn is_open(&self) -> bool {
                true
            }
            fn open_channel(&mut self, _: &[u8]) -> Result<(), Error> {
                unreachable!()
            }
            fn wait_int(&mut self) -> Result<Vec<u8>, Error> {
                Err(Error::Cancelled)
            }
            fn read_82(&mut self) -> Result<Vec<u8>, Error> {
                unreachable!()
            }
        }
        let mut s = Cancelling(Script::steps(vec![
            cmd(&glow, ok()),
            cmd(&sc.build_cmd_02(CaptureMode::Identify).unwrap(), ok()),
            cmd(&[0x04], vec![0x34, 0x12]),
            cmd(&unhex(GLOW_END_SCAN), ok()),
        ]));
        assert!(matches!(
            sc.identify(&mut s, |_| ControlFlow::Continue(())),
            Err(Error::Cancelled)
        ));
        s.0.done();
    }

    #[test]
    fn enroll_flow() {
        let sc = sensor();
        let b = blobs();
        let sid: Sid = "S-1-5-21-1-2-3-1000".parse().unwrap();
        let glow = unhex(GLOW_START_SCAN);
        let wen = b.db_write_enable.clone();

        // One update round: key exchange, two template updates around an interrupt.
        let update = |key_in: u32, key_out: u32, prev: &[u8], reply: Vec<u8>| {
            let mut k = vec![0x68];
            k.extend(key_in.to_le_bytes());
            k.extend([0; 4]);
            let mut upd = vec![0x6b];
            upd.extend(prev);
            vec![
                cmd(&k, [vec![0, 0], key_out.to_le_bytes().to_vec()].concat()),
                Step::Int(vec![3, 7, 7, 7, 7]),
                cmd(&wen, ok()),
                cmd(&upd, ok()),
                cmd(&[0x1a], ok()),
                Step::Int(vec![5, 7, 7, 7, 7]),
                cmd(&wen, ok()),
                cmd(&upd, [vec![0, 0], reply].concat()),
                cmd(&[0x1a], ok()),
            ]
        };
        let rec = |tag: u16, v: &[u8]| {
            let mut r = tag.to_le_bytes().to_vec();
            r.extend((v.len() as u16).to_le_bytes());
            r.extend([0; 0x34]);
            r.extend(v);
            r
        };
        let reply = |recs: Vec<Vec<u8>>| {
            let body = recs.concat();
            [(body.len() as u16).to_le_bytes().to_vec(), body].concat()
        };
        let tpl1 = rec(0, b"T1");
        let tpl2 = rec(0, b"T2");

        let mut steps = vec![cmd(&[0x69, 1, 0, 0, 0], ok()), cmd(&glow, ok())];
        steps.extend(capture_steps(&sc, CaptureMode::Enroll));
        steps.extend(update(
            0,
            0x0bad_cafe,
            &[],
            reply(vec![rec(1, b"H1"), tpl1.clone()]),
        ));
        steps.push(cmd(&[0x69, 0, 0, 0, 0], ok()));
        // Second round: the capture fails (scan error), then succeeds.
        steps.push(cmd(&glow, ok()));
        steps.push(cmd(&sc.build_cmd_02(CaptureMode::Enroll).unwrap(), ok()));
        steps.extend([
            Step::Int(vec![0, 1, 2, 3, 4]),
            Step::Int(vec![2, 9, 9, 9, 9]),
            Step::Int(vec![3, 0, 0x0c, 0, 0]),
            cmd(&[0x51, 0, 0x20, 0, 0], vec![7, 0]),
            cmd(&[0x04], vec![0x34, 0x12]),
            cmd(&[0x69, 0, 0, 0, 0], ok()),
            cmd(&glow, ok()),
        ]);
        steps.extend(capture_steps(&sc, CaptureMode::Enroll));
        steps.extend(update(
            0x0bad_cafe,
            0x0bad_cafe,
            &tpl1,
            reply(vec![tpl2.clone(), rec(1, b"H2"), rec(3, b"TID")]),
        ));
        steps.push(cmd(&[0x69, 0, 0, 0, 0], ok()));
        steps.push(cmd(&[0x69, 0, 0, 0, 0], ok()));
        // Finger record for a new user.
        let stg = {
            let mut r = vec![0, 0, 3, 0, 0, 0, 11, 0, 0, 0];
            r.extend(b"StgWindsor\0");
            r
        };
        let id = db::identity_to_bytes(&sid);
        let mut lookup = vec![0x4a, 0, 0, 3, 0, 0x4c, 0];
        lookup.extend(&id);
        let info = [vec![0, 0], vec![0; 24]].concat();
        let finger = db::make_finger_data(7, &tpl2, b"TID");
        steps.extend([
            cmd(&db::user_storage_cmd(0, "StgWindsor"), stg.clone()),
            cmd(&lookup, vec![0xb3, 0x04]),
            cmd(&db::user_storage_cmd(0, "StgWindsor"), stg.clone()),
            cmd(&[0x45], info.clone()),
            cmd(&wen, ok()),
            cmd(&db::new_record_cmd(3, 5, 3, &id), vec![0, 0, 0x11, 0]),
            cmd(&[0x1a], ok()),
            cmd(&db::user_storage_cmd(0, "StgWindsor"), stg),
            cmd(&[0x45], info),
            cmd(&wen, ok()),
            cmd(
                &db::new_record_cmd(0x11, 0xb, 3, &finger),
                vec![0, 0, 0x21, 0],
            ),
            cmd(&[0x1a], ok()),
            Step::Int(vec![6, 7, 7, 7, 7]),
            cmd(&unhex(GLOW_END_SCAN), ok()),
        ]);
        let mut s = Script::steps(steps).opened();
        let mut seen = Vec::new();
        let recid = sc
            .enroll(&mut s, &b, &sid, 7, |p| {
                seen.push(match p {
                    EnrollProgress::Image(h) => format!("image {:?}", h.map(<[u8]>::to_vec)),
                    EnrollProgress::Retry(e) => format!("retry {e}"),
                });
                ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(recid, 0x21);
        assert_eq!(
            seen,
            [
                format!("image {:?}", Some(b"H1".to_vec())),
                "retry sensor status 0007".to_string(),
                format!("image {:?}", Some(b"H2".to_vec())),
            ]
        );
        s.done();
    }

    #[test]
    fn enroll_stops_on_transport_error_and_on_break() {
        struct Gone(Script);
        impl Sensor for Gone {
            fn cmd(&mut self, p: &[u8]) -> Result<Vec<u8>, Error> {
                if p[0] == 0x39 {
                    return Err(Error::Transport(TransportError::Disconnected));
                }
                self.0.cmd(p)
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
        let sc = sensor();
        let b = blobs();
        let sid: Sid = "S-1-5-21-1".parse().unwrap();
        let mut s = Gone(Script::steps(vec![
            cmd(&[0x69, 1, 0, 0, 0], ok()),
            cmd(&[0x69, 0, 0, 0, 0], ok()),
        ]));
        let r = sc.enroll(&mut s, &b, &sid, 2, |_| ControlFlow::Continue(()));
        assert!(matches!(r, Err(Error::Transport(_))));
        s.0.done();

        let mut s = Script::steps(vec![
            cmd(&[0x69, 1, 0, 0, 0], ok()),
            cmd(&unhex(GLOW_START_SCAN), vec![9, 0]),
            cmd(&[0x69, 0, 0, 0, 0], ok()),
        ])
        .opened();
        let r = sc.enroll(&mut s, &b, &sid, 2, |_| ControlFlow::Break(()));
        assert!(matches!(r, Err(Error::Status(9))));
        s.done();
    }

    #[test]
    fn calibration_erases_a_stale_clean_slate() {
        let mut sc = sensor();
        sc.calibration_iterations = 0;
        let b = blobs();
        let wen = b.db_write_enable.clone();
        let raw: Vec<u8> = (0..80760u32).map(|i| (i * 7) as u8).collect();
        let blank = sc.geometry().average(&raw).unwrap();
        let slate = crate::calibration::clean_slate(&blank);
        let mut stale = vec![0, 0, 0x44, 0, 0, 0, 0, 0];
        stale.extend(vec![0x11; 0x44]);
        let mut steps = vec![
            cmd(&sc.build_cmd_02(CaptureMode::Calibrate).unwrap(), ok()),
            Step::Bulk(raw),
            cmd(&crate::cmd::read_flash_cmd(6, 0, 0x44), stale),
            cmd(&wen, ok()),
            cmd(&[0x3f, 6], ok()),
            cmd(&[0x1a], ok()),
        ];
        for (k, chunk) in slate.chunks(0x1000).enumerate() {
            steps.push(cmd(&wen, ok()));
            steps.push(cmd(
                &crate::flash::write_flash_cmd(6, 0x1000 * k as u32, chunk),
                ok(),
            ));
            steps.push(cmd(&[0x1a], ok()));
        }
        let mut s = Script::steps(steps).opened();
        sc.calibrate(&mut s, &b, None).unwrap();
        assert!(sc.calibrated);
        // No iteration ran: the calibration data stays empty, as in the reference.
        assert!(sc.calib_data.is_empty());
        s.done();
    }

    #[test]
    fn calibration_reuses_a_valid_clean_slate() {
        let mut sc = sensor();
        let frame: Vec<u8> = (0..13440u32).map(|i| i as u8).collect();
        let slate = crate::calibration::clean_slate(&frame);
        let read = |addr: u32, data: &[u8]| {
            let mut r = vec![0, 0];
            r.extend((data.len() as u32).to_le_bytes());
            r.extend([0, 0]);
            r.extend(data);
            Step::Cmd(
                crate::cmd::read_flash_cmd(6, addr, if addr == 0 { 0x44 } else { 0x1000 }),
                r,
            )
        };
        let body = &slate[0x44..];
        let mut steps = vec![read(0, &slate[..0x44])];
        for (k, chunk) in body.chunks(0x1000).enumerate() {
            let mut c = chunk.to_vec();
            c.resize(0x1000, 0xff);
            steps.push(read(0x44 + 0x1000 * k as u32, &c));
        }
        let mut s = Script::steps(steps).opened();
        sc.calibrate(&mut s, &blobs(), Some(&vec![1; 13440]))
            .unwrap();
        assert!(!sc.calibrated);
        assert_eq!(sc.calib_data, vec![1; 13440]);
        s.done();
    }
}
