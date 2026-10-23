//! Calibration arithmetic, the "clean slate" stored in flash partition 6, and the
//! host-side calibration file (python-validity `sensor.py`).
//!
//! # Calibration file format
//!
//! python-validity keeps the calibration data in a raw file under `/var/run`. This
//! crate uses a small self-describing binary file instead ([`CalibrationFile`]),
//! all integers little-endian:
//!
//! | offset | size | field                                              |
//! |--------|------|----------------------------------------------------|
//! | 0      | 8    | magic `VRCALIB1`                                   |
//! | 8      | 2    | sensor type (from `cmd 0x75`, e.g. 0x0199)         |
//! | 10     | 2    | bytes per calibration line                         |
//! | 12     | 2    | number of calibration lines                        |
//! | 14     | 2    | reserved, 0                                        |
//! | 16     | 4    | data length `n` (= lines x bytes per line)         |
//! | 20     | 32   | SHA-256 of the data                                |
//! | 52     | n    | calibration data, as sent in capture programs      |
//!
//! A file whose magic, sensor type, geometry, length or hash does not match is
//! rejected, and the sensor is calibrated again.

use sha2::{Digest, Sha256};

use crate::cmd::Error;

/// Saturates to a signed byte and returns its two's-complement bits.
pub fn clip(x: i32) -> u8 {
    x.clamp(-128, 127) as i8 as u8
}

/// Scales a raw calibration sample around 0x80 (factor 10/34, truncating towards
/// zero like the reference's `int()`).
pub fn scale(x: u8) -> u8 {
    clip((x as i32 - 0x80) * 10 / 0x22)
}

/// Saturating sum of two signed bytes.
pub fn add(l: u8, r: u8) -> u8 {
    clip(l as i8 as i32 + r as i8 as i32)
}

/// Packs values as offsets from their minimum, `u` bits each, least significant
/// first. Returns `(u, minimum, packed)`.
///
/// python-validity crashes when all values are equal (`u == 0`); that case has no
/// known encoding and is reported as an error.
pub fn bitpack(values: &[u8]) -> Result<(u8, u8, Vec<u8>), Error> {
    let (Some(&min), Some(&max)) = (values.iter().min(), values.iter().max()) else {
        return Err(Error::Protocol("no factory calibration values".into()));
    };
    let u = (8 - (max - min).leading_zeros()) as usize;
    if u == 0 {
        return Err(Error::Protocol(
            "factory calibration values are all equal: cannot bit-pack".into(),
        ));
    }
    let mut out = vec![0u8; (u * values.len()).div_ceil(8)];
    for (k, &v) in values.iter().enumerate() {
        let d = (v - min) as usize;
        for bit in 0..u {
            if d >> bit & 1 == 1 {
                let pos = k * u + bit;
                out[pos / 8] |= 1 << (pos % 8);
            }
        }
    }
    Ok((u as u8, min, out))
}

/// Sensor geometry the calibration arithmetic depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub lines_per_frame: usize,
    pub bytes_per_line: usize,
    pub lines_per_calibration_data: usize,
    pub calibration_frames: usize,
}

impl Geometry {
    pub fn frame_size(&self) -> usize {
        self.lines_per_frame * self.bytes_per_line
    }

    /// Averages the frames of a raw calibration capture into one frame.
    ///
    /// With interleaved lines the second frame's interleaved line groups are
    /// averaged; otherwise frames from the third on are averaged per byte. This is
    /// the reference's (DLL-derived) choice of frames, kept as is. Fixed here: the
    /// reference fails with a single frame (undefined base address) and returns an
    /// empty frame with two frames, and silently averages a short capture; all
    /// three are errors or well defined.
    pub fn average(&self, raw: &[u8]) -> Result<Vec<u8>, Error> {
        let fs = self.frame_size();
        let bpl = self.bytes_per_line;
        if fs == 0 || self.lines_per_calibration_data == 0 {
            return Err(Error::Protocol("empty sensor geometry".into()));
        }
        let interleave = self.lines_per_frame / self.lines_per_calibration_data;
        let mut frames = self.calibration_frames;
        let short = || {
            Error::Protocol(format!(
                "calibration capture too short: {} bytes",
                raw.len()
            ))
        };
        if interleave > 1 {
            let base = if frames > 1 { fs } else { 0 };
            let frame = raw.get(base..base + fs).ok_or_else(short)?;
            let mut out = Vec::with_capacity(fs / interleave);
            for group in frame.chunks(interleave * bpl) {
                let lines: Vec<&[u8]> = group.chunks(bpl).collect();
                let width = lines.iter().map(|l| l.len()).min().unwrap_or(0);
                for col in 0..width {
                    let sum: usize = lines.iter().map(|l| l[col] as usize).sum();
                    out.push((sum / lines.len()) as u8);
                }
            }
            Ok(out)
        } else {
            let base = if frames > 1 {
                frames -= 2;
                2 * fs
            } else {
                0
            };
            if frames == 0 {
                return Err(Error::Protocol(
                    "no calibration frame left to average".into(),
                ));
            }
            let data = raw.get(base..base + fs * frames).ok_or_else(short)?;
            Ok((0..fs)
                .map(|i| {
                    let sum: usize = (0..frames).map(|f| data[f * fs + i] as usize).sum();
                    (sum / frames) as u8
                })
                .collect())
        }
    }
}

/// Folds one averaged calibration frame into the calibration data: every line
/// keeps its first 8 bytes and the rest is scaled; on later rounds the scaled
/// corrections are added (saturating) to the previous data, whose 8-byte line
/// headers are kept. The reference silently truncates mismatched lengths; here
/// they are an error.
pub fn process_calibration_results(
    prev: &[u8],
    cooked: &[u8],
    bytes_per_line: usize,
) -> Result<Vec<u8>, Error> {
    let frame: Vec<u8> = cooked
        .chunks(bytes_per_line)
        .flat_map(|l| {
            let n = l.len().min(8);
            l[..n]
                .iter()
                .copied()
                .chain(l[n..].iter().map(|&x| scale(x)))
                .collect::<Vec<_>>()
        })
        .collect();
    if prev.is_empty() {
        return Ok(frame);
    }
    if prev.len() != frame.len() {
        return Err(Error::Protocol(format!(
            "calibration size changed: {} then {} bytes",
            prev.len(),
            frame.len()
        )));
    }
    Ok(prev
        .chunks(bytes_per_line)
        .zip(frame.chunks(bytes_per_line))
        .flat_map(|(l, r)| {
            let n = l.len().min(8);
            l[..n]
                .iter()
                .copied()
                .chain(l[n..].iter().zip(&r[n..]).map(|(&a, &b)| add(a, b)))
                .collect::<Vec<_>>()
        })
        .collect())
}

/// The calibration line patched into timeslot tables, with 5 replaced by 4.
pub fn key_line(
    calib: &[u8],
    lines_per_calibration_data: usize,
    key_calibration_line: usize,
    line_width: usize,
) -> Result<Vec<u8>, Error> {
    if calib.is_empty() {
        return Ok(vec![0; line_width]);
    }
    let bpcl = calib.len() / lines_per_calibration_data;
    let off = 8 + bpcl * key_calibration_line;
    let line = calib.get(off..off + line_width).ok_or(Error::Protocol(
        "calibration data too short for the key line".into(),
    ))?;
    Ok(line.iter().map(|&b| if b == 5 { 4 } else { b }).collect())
}

pub const CLEAN_SLATE_MAGIC: u16 = 0x5002;
/// Header: magic, length, SHA-256, 32 zero bytes.
pub const CLEAN_SLATE_HDR: usize = 0x44;

/// Partition-6 image of a blank capture:
/// `5002 || len || sha256(body) || 0*32 || body`, `body = len(frame) || frame || 0000`.
pub fn clean_slate(frame: &[u8]) -> Vec<u8> {
    let mut body = (frame.len() as u16).to_le_bytes().to_vec();
    body.extend_from_slice(frame);
    body.extend_from_slice(&[0, 0]);
    let mut out = CLEAN_SLATE_MAGIC.to_le_bytes().to_vec();
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(&Sha256::digest(&body));
    out.extend_from_slice(&[0; 0x20]);
    out.extend(body);
    out
}

/// Parses a clean-slate header: `Some((body length, body hash))` when the magic
/// and the zero padding are right.
pub fn clean_slate_header(hdr: &[u8]) -> Option<(u16, [u8; 32])> {
    if hdr.len() < CLEAN_SLATE_HDR {
        return None;
    }
    if u16::from_le_bytes([hdr[0], hdr[1]]) != CLEAN_SLATE_MAGIC {
        return None;
    }
    if hdr[0x24..0x44].iter().any(|&b| b != 0) {
        log::warn!("unexpected contents in calibration flash partition");
        return None;
    }
    Some((
        u16::from_le_bytes([hdr[2], hdr[3]]),
        hdr[4..0x24].try_into().expect("32 bytes"),
    ))
}

const FILE_MAGIC: &[u8; 8] = b"VRCALIB1";
const FILE_HDR: usize = 52;

/// Host-side calibration data (see the module documentation for the format).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalibrationFile {
    pub sensor_type: u16,
    pub bytes_per_line: u16,
    pub lines: u16,
    pub data: Vec<u8>,
}

impl CalibrationFile {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = FILE_MAGIC.to_vec();
        for v in [self.sensor_type, self.bytes_per_line, self.lines, 0] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        b.extend_from_slice(&Sha256::digest(&self.data));
        b.extend_from_slice(&self.data);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let bad = |what: &str| Error::Protocol(format!("calibration file: {what}"));
        if b.len() < FILE_HDR || &b[..8] != FILE_MAGIC {
            return Err(bad("bad magic"));
        }
        let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let len = u32::from_le_bytes(b[16..20].try_into().expect("4 bytes")) as usize;
        let data = &b[FILE_HDR..];
        if data.len() != len {
            return Err(bad("length mismatch"));
        }
        if Sha256::digest(data).as_slice() != &b[20..52] {
            return Err(bad("hash mismatch"));
        }
        let f = CalibrationFile {
            sensor_type: u16_at(8),
            bytes_per_line: u16_at(10),
            lines: u16_at(12),
            data: data.to_vec(),
        };
        if f.bytes_per_line as usize * f.lines as usize != f.data.len() {
            return Err(bad("geometry does not match the data length"));
        }
        Ok(f)
    }

    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        Self::from_bytes(&std::fs::read(path)?)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    /// Writes through a temporary file and a rename, so a crash never leaves a
    /// truncated file behind.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.to_bytes())?;
        std::fs::rename(tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic() {
        assert_eq!(clip(-200), 0x80);
        assert_eq!(clip(200), 0x7f);
        assert_eq!(clip(-1), 0xff);
        assert_eq!(scale(0x80), 0);
        assert_eq!(scale(0x80 + 34), 10);
        assert_eq!(scale(0x80 + 33), 9);
        assert_eq!(scale(0x80 - 33), 0xf7); // -9, truncated towards zero
        assert_eq!(scale(0), 0xdb); // -128*10/34 = -37
        assert_eq!(add(0x7f, 1), 0x7f);
        assert_eq!(add(0x80, 0xff), 0x80);
        assert_eq!(add(0xfe, 3), 1);
    }

    #[test]
    fn bitpack_layout() {
        // deltas 0,1,2,3 in 2 bits each, LSB first: 0b11_10_01_00.
        assert_eq!(bitpack(&[5, 6, 7, 8]).unwrap(), (2, 5, vec![0xe4]));
        // 3 bits x 3 values = 9 bits -> 2 bytes.
        assert_eq!(bitpack(&[0, 7, 1]).unwrap(), (3, 0, vec![0x78, 0]));
        assert!(bitpack(&[4, 4]).is_err());
        assert!(bitpack(&[]).is_err());
        assert_eq!(bitpack(&[0, 255]).unwrap(), (8, 0, vec![0, 255]));
    }

    #[test]
    fn average_interleaved_and_plain() {
        let g = Geometry {
            lines_per_frame: 4,
            bytes_per_line: 2,
            lines_per_calibration_data: 2,
            calibration_frames: 3,
        };
        // frame 0 ignored; frame 1 = lines [1,2] [3,4] [5,6] [8,9]
        let raw = [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 8, 9, 7, 7];
        assert_eq!(g.average(&raw).unwrap(), [2, 3, 6, 7]);
        assert!(g.average(&raw[..15]).is_err());
        let g1 = Geometry {
            calibration_frames: 1,
            ..g
        };
        assert_eq!(g1.average(&raw[8..16]).unwrap(), [2, 3, 6, 7]);

        let p = Geometry {
            lines_per_frame: 1,
            bytes_per_line: 2,
            lines_per_calibration_data: 1,
            calibration_frames: 4,
        };
        // frames 2 and 3 averaged.
        assert_eq!(p.average(&[9, 9, 9, 9, 1, 2, 4, 7]).unwrap(), [2, 4]);
        let p2 = Geometry {
            calibration_frames: 2,
            ..p
        };
        assert!(p2.average(&[0; 8]).is_err());
    }

    #[test]
    fn process_and_key_line() {
        let cooked: Vec<u8> = (0..20).map(|i| 0x80 + i * 4).collect();
        let first = process_calibration_results(&[], &cooked, 10).unwrap();
        assert_eq!(&first[..8], &cooked[..8]);
        assert_eq!(first[8], scale(cooked[8]));
        let second = process_calibration_results(&first, &cooked, 10).unwrap();
        assert_eq!(&second[10..18], &first[10..18]);
        assert_eq!(second[19], add(first[19], scale(cooked[19])));
        assert!(process_calibration_results(&first, &cooked[..10], 10).is_err());

        let calib: Vec<u8> = (0..40).map(|i| if i == 19 { 5 } else { i }).collect();
        assert_eq!(key_line(&calib, 2, 1, 3).unwrap(), [28, 29, 30]);
        assert_eq!(key_line(&calib, 4, 1, 3).unwrap(), [18, 4, 20]);
        assert_eq!(key_line(&[], 4, 1, 3).unwrap(), [0, 0, 0]);
        assert!(key_line(&calib, 2, 1, 13).is_err());
    }

    #[test]
    fn clean_slate_format() {
        let cs = clean_slate(&[1, 2, 3]);
        assert_eq!(cs.len(), CLEAN_SLATE_HDR + 7);
        assert_eq!(&cs[..4], [0x02, 0x50, 7, 0]);
        let (len, hash) = clean_slate_header(&cs).unwrap();
        assert_eq!(len, 7);
        assert_eq!(&hash[..], Sha256::digest(&cs[CLEAN_SLATE_HDR..]).as_slice());
        assert_eq!(&cs[CLEAN_SLATE_HDR..], [3, 0, 1, 2, 3, 0, 0]);
        assert!(clean_slate_header(&[0xff; 0x44]).is_none());
        let mut bad = cs.clone();
        bad[0x30] = 1;
        assert!(clean_slate_header(&bad).is_none());
    }

    #[test]
    fn file_round_trip() {
        let f = CalibrationFile {
            sensor_type: 0x199,
            bytes_per_line: 3,
            lines: 2,
            data: vec![1, 2, 3, 4, 5, 6],
        };
        let b = f.to_bytes();
        assert_eq!(b.len(), 52 + 6);
        assert_eq!(&b[..8], b"VRCALIB1");
        assert_eq!(CalibrationFile::from_bytes(&b).unwrap(), f);
        let mut t = b.clone();
        t[53] ^= 1;
        assert!(CalibrationFile::from_bytes(&t).is_err());
        assert!(CalibrationFile::from_bytes(&b[..57]).is_err());
        let g = CalibrationFile {
            lines: 3,
            ..f.clone()
        };
        assert!(CalibrationFile::from_bytes(&g.to_bytes()).is_err());

        let dir = std::env::temp_dir().join(format!("vrcal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("calib.bin");
        f.save(&p).unwrap();
        assert_eq!(CalibrationFile::load(&p).unwrap(), f);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
