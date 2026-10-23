//! Flash partitions, firmware info and raw flash access (python-validity `flash.py`).

use crate::cmd::{Error, Reader, checked, parse_read_flash, read_flash_cmd, status, status_word};
use crate::session::Sensor;
use crate::tables::{FlashIcInfo, flash_ic_lookup};
use crate::vendor::Blobs;

/// Partition types: 1 is the firmware (written blocks are decrypted with the
/// firmware key on the fly). Access level 2 is write only, 7 is readable and
/// writable without the channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionInfo {
    pub id: u8,
    pub kind: u8,
    pub access_lvl: u16,
    pub offset: u32,
    pub size: u32,
}

impl PartitionInfo {
    pub const LEN: usize = 12;

    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(b, "partition entry");
        let p = PartitionInfo {
            id: r.u8()?,
            kind: r.u8()?,
            access_lvl: r.u16()?,
            offset: r.u32()?,
            size: r.u32()?,
        };
        r.end()?;
        Ok(p)
    }

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0] = self.id;
        b[1] = self.kind;
        b[2..4].copy_from_slice(&self.access_lvl.to_le_bytes());
        b[4..8].copy_from_slice(&self.offset.to_le_bytes());
        b[8..12].copy_from_slice(&self.size.to_le_bytes());
        b
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashInfo {
    pub ic: &'static FlashIcInfo,
    pub blocks: u16,
    pub unknown0: u16,
    pub blocksize: u16,
    pub unknown1: u16,
    pub partitions: Vec<PartitionInfo>,
}

/// Parses the reply to `0x3e`.
pub fn parse_flash_info(rsp: &[u8]) -> Result<FlashInfo, Error> {
    let mut r = Reader::new(status(rsp)?, "flash info");
    let (jid0, jid1) = (r.u16()?, r.u16()?);
    let (blocks, unknown0, blocksize, unknown1) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
    let count = r.u16()? as usize;
    let partitions = (0..count)
        .map(|_| PartitionInfo::parse(r.bytes(PartitionInfo::LEN)?))
        .collect::<Result<Vec<_>, _>>()?;
    let size = blocks as u32 * blocksize as u32;
    let ic = flash_ic_lookup(jid0, jid1, size).ok_or_else(|| {
        Error::Protocol(format!(
            "unknown flash IC: JEDEC id {jid0:x}:{jid1:x}, size {blocks}x{blocksize}"
        ))
    })?;
    Ok(FlashInfo {
        ic,
        blocks,
        unknown0,
        blocksize,
        unknown1,
        partitions,
    })
}

pub fn get_flash_info(s: &mut impl Sensor) -> Result<FlashInfo, Error> {
    parse_flash_info(&s.cmd(&[0x3e])?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleInfo {
    pub kind: u16,
    pub subtype: u16,
    pub major: u16,
    pub minor: u16,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareInfo {
    pub major: u16,
    pub minor: u16,
    pub buildtime: u32,
    pub modules: Vec<ModuleInfo>,
}

/// Status of `0x43` when the partition holds no firmware.
pub const STATUS_NO_FIRMWARE: u16 = 0x04b0;

/// Parses the reply to `0x43 partition`; `None` when no firmware is present.
pub fn parse_fw_info(rsp: &[u8]) -> Result<Option<FirmwareInfo>, Error> {
    if rsp.len() == 2 && status_word(rsp)? == STATUS_NO_FIRMWARE {
        return Ok(None);
    }
    let mut r = Reader::new(status(rsp)?, "firmware info");
    let (major, minor, count, buildtime) = (r.u16()?, r.u16()?, r.u16()?, r.u32()?);
    let modules = (0..count)
        .map(|_| {
            Ok(ModuleInfo {
                kind: r.u16()?,
                subtype: r.u16()?,
                major: r.u16()?,
                minor: r.u16()?,
                size: r.u32()?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(Some(FirmwareInfo {
        major,
        minor,
        buildtime,
        modules,
    }))
}

pub fn get_fw_info(s: &mut impl Sensor, partition: u8) -> Result<Option<FirmwareInfo>, Error> {
    parse_fw_info(&s.cmd(&[0x43, partition])?)
}

/// Unlocks flash and database writes until the next `call_cleanups`.
pub fn write_enable(s: &mut impl Sensor, blobs: &Blobs) -> Result<(), Error> {
    checked(s, &blobs.db_write_enable).map(|_| ())
}

/// Status of `0x1a` when there is nothing to commit.
pub const STATUS_NOTHING_TO_COMMIT: u16 = 0x0491;

/// Commits (and locks) after writes.
pub fn call_cleanups(s: &mut impl Sensor) -> Result<(), Error> {
    let rsp = s.cmd(&[0x1a])?;
    if status_word(&rsp)? == STATUS_NOTHING_TO_COMMIT {
        return Ok(());
    }
    status(&rsp).map(|_| ())
}

/// Runs `body` then `call_cleanups`, like the reference's `try/finally`: the first
/// error wins, and the cleanup runs even when `body` failed.
pub(crate) fn with_cleanups<T>(
    s: &mut impl Sensor,
    body: impl FnOnce(&mut dyn FnMut(&[u8]) -> Result<Vec<u8>, Error>) -> Result<T, Error>,
) -> Result<T, Error> {
    let r = body(&mut |p| s.cmd(p));
    let c = call_cleanups(s);
    let v = r?;
    c?;
    Ok(v)
}

pub fn erase_flash(s: &mut impl Sensor, blobs: &Blobs, partition: u8) -> Result<(), Error> {
    write_enable(s, blobs)?;
    with_cleanups(s, |cmd| status(&cmd(&[0x3f, partition])?).map(|_| ()))
}

pub fn read_flash(
    s: &mut impl Sensor,
    partition: u8,
    addr: u32,
    size: u32,
) -> Result<Vec<u8>, Error> {
    let rsp = s.cmd(&read_flash_cmd(partition, addr, size))?;
    Ok(parse_read_flash(&rsp)?.to_vec())
}

/// `0x41 partition 01 0000 addr(le32) len(le32) data`.
pub fn write_flash_cmd(partition: u8, addr: u32, buf: &[u8]) -> Vec<u8> {
    let mut c = vec![0x41, partition, 1, 0, 0];
    c.extend_from_slice(&addr.to_le_bytes());
    c.extend_from_slice(&(buf.len() as u32).to_le_bytes());
    c.extend_from_slice(buf);
    c
}

// python-validity ignores the status of the write-enable blob here (but not in
// `erase_flash`); a refused unlock is reported instead of writing anyway.
pub fn write_flash(
    s: &mut impl Sensor,
    blobs: &Blobs,
    partition: u8,
    addr: u32,
    buf: &[u8],
) -> Result<(), Error> {
    write_enable(s, blobs)?;
    with_cleanups(s, |cmd| {
        status(&cmd(&write_flash_cmd(partition, addr, buf))?).map(|_| ())
    })
}

pub const FLASH_CHUNK: usize = 0x1000;

pub fn write_flash_all(
    s: &mut impl Sensor,
    blobs: &Blobs,
    partition: u8,
    mut addr: u32,
    buf: &[u8],
) -> Result<(), Error> {
    for chunk in buf.chunks(FLASH_CHUNK) {
        write_flash(s, blobs, partition, addr, chunk)?;
        addr += chunk.len() as u32;
    }
    Ok(())
}

/// Reads `size` bytes from `start`, one 4 KiB read at a time.
pub fn read_flash_all(
    s: &mut impl Sensor,
    partition: u8,
    start: u32,
    size: u32,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(size as usize);
    for addr in (start..start + size).step_by(FLASH_CHUNK) {
        out.extend(read_flash(s, partition, addr, FLASH_CHUNK as u32)?);
    }
    out.truncate(size as usize);
    Ok(out)
}

/// `0x42 partition 00 len(le16) signature`.
pub fn write_fw_signature(
    s: &mut impl Sensor,
    partition: u8,
    signature: &[u8],
) -> Result<(), Error> {
    let mut c = vec![0x42, partition, 0];
    c.extend_from_slice(&(signature.len() as u16).to_le_bytes());
    c.extend_from_slice(signature);
    checked(s, &c).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Script, blobs};

    fn flash_info_reply(parts: &[PartitionInfo]) -> Vec<u8> {
        let mut r = vec![0, 0];
        for v in [0xefu16, 0x40, 0x100, 0, 0x1000, 0, parts.len() as u16] {
            r.extend_from_slice(&v.to_le_bytes());
        }
        for p in parts {
            r.extend_from_slice(&p.to_bytes());
        }
        r
    }

    #[test]
    fn flash_info() {
        let p = PartitionInfo {
            id: 4,
            kind: 3,
            access_lvl: 5,
            offset: 0x50000,
            size: 0x80000,
        };
        assert_eq!(PartitionInfo::parse(&p.to_bytes()).unwrap(), p);
        let info = parse_flash_info(&flash_info_reply(&[p])).unwrap();
        assert_eq!(info.ic.name, "W25Q80B");
        assert_eq!((info.blocks, info.blocksize), (0x100, 0x1000));
        assert_eq!(info.partitions, [p]);
        assert!(
            parse_flash_info(&flash_info_reply(&[]))
                .unwrap()
                .partitions
                .is_empty()
        );
        let mut short = flash_info_reply(&[p]);
        short.pop();
        assert!(parse_flash_info(&short).is_err());
        let mut unknown = flash_info_reply(&[]);
        unknown[2] = 0x99;
        assert!(matches!(
            parse_flash_info(&unknown),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn fw_info() {
        assert_eq!(parse_fw_info(&[0xb0, 0x04]).unwrap(), None);
        assert!(matches!(
            parse_fw_info(&[0xb1, 0x04]),
            Err(Error::Status(0x04b1))
        ));
        let mut r = vec![0, 0, 1, 0, 2, 0, 1, 0, 0xc2, 0x8c, 0x74, 0x5a];
        r.extend_from_slice(&[1, 0, 0x34, 0x46, 2, 0, 7, 0, 0xd0, 0x3e, 0, 0]);
        let fw = parse_fw_info(&r).unwrap().unwrap();
        assert_eq!((fw.major, fw.minor, fw.buildtime), (1, 2, 0x5a748cc2));
        assert_eq!(
            fw.modules,
            [ModuleInfo {
                kind: 1,
                subtype: 0x4634,
                major: 2,
                minor: 7,
                size: 0x3ed0
            }]
        );
        assert!(parse_fw_info(&r[..r.len() - 1]).is_err());
    }

    #[test]
    fn write_erase_read_sequences() {
        let b = blobs();
        let wen = b.db_write_enable.clone();
        let data: Vec<u8> = (0..0x1801u32).map(|i| i as u8).collect();
        let mut s = Script::new(vec![
            (wen.clone(), vec![0, 0]),
            (
                write_flash_cmd(6, 0x10, &data[..0x1000]),
                vec![0, 0, 0, 0x10, 0, 0],
            ),
            (vec![0x1a], vec![0, 0]),
            (wen.clone(), vec![0, 0]),
            (write_flash_cmd(6, 0x1010, &data[0x1000..]), vec![0, 0]),
            (vec![0x1a], vec![0x91, 0x04]),
            (wen.clone(), vec![0, 0]),
            (vec![0x3f, 2], vec![0x01, 0x04]),
            (vec![0x1a], vec![0, 0]),
            (wen.clone(), vec![0x4f, 0x04]),
            (read_flash_cmd(6, 0x44, 0x1000), {
                let mut r = vec![0, 0, 0, 0x10, 0, 0, 0, 0];
                r.extend(&data[..0x1000]);
                r
            }),
            (read_flash_cmd(6, 0x1044, 0x1000), {
                let mut r = vec![0, 0, 0, 0x10, 0, 0, 0, 0];
                r.extend(&data[0x800..0x1800]);
                r
            }),
            (
                {
                    let mut c = vec![0x42, 2, 0, 3, 0];
                    c.extend([9, 9, 9]);
                    c
                },
                vec![0, 0],
            ),
        ]);
        write_flash_all(&mut s, &b, 6, 0x10, &data).unwrap();
        // The erase command fails; the cleanup still runs and the first error wins.
        assert!(matches!(
            erase_flash(&mut s, &b, 2),
            Err(Error::Status(0x0401))
        ));
        // A refused write enable stops the write before any data is sent.
        assert!(matches!(
            write_flash(&mut s, &b, 1, 0, &[1]),
            Err(Error::Status(0x044f))
        ));
        let r = read_flash_all(&mut s, 6, 0x44, 0x1001).unwrap();
        assert_eq!(&r[..0x1000], &data[..0x1000]);
        assert_eq!(r[0x1000], data[0x800]);
        assert_eq!(r.len(), 0x1001);
        write_fw_signature(&mut s, 2, &[9, 9, 9]).unwrap();
        s.done();
    }
}
