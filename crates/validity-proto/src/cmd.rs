//! Plain sensor commands and status handling (python-validity `usb.py`, `flash.py`).

use crate::transport::{Transport, TransportError};
use crate::vendor::Blobs;

#[derive(Debug)]
pub enum Error {
    Transport(TransportError),
    /// Non-zero status word returned by the sensor (0x044f: signature validation failed).
    Status(u16),
    Short,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Transport(e) => e.fmt(f),
            Error::Status(0x044f) => f.write_str("sensor status 044f: signature validation failed"),
            Error::Status(s) => write!(f, "sensor status {s:04x}"),
            Error::Short => f.write_str("reply too short"),
        }
    }
}

impl std::error::Error for Error {}

impl From<TransportError> for Error {
    fn from(e: TransportError) -> Self {
        Error::Transport(e)
    }
}

/// Splits a reply into its little-endian status word and payload.
pub fn status(rsp: &[u8]) -> Result<&[u8], Error> {
    if rsp.len() < 2 {
        return Err(Error::Short);
    }
    match u16::from_le_bytes([rsp[0], rsp[1]]) {
        0 => Ok(&rsp[2..]),
        s => Err(Error::Status(s)),
    }
}

pub fn checked(t: &mut impl Transport, out: &[u8]) -> Result<Vec<u8>, Error> {
    let rsp = t.cmd(out)?;
    status(&rsp)?;
    Ok(rsp)
}

/// Whether the firmware extension was already loaded when we started.
#[derive(Debug, PartialEq, Eq)]
pub enum FwextState {
    Loaded,
    CleanSlate,
}

/// Session start: ROM info, unknown 0x19, firmware info, then the init blob(s).
pub fn send_init(t: &mut impl Transport, blobs: &Blobs) -> Result<FwextState, Error> {
    checked(t, &[0x01])?;
    checked(t, &[0x19])?;
    let fw_info = t.cmd(&[0x43, 0x02])?;
    checked(t, &blobs.init_hardcoded)?;
    if fw_info.len() >= 2 && fw_info[..2] != [0, 0] {
        // The reply status of the clean-slate blob is not checked by the reference either.
        t.cmd(&blobs.init_hardcoded_clean_slate)?;
        return Ok(FwextState::CleanSlate);
    }
    Ok(FwextState::Loaded)
}

/// `0x40 partition 01 0000 addr(le32) size(le32)`; reply: status, `xx xx len(le32) xx xx`, data.
pub fn read_flash_cmd(partition: u8, addr: u32, size: u32) -> Vec<u8> {
    let mut c = vec![0x40, partition, 1, 0, 0];
    c.extend_from_slice(&addr.to_le_bytes());
    c.extend_from_slice(&size.to_le_bytes());
    c
}

pub fn parse_read_flash(rsp: &[u8]) -> Result<&[u8], Error> {
    let p = status(rsp)?;
    if p.len() < 6 {
        return Err(Error::Short);
    }
    let len = u32::from_le_bytes(p[..4].try_into().expect("4 bytes")) as usize;
    p.get(6..6 + len).ok_or(Error::Short)
}

/// Reads the TLS partition (1) in the clear, before the channel is open.
pub fn read_tls_flash(t: &mut impl Transport) -> Result<Vec<u8>, Error> {
    let rsp = t.cmd(&read_flash_cmd(1, 0, 0x1000))?;
    Ok(parse_read_flash(&rsp)?.to_vec())
}

/// Reboot command (sent over the channel once open). The sensor disconnects.
pub const REBOOT: [u8; 3] = [0x05, 0x02, 0x00];

/// Flash info (`0x3e`).
pub const GET_FLASH_INFO: [u8; 1] = [0x3e];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_flash_framing() {
        assert_eq!(
            read_flash_cmd(1, 0, 0x1000),
            [0x40, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0]
        );
        let rsp = [0, 0, 3, 0, 0, 0, 0xaa, 0xbb, 1, 2, 3, 9];
        assert_eq!(parse_read_flash(&rsp).unwrap(), [1, 2, 3]);
        assert!(matches!(
            parse_read_flash(&[0x4f, 0x04]),
            Err(Error::Status(0x044f))
        ));
        assert!(matches!(
            parse_read_flash(&[0, 0, 9, 0, 0, 0, 0, 0, 1]),
            Err(Error::Short)
        ));
    }
}
