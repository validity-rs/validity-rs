//! Plain sensor commands, status handling and the crate error type (python-validity
//! `usb.py`, `util.py`).

use crate::channel;
use crate::session::Sensor;
use crate::transport::TransportError;
use crate::vendor::Blobs;

#[derive(Debug)]
pub enum Error {
    Transport(TransportError),
    /// Non-zero status word returned by the sensor (0x044f: signature validation failed).
    Status(u16),
    Short,
    /// The encrypted channel failed (handshake, MAC, pairing material).
    Channel(channel::Error),
    /// A reply did not have the expected layout.
    Malformed(&'static str),
    /// A reply was well formed but its content is not what the protocol expects.
    Protocol(String),
    /// The operation was cancelled while waiting for the sensor.
    Cancelled,
    /// The operation is not available on this sensor or transport.
    Unsupported(&'static str),
    /// A replayed session diverged from the recorded one.
    Replay(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Transport(e) => e.fmt(f),
            Error::Status(0x044f) => f.write_str("sensor status 044f: signature validation failed"),
            Error::Status(s) => write!(f, "sensor status {s:04x}"),
            Error::Short => f.write_str("reply too short"),
            Error::Channel(e) => e.fmt(f),
            Error::Malformed(s) => write!(f, "malformed reply: {s}"),
            Error::Protocol(s) => f.write_str(s),
            Error::Cancelled => f.write_str("cancelled"),
            Error::Unsupported(s) => write!(f, "unsupported: {s}"),
            Error::Replay(s) => write!(f, "replay mismatch: {s}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<TransportError> for Error {
    fn from(e: TransportError) -> Self {
        Error::Transport(e)
    }
}

impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Error::Channel(e)
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

/// The status word of a reply, without failing on a non-zero value.
pub fn status_word(rsp: &[u8]) -> Result<u16, Error> {
    match rsp {
        [a, b, ..] => Ok(u16::from_le_bytes([*a, *b])),
        _ => Err(Error::Short),
    }
}

/// Sends a command and fails unless the reply status is zero; returns the whole reply.
pub fn checked(s: &mut impl Sensor, out: &[u8]) -> Result<Vec<u8>, Error> {
    let rsp = s.cmd(out)?;
    status(&rsp)?;
    Ok(rsp)
}

/// ROM version (`cmd 0x01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RomInfo {
    pub timestamp: u32,
    pub build: u32,
    pub major: u8,
    pub minor: u8,
    pub product: u8,
    pub u1: u8,
}

impl RomInfo {
    pub fn parse(rsp: &[u8]) -> Result<Self, Error> {
        let b = status(rsp)?;
        if b.len() < 0x10 {
            return Err(Error::Malformed("ROM info"));
        }
        Ok(RomInfo {
            timestamp: u32::from_le_bytes(b[0..4].try_into().expect("4 bytes")),
            build: u32::from_le_bytes(b[4..8].try_into().expect("4 bytes")),
            major: b[8],
            minor: b[9],
            product: b[11],
            u1: b[15],
        })
    }

    pub fn get(s: &mut impl Sensor) -> Result<Self, Error> {
        Self::parse(&s.cmd(&[0x01])?)
    }
}

/// Whether the firmware extension was already loaded when we started.
#[derive(Debug, PartialEq, Eq)]
pub enum FwextState {
    Loaded,
    CleanSlate,
}

/// Session start: ROM info, unknown 0x19, firmware info, then the init blob(s).
pub fn send_init(s: &mut impl Sensor, blobs: &Blobs) -> Result<FwextState, Error> {
    checked(s, &[0x01])?;
    checked(s, &[0x19])?;
    let fw_info = s.cmd(&[0x43, 0x02])?;
    checked(s, &blobs.init_hardcoded)?;
    if fw_info.len() >= 2 && fw_info[..2] != [0, 0] {
        // The reply status of the clean-slate blob is not checked by the reference either.
        s.cmd(&blobs.init_hardcoded_clean_slate)?;
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

/// Reads the TLS partition (1). Called before the channel is open, so it goes in the clear.
pub fn read_tls_flash(s: &mut impl Sensor) -> Result<Vec<u8>, Error> {
    let rsp = s.cmd(&read_flash_cmd(1, 0, 0x1000))?;
    Ok(parse_read_flash(&rsp)?.to_vec())
}

/// Reboot command (sent over the channel once open). The sensor disconnects.
pub const REBOOT: [u8; 3] = [0x05, 0x02, 0x00];

/// Flash info (`0x3e`).
pub const GET_FLASH_INFO: [u8; 1] = [0x3e];

/// Little-endian readers over a reply; every read is bounds-checked.
pub(crate) struct Reader<'a> {
    pub buf: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8], what: &'static str) -> Self {
        Reader { buf, what }
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.buf.len() < n {
            return Err(Error::Malformed(self.what));
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Ok(a)
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(
            self.bytes(2)?.try_into().expect("2 bytes"),
        ))
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.bytes(4)?.try_into().expect("4 bytes"),
        ))
    }

    pub fn skip(&mut self, n: usize) -> Result<(), Error> {
        self.bytes(n).map(|_| ())
    }

    pub fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.buf)
    }

    /// Fails unless everything was consumed.
    pub fn end(&self) -> Result<(), Error> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed(self.what))
        }
    }
}

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

    #[test]
    fn reader_bounds() {
        let mut r = Reader::new(&[1, 2, 3, 4, 5, 6, 7], "t");
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u16().unwrap(), 0x0302);
        assert!(r.end().is_err());
        assert_eq!(r.u32().unwrap(), 0x07060504);
        assert!(r.end().is_ok());
        assert!(matches!(r.u8(), Err(Error::Malformed("t"))));
        assert_eq!(status_word(&[0xb3, 0x04, 9]).unwrap(), 0x04b3);
        assert!(matches!(status_word(&[1]), Err(Error::Short)));
    }
}
