//! Replaying recorded sessions: a parser for python-validity debug logs (with
//! `usb.trace_enabled` and `tls.trace_enabled`) and a [`Sensor`] that answers from
//! the recording while checking that every command we send is byte-identical to
//! the recorded one.
//!
//! Log lines used (after the `logging` timestamp):
//! - `>cmd> HEX` / `<cmd< HEX`: raw USB command and reply;
//! - `>tls> 17: HEX` / `<tls< 17: HEX`: application plaintext inside the channel
//!   (the raw record that follows or precedes it is skipped);
//! - `>tls> 16: …` / `<tls< 16: …`: encrypted handshake (Finished) messages;
//! - `<int< HEX`: an interrupt; `<130< N bytes`: a bulk read on endpoint 0x82
//!   (only its length is logged);
//! - `RESULT …`: outcome lines written by the capturing script.
//!
//! Recordings contain device secrets (pairing keys, serials, templates); they are
//! read at test time and never stored in this repository.

use std::collections::BTreeMap;
use std::ops::Range;

use p256::ecdsa::VerifyingKey;

use crate::channel::{firmware_key, parse_ecdh_block};
use crate::cmd::Error;
use crate::db::parse_identity;
use crate::hex;
use crate::pairing::{CERT_LEN, tls_flash_blocks};
use crate::session::Sensor;
use crate::sid::Sid;
use crate::timeslot::{self, split_chunks};
use crate::tls;

/// One recorded exchange or event, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A command in the clear; `rx` is `None` when no reply was logged.
    Plain {
        tx: Vec<u8>,
        rx: Option<Vec<u8>>,
    },
    /// A raw handshake exchange (`44000000…`).
    Handshake {
        tx: Vec<u8>,
        rx: Option<Vec<u8>>,
    },
    /// An application command inside the channel, as plaintext.
    App {
        tx: Vec<u8>,
        rx: Option<Vec<u8>>,
    },
    Interrupt(Vec<u8>),
    /// A bulk read on endpoint 0x82 of this many bytes (`None`: the read failed).
    Bulk82(Option<usize>),
}

impl Event {
    fn describe(&self) -> String {
        let short = |b: &[u8]| {
            let h = hex::encode(&b[..b.len().min(12)]);
            format!(
                "{h}{} ({} bytes)",
                if b.len() > 12 { "…" } else { "" },
                b.len()
            )
        };
        match self {
            Event::Plain { tx, .. } => format!("plain command {}", short(tx)),
            Event::Handshake { tx, .. } => format!("handshake {}", short(tx)),
            Event::App { tx, .. } => format!("application command {}", short(tx)),
            Event::Interrupt(b) => format!("interrupt {}", hex::encode(b)),
            Event::Bulk82(n) => format!("bulk read {n:?}"),
        }
    }
}

/// A parsed recording.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trace {
    pub events: Vec<Event>,
    /// `RESULT` lines, without the prefix.
    pub results: Vec<String>,
}

const HANDSHAKE_PREFIX: [u8; 4] = [0x44, 0, 0, 0];

#[derive(Default)]
struct Pending {
    app_tx: Option<Vec<u8>>,
    finished_tx: bool,
    current: Option<Event>,
}

impl Pending {
    fn flush(&mut self, out: &mut Vec<Event>) {
        if let Some(e) = self.current.take() {
            out.push(e);
        }
    }
}

fn bad(line: usize, what: &str) -> Error {
    Error::Replay(format!("log line {line}: {what}"))
}

/// The message part of a log line: after `YYYY-MM-DD HH:MM:SS,mmm ` or `LEVEL:logger:`.
fn message(line: &str) -> &str {
    let b = line.as_bytes();
    if b.len() > 24 && b[4] == b'-' && b[10] == b' ' && b[19] == b',' && b[23] == b' ' {
        return &line[24..];
    }
    for level in ["DEBUG:", "INFO:", "WARNING:", "ERROR:"] {
        if let Some(rest) = line.strip_prefix(level)
            && let Some((_, msg)) = rest.split_once(':')
        {
            return msg;
        }
    }
    line
}

/// Parses a python-validity debug log into the exchange sequence.
pub fn parse_log(text: &str) -> Result<Trace, Error> {
    let mut t = Trace::default();
    let mut p = Pending::default();
    for (n, line) in text.lines().enumerate() {
        let n = n + 1;
        let msg = message(line.trim_end());
        let hex_arg = |s: &str| hex::decode(s.trim()).ok_or_else(|| bad(n, "bad hex"));
        if let Some(rest) = msg.strip_prefix(">tls> ") {
            let (kind, body) = rest
                .split_once(": ")
                .ok_or_else(|| bad(n, "bad >tls> line"))?;
            match kind {
                "17" => {
                    if p.app_tx.is_some() {
                        return Err(bad(n, "two application payloads for one record"));
                    }
                    p.app_tx = Some(hex_arg(body)?);
                }
                "16" => p.finished_tx = true,
                _ => return Err(bad(n, "unknown record type")),
            }
        } else if let Some(rest) = msg.strip_prefix(">cmd> ") {
            p.flush(&mut t.events);
            let raw = hex_arg(rest)?;
            p.current = Some(if let Some(tx) = p.app_tx.take() {
                if !raw.starts_with(&[tls::CONTENT_APP_DATA, 3, 3]) {
                    return Err(bad(n, "application payload not followed by a record"));
                }
                Event::App { tx, rx: None }
            } else if raw.starts_with(&HANDSHAKE_PREFIX) {
                p.finished_tx = false;
                Event::Handshake { tx: raw, rx: None }
            } else {
                if p.finished_tx {
                    return Err(bad(n, "Finished not followed by a handshake"));
                }
                Event::Plain { tx: raw, rx: None }
            });
        } else if let Some(rest) = msg.strip_prefix("<cmd< ") {
            let raw = hex_arg(rest)?;
            match &mut p.current {
                Some(Event::Plain { rx, .. } | Event::Handshake { rx, .. }) if rx.is_none() => {
                    *rx = Some(raw)
                }
                Some(Event::App { rx, .. }) if rx.is_none() => *rx = Some(Vec::new()),
                _ => return Err(bad(n, "reply without command")),
            }
        } else if let Some(rest) = msg.strip_prefix("<tls< ") {
            let (kind, body) = rest
                .split_once(": ")
                .ok_or_else(|| bad(n, "bad <tls< line"))?;
            match (kind, &mut p.current) {
                ("17", Some(Event::App { rx: Some(rx), .. })) => rx.extend(hex_arg(body)?),
                ("16", Some(Event::Handshake { rx: Some(_), .. })) => {}
                _ => return Err(bad(n, "record outside its exchange")),
            }
        } else if let Some(rest) = msg.strip_prefix("<int< ") {
            p.flush(&mut t.events);
            t.events.push(Event::Interrupt(hex_arg(rest)?));
        } else if let Some(rest) = msg.strip_prefix("<130< ") {
            p.flush(&mut t.events);
            let n_bytes = rest.strip_suffix(" bytes").and_then(|s| s.parse().ok());
            t.events.push(Event::Bulk82(n_bytes));
        } else if let Some(rest) = msg.strip_prefix("RESULT ") {
            p.flush(&mut t.events);
            t.results.push(rest.to_string());
        }
    }
    if p.app_tx.is_some() || p.finished_tx {
        return Err(Error::Replay("log ends inside an exchange".into()));
    }
    p.flush(&mut t.events);
    Ok(t)
}

/// Which bytes of a recorded command a [`Mask`] ignores, if it applies to it.
pub type MaskRanges = Box<dyn Fn(&[u8]) -> Option<Vec<Range<usize>>>>;

/// Bytes of a recorded command that are allowed to differ, with the reason.
pub struct Mask {
    pub name: &'static str,
    /// The ranges to ignore if the mask applies to this recorded command.
    pub ranges: MaskRanges,
}

impl core::fmt::Debug for Mask {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mask")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Comparison counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    /// Commands identical to the recording.
    pub exact: usize,
    /// Commands identical outside masked ranges, per mask.
    pub masked: BTreeMap<&'static str, usize>,
    /// Bytes compared (recorded command lengths) and bytes excluded by masks.
    pub bytes_compared: usize,
    pub bytes_masked: usize,
    /// Handshakes checked structurally.
    pub handshakes: usize,
    pub interrupts: usize,
    pub bulk_reads: usize,
}

/// A sensor that plays back a [`Trace`].
pub struct ReplaySensor {
    events: Vec<Event>,
    pos: usize,
    open: bool,
    masks: Vec<Mask>,
    /// First divergence; every later call fails with it.
    failed: Option<String>,
    /// Key that must have signed the sensor's ECDH key (TLS flash block 6).
    fw_key: VerifyingKey,
    pub stats: Stats,
}

impl core::fmt::Debug for ReplaySensor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReplaySensor")
            .field("events", &self.events.len())
            .field("pos", &self.pos)
            .field("open", &self.open)
            .field("masks", &self.masks)
            .field("failed", &self.failed)
            .field("stats", &self.stats)
            .finish()
    }
}

impl ReplaySensor {
    pub fn new(trace: &Trace) -> Self {
        ReplaySensor {
            events: trace.events.clone(),
            pos: 0,
            open: false,
            masks: Vec::new(),
            failed: None,
            fw_key: firmware_key(),
            stats: Stats::default(),
        }
    }

    /// Replaces the firmware key that must have signed the sensor's ECDH key in
    /// the TLS flash image given to [`Sensor::open_channel`] (by default the
    /// vendor key of real sensors, as in [`crate::session::UsbSession`]). A test
    /// seam: synthetic recordings sign their sensor key with their own firmware
    /// key, so that the handshake checks can be exercised without device data.
    pub fn with_firmware_key(mut self, key: VerifyingKey) -> Self {
        self.fw_key = key;
        self
    }

    pub fn with_mask(mut self, m: Mask) -> Self {
        self.masks.push(m);
        self
    }

    /// Events not consumed yet.
    pub fn remaining(&self) -> usize {
        self.events.len() - self.pos
    }

    pub fn finish(&self) -> Result<&Stats, Error> {
        if let Some(f) = &self.failed {
            return Err(Error::Replay(f.clone()));
        }
        match self.events.get(self.pos) {
            None => Ok(&self.stats),
            Some(e) => Err(Error::Replay(format!(
                "event {}: session ended early; next: {}",
                self.pos,
                e.describe()
            ))),
        }
    }

    fn err(&mut self, what: String) -> Error {
        let msg = format!("event {}: {what}", self.pos);
        self.failed.get_or_insert(msg.clone());
        Error::Replay(msg)
    }

    fn next(&mut self, want: &str) -> Result<Event, Error> {
        if let Some(f) = &self.failed {
            return Err(Error::Replay(f.clone()));
        }
        let e = self
            .events
            .get(self.pos)
            .cloned()
            .ok_or_else(|| self.err(format!("recording ended, wanted {want}")))?;
        self.pos += 1;
        Ok(e)
    }

    fn unexpected(&mut self, e: &Event, want: String) -> Error {
        self.pos -= 1;
        self.err(format!("recording has {}, we did {want}", e.describe()))
    }

    fn compare(&mut self, recorded: &[u8], ours: &[u8]) -> Result<(), Error> {
        self.stats.bytes_compared += recorded.len();
        if recorded == ours {
            self.stats.exact += 1;
            return Ok(());
        }
        let first_diff = recorded
            .iter()
            .zip(ours)
            .position(|(a, b)| a != b)
            .unwrap_or(recorded.len().min(ours.len()));
        if recorded.len() == ours.len() {
            for m in &self.masks {
                let Some(ranges) = (m.ranges)(recorded) else {
                    continue;
                };
                let masked = |i: usize| ranges.iter().any(|r| r.contains(&i));
                if recorded
                    .iter()
                    .zip(ours)
                    .enumerate()
                    .all(|(i, (a, b))| a == b || masked(i))
                {
                    *self.stats.masked.entry(m.name).or_default() += 1;
                    self.stats.bytes_masked += ranges.iter().map(|r| r.len()).sum::<usize>();
                    return Ok(());
                }
            }
        }
        self.pos -= 1;
        Err(self.err(format!(
            "command differs from the recording at byte {first_diff} (recorded {} bytes, ours {}): recorded {}…, ours {}…",
            recorded.len(),
            ours.len(),
            hex::encode(&recorded[first_diff.min(recorded.len())..(first_diff + 16).min(recorded.len())]),
            hex::encode(&ours[first_diff.min(ours.len())..(first_diff + 16).min(ours.len())]),
        )))
    }

    /// Checks the two handshake exchanges against what our channel would send:
    /// the ClientHello rebuilt from its recorded random, and the certificate
    /// message built from the TLS flash image. The key exchange, the signature
    /// and the encrypted Finished depend on fresh randomness and are not compared.
    fn check_handshake(&mut self, tls_flash: &[u8]) -> Result<(), Error> {
        let blocks = tls_flash_blocks(tls_flash)?;
        let block = |id| {
            blocks
                .iter()
                .find(|(i, _)| *i == id)
                .map(|(_, b)| *b)
                .ok_or_else(|| Error::Replay(format!("TLS flash image without block {id}")))
        };
        let cert = block(3)?;
        // The real sensor's ECDH key must verify under the firmware key.
        parse_ecdh_block(block(6)?, &self.fw_key)?;

        let hello = match self.next("handshake")? {
            Event::Handshake { tx, .. } => tx,
            e => return Err(self.unexpected(&e, "a handshake".into())),
        };
        let random: [u8; 32] = hello
            .get(15..47)
            .and_then(|r| r.try_into().ok())
            .ok_or(Error::Malformed("short ClientHello"))?;
        let mut ours = HANDSHAKE_PREFIX.to_vec();
        ours.extend(tls::record(
            tls::CONTENT_HANDSHAKE,
            &tls::client_hello(&random),
        ));
        self.compare(&hello, &ours)?;

        let second = match self.next("handshake")? {
            Event::Handshake { tx, .. } => tx,
            e => return Err(self.unexpected(&e, "a handshake".into())),
        };
        let l = (cert.len() as u16).to_be_bytes();
        let mut body = vec![0, l[0], l[1], 0, l[0], l[1], 0xac, 0x16];
        body.extend_from_slice(cert);
        let cert_msg = tls::handshake_msg(0x0b, &body);
        let structure_ok = (|| {
            let rec_len = u16::from_be_bytes(second.get(7..9)?.try_into().ok()?) as usize;
            let hs = second.get(9..9 + rec_len)?;
            let rest = second.get(9 + rec_len..)?;
            let (c, hs) = hs.split_at_checked(cert_msg.len())?;
            if c != cert_msg.as_slice() || second[4..7] != [tls::CONTENT_HANDSHAKE, 3, 3] {
                return None;
            }
            // ClientKeyExchange: an uncompressed point (python-validity drops leading
            // zero bytes of the coordinates, so the length may be short).
            let msg_len = |h: &[u8]| {
                Some(u32::from_be_bytes([0, *h.get(1)?, *h.get(2)?, *h.get(3)?]) as usize)
            };
            let kex_len = msg_len(hs)?;
            if hs[0] != 0x10 || hs.get(4) != Some(&4) || kex_len > 65 {
                return None;
            }
            let hs = hs.get(4 + kex_len..)?;
            let ver_len = msg_len(hs)?;
            if hs[0] != 0x0f || hs.len() != 4 + ver_len {
                return None;
            }
            // ChangeCipherSpec, then the encrypted Finished (IV + 16 + 32 + padding).
            (rest.starts_with(&[
                tls::CONTENT_CHANGE_CIPHER_SPEC,
                3,
                3,
                0,
                1,
                1,
                tls::CONTENT_HANDSHAKE,
                3,
                3,
            ]) && rest.len() == 11 + 80)
                .then_some(())
        })();
        if structure_ok.is_none() {
            self.pos -= 1;
            return Err(self.err("second handshake message does not carry our certificate".into()));
        }
        self.stats.bytes_compared += 9 + cert_msg.len();
        self.stats.handshakes += 1;
        Ok(())
    }
}

/// Deterministic stand-in for image data, which the logs do not contain.
fn synthetic_image(n: usize) -> Vec<u8> {
    let mut x = 0x1234_5678u32;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (x >> 16) as u8
        })
        .collect()
}

impl Sensor for ReplaySensor {
    fn cmd(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let e = self.next("a command")?;
        let (tx, rx) = match (&e, self.open) {
            (Event::Plain { tx, rx }, false) | (Event::App { tx, rx }, true) => {
                (tx.clone(), rx.clone())
            }
            _ => {
                let kind = if self.open {
                    "an application"
                } else {
                    "a plain"
                };
                return Err(self.unexpected(
                    &e,
                    format!(
                        "{kind} command {}",
                        hex::encode(&payload[..payload.len().min(12)])
                    ),
                ));
            }
        };
        self.compare(&tx, payload)?;
        rx.ok_or(Error::Transport(
            crate::transport::TransportError::Disconnected,
        ))
    }

    fn is_open(&self) -> bool {
        self.open
    }

    fn open_channel(&mut self, tls_flash: &[u8]) -> Result<(), Error> {
        self.check_handshake(tls_flash)?;
        self.open = true;
        Ok(())
    }

    fn wait_int(&mut self) -> Result<Vec<u8>, Error> {
        match self.next("an interrupt")? {
            Event::Interrupt(b) => {
                self.stats.interrupts += 1;
                Ok(b)
            }
            e => Err(self.unexpected(&e, "an interrupt wait".into())),
        }
    }

    fn read_82(&mut self) -> Result<Vec<u8>, Error> {
        match self.next("a bulk read")? {
            Event::Bulk82(Some(n)) => {
                self.stats.bulk_reads += 1;
                Ok(synthetic_image(n))
            }
            Event::Bulk82(None) => Err(Error::Transport(crate::transport::TransportError::Timeout)),
            e => Err(self.unexpected(&e, "a bulk read".into())),
        }
    }
}

/// Mask: the host public key and its signature in the pairing command (`0x4f`),
/// generated afresh at each pairing.
pub fn mask_pairing_cert() -> Mask {
    Mask {
        name: "pairing: host public key and ECDSA signature in the certificate request (0x4f)",
        ranges: Box::new(|tx| {
            if tx.first() != Some(&0x4f) {
                return None;
            }
            let mut off = 5;
            while off + 4 <= tx.len() {
                let id = u16::from_le_bytes([tx[off], tx[off + 1]]);
                let len = u16::from_le_bytes([tx[off + 2], tx[off + 3]]) as usize;
                let body = off + 4;
                if id == 5 && len == CERT_LEN {
                    return Some(vec![
                        body + 8..body + 40,
                        body + 76..body + 108,
                        body + 184..body + CERT_LEN,
                    ]);
                }
                off = body + len;
            }
            None
        }),
    }
}

/// Mask: block 4 (host private key sealed under a random IV) of the TLS flash
/// image written to partition 1.
pub fn mask_sealed_key() -> Mask {
    Mask {
        name: "pairing: sealed host key (TLS flash block 4: random key, IV, MAC)",
        ranges: Box::new(|tx| {
            if !tx.starts_with(&[0x41, 1, 1, 0, 0, 0, 0, 0, 0]) {
                return None;
            }
            let img = &tx[13..];
            let mut off = 0;
            while off + 36 <= img.len() {
                let id = u16::from_le_bytes([img[off], img[off + 1]]);
                let len = u16::from_le_bytes([img[off + 2], img[off + 3]]) as usize;
                if id == 0xffff {
                    break;
                }
                if id == 4 {
                    return Some(std::iter::once(13 + off + 4..13 + off + 36 + len).collect());
                }
                off += 36 + len;
            }
            None
        }),
    }
}

/// Mask: in capture programs, the bytes derived from calibration captures (the
/// key line at the head of the timeslot table, and the calibration lines of the
/// line update). Needed only while calibrating, whose image data is not logged.
pub fn mask_calibration_program(line_width: usize) -> Mask {
    Mask {
        name: "calibration: key line and calibration lines in capture programs (from unlogged image data)",
        ranges: Box::new(move |tx| {
            if tx.first() != Some(&0x02) || tx.len() < 5 {
                return None;
            }
            let mut ranges = Vec::new();
            let mut off = 5;
            while off + 4 <= tx.len() {
                let kind = u16::from_le_bytes([tx[off], tx[off + 1]]);
                let len = u16::from_le_bytes([tx[off + 2], tx[off + 3]]) as usize;
                let body = off + 4;
                match kind {
                    timeslot::CHUNK_TIMESLOT_TABLE_2D => {
                        ranges.push(body..body + line_width.min(len))
                    }
                    timeslot::CHUNK_LINE_UPDATE if len >= 4 => {
                        let count =
                            u32::from_le_bytes(tx[body..body + 4].try_into().ok()?) as usize;
                        ranges.push(body + 4 + 8 * count..body + len);
                    }
                    _ => {}
                }
                off = body + len;
            }
            Some(ranges)
        }),
    }
}

/// Mask: the clean slate written to partition 6 (an averaged blank image, from
/// unlogged image data) and its hash; magic, lengths and padding are compared.
pub fn mask_clean_slate() -> Mask {
    Mask {
        name: "calibration: clean slate image and hash written to partition 6",
        ranges: Box::new(|tx| {
            if !tx.starts_with(&[0x41, 6, 1, 0, 0]) || tx.len() < 13 {
                return None;
            }
            let addr = u32::from_le_bytes(tx[5..9].try_into().ok()?);
            Some(if addr == 0 {
                vec![13 + 4..13 + 0x24, 13 + 0x46..tx.len()]
            } else {
                std::iter::once(13..tx.len()).collect()
            })
        }),
    }
}

/// Rebuilds the host calibration data from a recorded capture program: the
/// calibration lines of its line update hold bytes 8.. of every calibration line
/// (bytes 0..8 are never sent and are left zero).
pub fn calibration_from_capture(
    cmd02: &[u8],
    lines: usize,
    bytes_per_line: usize,
) -> Result<Vec<u8>, Error> {
    let chunks = split_chunks(cmd02.get(5..).ok_or(Error::Malformed("capture command"))?)?;
    let lu = chunks
        .iter()
        .find(|c| c.kind == timeslot::CHUNK_LINE_UPDATE)
        .ok_or(Error::Malformed("capture without line update"))?;
    let v = &lu.value;
    let count = u32::from_le_bytes(
        v.get(..4)
            .ok_or(Error::Malformed("line update"))?
            .try_into()
            .expect("4"),
    ) as usize;
    let mut data_off = 4 + 8 * count;
    let mut calib = vec![0u8; lines * bytes_per_line];
    for k in 0..count {
        let e = v
            .get(4 + 8 * k..12 + 8 * k)
            .ok_or(Error::Malformed("line update"))?;
        let flags = u32::from_le_bytes(e[4..8].try_into().expect("4"));
        if (flags & 0x00f0_0000) >> 20 > 1 {
            continue; // in the transform chunk
        }
        if flags >> 24 != 0x85 {
            return Err(Error::Malformed("unexpected direct line update"));
        }
        let i = (flags & 0xff) as usize;
        let d = v
            .get(data_off..data_off + 4 * lines)
            .ok_or(Error::Malformed("line update data"))?;
        for j in 0..lines {
            let p = 8 + j * bytes_per_line + i;
            calib
                .get_mut(p..p + 4)
                .ok_or(Error::Malformed("calibration geometry"))?
                .copy_from_slice(&d[4 * j..4 * j + 4]);
        }
        data_off += 4 * lines;
    }
    Ok(calib)
}

/// The identity used in a recorded user lookup (`0x4a 0000 storage len identity`).
pub fn identity_from_lookup(tx: &[u8]) -> Result<Sid, Error> {
    if tx.first() != Some(&0x4a) || tx.get(1..3) != Some(&[0, 0]) {
        return Err(Error::Malformed("not a user lookup"));
    }
    parse_identity(tx.get(7..).ok_or(Error::Malformed("user lookup"))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "\
2026-01-01 00:00:00,000 step=x
2026-01-01 00:00:00,001 >cmd> 3e
2026-01-01 00:00:00,002 <cmd< 0000aa
2026-01-01 00:00:00,003 >cmd> 44000000160303
2026-01-01 00:00:00,004 <cmd< 160303
2026-01-01 00:00:00,005 >tls> 16: 1400000c00
2026-01-01 00:00:00,006 >cmd> 4400000016030301
2026-01-01 00:00:00,007 <cmd< 140303000101
2026-01-01 00:00:00,008 <tls< 16: 1400000c
2026-01-01 00:00:00,009 >tls> 17: 4302
2026-01-01 00:00:00,010 >cmd> 1703030040ffff
2026-01-01 00:00:00,011 <cmd< 1703030040eeee
2026-01-01 00:00:00,012 <tls< 17: 0000
2026-01-01 00:00:00,013 <tls< 17: 0102
2026-01-01 00:00:00,014 <int< 0201020304
2026-01-01 00:00:00,015 <130< 80 bytes
2026-01-01 00:00:00,016 <130< Error: timeout
2026-01-01 00:00:00,017 RESULT open: ok
DEBUG:root:>cmd> 050200
";

    #[test]
    fn parses_exchanges() {
        let t = parse_log(LOG).unwrap();
        assert_eq!(
            t.events,
            [
                Event::Plain {
                    tx: vec![0x3e],
                    rx: Some(vec![0, 0, 0xaa])
                },
                Event::Handshake {
                    tx: vec![0x44, 0, 0, 0, 0x16, 3, 3],
                    rx: Some(vec![0x16, 3, 3])
                },
                Event::Handshake {
                    tx: vec![0x44, 0, 0, 0, 0x16, 3, 3, 1],
                    rx: Some(vec![0x14, 3, 3, 0, 1, 1])
                },
                Event::App {
                    tx: vec![0x43, 2],
                    rx: Some(vec![0, 0, 1, 2])
                },
                Event::Interrupt(vec![2, 1, 2, 3, 4]),
                Event::Bulk82(Some(80)),
                Event::Bulk82(None),
                Event::Plain {
                    tx: vec![5, 2, 0],
                    rx: None
                },
            ]
        );
        assert_eq!(t.results, ["open: ok"]);
    }

    #[test]
    fn rejects_inconsistent_logs() {
        let l = "2026-01-01 00:00:00,000 >tls> 17: 01\n2026-01-01 00:00:00,000 >cmd> 3e\n";
        assert!(parse_log(l).is_err());
        let l = "2026-01-01 00:00:00,000 <cmd< 0000\n";
        assert!(parse_log(l).is_err());
        let l = "2026-01-01 00:00:00,000 >cmd> 3e\n2026-01-01 00:00:00,000 <tls< 17: 00\n";
        assert!(parse_log(l).is_err());
        let l = "2026-01-01 00:00:00,000 >tls> 17: 01\n";
        assert!(parse_log(l).is_err());
        let l = "2026-01-01 00:00:00,000 >cmd> 3x\n";
        assert!(parse_log(l).is_err());
    }

    #[test]
    fn replay_compares_and_orders() {
        let t = parse_log(LOG).unwrap();
        let mut r = ReplaySensor::new(&t);
        assert_eq!(r.cmd(&[0x3e]).unwrap(), [0, 0, 0xaa]);
        // Out of order: an interrupt wait while the recording has a handshake.
        assert!(matches!(r.wait_int(), Err(Error::Replay(_))));
        // The divergence is sticky.
        assert!(matches!(r.cmd(&[0x3e]), Err(Error::Replay(m)) if m.contains("interrupt")));
        r.failed = None;
        r.pos = 3;
        r.open = true;
        assert!(matches!(r.cmd(&[0x43, 3]), Err(Error::Replay(_))));
        r.failed = None;
        assert_eq!(r.cmd(&[0x43, 2]).unwrap(), [0, 0, 1, 2]);
        assert_eq!(r.wait_int().unwrap(), [2, 1, 2, 3, 4]);
        assert_eq!(r.read_82().unwrap().len(), 80);
        assert!(matches!(r.read_82(), Err(Error::Transport(_))));
        assert!(r.finish().is_err());
        r.open = false;
        assert!(matches!(r.cmd(&[5, 2, 0]), Err(Error::Transport(_))));
        // The unanswered reboot was still compared.
        assert_eq!(r.finish().unwrap().exact, 3);
    }

    #[test]
    fn masks() {
        let rec = vec![0x41, 6, 1, 0, 0, 0, 0x10, 0, 0, 3, 0, 0, 0, 1, 2, 3];
        let mut ours = rec.clone();
        ours[14] = 9;
        let t = Trace {
            events: vec![Event::Plain {
                tx: rec.clone(),
                rx: Some(vec![0, 0]),
            }],
            results: vec![],
        };
        let mut r = ReplaySensor::new(&t);
        assert!(r.cmd(&ours).is_err());
        let mut r = ReplaySensor::new(&t).with_mask(mask_clean_slate());
        r.cmd(&ours).unwrap();
        assert_eq!(r.stats.masked.values().sum::<usize>(), 1);
        // A different length is never masked.
        let mut r = ReplaySensor::new(&t).with_mask(mask_clean_slate());
        assert!(r.cmd(&ours[..15]).is_err());

        // Pairing certificate: only the key and signature ranges are ignored.
        let ic = crate::tables::flash_ic_lookup(0xef, 0x40, 0x100000).unwrap();
        let a = crate::pairing::partition_flash_cmd(
            ic,
            &crate::pairing::FLASH_LAYOUT,
            &[1; 256],
            &[2; CERT_LEN],
        );
        let mut b = a.clone();
        let cert_at = a.len() - (4 + 420) - CERT_LEN;
        b[cert_at + 8] = 0;
        b[cert_at + 300] = 0;
        let rs = (mask_pairing_cert().ranges)(&a).unwrap();
        assert!(rs.iter().any(|r| r.contains(&(cert_at + 8))));
        assert!(rs.iter().any(|r| r.contains(&(cert_at + 300))));
        assert!(
            !rs.iter()
                .any(|r| r.contains(&(cert_at + 4)) || r.contains(&(cert_at + 50)))
        );
    }

    #[test]
    fn calibration_round_trip_through_a_program() {
        // Build line data the way type-1 programs do, then recover it.
        let (lines, bpl) = (112, 120);
        let calib: Vec<u8> = (0..lines * bpl)
            .map(|i| if i % bpl < 8 { 0 } else { (i * 7 % 251) as u8 })
            .collect();
        let mut lu = 30u32.to_le_bytes().to_vec();
        lu.extend([0xff, 0, 0, 0, 1, 0, 0x27, 7]);
        lu.extend([0xff, 0, 0, 0, 2, 0, 0x37, 7]);
        for i in (0..112).step_by(4) {
            lu.extend(0xffff_ffffu32.to_le_bytes());
            lu.extend((i as u32 | 0x85 << 24).to_le_bytes());
        }
        for i in (0..112).step_by(4) {
            for j in 0..112 {
                let p = 8 + j * bpl + i;
                lu.extend(&calib[p..p + 4]);
            }
        }
        let mut c = vec![2, 0x78, 0, 0, 0];
        c.extend(timeslot::merge_chunks(&[timeslot::Chunk::new(
            timeslot::CHUNK_LINE_UPDATE,
            lu,
        )]));
        assert_eq!(calibration_from_capture(&c, lines, bpl).unwrap(), calib);
    }

    #[test]
    fn lookup_identity() {
        let sid: Sid = "S-1-5-21-9-8-7-1000".parse().unwrap();
        let mut tx = vec![0x4a, 0, 0, 3, 0, 0x4c, 0];
        tx.extend(crate::db::identity_to_bytes(&sid));
        assert_eq!(identity_from_lookup(&tx).unwrap(), sid);
        assert!(identity_from_lookup(&[0x4a, 4, 0, 0, 0, 0, 0]).is_err());
    }
}
