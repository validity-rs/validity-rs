//! Capture programs: a list of `type (le16) || len (le16) || value` chunks, one of
//! which (0x34) is a timeslot table, a small instruction stream run by the sensor.
//! Ported from python-validity `timeslot.py`.

use crate::cmd::Error;

/// One program chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub kind: u16,
    pub value: Vec<u8>,
}

impl Chunk {
    pub fn new(kind: u16, value: impl Into<Vec<u8>>) -> Self {
        Chunk {
            kind,
            value: value.into(),
        }
    }
}

pub const CHUNK_REPLY_CONFIG: u16 = 0x17;
pub const CHUNK_FINGER_DETECT: u16 = 0x26;
pub const CHUNK_IMAGE_RECONSTRUCTION: u16 = 0x2e;
pub const CHUNK_2D: u16 = 0x2f;
pub const CHUNK_LINE_UPDATE: u16 = 0x30;
pub const CHUNK_TIMESLOT_TABLE_2D: u16 = 0x34;
pub const CHUNK_LINE_UPDATE_TRANSFORM: u16 = 0x43;
pub const CHUNK_LINE_UPDATE_INTERLEAVE: u16 = 0x44;
/// Identify-only chunk, close to Finger Detect (unnamed in the reference).
pub const CHUNK_IDENTIFY_DETECT: u16 = 0x4e;

/// Splits a program into chunks. Unlike the reference (which silently truncates),
/// a chunk running past the end is an error.
pub fn split_chunks(mut b: &[u8]) -> Result<Vec<Chunk>, Error> {
    let mut out = Vec::new();
    while !b.is_empty() {
        if b.len() < 4 {
            return Err(Error::Malformed("truncated chunk header"));
        }
        let kind = u16::from_le_bytes([b[0], b[1]]);
        let len = u16::from_le_bytes([b[2], b[3]]) as usize;
        let value = b
            .get(4..4 + len)
            .ok_or(Error::Malformed("truncated chunk"))?;
        out.push(Chunk::new(kind, value));
        b = &b[4 + len..];
    }
    Ok(out)
}

pub fn merge_chunks(chunks: &[Chunk]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in chunks {
        out.extend_from_slice(&c.kind.to_le_bytes());
        out.extend_from_slice(&(c.value.len() as u16).to_le_bytes());
        out.extend_from_slice(&c.value);
    }
    out
}

/// A decoded timeslot instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insn {
    Noop,
    EndOfTable,
    Return,
    ClearSo,
    EndOfData,
    Macro(u8),
    EnableRx(u8),
    IdleRx(u16),
    EnableSo(u16),
    DisableSo(u16),
    Interrupt(u8),
    Call { rx_inc: u8, addr: u16, repeat: u16 },
    Features(u8),
    RegWrite { addr: u32, value: u16 },
    Sample(u8, u8),
    SampleRepeat(u8, u8, u16),
}

impl Insn {
    /// The reference's opcode numbers (index into its mnemonic table).
    pub fn opcode(&self) -> u8 {
        match self {
            Insn::Noop => 0,
            Insn::EndOfTable => 1,
            Insn::Return => 2,
            Insn::ClearSo => 3,
            Insn::EndOfData => 4,
            Insn::Macro(_) => 5,
            Insn::EnableRx(_) => 6,
            Insn::IdleRx(_) => 7,
            Insn::EnableSo(_) => 8,
            Insn::DisableSo(_) => 9,
            Insn::Interrupt(_) => 10,
            Insn::Call { .. } => 11,
            Insn::Features(_) => 12,
            Insn::RegWrite { .. } => 13,
            Insn::Sample(..) => 14,
            Insn::SampleRepeat(..) => 15,
        }
    }

    /// Ends a linear scan (End of Table, Return, End of Data).
    pub fn is_terminator(&self) -> bool {
        matches!(self, Insn::EndOfTable | Insn::Return | Insn::EndOfData)
    }
}

impl core::fmt::Display for Insn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Insn::Noop => f.write_str("NOOP"),
            Insn::EndOfTable => f.write_str("End of Table"),
            Insn::Return => f.write_str("Return"),
            Insn::ClearSo => f.write_str("Clear SO"),
            Insn::EndOfData => f.write_str("End of Data"),
            Insn::Macro(m) => write!(f, "Macro {m:02x}"),
            Insn::EnableRx(r) => write!(f, "Enable Rx 0x{r:02x}"),
            Insn::IdleRx(r) => write!(f, "Idle Rx 0x{r:03x}"),
            Insn::EnableSo(r) => write!(f, "Enable SO 0x{r:03x}"),
            Insn::DisableSo(r) => write!(f, "Disable SO 0x{r:03x}"),
            Insn::Interrupt(i) => write!(f, "Interrupt {i:x}"),
            Insn::Call {
                rx_inc,
                addr,
                repeat,
            } => write!(f, "Call rx_inc={rx_inc}, addr={addr:x}, repeat={repeat}"),
            Insn::Features(x) => write!(f, "Features {x:02x}"),
            Insn::RegWrite { addr, value } => {
                write!(f, "Register Write *0x{addr:08x} = 0x{value:04x}")
            }
            Insn::Sample(a, b) => write!(f, "Sample {a:x}, {b:x}"),
            Insn::SampleRepeat(a, b, r) => write!(f, "Sample Repeat {a:x}, {b:x}, repeat={r:x}"),
        }
    }
}

/// Decodes the instruction at the start of `b`; returns it and its length.
pub fn decode_insn(b: &[u8]) -> Result<(Insn, usize), Error> {
    let op = *b.first().ok_or(Error::Malformed("empty timeslot table"))?;
    let arg = |i: usize| b.get(i).copied().ok_or(Error::Malformed("truncated insn"));
    let n256 = |x: u8| if x == 0 { 0x100 } else { x as u16 };
    Ok(match op {
        0 => (Insn::Noop, 1),
        1 => (Insn::EndOfTable, 1),
        2 => (Insn::Return, 1),
        3 => (Insn::ClearSo, 1),
        4 => (Insn::EndOfData, 1),
        5 => (Insn::Macro(arg(1)?), 2),
        6 => (Insn::EnableRx(arg(1)?), 2),
        7 => (Insn::IdleRx(n256(arg(1)?)), 2),
        _ if op & 0xfe == 0x08 => (Insn::EnableSo(((op as u16 & 1) << 8) | arg(1)? as u16), 2),
        _ if op & 0xfe == 0x0a => (Insn::DisableSo(((op as u16 & 1) << 8) | arg(1)? as u16), 2),
        _ if op & 0xfc == 0x0c => (Insn::Interrupt(op & 3), 1),
        _ if op & 0xf8 == 0x10 => (
            Insn::Call {
                rx_inc: op & 7,
                addr: (arg(1)? as u16) << 2,
                repeat: n256(arg(2)?),
            },
            3,
        ),
        _ if op & 0xe0 == 0x20 => (Insn::Features(op & 0x1f), 1),
        _ if op & 0xc0 == 0x40 => (
            Insn::RegWrite {
                addr: (op as u32 & 0x3f) * 4 + 0x8000_2000,
                value: arg(1)? as u16 | ((arg(2)? as u16) << 8),
            },
            3,
        ),
        _ if op & 0xc0 == 0x80 => (Insn::Sample((op & 0x38) >> 3, op & 7), 1),
        _ if op & 0xc0 == 0xc0 => (
            Insn::SampleRepeat((op & 0x38) >> 3, op & 7, n256(arg(1)?)),
            2,
        ),
        _ => {
            return Err(Error::Protocol(format!(
                "unhandled timeslot instruction {op:02x}"
            )));
        }
    })
}

/// Offset of the `n`-th (1-based) instruction with the given opcode, scanning the
/// whole table.
pub fn find_nth_insn(mut b: &[u8], opcode: u8, mut n: usize) -> Result<Option<usize>, Error> {
    let mut pc = 0;
    while !b.is_empty() {
        let (insn, sz) = decode_insn(b)?;
        if insn.opcode() == opcode {
            n -= 1;
            if n == 0 {
                return Ok(Some(pc));
            }
        }
        b = &b[sz..];
        pc += sz;
    }
    Ok(None)
}

/// Offset of the `n`-th (1-based) register write to `reg`.
pub fn find_nth_regwrite(mut b: &[u8], reg: u32, mut n: usize) -> Result<Option<usize>, Error> {
    let mut pc = 0;
    while !b.is_empty() {
        let (insn, sz) = decode_insn(b)?;
        if let Insn::RegWrite { addr, .. } = insn
            && addr == reg
        {
            n -= 1;
            if n == 0 {
                return Ok(Some(pc));
            }
        }
        b = &b[sz..];
        pc += sz;
    }
    Ok(None)
}

/// Disassembles a timeslot table starting at `off`, one instruction per line.
pub fn disassemble(table: &[u8], off: usize) -> Result<String, Error> {
    use core::fmt::Write;
    let mut out = String::new();
    let mut pc = off;
    let mut b = table.get(off..).ok_or(Error::Malformed("offset"))?;
    while !b.is_empty() {
        let (insn, sz) = decode_insn(b)?;
        let raw: String = b[..sz].iter().map(|x| format!("{x:02x}")).collect();
        writeln!(out, "    {pc:04x}: {raw:<6} {insn}").expect("write to String");
        b = &b[sz..];
        pc += sz;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_round_trip_and_reject_truncation() {
        let c = vec![Chunk::new(0x2f, [1, 0, 0, 0]), Chunk::new(0x17, [])];
        let b = merge_chunks(&c);
        assert_eq!(b, [0x2f, 0, 4, 0, 1, 0, 0, 0, 0x17, 0, 0, 0]);
        assert_eq!(split_chunks(&b).unwrap(), c);
        assert!(split_chunks(&b[..b.len() - 1]).is_err());
        assert!(split_chunks(&[0x2f, 0, 4, 0, 1]).is_err());
    }

    #[test]
    fn decode_every_form() {
        let cases: &[(&[u8], Insn, usize)] = &[
            (&[0], Insn::Noop, 1),
            (&[4], Insn::EndOfData, 1),
            (&[5, 9], Insn::Macro(9), 2),
            (&[6, 2], Insn::EnableRx(2), 2),
            (&[7, 0], Insn::IdleRx(0x100), 2),
            (&[9, 3], Insn::EnableSo(0x103), 2),
            (&[0x0a, 3], Insn::DisableSo(3), 2),
            (&[0x0f], Insn::Interrupt(3), 1),
            (
                &[0x13, 0x10, 0],
                Insn::Call {
                    rx_inc: 3,
                    addr: 0x40,
                    repeat: 0x100,
                },
                3,
            ),
            (&[0x25], Insn::Features(5), 1),
            (
                &[0x4f, 0x34, 0x12],
                Insn::RegWrite {
                    addr: 0x8000_203c,
                    value: 0x1234,
                },
                3,
            ),
            (&[0x9a], Insn::Sample(3, 2), 1),
            (&[0xd1, 5], Insn::SampleRepeat(2, 1, 5), 2),
        ];
        for (b, insn, sz) in cases {
            assert_eq!(decode_insn(b).unwrap(), (*insn, *sz), "{b:02x?}");
        }
        assert!(decode_insn(&[0x18]).is_err());
        assert!(decode_insn(&[0x4f, 1]).is_err());
        assert!(decode_insn(&[]).is_err());
    }

    #[test]
    fn find_and_disassemble() {
        let t = [6, 1, 0x4f, 1, 0, 6, 2, 0x4f, 2, 0, 1];
        assert_eq!(find_nth_insn(&t, 6, 2).unwrap(), Some(5));
        assert_eq!(find_nth_insn(&t, 6, 3).unwrap(), None);
        assert_eq!(find_nth_regwrite(&t, 0x8000_203c, 2).unwrap(), Some(7));
        assert_eq!(find_nth_regwrite(&t, 0x8000_2000, 1).unwrap(), None);
        let d = disassemble(&t, 5).unwrap();
        assert_eq!(
            d,
            "    0005: 0602   Enable Rx 0x02\n    0007: 4f0200 Register Write *0x8000203c = 0x0002\n    000a: 01     End of Table\n"
        );
    }
}
