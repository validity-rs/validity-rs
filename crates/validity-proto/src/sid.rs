//! Windows security identifiers, the identity format of database users
//! (python-validity `sid.py`).

use crate::cmd::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    pub revision: u8,
    /// 48-bit identifier authority.
    pub auth: u64,
    pub subauth: Vec<u32>,
}

impl Sid {
    /// Binary form: `revision || count || authority (be48) || subauthorities (le32)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![self.revision, self.subauth.len() as u8];
        b.extend_from_slice(&self.auth.to_be_bytes()[2..]);
        for s in &self.subauth {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b
    }

    /// Parses the binary form; the length must match the subauthority count exactly.
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() < 8 {
            return Err(Error::Malformed("SID"));
        }
        let n = b[1] as usize;
        if b.len() != 8 + 4 * n {
            return Err(Error::Malformed("SID"));
        }
        let auth = b[2..8].iter().fold(0u64, |a, &x| (a << 8) | x as u64);
        let subauth = b[8..]
            .chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes")))
            .collect();
        Ok(Sid {
            revision: b[0],
            auth,
            subauth,
        })
    }
}

impl core::str::FromStr for Sid {
    type Err = Error;

    /// `S-<revision>-<authority>[-<subauthority>...]`.
    fn from_str(s: &str) -> Result<Self, Error> {
        let bad = || Error::Protocol(format!("not a SID: {s:?}"));
        let mut parts = s.split('-');
        if parts.next() != Some("S") {
            return Err(bad());
        }
        let revision = parts.next().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
        let auth: u64 = parts.next().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
        if auth >= 1 << 48 {
            return Err(bad());
        }
        let subauth = parts
            .map(|p| p.parse().map_err(|_| bad()))
            .collect::<Result<Vec<u32>, _>>()?;
        if subauth.len() > 255 {
            return Err(bad());
        }
        Ok(Sid {
            revision,
            auth,
            subauth,
        })
    }
}

impl core::fmt::Display for Sid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "S-{}-{}", self.revision, self.auth)?;
        for s in &self.subauth {
            write!(f, "-{s}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let s: Sid = "S-1-5-21-111-222-333-1001".parse().unwrap();
        assert_eq!(s.subauth, [21, 111, 222, 333, 1001]);
        let b = s.to_bytes();
        assert_eq!(&b[..8], [1, 5, 0, 0, 0, 0, 0, 5]);
        assert_eq!(&b[8..12], 21u32.to_le_bytes());
        assert_eq!(b.len(), 8 + 20);
        assert_eq!(Sid::from_bytes(&b).unwrap(), s);
        assert_eq!(s.to_string(), "S-1-5-21-111-222-333-1001");

        let big: Sid = "S-1-281474976710655".parse().unwrap();
        assert_eq!(&big.to_bytes()[2..8], [0xff; 6]);
        assert_eq!(big.to_string(), "S-1-281474976710655");

        assert!("S-1-281474976710656".parse::<Sid>().is_err());
        assert!("X-1-5".parse::<Sid>().is_err());
        assert!("S-1-5-x".parse::<Sid>().is_err());
        assert!("S-1".parse::<Sid>().is_err());
        assert!(Sid::from_bytes(&b[..b.len() - 1]).is_err());
        assert!(Sid::from_bytes(&[1, 0, 0, 0, 0, 0, 0]).is_err());
    }
}
