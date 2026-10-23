//! Hex helpers (tables, traces, diagnostics).

/// Lowercase hex of `b`.
pub fn encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Decodes an even-length hex string; `None` on any other character.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.chunks(2)
        .map(|p| Some(nib(p[0])? << 4 | nib(p[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn round_trip() {
        assert_eq!(super::decode("00fFa1").unwrap(), [0, 0xff, 0xa1]);
        assert_eq!(super::encode(&[0, 0xff, 0xa1]), "00ffa1");
        assert!(super::decode("0").is_none());
        assert!(super::decode("0g").is_none());
        assert_eq!(super::decode("").unwrap(), Vec::<u8>::new());
    }
}
