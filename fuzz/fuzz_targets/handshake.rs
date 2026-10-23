//! The handshake and application commands against a hostile sensor: the input is
//! the sequence of replies (each prefixed by a big-endian u16 length). The client
//! must fail cleanly and never report an open channel unless the server proved
//! knowledge of the session keys, which random input cannot.
#![no_main]

use libfuzzer_sys::fuzz_target;
use p256::SecretKey;
use validity_proto::channel::{Channel, TlsFlash};
use validity_proto::transport::{Entropy, Transport, TransportError};

struct Replies<'a>(&'a [u8]);

impl Transport for Replies<'_> {
    fn cmd(&mut self, _out: &[u8]) -> Result<Vec<u8>, TransportError> {
        if self.0.len() < 2 {
            return Err(TransportError::Disconnected);
        }
        let n = (u16::from_be_bytes([self.0[0], self.0[1]]) as usize).min(self.0.len() - 2);
        let r = self.0[2..2 + n].to_vec();
        self.0 = &self.0[2 + n..];
        Ok(r)
    }
}

struct Fixed;

impl Entropy for Fixed {
    fn fill(&mut self, buf: &mut [u8]) {
        buf.fill(7);
    }
}

fuzz_target!(|data: &[u8]| {
    let key = |b: u8| SecretKey::from_slice(&[b; 32]).expect("valid scalar");
    let flash = TlsFlash { host_key: key(1), cert: vec![0xc3; 184], sensor_key: key(2).public_key() };
    let mut ch = Channel::new(flash);
    let mut t = Replies(data);
    let opened = ch.open(&mut t, &mut Fixed).is_ok();
    assert!(!opened, "a random server cannot complete the handshake");
    assert!(!ch.is_open());
    assert!(ch.app(&mut t, &mut Fixed, &[0x3e]).is_err());
});
