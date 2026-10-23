//! A whole USB session against a fake sensor with synthetic keys: commands in the
//! clear, a TLS partition image built by the pairing code, the handshake, then
//! encrypted commands and interrupts through `UsbSession`.

use std::collections::VecDeque;
use std::time::Duration;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use validity_proto::channel;
use validity_proto::pairing::{ECDH_BLOCK_LEN, encrypt_key, make_tls_flash};
use validity_proto::session::{Sensor, UsbLink, UsbSession};
use validity_proto::tls::{self, PskKeys, SessionKeys};
use validity_proto::transport::{Entropy, Transport, TransportError};
use validity_proto::{Error, scanner};

fn key(tag: &str) -> SecretKey {
    (0u32..)
        .find_map(|i| SecretKey::from_slice(&Sha256::digest(format!("{tag}-{i}"))).ok())
        .unwrap()
}

struct Det(u64);
impl Entropy for Det {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.0 >> 56) as u8;
        }
    }
}

fn le(b: &[u8]) -> Vec<u8> {
    b.iter().rev().copied().collect()
}

/// Sensor ECDH key block (flash block 6) signed by `fw`.
fn ecdh_block(sensor: &PublicKey, fw: &SigningKey) -> Vec<u8> {
    let p = sensor.to_sec1_point(false);
    let mut k = vec![0u8; 0x90];
    k[0x08..0x28].copy_from_slice(&le(&p.as_bytes()[1..33]));
    k[0x4c..0x6c].copy_from_slice(&le(&p.as_bytes()[33..65]));
    let sig: DerSignature = fw.sign(&k);
    k.extend_from_slice(&(sig.as_bytes().len() as u32).to_le_bytes());
    k.extend_from_slice(sig.as_bytes());
    k.resize(ECDH_BLOCK_LEN, 0);
    k
}

/// Minimal sensor: answers plain commands, plays the server side of the
/// handshake, echoes application commands reversed, and queues interrupts.
struct FakeLink {
    sensor: SecretKey,
    transcript: Sha256,
    client_random: [u8; 32],
    keys: Option<SessionKeys>,
    handshakes: u8,
    plain: Vec<Vec<u8>>,
    ints: VecDeque<Option<Vec<u8>>>,
}

const SERVER_RANDOM: [u8; 32] = [0x5a; 32];

impl FakeLink {
    fn server_keys(&self) -> SessionKeys {
        let k = self.keys.clone().unwrap();
        SessionKeys {
            sign: k.validation,
            validation: k.sign,
            encryption: k.decryption,
            decryption: k.encryption,
            ..k
        }
    }
}

impl Transport for FakeLink {
    fn cmd(&mut self, out: &[u8]) -> Result<Vec<u8>, TransportError> {
        if out.starts_with(&[0x44, 0, 0, 0]) {
            self.handshakes += 1;
            let recs = tls::split_records(&out[4..]).unwrap();
            if self.handshakes == 1 {
                let hello = recs[0].1;
                self.client_random = hello[6..38].try_into().unwrap();
                self.transcript.update(hello);
                let mut sh = vec![3, 3];
                sh.extend_from_slice(&SERVER_RANDOM);
                sh.extend_from_slice(&[0, 0xc0, 0x05, 0]);
                let mut hs = tls::handshake_msg(0x02, &sh);
                hs.extend(tls::handshake_msg(0x0d, &[0x01, 0x40, 0, 0]));
                hs.extend(tls::handshake_msg(0x0e, &[]));
                self.transcript.update(&hs);
                return Ok(tls::record(tls::CONTENT_HANDSHAKE, &hs));
            }
            // Certificate, key exchange, certificate verify; then CCS and Finished.
            let hs = recs[0].1;
            self.transcript.update(hs);
            let cert_len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
            let kex = &hs[4 + cert_len..];
            let eph = PublicKey::from_sec1_bytes(&kex[4..4 + kex[3] as usize]).unwrap();
            self.keys = Some(SessionKeys::derive(
                &self.sensor,
                &eph,
                &self.client_random,
                &SERVER_RANDOM,
            ));
            let h: [u8; 32] = self.transcript.clone().finalize().into();
            let fin = tls::open(&self.server_keys(), tls::CONTENT_HANDSHAKE, recs[2].1).unwrap();
            let k = self.keys.as_ref().unwrap();
            assert_eq!(
                fin,
                tls::handshake_msg(0x14, &k.verify_data(b"client finished", &h))
            );
            let sfin = tls::handshake_msg(0x14, &k.verify_data(b"server finished", &h));
            let mut rsp = tls::record(tls::CONTENT_CHANGE_CIPHER_SPEC, &[1]);
            rsp.extend(tls::record(
                tls::CONTENT_HANDSHAKE,
                &tls::seal(&self.server_keys(), tls::CONTENT_HANDSHAKE, &sfin, &[9; 16]),
            ));
            return Ok(rsp);
        }
        if out.first() == Some(&tls::CONTENT_APP_DATA) {
            let recs = tls::split_records(out).unwrap();
            let c = tls::open(&self.server_keys(), tls::CONTENT_APP_DATA, recs[0].1).unwrap();
            let mut reply = vec![0, 0];
            reply.extend(c.iter().rev());
            return Ok(tls::record(
                tls::CONTENT_APP_DATA,
                &tls::seal(&self.server_keys(), tls::CONTENT_APP_DATA, &reply, &[3; 16]),
            ));
        }
        self.plain.push(out.to_vec());
        Ok(vec![0, 0, 0x77])
    }
}

impl UsbLink for FakeLink {
    fn interrupt(&mut self, _t: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(self.ints.pop_front().unwrap_or(None))
    }
    fn bulk_82(&mut self, _t: Duration) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::Timeout)
    }
}

#[test]
fn usb_session_end_to_end() {
    let psk = PskKeys::from_hw("Synthetic Laptop", "SN-SESSION");
    let fw = SigningKey::from(&key("fw"));
    let sensor = key("sensor");
    let host = key("host");
    let image = make_tls_flash(
        &encrypt_key(&host, &psk, &[1; 16]),
        &(0..184u8).collect::<Vec<_>>(),
        &ecdh_block(&sensor.public_key(), &fw),
    )
    .unwrap();
    let link = FakeLink {
        sensor,
        transcript: Sha256::new(),
        client_random: [0; 32],
        keys: None,
        handshakes: 0,
        plain: vec![],
        ints: VecDeque::from([None, Some(vec![2, 1]), None]),
    };
    let mut s =
        UsbSession::new(link, Det(7), psk.clone()).with_firmware_key(VerifyingKey::from(&fw));

    // In the clear before the channel is open; app commands are refused.
    assert_eq!(s.cmd(&[0x3e]).unwrap(), [0, 0, 0x77]);
    assert!(s.app(&[0x3e]).is_err());

    // The production firmware key rejects the synthetic sensor key.
    let mut strict = UsbSession::new(
        FakeLink {
            sensor: key("sensor"),
            transcript: Sha256::new(),
            client_random: [0; 32],
            keys: None,
            handshakes: 0,
            plain: vec![],
            ints: VecDeque::new(),
        },
        Det(1),
        psk.clone(),
    );
    assert!(matches!(
        strict.open_channel(&image),
        Err(Error::Channel(channel::Error::BadEcdhSignature))
    ));
    assert!(!strict.is_open());

    // Paired with another host: the sealed key does not open.
    let mut other = UsbSession::new(
        FakeLink {
            sensor: key("sensor"),
            transcript: Sha256::new(),
            client_random: [0; 32],
            keys: None,
            handshakes: 0,
            plain: vec![],
            ints: VecDeque::new(),
        },
        Det(1),
        PskKeys::from_hw("Synthetic Laptop", "SN-OTHER"),
    )
    .with_firmware_key(VerifyingKey::from(&fw));
    assert!(matches!(
        other.open_channel(&image),
        Err(Error::Channel(channel::Error::Tls(
            tls::Error::PairedElsewhere
        )))
    ));

    s.open_channel(&image).unwrap();
    assert!(s.is_open());
    // Encrypted from now on: the fake echoes the decrypted command reversed.
    assert_eq!(s.cmd(&[0x01, 0x02]).unwrap(), [0, 0, 2, 1]);
    assert_eq!(s.app(&[0x75]).unwrap(), [0, 0, 0x75]);
    // Status 0 then the echoed command: a reboot reply the session accepts.
    scanner::reboot(&mut s).unwrap();
    // Interrupts are polled until one arrives.
    assert_eq!(s.wait_int().unwrap(), [2, 1]);
    // Cancellation from another handle ends a wait.
    let h = s.cancel_handle();
    h.cancel();
    assert!(matches!(s.wait_int(), Err(Error::Cancelled)));
    // No image endpoint on this link.
    assert!(matches!(
        s.read_82(),
        Err(Error::Transport(TransportError::Timeout))
    ));
    assert_eq!(s.into_link().plain, [vec![0x3e]]);
}

#[test]
fn cancel_handle_take_consumes_one_cancellation() {
    // Other `Sensor` implementations honour the handle through `take`.
    let h = validity_proto::session::CancelHandle::default();
    assert!(!h.take());
    let other = h.clone();
    other.cancel();
    assert!(h.take());
    assert!(!h.take());
    h.cancel();
    h.cancel();
    assert!(other.take());
    assert!(!other.take());
}
