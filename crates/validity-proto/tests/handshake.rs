//! Full handshake and an application command against a fake sensor that plays the
//! server role with synthetic keys. The primitives themselves are checked byte-exact
//! against python-validity in `tls_vectors.rs`; this exercises the state machine,
//! the transcript and the flash parsing.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Ephemeral keys seen with a coordinate starting with a zero byte.
static LEADING_ZERO_KEYS: AtomicUsize = AtomicUsize::new(0);
use validity_proto::channel::{Channel, Error, TlsFlash, parse_ecdh_block};
use validity_proto::tls::{self, PskKeys, SessionKeys};
use validity_proto::transport::{Entropy, Transport, TransportError};

fn key(tag: &str) -> SecretKey {
    let mut i = 0u32;
    loop {
        let d = Sha256::digest(format!("{tag}-{i}"));
        if let Ok(k) = SecretKey::from_slice(&d) {
            return k;
        }
        i += 1;
    }
}

/// Counter-based deterministic entropy.
struct Det(u64);
impl Entropy for Det {
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(32) {
            self.0 += 1;
            let h = Sha256::digest(self.0.to_le_bytes());
            chunk.copy_from_slice(&h[..chunk.len()]);
        }
    }
}

fn le(b: &[u8]) -> Vec<u8> {
    b.iter().rev().copied().collect()
}

/// Block 6 as the sensor stores it, signed by `fw`.
fn ecdh_block(sensor: &PublicKey, fw: &SigningKey) -> Vec<u8> {
    let p = sensor.to_sec1_point(false);
    let mut k = vec![0u8; 0x90];
    k[0x08..0x28].copy_from_slice(&le(&p.as_bytes()[1..33]));
    k[0x4c..0x6c].copy_from_slice(&le(&p.as_bytes()[33..65]));
    let sig: DerSignature = fw.sign(&k);
    let mut b = k;
    b.extend_from_slice(&(sig.as_bytes().len() as u32).to_le_bytes());
    b.extend_from_slice(sig.as_bytes());
    b.resize(b.len() + 8, 0);
    b
}

/// Host key sealed like a paired sensor stores it (block 4).
fn priv_blob(psk: &PskKeys, host: &SecretKey) -> Vec<u8> {
    use aes::Aes256;
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
    use hmac::{Hmac, KeyInit, Mac};
    let p = host.public_key().to_sec1_point(false);
    let mut plain = le(&p.as_bytes()[1..33]);
    plain.extend(le(&p.as_bytes()[33..65]));
    plain.extend(le(&host.to_bytes()));
    let iv = [7u8; 16];
    let mut c = iv.to_vec();
    c.extend(
        cbc::Encryptor::<Aes256>::new((&psk.encryption).into(), (&iv).into())
            .encrypt_padded_vec::<Pkcs7>(&plain),
    );
    let mut m = Hmac::<Sha256>::new_from_slice(&psk.validation).unwrap();
    m.update(&c);
    let mut blob = vec![2];
    blob.extend(c);
    blob.extend(m.finalize().into_bytes());
    blob
}

struct Fixture {
    psk: PskKeys,
    fw: SigningKey,
    host: SecretKey,
    sensor: SecretKey,
    cert: Vec<u8>,
}

fn fixture() -> Fixture {
    Fixture {
        psk: PskKeys::from_hw("Synthetic Laptop", "SN-TEST"),
        fw: SigningKey::from(&key("fw")),
        host: key("host"),
        sensor: key("sensor"),
        cert: (0..184u8).collect(),
    }
}

impl Fixture {
    fn flash(&self) -> Vec<u8> {
        let mut f = tls::flash_block(0, &[0]);
        f.extend(tls::flash_block(4, &priv_blob(&self.psk, &self.host)));
        f.extend(tls::flash_block(3, &self.cert));
        f.extend(tls::flash_block(1, &[0; 0x100]));
        f.extend(tls::flash_block(2, &[0; 0x100]));
        f.extend(tls::flash_block(
            6,
            &ecdh_block(&self.sensor.public_key(), &self.fw),
        ));
        f.resize(0x1000, 0xff);
        f
    }
}

/// Server side of the handshake, written independently from `Channel`.
struct FakeSensor {
    sensor: SecretKey,
    host_pub: VerifyingKey,
    cert: Vec<u8>,
    transcript: Sha256,
    server_random: [u8; 32],
    keys: Option<SessionKeys>,
    step: u8,
}

fn split_hs(mut b: &[u8]) -> Vec<(u8, &[u8], &[u8])> {
    let mut v = Vec::new();
    while b.len() >= 4 {
        let l = u32::from_be_bytes([0, b[1], b[2], b[3]]) as usize;
        v.push((b[0], &b[..4 + l], &b[4..4 + l]));
        b = &b[4 + l..];
    }
    v
}

impl FakeSensor {
    /// Server keys = client keys mirrored.
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

impl Transport for FakeSensor {
    fn cmd(&mut self, out: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.step += 1;
        match self.step {
            1 => {
                assert_eq!(&out[..4], &[0x44, 0, 0, 0]);
                let recs = tls::split_records(&out[4..]).unwrap();
                assert_eq!(recs.len(), 1);
                let (t, hello) = recs[0];
                assert_eq!(t, tls::CONTENT_HANDSHAKE);
                assert_eq!(hello[0], 1);
                let client_random: [u8; 32] = hello[6..38].try_into().unwrap();
                self.transcript.update(hello);
                self.server_random = [0x5a; 32];
                let mut sh = vec![3, 3];
                sh.extend_from_slice(&self.server_random);
                sh.extend_from_slice(&[4, 1, 2, 3, 4, 0xc0, 0x05, 0]);
                let mut hs = tls::handshake_msg(0x02, &sh);
                hs.extend(tls::handshake_msg(0x0d, &[0x01, 0x40, 0, 0]));
                hs.extend(tls::handshake_msg(0x0e, &[]));
                self.transcript.update(&hs);
                // Stash the client random in the keys slot until we see the ephemeral key.
                self.keys = Some(SessionKeys {
                    master_secret: [0; 48],
                    sign: client_random,
                    validation: [0; 32],
                    encryption: [0; 32],
                    decryption: [0; 32],
                });
                Ok(tls::record(tls::CONTENT_HANDSHAKE, &hs))
            }
            2 => {
                assert_eq!(&out[..4], &[0x44, 0, 0, 0]);
                let recs = tls::split_records(&out[4..]).unwrap();
                assert_eq!(recs.len(), 3);
                assert_eq!(recs[1], (tls::CONTENT_CHANGE_CIPHER_SPEC, &[1u8][..]));
                let client_random = self.keys.as_ref().unwrap().sign;
                let msgs = split_hs(recs[0].1);
                assert_eq!(
                    msgs.iter().map(|m| m.0).collect::<Vec<_>>(),
                    [0x0b, 0x10, 0x0f]
                );
                // Certificate with the vendor quirks.
                let l = (self.cert.len() as u16).to_be_bytes();
                assert_eq!(&msgs[0].2[..8], &[0, l[0], l[1], 0, l[0], l[1], 0xac, 0x16]);
                assert_eq!(&msgs[0].2[8..], &self.cert[..]);
                self.transcript.update(msgs[0].1);
                assert_eq!(
                    msgs[1].2.len(),
                    65,
                    "uncompressed point, fixed-width coordinates"
                );
                if msgs[1].2[1] == 0 || msgs[1].2[33] == 0 {
                    LEADING_ZERO_KEYS.fetch_add(1, Ordering::Relaxed);
                }
                let eph = PublicKey::from_sec1_bytes(msgs[1].2).unwrap();
                self.transcript.update(msgs[1].1);
                let h: [u8; 32] = self.transcript.clone().finalize().into();
                let sig = DerSignature::from_bytes(msgs[2].2).unwrap();
                self.host_pub
                    .verify_prehash(&h, &sig)
                    .expect("CertificateVerify signed by the host key");
                self.transcript.update(msgs[2].1);
                // ECDH is symmetric: derive with roles swapped, then mirror.
                self.keys = Some(SessionKeys::derive(
                    &self.sensor,
                    &eph,
                    &client_random,
                    &self.server_random,
                ));
                let fin = tls::open(&self.server_keys(), tls::CONTENT_HANDSHAKE, recs[2].1)
                    .expect("client Finished authentic");
                let h: [u8; 32] = self.transcript.clone().finalize().into();
                let want = self
                    .keys
                    .as_ref()
                    .unwrap()
                    .verify_data(b"client finished", &h);
                assert_eq!(fin, tls::handshake_msg(0x14, &want));
                let sfin = tls::handshake_msg(
                    0x14,
                    &self
                        .keys
                        .as_ref()
                        .unwrap()
                        .verify_data(b"server finished", &h),
                );
                let mut rsp = tls::record(tls::CONTENT_CHANGE_CIPHER_SPEC, &[1]);
                rsp.extend(tls::record(
                    tls::CONTENT_HANDSHAKE,
                    &tls::seal(&self.server_keys(), tls::CONTENT_HANDSHAKE, &sfin, &[9; 16]),
                ));
                Ok(rsp)
            }
            _ => {
                let recs = tls::split_records(out).unwrap();
                let cmd = tls::open(&self.server_keys(), tls::CONTENT_APP_DATA, recs[0].1).unwrap();
                let mut reply = vec![0, 0];
                reply.extend(cmd.iter().rev());
                Ok(tls::record(
                    tls::CONTENT_APP_DATA,
                    &tls::seal(&self.server_keys(), tls::CONTENT_APP_DATA, &reply, &[3; 16]),
                ))
            }
        }
    }
}

fn fake(fx: &Fixture) -> FakeSensor {
    FakeSensor {
        sensor: fx.sensor.clone(),
        host_pub: VerifyingKey::from(&SigningKey::from(&fx.host)),
        cert: fx.cert.clone(),
        transcript: Sha256::new(),
        server_random: [0; 32],
        keys: None,
        step: 0,
    }
}

#[test]
fn flash_parses_and_checks_signatures() {
    let fx = fixture();
    let flash = TlsFlash::parse(&fx.flash(), &fx.psk, fx.fw.verifying_key()).unwrap();
    assert_eq!(flash.host_key.to_bytes(), fx.host.to_bytes());
    assert_eq!(flash.cert, fx.cert);
    assert_eq!(flash.sensor_key, fx.sensor.public_key());

    // Another host: the private key blob does not open.
    let other = PskKeys::from_hw("Synthetic Laptop", "SN-OTHER");
    assert!(matches!(
        TlsFlash::parse(&fx.flash(), &other, fx.fw.verifying_key()),
        Err(Error::Tls(tls::Error::PairedElsewhere))
    ));
    // ECDH key not signed by the firmware key.
    let forged = ecdh_block(&fx.sensor.public_key(), &SigningKey::from(&key("not-fw")));
    assert!(matches!(
        parse_ecdh_block(&forged, fx.fw.verifying_key()),
        Err(Error::BadEcdhSignature)
    ));
    // Corrupted block body: hash mismatch.
    let mut f = fx.flash();
    f[36] ^= 1; // the single body byte of block 0
    assert!(matches!(
        TlsFlash::parse(&f, &fx.psk, fx.fw.verifying_key()),
        Err(Error::FlashHash(0))
    ));
}

#[test]
fn handshake_then_app_command() {
    let fx = fixture();
    let flash = TlsFlash::parse(&fx.flash(), &fx.psk, fx.fw.verifying_key()).unwrap();
    let mut ch = Channel::new(flash);
    let mut sensor = fake(&fx);
    let mut rng = Det(0);
    assert!(!ch.is_open());
    ch.open(&mut sensor, &mut rng).unwrap();
    assert!(ch.is_open());
    let reply = ch.app(&mut sensor, &mut rng, &[0x3e, 1, 2]).unwrap();
    assert_eq!(reply, [0, 0, 2, 1, 0x3e]);
}

#[test]
fn many_handshakes_with_random_ephemeral_keys() {
    // Coordinates with leading zero bytes must not break the handshake (python-validity
    // drops them); 300 runs make such keys near-certain to occur.
    let fx = fixture();
    for seed in 0..300 {
        let flash = TlsFlash::parse(&fx.flash(), &fx.psk, fx.fw.verifying_key()).unwrap();
        let mut ch = Channel::new(flash);
        ch.open(&mut fake(&fx), &mut Det(seed * 1000)).unwrap();
    }
    let n = LEADING_ZERO_KEYS.load(Ordering::Relaxed);
    eprintln!("ephemeral keys with a leading zero coordinate byte: {n}");
    assert!(
        n > 0,
        "the run must cover the case python-validity gets wrong"
    );
}

#[test]
fn tampered_server_finished_is_rejected() {
    struct Tamper(FakeSensor);
    impl Transport for Tamper {
        fn cmd(&mut self, out: &[u8]) -> Result<Vec<u8>, TransportError> {
            let mut r = self.0.cmd(out)?;
            if self.0.step == 2 {
                let n = r.len();
                r[n - 20] ^= 1;
            }
            Ok(r)
        }
    }
    let fx = fixture();
    let flash = TlsFlash::parse(&fx.flash(), &fx.psk, fx.fw.verifying_key()).unwrap();
    let mut ch = Channel::new(flash);
    assert!(ch.open(&mut Tamper(fake(&fx)), &mut Det(0)).is_err());
    assert!(!ch.is_open());
}
