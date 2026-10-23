//! Exact-boundary and exact-error tests for input validation, written from the
//! survivors of a mutation-testing run: each test pins the behaviour one byte on
//! either side of a length check, and the precise error, so that loosening a check
//! (`<` to `<=`, `||` to `&&`) is caught.

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use p256::SecretKey;
use sha2::Sha256;
use validity_proto::channel::{self, Channel, TlsFlash, firmware_key, parse_ecdh_block};
use validity_proto::cmd::{self, FwextState};
use validity_proto::tls::{self, Error as TlsError, PskKeys, SessionKeys};
use validity_proto::transport::{Entropy, Transport, TransportError};
use validity_proto::vendor::Blobs;

fn keys() -> SessionKeys {
    SessionKeys {
        master_secret: [1; 48],
        sign: [2; 32],
        validation: [3; 32],
        encryption: [4; 32],
        decryption: [5; 32],
    }
}

/// AES-256-CBC of already padded `plain`, prefixed by the IV.
fn cbc(key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    let iv = [9u8; 16];
    let mut out = iv.to_vec();
    out.extend(
        cbc::Encryptor::<Aes256>::new(key.into(), (&iv).into())
            .encrypt_padded_vec::<NoPadding>(plain),
    );
    out
}

#[test]
fn record_open_length_checks() {
    let k = keys();
    // Not enough for IV + one block: rejected on length, not later on padding.
    assert_eq!(
        tls::open(&k, tls::CONTENT_APP_DATA, &[0; 16]),
        Err(TlsError::BadLength)
    );
    // Not a whole number of blocks.
    assert_eq!(
        tls::open(&k, tls::CONTENT_APP_DATA, &[0; 33]),
        Err(TlsError::BadLength)
    );
    // 31 bytes left after unpadding: too short to hold the MAC.
    let mut p = vec![0xaa; 31];
    p.push(0); // one padding byte of value 0
    assert_eq!(
        tls::open(&k, tls::CONTENT_APP_DATA, &cbc(&k.decryption, &p)),
        Err(TlsError::BadLength)
    );
    // Exactly 32 bytes: long enough, so it fails on the MAC instead.
    let mut p = vec![0xaa; 32];
    p.extend([15; 16]);
    assert_eq!(
        tls::open(&k, tls::CONTENT_APP_DATA, &cbc(&k.decryption, &p)),
        Err(TlsError::BadMac)
    );
}

#[test]
fn record_versions() {
    assert_eq!(
        tls::split_records(&[0x17, 3, 1, 0, 0]),
        Err(TlsError::BadVersion(3, 1))
    );
    assert_eq!(
        tls::split_records(&[0x17, 1, 3, 0, 0]),
        Err(TlsError::BadVersion(1, 3))
    );
    assert_eq!(
        tls::split_records(&[0x17, 3, 3, 0, 1, 7]).unwrap(),
        vec![(0x17, &[7u8][..])]
    );
}

#[test]
fn public_key_coordinate_lengths() {
    let k = SecretKey::from_slice(&[3; 32]).unwrap().public_key();
    let p = p256::elliptic_curve::sec1::ToSec1Point::to_sec1_point(&k, false);
    let x: Vec<u8> = p.as_bytes()[1..33].iter().rev().copied().collect();
    let y: Vec<u8> = p.as_bytes()[33..65].iter().rev().copied().collect();
    assert_eq!(tls::public_key_le(&x, &y).unwrap(), k);
    assert_eq!(tls::public_key_le(&x[1..], &y), Err(TlsError::BadLength));
    assert_eq!(tls::public_key_le(&x, &y[1..]), Err(TlsError::BadLength));
}

/// `02 || iv || AES-CBC(plain) || HMAC`, sealed with `psk`; `plain` is passed already padded.
fn sealed_blob(psk: &PskKeys, plain: &[u8]) -> Vec<u8> {
    let c = cbc(&psk.encryption, plain);
    let mut m = Hmac::<Sha256>::new_from_slice(&psk.validation).unwrap();
    m.update(&c);
    let mut blob = vec![2];
    blob.extend(&c);
    blob.extend(m.finalize().into_bytes());
    blob
}

#[test]
fn private_key_blob_checks() {
    let psk = PskKeys::from_hw("Boundary Laptop", "B0");
    // Body (after the prefix) shorter than a MAC: length error, not a MAC error.
    assert_eq!(
        psk.open_priv_blob(&[[2u8].as_slice(), &[0; 31]].concat())
            .err(),
        Some(TlsError::BadLength)
    );
    // Exactly a MAC long: it is checked, and does not match.
    assert_eq!(
        psk.open_priv_blob(&[[2u8].as_slice(), &[0; 32]].concat())
            .err(),
        Some(TlsError::PairedElsewhere)
    );

    let mut d = [0u8; 32];
    d[31] = 5; // little-endian scalar 5 << 248: valid
    let mut good = vec![0u8; 0x40];
    good.extend(d);
    // Valid: 0x60 bytes of key material + 16 bytes of PKCS#7 padding.
    let mut p = good.clone();
    p.extend([16; 16]);
    assert!(psk.open_priv_blob(&sealed_blob(&psk, &p)).is_ok());
    // Padding byte 0 is invalid PKCS#7.
    let mut p = good.clone();
    p.extend([0; 16]);
    assert_eq!(
        psk.open_priv_blob(&sealed_blob(&psk, &p)).err(),
        Some(TlsError::BadPadding)
    );
    // Padding longer than the data.
    let mut p = good.clone();
    p.extend([0xff; 16]);
    assert_eq!(
        psk.open_priv_blob(&sealed_blob(&psk, &p)).err(),
        Some(TlsError::BadPadding)
    );
    // One byte of key material missing once the padding is removed.
    let mut p = good[..0x5f].to_vec();
    p.push(1); // a single padding byte: 0x5f bytes remain
    assert_eq!(
        psk.open_priv_blob(&sealed_blob(&psk, &p)).err(),
        Some(TlsError::BadPadding)
    );
}

#[test]
fn ecdh_block_lengths() {
    let fw = firmware_key();
    // One byte short of key structure + signature length field.
    assert!(matches!(
        parse_ecdh_block(&[0; 0x93], &fw),
        Err(channel::Error::Tls(TlsError::BadLength))
    ));
    // Long enough: rejected later, because all-zero coordinates are not a point.
    assert!(matches!(
        parse_ecdh_block(&[0; 0x94], &fw),
        Err(channel::Error::Tls(TlsError::BadKey))
    ));
}

#[test]
fn tls_flash_reserved_blocks_must_be_empty() {
    let psk = PskKeys::from_hw("Boundary Laptop", "B0");
    let f = tls::flash_block(0, &[1]);
    assert!(matches!(
        TlsFlash::parse(&f, &psk, &firmware_key()),
        Err(channel::Error::NotEmpty(0))
    ));
    let f = tls::flash_block(2, &[0, 0, 7]);
    assert!(matches!(
        TlsFlash::parse(&f, &psk, &firmware_key()),
        Err(channel::Error::NotEmpty(2))
    ));
}

#[test]
fn read_flash_reply_lengths() {
    // status, len = 0, 2 bytes, no data: valid and empty.
    assert_eq!(
        cmd::parse_read_flash(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
        b""
    );
    // One header byte missing.
    assert!(matches!(
        cmd::parse_read_flash(&[0, 0, 0, 0, 0, 0, 0]),
        Err(cmd::Error::Short)
    ));
}

/// Answers each command from a script and records what was sent.
struct Script {
    replies: Vec<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}

impl Transport for Script {
    fn cmd(&mut self, out: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.sent.push(out.to_vec());
        if self.replies.is_empty() {
            return Err(TransportError::Disconnected);
        }
        Ok(self.replies.remove(0))
    }
}

fn script(replies: &[&[u8]]) -> Script {
    Script {
        replies: replies.iter().map(|r| r.to_vec()).collect(),
        sent: Vec::new(),
    }
}

#[test]
fn read_tls_flash_returns_the_data() {
    let mut s = script(&[&[0, 0, 3, 0, 0, 0, 0, 0, 7, 8, 9]]);
    assert_eq!(cmd::read_tls_flash(&mut s).unwrap(), [7, 8, 9]);
    assert_eq!(s.sent, [cmd::read_flash_cmd(1, 0, 0x1000)]);
}

fn blobs() -> Blobs {
    Blobs {
        init_hardcoded: vec![6, 1],
        init_hardcoded_clean_slate: vec![6, 2],
        reset_blob: vec![6, 3],
        db_write_enable: vec![6, 4],
        partition_signature: vec![5],
    }
}

#[test]
fn send_init_detects_the_firmware_extension() {
    let ok: &[u8] = &[0, 0];
    // Firmware info status 0: extension loaded, no clean-slate blob.
    let mut s = script(&[ok, ok, &[0, 0, 9], ok]);
    assert_eq!(
        cmd::send_init(&mut s, &blobs()).unwrap(),
        FwextState::Loaded
    );
    assert_eq!(s.sent.len(), 4);
    // Non-zero status in either byte: clean slate, and the clean-slate blob follows.
    for fw in [[1u8, 0], [0, 1]] {
        let mut s = script(&[ok, ok, &fw, ok, ok]);
        assert_eq!(
            cmd::send_init(&mut s, &blobs()).unwrap(),
            FwextState::CleanSlate
        );
        assert_eq!(s.sent.last().unwrap(), &blobs().init_hardcoded_clean_slate);
    }
    // A one-byte firmware reply carries no status: treated as loaded.
    let mut s = script(&[ok, ok, &[1], ok]);
    assert_eq!(
        cmd::send_init(&mut s, &blobs()).unwrap(),
        FwextState::Loaded
    );
}

struct Fixed;

impl Entropy for Fixed {
    fn fill(&mut self, buf: &mut [u8]) {
        buf.fill(7);
    }
}

fn server_hello() -> Vec<u8> {
    let mut sh = vec![3, 3];
    sh.extend([0x5a; 32]);
    sh.extend([0, 0xc0, 0x05, 0]);
    let mut hs = tls::handshake_msg(0x02, &sh);
    hs.extend(tls::handshake_msg(0x0d, &[0x01, 0x40, 0, 0]));
    hs.extend(tls::handshake_msg(0x0e, &[]));
    tls::record(tls::CONTENT_HANDSHAKE, &hs)
}

fn flash() -> TlsFlash {
    let k = |b: u8| SecretKey::from_slice(&[b; 32]).unwrap();
    TlsFlash {
        host_key: k(1),
        cert: vec![0xc3; 8],
        sensor_key: k(2).public_key(),
    }
}

#[test]
fn handshake_needs_the_server_finished() {
    // The server switches to encryption but never proves it holds the session keys.
    let ccs = tls::record(tls::CONTENT_CHANGE_CIPHER_SPEC, &[1]);
    let mut s = script(&[&server_hello(), &ccs]);
    let mut ch = Channel::new(flash());
    assert!(matches!(
        ch.open(&mut s, &mut Fixed),
        Err(channel::Error::Handshake("no server Finished"))
    ));
    assert!(!ch.is_open());
    assert!(ch.app(&mut s, &mut Fixed, &[0x3e]).is_err());
}

#[test]
fn server_hello_lengths() {
    // A ServerHello one byte short of version + random + session id length.
    let short = tls::record(tls::CONTENT_HANDSHAKE, &tls::handshake_msg(0x02, &[3; 34]));
    let mut ch = Channel::new(flash());
    assert!(matches!(
        ch.open(&mut script(&[&short]), &mut Fixed),
        Err(channel::Error::Handshake("malformed ServerHello"))
    ));
    // Right length, wrong version.
    let mut sh = vec![3, 1];
    sh.extend([0; 33]);
    let bad = tls::record(tls::CONTENT_HANDSHAKE, &tls::handshake_msg(0x02, &sh));
    assert!(matches!(
        ch.open(&mut script(&[&bad]), &mut Fixed),
        Err(channel::Error::Handshake("malformed ServerHello"))
    ));
}

#[test]
fn server_hello_of_minimal_length_is_parsed() {
    // Exactly version + random + empty session id: well formed, so the error is about
    // the (missing) cipher suite, not the length.
    let mut sh = vec![3, 3];
    sh.extend([0; 33]);
    let rec = tls::record(tls::CONTENT_HANDSHAKE, &tls::handshake_msg(0x02, &sh));
    let mut ch = Channel::new(flash());
    assert!(matches!(
        ch.open(&mut script(&[&rec]), &mut Fixed),
        Err(channel::Error::Handshake(
            "unsupported cipher suite or compression"
        ))
    ));
}

#[test]
fn private_key_blob_of_one_block_is_decrypted() {
    // IV + a single block is a valid ciphertext length: it decrypts, then fails on
    // the missing key material rather than on the length.
    let psk = PskKeys::from_hw("Boundary Laptop", "B0");
    assert_eq!(
        psk.open_priv_blob(&sealed_blob(&psk, &[16; 16])).err(),
        Some(TlsError::BadPadding)
    );
}

#[test]
fn errors_explain_themselves() {
    for (e, want) in [
        (TlsError::BadMac, "record MAC check failed"),
        (TlsError::PairedElsewhere, "paired with another computer"),
        (TlsError::BadVersion(3, 1), "unexpected TLS version 3.1"),
    ] {
        assert!(e.to_string().contains(want), "{e}");
    }
    for (e, want) in [
        (
            channel::Error::BadEcdhSignature,
            "not signed by the firmware key",
        ),
        (channel::Error::FlashHash(4), "block 4 hash mismatch"),
        (
            channel::Error::Tls(TlsError::BadKey),
            "invalid elliptic curve key",
        ),
    ] {
        assert!(e.to_string().contains(want), "{e}");
    }
}
