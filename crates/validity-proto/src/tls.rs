//! The TLS-1.2-like channel spoken by the sensor (cipher suite 0xc005,
//! TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, with HMAC-SHA256 record MACs).
//!
//! Ported from python-validity `validitysensor/tls.py`. The sensor deviates from the
//! standard in several places (padding byte, length fields); those quirks are kept
//! byte-exact and marked where they occur.

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Hardcoded in the vendor driver; seeds the pre-shared keys and the handshake key pair.
const PASSWORD_HARDCODED: [u8; 32] = [
    0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a, 0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19,
    0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38, 0x38, 0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33,
];
const GWK_SIGN_HARDCODED: [u8; 32] = [
    0x3a, 0x4c, 0x76, 0xb7, 0x6a, 0x97, 0x98, 0x1d, 0x12, 0x74, 0x24, 0x7e, 0x16, 0x66, 0x10, 0xe7,
    0x7f, 0x4d, 0x9c, 0x9d, 0x07, 0xd3, 0xc7, 0x28, 0xe5, 0x32, 0x91, 0x6b, 0xdd, 0x28, 0xb4, 0x54,
];

pub const CONTENT_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const CONTENT_HANDSHAKE: u8 = 0x16;
pub const CONTENT_APP_DATA: u8 = 0x17;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    BadMac,
    BadPadding,
    BadLength,
    BadVersion(u8, u8),
    UnknownPrivKeyPrefix(u8),
    /// The private key blob was not sealed with this host's keys: the sensor is
    /// paired with another computer.
    PairedElsewhere,
    BadKey,
    NotSecure,
    UnexpectedContent(u8),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::BadMac => f.write_str("record MAC check failed"),
            Error::BadPadding => f.write_str("bad CBC padding"),
            Error::BadLength => f.write_str("truncated or misaligned data"),
            Error::BadVersion(a, b) => write!(f, "unexpected TLS version {a}.{b}"),
            Error::UnknownPrivKeyPrefix(p) => write!(f, "unknown private key prefix {p:#04x}"),
            Error::PairedElsewhere => {
                f.write_str("private key signature mismatch: sensor paired with another computer")
            }
            Error::BadKey => f.write_str("invalid elliptic curve key"),
            Error::NotSecure => f.write_str("encrypted record before the channel is secure"),
            Error::UnexpectedContent(t) => write!(f, "unexpected record type {t:#04x}"),
        }
    }
}

impl std::error::Error for Error {}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// TLS 1.2 PRF with HMAC-SHA256 (RFC 5246 §5); `seed` already includes the label.
pub fn prf(secret: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len.div_ceil(32) * 32);
    let mut a = hmac_sha256(secret, &[seed]);
    while out.len() < len {
        out.extend_from_slice(&hmac_sha256(secret, &[&a, seed]));
        a = hmac_sha256(secret, &[&a]);
    }
    out.truncate(len);
    out
}

/// Private scalar of the hardcoded handshake key pair, big-endian.
pub fn hs_key() -> [u8; 32] {
    let mut seed = b"HS_KEY_PAIR_GEN".to_vec();
    seed.extend_from_slice(&PASSWORD_HARDCODED[0x10..]);
    seed.extend_from_slice(&[0xaa, 0xaa]);
    let mut k: [u8; 32] = prf(&PASSWORD_HARDCODED[..0x10], &seed, 0x20)
        .try_into()
        .expect("prf returns the requested length");
    k.reverse(); // the vendor reads it little-endian
    k
}

/// Sensor padding: TLS style, `n` bytes of value `n - 1`, always at least one byte.
pub fn pad(b: &[u8]) -> Vec<u8> {
    let n = 16 - b.len() % 16;
    let mut out = b.to_vec();
    out.resize(b.len() + n, (n - 1) as u8);
    out
}

pub fn unpad(b: &[u8]) -> Result<&[u8], Error> {
    let n = *b.last().ok_or(Error::BadPadding)? as usize + 1;
    if n > b.len() {
        return Err(Error::BadPadding);
    }
    Ok(&b[..b.len() - n])
}

fn cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], padded: &[u8]) -> Vec<u8> {
    cbc::Encryptor::<Aes256>::new(key.into(), iv.into()).encrypt_padded_vec::<NoPadding>(padded)
}

fn cbc_decrypt(key: &[u8; 32], iv_and_ct: &[u8]) -> Result<Vec<u8>, Error> {
    if iv_and_ct.len() < 32 || !iv_and_ct.len().is_multiple_of(16) {
        return Err(Error::BadLength);
    }
    let (iv, ct) = iv_and_ct.split_at(16);
    let iv: &[u8; 16] = iv.try_into().expect("split at 16");
    cbc::Decryptor::<Aes256>::new(key.into(), iv.into())
        .decrypt_padded_vec::<NoPadding>(ct)
        .map_err(|_| Error::BadLength)
}

fn key32(b: &[u8]) -> [u8; 32] {
    b.try_into().expect("32-byte slice")
}

/// Pre-shared keys derived from the host's DMI product name and serial number.
/// They seal the host private key in the sensor flash at pairing time.
#[derive(Clone)]
pub struct PskKeys {
    pub encryption: [u8; 32],
    pub validation: [u8; 32],
}

impl PskKeys {
    pub fn from_hw(product_name: &str, serial_number: &str) -> Self {
        let mut hw_key = product_name.as_bytes().to_vec();
        hw_key.push(0);
        hw_key.extend_from_slice(serial_number.as_bytes());
        hw_key.push(0);
        let encryption = key32(&prf(
            &PASSWORD_HARDCODED,
            &[b"GWK".as_slice(), &hw_key].concat(),
            0x20,
        ));
        let validation = key32(&prf(
            &encryption,
            &[b"GWK_SIGN".as_slice(), &GWK_SIGN_HARDCODED].concat(),
            0x20,
        ));
        PskKeys {
            encryption,
            validation,
        }
    }

    /// Opens flash block 4: `02 || iv || AES-CBC(x || y || d, PKCS#7) || HMAC`.
    /// Coordinates and scalar are little-endian; only `d` is used (some Windows
    /// pairings leave x and y zeroed).
    pub fn open_priv_blob(&self, blob: &[u8]) -> Result<SecretKey, Error> {
        let (&prefix, body) = blob.split_first().ok_or(Error::BadLength)?;
        if prefix != 2 {
            return Err(Error::UnknownPrivKeyPrefix(prefix));
        }
        if body.len() < 32 {
            return Err(Error::BadLength);
        }
        let (c, mac) = body.split_at(body.len() - 32);
        let mut m = HmacSha256::new_from_slice(&self.validation).expect("any key length");
        m.update(c);
        m.verify_slice(mac).map_err(|_| Error::PairedElsewhere)?;
        let plain = cbc_decrypt(&self.encryption, c)?;
        // Standard PKCS#7 here, unlike the record layer.
        let n = *plain.last().ok_or(Error::BadPadding)? as usize;
        if n == 0 || n > plain.len() || plain.len() - n < 0x60 {
            return Err(Error::BadPadding);
        }
        let mut d = key32(&plain[0x40..0x60]);
        d.reverse();
        SecretKey::from_slice(&d).map_err(|_| Error::BadKey)
    }
}

/// `id (le16) || len (le16) || sha256(body) || body`, as stored in the TLS flash partition.
pub fn flash_block(id: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(36 + body.len());
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(&Sha256::digest(body));
    out.extend_from_slice(body);
    out
}

/// Builds a public key from little-endian affine coordinates, as the sensor stores them.
pub fn public_key_le(x: &[u8], y: &[u8]) -> Result<PublicKey, Error> {
    if x.len() != 32 || y.len() != 32 {
        return Err(Error::BadLength);
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(4);
    sec1.extend(x.iter().rev());
    sec1.extend(y.iter().rev());
    PublicKey::from_sec1_bytes(&sec1).map_err(|_| Error::BadKey)
}

/// Keys from the TLS key block (note the order differs from RFC 5246).
#[derive(Clone)]
pub struct SessionKeys {
    pub master_secret: [u8; 48],
    pub sign: [u8; 32],
    pub validation: [u8; 32],
    pub encryption: [u8; 32],
    pub decryption: [u8; 32],
}

impl SessionKeys {
    pub fn derive(
        ephemeral: &SecretKey,
        server: &PublicKey,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> Self {
        let shared = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), server.as_affine());
        let seed = [client_random.as_slice(), server_random].concat();
        let master: [u8; 48] = prf(
            shared.raw_secret_bytes(),
            &[b"master secret".as_slice(), &seed].concat(),
            0x30,
        )
        .try_into()
        .expect("prf returns the requested length");
        let kb = prf(
            &master,
            &[b"key expansion".as_slice(), &seed].concat(),
            0x120,
        );
        SessionKeys {
            master_secret: master,
            sign: key32(&kb[0x00..0x20]),
            validation: key32(&kb[0x20..0x40]),
            encryption: key32(&kb[0x40..0x60]),
            decryption: key32(&kb[0x60..0x80]),
        }
    }

    /// `verify_data` of a Finished message; `label` is `client finished` or `server finished`.
    pub fn verify_data(&self, label: &[u8], handshake_hash: &[u8; 32]) -> [u8; 12] {
        prf(&self.master_secret, &[label, handshake_hash].concat(), 0xc)
            .try_into()
            .expect("prf returns the requested length")
    }
}

fn record_mac(key: &[u8; 32], t: u8, b: &[u8]) -> [u8; 32] {
    let len = (b.len() as u16).to_be_bytes();
    hmac_sha256(key, &[&[t, 3, 3, len[0], len[1]], b])
}

/// `type || 03 03 || len (be16) || body`.
pub fn record(t: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![t, 3, 3];
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// MAC-then-encrypt a record body with the client keys; `iv` must be fresh randomness.
pub fn seal(keys: &SessionKeys, t: u8, payload: &[u8], iv: &[u8; 16]) -> Vec<u8> {
    let mut m = payload.to_vec();
    m.extend_from_slice(&record_mac(&keys.sign, t, payload));
    let mut out = iv.to_vec();
    out.extend(cbc_encrypt(&keys.encryption, iv, &pad(&m)));
    out
}

/// Decrypt and authenticate a record body with the server keys.
pub fn open(keys: &SessionKeys, t: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    let plain = cbc_decrypt(&keys.decryption, body)?;
    let m = unpad(&plain)?;
    if m.len() < 32 {
        return Err(Error::BadLength);
    }
    let (payload, mac) = m.split_at(m.len() - 32);
    let mut h = HmacSha256::new_from_slice(&keys.validation).expect("any key length");
    let len = (payload.len() as u16).to_be_bytes();
    h.update(&[t, 3, 3, len[0], len[1]]);
    h.update(payload);
    h.verify_slice(mac).map_err(|_| Error::BadMac)?;
    Ok(payload.to_vec())
}

/// Splits a response into `(type, body)` records. Like the reference, a short
/// trailing header is zero-extended rather than rejected.
pub fn split_records(mut rsp: &[u8]) -> Result<Vec<(u8, &[u8])>, Error> {
    let mut out = Vec::new();
    while !rsp.is_empty() {
        let mut hdr = [0u8; 5];
        let n = rsp.len().min(5);
        hdr[..n].copy_from_slice(&rsp[..n]);
        rsp = &rsp[n..];
        if hdr[1] != 3 || hdr[2] != 3 {
            return Err(Error::BadVersion(hdr[1], hdr[2]));
        }
        let sz = (u16::from_be_bytes([hdr[3], hdr[4]]) as usize).min(rsp.len());
        out.push((hdr[0], &rsp[..sz]));
        rsp = &rsp[sz..];
    }
    Ok(out)
}

/// Handshake message: `type || len (be24) || body`.
pub fn handshake_msg(t: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len() as u32;
    let mut out = vec![t, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    out.extend_from_slice(body);
    out
}

/// ClientHello offering 0xc005 (plus two suites the sensor ignores).
pub fn client_hello(random: &[u8; 32]) -> Vec<u8> {
    let mut h = vec![3, 3];
    h.extend_from_slice(random);
    h.extend_from_slice(&[7, 0, 0, 0, 0, 0, 0, 0]); // 7-byte zero session id
    h.extend_from_slice(&[0, 6, 0xc0, 0x05, 0x00, 0x3d, 0x00, 0x8d]);
    h.push(0); // no compression methods
    let exts: [u8; 12] = [
        0x00, 0x04, 0x00, 0x02, 0x00, 0x17, // truncated_hmac (sic)
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, // ec_point_formats: uncompressed
    ];
    // Quirk: the extensions length is two bytes short, as the vendor driver sends it.
    h.extend_from_slice(&((exts.len() - 2) as u16).to_be_bytes());
    h.extend_from_slice(&exts);
    handshake_msg(0x01, &h)
}
