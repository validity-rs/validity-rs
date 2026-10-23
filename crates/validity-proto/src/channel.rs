//! The encrypted channel: pairing material read from flash, the handshake, and
//! application commands. Ported from python-validity `Tls.open`, `parse_tls_flash`
//! and `app`.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::tls::{self, Error as TlsError, PskKeys, SessionKeys};
use crate::transport::{Entropy, Transport, TransportError};

/// Public key the firmware signs the sensor's ECDH key with (hardcoded per
/// firmware revision in the vendor driver), as big-endian affine coordinates.
pub const FW_PUBKEY_X: [u8; 32] = [
    0xf7, 0x27, 0x65, 0x3b, 0x4e, 0x16, 0xce, 0x06, 0x65, 0xa6, 0x89, 0x4d, 0x7f, 0x3a, 0x30, 0xd7,
    0xd0, 0xa0, 0xbe, 0x31, 0x0d, 0x12, 0x92, 0xa7, 0x43, 0x67, 0x1f, 0xdf, 0x69, 0xf6, 0xa8, 0xd3,
];
pub const FW_PUBKEY_Y: [u8; 32] = [
    0xa8, 0x55, 0x38, 0xf8, 0xb6, 0xbe, 0xc5, 0x0d, 0x6e, 0xef, 0x8b, 0xd5, 0xf4, 0xd0, 0x7a, 0x88,
    0x62, 0x43, 0xc5, 0x8b, 0x23, 0x93, 0x94, 0x8d, 0xf7, 0x61, 0xa8, 0x47, 0x21, 0xa6, 0xca, 0x94,
];

/// Prefix of handshake commands (application records are sent bare).
const HANDSHAKE_CMD: [u8; 4] = [0x44, 0, 0, 0];

#[derive(Debug)]
pub enum Error {
    Tls(TlsError),
    Transport(TransportError),
    FlashHash(u16),
    FlashBlockMissing(u16),
    NotEmpty(u16),
    BadEcdhSignature,
    Handshake(&'static str),
    UnknownHandshake(u8),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Tls(e) => e.fmt(f),
            Error::Transport(e) => e.fmt(f),
            Error::FlashHash(id) => write!(f, "TLS flash block {id} hash mismatch"),
            Error::FlashBlockMissing(id) => write!(f, "TLS flash block {id} missing"),
            Error::NotEmpty(id) => write!(f, "TLS flash block {id} expected empty"),
            Error::BadEcdhSignature => {
                f.write_str("sensor ECDH key not signed by the firmware key")
            }
            Error::Handshake(s) => write!(f, "handshake: {s}"),
            Error::UnknownHandshake(t) => write!(f, "unknown handshake message {t:#04x}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<TlsError> for Error {
    fn from(e: TlsError) -> Self {
        Error::Tls(e)
    }
}

impl From<TransportError> for Error {
    fn from(e: TransportError) -> Self {
        Error::Transport(e)
    }
}

/// Pairing material stored in the TLS flash partition.
#[derive(Debug)]
pub struct TlsFlash {
    /// Host key (block 4), sealed with the host's pre-shared keys.
    pub host_key: SecretKey,
    /// Host certificate (block 3), sent verbatim in the handshake.
    pub cert: Vec<u8>,
    /// Sensor ECDH key (block 6), signed by the firmware key.
    pub sensor_key: PublicKey,
}

impl TlsFlash {
    /// Parses the partition: `id (le16) || len (le16) || sha256 || body`, until id 0xffff.
    pub fn parse(mut reply: &[u8], psk: &PskKeys, fw_key: &VerifyingKey) -> Result<Self, Error> {
        let (mut host_key, mut cert, mut sensor_key) = (None, None, None);
        while reply.len() >= 36 {
            let id = u16::from_le_bytes([reply[0], reply[1]]);
            let sz = u16::from_le_bytes([reply[2], reply[3]]) as usize;
            if id == 0xffff {
                break;
            }
            let hash = &reply[4..36];
            let body = reply.get(36..36 + sz).ok_or(TlsError::BadLength)?;
            reply = &reply[36 + sz..];
            if Sha256::digest(body).as_slice() != hash {
                return Err(Error::FlashHash(id));
            }
            match id {
                0..=2 if body.iter().any(|&b| b != 0) => return Err(Error::NotEmpty(id)),
                3 => cert = Some(body.to_vec()),
                4 => host_key = Some(psk.open_priv_blob(body)?),
                6 => sensor_key = Some(parse_ecdh_block(body, fw_key)?),
                _ => log::trace!("TLS flash block {id} ({sz} bytes) ignored"),
            }
        }
        Ok(TlsFlash {
            host_key: host_key.ok_or(Error::FlashBlockMissing(4))?,
            cert: cert.ok_or(Error::FlashBlockMissing(3))?,
            sensor_key: sensor_key.ok_or(Error::FlashBlockMissing(6))?,
        })
    }
}

pub fn firmware_key() -> VerifyingKey {
    let mut sec1 = vec![4];
    sec1.extend_from_slice(&FW_PUBKEY_X);
    sec1.extend_from_slice(&FW_PUBKEY_Y);
    VerifyingKey::from_sec1_bytes(&sec1).expect("valid hardcoded firmware key")
}

/// Block 6: a 0x90-byte key structure (x at 0x08, y at 0x4c, little-endian),
/// then `len (le32) || DER ECDSA-SHA256 signature || zero padding`.
pub fn parse_ecdh_block(body: &[u8], fw_key: &VerifyingKey) -> Result<PublicKey, Error> {
    if body.len() < 0x94 {
        return Err(TlsError::BadLength.into());
    }
    let (key, rest) = body.split_at(0x90);
    let public = tls::public_key_le(&key[0x08..0x28], &key[0x4c..0x6c])?;
    let l = u32::from_le_bytes(rest[..4].try_into().expect("4 bytes")) as usize;
    let sig = rest.get(4..4 + l).ok_or(TlsError::BadLength)?;
    if rest[4 + l..].iter().any(|&b| b != 0) {
        return Err(Error::Handshake("garbage after ECDH signature"));
    }
    let sig = DerSignature::from_bytes(sig).map_err(|_| Error::BadEcdhSignature)?;
    fw_key
        .verify(key, &sig)
        .map_err(|_| Error::BadEcdhSignature)?;
    Ok(public)
}

/// An open (or opening) channel to the sensor.
pub struct Channel {
    flash: TlsFlash,
    keys: Option<SessionKeys>,
    secure_tx: bool,
    secure_rx: bool,
    transcript: Sha256,
}

/// State only: keys and transcript stay out of logs.
impl core::fmt::Debug for Channel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Channel")
            .field("keys", &self.keys.is_some())
            .field("secure_tx", &self.secure_tx)
            .field("secure_rx", &self.secure_rx)
            .finish_non_exhaustive()
    }
}

impl Channel {
    pub fn new(flash: TlsFlash) -> Self {
        Channel {
            flash,
            keys: None,
            secure_tx: false,
            secure_rx: false,
            transcript: Sha256::new(),
        }
    }

    pub fn is_open(&self) -> bool {
        self.secure_tx && self.secure_rx
    }

    fn keys(&self) -> Result<&SessionKeys, Error> {
        self.keys.as_ref().ok_or(Error::Tls(TlsError::NotSecure))
    }

    fn transcript_hash(&self) -> [u8; 32] {
        self.transcript.clone().finalize().into()
    }

    /// Handshake message added to the transcript.
    fn neg(&mut self, t: u8, body: &[u8]) -> Vec<u8> {
        let m = tls::handshake_msg(t, body);
        self.transcript.update(&m);
        m
    }

    fn handshake_record(&self, body: &[u8], rng: &mut impl Entropy) -> Result<Vec<u8>, Error> {
        Ok(if self.secure_tx {
            let mut iv = [0u8; 16];
            rng.fill(&mut iv);
            tls::record(
                tls::CONTENT_HANDSHAKE,
                &tls::seal(self.keys()?, tls::CONTENT_HANDSHAKE, body, &iv),
            )
        } else {
            tls::record(tls::CONTENT_HANDSHAKE, body)
        })
    }

    fn reset(&mut self) {
        self.secure_tx = false;
        self.secure_rx = false;
        self.keys = None;
        self.transcript = Sha256::new();
    }

    /// Runs the full handshake. On success the channel carries application commands;
    /// on failure it is left closed.
    pub fn open(&mut self, t: &mut impl Transport, rng: &mut impl Entropy) -> Result<(), Error> {
        self.reset();
        let r = self.handshake(t, rng);
        if r.is_err() {
            self.reset();
        }
        r
    }

    fn handshake(&mut self, t: &mut impl Transport, rng: &mut impl Entropy) -> Result<(), Error> {
        let mut client_random = [0u8; 32];
        rng.fill(&mut client_random);
        let hello = tls::client_hello(&client_random);
        self.transcript.update(&hello);
        let mut out = HANDSHAKE_CMD.to_vec();
        out.extend(self.handshake_record(&hello, rng)?);
        let rsp = t.cmd(&out)?;
        let server_random = self
            .parse_response(&rsp)?
            .server_random
            .ok_or(Error::Handshake("no ServerHello"))?;

        let ephemeral = loop {
            let mut d = [0u8; 32];
            rng.fill(&mut d);
            if let Ok(k) = SecretKey::from_slice(&d) {
                break k;
            }
        };
        self.keys = Some(SessionKeys::derive(
            &ephemeral,
            &self.flash.sensor_key,
            &client_random,
            &server_random,
        ));

        // Certificate. Quirk: both length fields carry the bare certificate length,
        // and an unexplained `ac 16` precedes the certificate.
        let cert_len = (self.flash.cert.len() as u16).to_be_bytes();
        let mut body = vec![
            0,
            cert_len[0],
            cert_len[1],
            0,
            cert_len[0],
            cert_len[1],
            0xac,
            0x16,
        ];
        body.extend_from_slice(&self.flash.cert);
        let mut hs = self.neg(0x0b, &body);

        // ClientKeyExchange: uncompressed ephemeral point. (python-validity drops leading
        // zero bytes of each coordinate, which breaks 1 handshake in ~128; we keep 32.)
        let point = ephemeral.public_key().to_sec1_point(false);
        hs.extend(self.neg(0x10, point.as_bytes()));

        // CertificateVerify over the transcript so far, DER, deterministic (RFC 6979).
        let sig: DerSignature = SigningKey::from(&self.flash.host_key)
            .sign_prehash(&self.transcript_hash())
            .map_err(|_| Error::Handshake("signing failed"))?;
        hs.extend(self.neg(0x0f, sig.as_bytes()));

        // Finished is computed over the transcript without itself, and is not added to it.
        self.secure_tx = true;
        let verify = self
            .keys()?
            .verify_data(b"client finished", &self.transcript_hash());
        let finished = tls::handshake_msg(0x14, &verify);

        let mut out = HANDSHAKE_CMD.to_vec();
        out.extend(tls::record(tls::CONTENT_HANDSHAKE, &hs));
        out.extend(tls::record(tls::CONTENT_CHANGE_CIPHER_SPEC, &[1]));
        out.extend(self.handshake_record(&finished, rng)?);
        let rsp = t.cmd(&out)?;
        let r = self.parse_response(&rsp)?;
        if !r.finished || !self.secure_rx {
            return Err(Error::Handshake("no server Finished"));
        }
        Ok(())
    }

    /// Sends an application command over the open channel and returns the reply.
    pub fn app(
        &mut self,
        t: &mut impl Transport,
        rng: &mut impl Entropy,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if !self.is_open() {
            return Err(TlsError::NotSecure.into());
        }
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        let rec = tls::record(
            tls::CONTENT_APP_DATA,
            &tls::seal(self.keys()?, tls::CONTENT_APP_DATA, payload, &iv),
        );
        let rsp = t.cmd(&rec)?;
        Ok(self.parse_response(&rsp)?.app_data)
    }

    fn parse_response(&mut self, rsp: &[u8]) -> Result<Parsed, Error> {
        let mut p = Parsed::default();
        for (t, body) in tls::split_records(rsp)? {
            match t {
                tls::CONTENT_HANDSHAKE => {
                    let plain = if self.secure_rx {
                        tls::open(self.keys()?, t, body)?
                    } else {
                        body.to_vec()
                    };
                    self.parse_handshake(&plain, &mut p)?;
                }
                tls::CONTENT_CHANGE_CIPHER_SPEC => {
                    if body != [1] {
                        return Err(Error::Handshake("bad ChangeCipherSpec"));
                    }
                    self.secure_rx = true;
                }
                tls::CONTENT_APP_DATA => {
                    if !self.secure_rx {
                        return Err(TlsError::NotSecure.into());
                    }
                    p.app_data.extend(tls::open(self.keys()?, t, body)?);
                }
                other => return Err(TlsError::UnexpectedContent(other).into()),
            }
        }
        Ok(p)
    }

    fn parse_handshake(&mut self, mut hs: &[u8], p: &mut Parsed) -> Result<(), Error> {
        while !hs.is_empty() {
            // Like the reference, a short header is zero-extended.
            let mut hdr = [0u8; 4];
            let n = hs.len().min(4);
            hdr[..n].copy_from_slice(&hs[..n]);
            hs = &hs[n..];
            let l = (u32::from_be_bytes(hdr) & 0xff_ffff) as usize;
            let body = &hs[..l.min(hs.len())];
            hs = &hs[body.len()..];
            match hdr[0] {
                0x02 => p.server_random = Some(parse_server_hello(body)?),
                0x0d => {
                    if body != [0x01, 0x40, 0x00, 0x00] {
                        return Err(Error::Handshake("unsupported CertificateRequest"));
                    }
                }
                0x0e => {
                    if !body.is_empty() {
                        return Err(Error::Handshake("non-empty ServerHelloDone"));
                    }
                }
                0x14 => {
                    let want = self
                        .keys()?
                        .verify_data(b"server finished", &self.transcript_hash());
                    if body != want {
                        return Err(Error::Handshake("server Finished mismatch"));
                    }
                    p.finished = true;
                }
                t => return Err(Error::UnknownHandshake(t)),
            }
            self.transcript.update(hdr);
            self.transcript.update(body);
        }
        Ok(())
    }
}

#[derive(Default)]
struct Parsed {
    server_random: Option<[u8; 32]>,
    finished: bool,
    app_data: Vec<u8>,
}

fn parse_server_hello(b: &[u8]) -> Result<[u8; 32], Error> {
    let bad = Error::Handshake("malformed ServerHello");
    if b.len() < 35 || b[..2] != [3, 3] {
        return Err(bad);
    }
    let random: [u8; 32] = b[2..34].try_into().expect("32 bytes");
    let sid = b[34] as usize;
    let rest = b
        .get(35 + sid..)
        .ok_or(Error::Handshake("malformed ServerHello"))?;
    if rest != [0xc0, 0x05, 0x00] {
        return Err(Error::Handshake("unsupported cipher suite or compression"));
    }
    Ok(random)
}
