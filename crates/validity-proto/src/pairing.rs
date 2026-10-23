//! First-time initialisation: partitioning the flash and pairing the host with the
//! sensor (python-validity `init_flash.py`, `tls.make_tls_flash`).
//!
//! Pairing generates a host key pair, has the sensor certify the host public key
//! (the certificate comes back in the reply), seals the host private key with the
//! host's pre-shared keys, and stores everything in the TLS partition. It rewrites
//! the sensor flash: any previous pairing and enrolment is lost.

use aes::Aes256;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::cmd::{Error, Reader, checked, status};
use crate::flash::{
    FlashInfo, PartitionInfo, call_cleanups, erase_flash, get_flash_info, write_flash,
};
use crate::scanner::{RomInfo, reboot};
use crate::session::Sensor;
use crate::tables::FlashIcInfo;
use crate::tls::{self, PskKeys};
use crate::transport::Entropy;
use crate::vendor::Blobs;

/// Partition layout written by the Windows driver (all supported devices but
/// 138a:0090, whose layout and signature come from another driver package).
pub const FLASH_LAYOUT: [PartitionInfo; 5] = [
    // certificate store
    PartitionInfo {
        id: 1,
        kind: 4,
        access_lvl: 7,
        offset: 0x1000,
        size: 0x1000,
    },
    // firmware extension
    PartitionInfo {
        id: 2,
        kind: 1,
        access_lvl: 2,
        offset: 0x2000,
        size: 0x3e000,
    },
    // unknown
    PartitionInfo {
        id: 5,
        kind: 5,
        access_lvl: 3,
        offset: 0x40000,
        size: 0x8000,
    },
    // calibration data
    PartitionInfo {
        id: 6,
        kind: 6,
        access_lvl: 3,
        offset: 0x48000,
        size: 0x8000,
    },
    // template database
    PartitionInfo {
        id: 4,
        kind: 3,
        access_lvl: 5,
        offset: 0x50000,
        size: 0x80000,
    },
];

/// Order in which the new partitions are wiped after pairing.
pub const ERASE_ORDER: [u8; 5] = [1, 2, 5, 6, 4];

/// Size of a host certificate request, zero-padded.
pub const CERT_LEN: usize = 444;
/// Size of the sensor's ECDH key block in the reply to `0x50`.
pub const ECDH_BLOCK_LEN: usize = 400;
/// Size of the TLS partition image.
pub const TLS_FLASH_LEN: usize = 0x1000;

fn le32(be: &[u8]) -> Vec<u8> {
    be.iter().rev().copied().collect()
}

fn xy_le(public: &PublicKey) -> (Vec<u8>, Vec<u8>) {
    let p = public.to_sec1_point(false);
    let b = p.as_bytes();
    (le32(&b[1..33]), le32(&b[33..65]))
}

/// P-256 domain parameters (SEC 2), big-endian: a, b, Gx, Gy, n, p.
const P256_PARAMS: [&str; 6] = [
    "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
];

/// The curve description the host hands the sensor (python-validity
/// `crt_hardcoded`, TLS flash block 5): `0x17, 256 bits, 1`, then the P-256
/// parameters little-endian, each in a 68-byte slot.
pub fn curve_block() -> Vec<u8> {
    let mut b = Vec::with_capacity(12 + 6 * 68);
    for v in [0x17u32, 0x100, 1] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    for p in P256_PARAMS {
        let mut v = le32(&crate::hex::decode(p).expect("valid constant"));
        v.resize(68, 0);
        b.extend(v);
    }
    b
}

/// Host certificate request: `0x17, 0x20`, the public key little-endian in 68-byte
/// slots, then the length-prefixed DER ECDSA-SHA256 signature by the hardcoded
/// handshake key, zero-padded to 444 bytes.
///
/// The signature is deterministic (RFC 6979); the reference signs with a random nonce.
pub fn make_cert(public: &PublicKey) -> Vec<u8> {
    let (x, y) = xy_le(public);
    let mut msg = Vec::with_capacity(CERT_LEN);
    msg.extend_from_slice(&0x17u32.to_le_bytes());
    msg.extend_from_slice(&0x20u32.to_le_bytes());
    msg.extend(x);
    msg.extend_from_slice(&[0; 0x24]);
    msg.extend(y);
    msg.extend_from_slice(&[0; 0x4c]);
    let key = SigningKey::from_slice(&tls::hs_key()).expect("valid hardcoded key");
    let sig: DerSignature = key.sign(&msg);
    msg.extend_from_slice(&(sig.as_bytes().len() as u32).to_le_bytes());
    msg.extend_from_slice(sig.as_bytes());
    msg.resize(CERT_LEN, 0);
    msg
}

/// Seals the host private key for flash block 4:
/// `02 || iv || AES-256-CBC(x || y || d, PKCS#7) || HMAC-SHA256`, little-endian values.
pub fn encrypt_key(key: &SecretKey, psk: &PskKeys, iv: &[u8; 16]) -> Vec<u8> {
    let (x, y) = xy_le(&key.public_key());
    let mut m = x;
    m.extend(y);
    m.extend(le32(&key.to_bytes()));
    let mut c = iv.to_vec();
    c.extend(
        cbc::Encryptor::<Aes256>::new((&psk.encryption).into(), iv.into())
            .encrypt_padded_vec::<Pkcs7>(&m),
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(&psk.validation).expect("any key length");
    mac.update(&c);
    let mut out = vec![2];
    out.extend(c);
    out.extend(mac.finalize().into_bytes());
    out
}

/// `size (le32) || sector size (le32) || 00 00 || erase command || 00`.
pub fn serialize_flash_params(ic: &FlashIcInfo) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0..4].copy_from_slice(&ic.size.to_le_bytes());
    b[4..8].copy_from_slice(&ic.sector_size.to_le_bytes());
    b[10] = ic.sector_erase_cmd;
    b
}

/// Partition entry, four zero bytes, SHA-256 of the entry.
pub fn serialize_partition(p: &PartitionInfo) -> Vec<u8> {
    let e = p.to_bytes();
    let mut b = e.to_vec();
    b.extend_from_slice(&[0; 4]);
    b.extend_from_slice(&Sha256::digest(e));
    b
}

fn with_hdr(id: u16, buf: &[u8]) -> Vec<u8> {
    let mut b = id.to_le_bytes().to_vec();
    b.extend_from_slice(&(buf.len() as u16).to_le_bytes());
    b.extend_from_slice(buf);
    b
}

/// `0x4f`: flash parameters (0), partition table and its vendor signature (1),
/// host certificate request (5), curve description (3).
pub fn partition_flash_cmd(
    ic: &FlashIcInfo,
    layout: &[PartitionInfo],
    signature: &[u8],
    cert: &[u8],
) -> Vec<u8> {
    let mut c = vec![0x4f, 0, 0, 0, 0];
    c.extend(with_hdr(0, &serialize_flash_params(ic)));
    let mut table: Vec<u8> = layout.iter().flat_map(serialize_partition).collect();
    table.extend_from_slice(signature);
    c.extend(with_hdr(1, &table));
    c.extend(with_hdr(5, cert));
    c.extend(with_hdr(3, &curve_block()));
    c
}

/// The host certificate issued by the sensor, from the reply to `0x4f`
/// (the rest of the reply is not understood).
pub fn parse_partition_reply(rsp: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(status(rsp)?, "partition reply");
    let len = r.u32()? as usize;
    Ok(r.bytes(len)?.to_vec())
}

/// The sensor ECDH key block from the reply to `0x50`: `len (le32, counting
/// itself) || zeros || 400-byte block`.
pub fn parse_ecdh_reply(rsp: &[u8]) -> Result<Vec<u8>, Error> {
    let p = status(rsp)?;
    let mut r = Reader::new(p, "ECDH reply");
    if r.u32()? as usize != p.len() {
        return Err(Error::Malformed("ECDH reply length"));
    }
    let rest = r.rest();
    if rest.len() < ECDH_BLOCK_LEN {
        return Err(Error::Malformed("ECDH reply length"));
    }
    let (zeros, block) = rest.split_at(rest.len() - ECDH_BLOCK_LEN);
    if zeros.iter().any(|&b| b != 0) {
        return Err(Error::Malformed("ECDH reply padding"));
    }
    Ok(block.to_vec())
}

/// The TLS partition image: blocks 0 (empty), 4 (sealed host key), 3 (host
/// certificate), 5 (curve), 1 and 2 (empty), 6 (sensor ECDH key), then 0xff.
pub fn make_tls_flash(priv_blob: &[u8], cert: &[u8], ecdh: &[u8]) -> Result<Vec<u8>, Error> {
    let mut b = tls::flash_block(0, &[0]);
    b.extend(tls::flash_block(4, priv_blob));
    b.extend(tls::flash_block(3, cert));
    b.extend(tls::flash_block(5, &curve_block()));
    b.extend(tls::flash_block(1, &[0; 0x100]));
    b.extend(tls::flash_block(2, &[0; 0x100]));
    b.extend(tls::flash_block(6, ecdh));
    if b.len() > TLS_FLASH_LEN {
        return Err(Error::Protocol(
            "TLS flash image larger than its partition".into(),
        ));
    }
    b.resize(TLS_FLASH_LEN, 0xff);
    Ok(b)
}

/// Blocks of a TLS partition image: `(id, body)` until id 0xffff. Hashes are not
/// checked here (`channel::TlsFlash::parse` does).
pub fn tls_flash_blocks(mut b: &[u8]) -> Result<Vec<(u16, &[u8])>, Error> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let id = u16::from_le_bytes([b[0], b[1]]);
        if id == 0xffff {
            break;
        }
        let len = u16::from_le_bytes([b[2], b[3]]) as usize;
        let body = b
            .get(36..36 + len)
            .ok_or(Error::Malformed("TLS flash block"))?;
        out.push((id, body));
        b = &b[36 + len..];
    }
    Ok(out)
}

fn generate_key(rng: &mut impl Entropy) -> SecretKey {
    loop {
        let mut d = [0u8; 32];
        rng.fill(&mut d);
        if let Ok(k) = SecretKey::from_slice(&d) {
            return k;
        }
    }
}

#[derive(Debug)]
pub enum InitFlash {
    /// The flash was already partitioned (and presumably paired).
    AlreadyPartitioned(FlashInfo),
    /// The flash was partitioned and paired; the sensor rebooted.
    Paired,
}

/// `init_flash`: partitions and pairs a blank sensor, then reboots it.
/// `psk` must be the keys the session will later open the channel with.
pub fn init_flash(
    s: &mut impl Sensor,
    blobs: &Blobs,
    psk: &PskKeys,
    rng: &mut impl Entropy,
) -> Result<InitFlash, Error> {
    let info = get_flash_info(s)?;
    if !info.partitions.is_empty() {
        log::info!("flash has {} partitions", info.partitions.len());
        return Ok(InitFlash::AlreadyPartitioned(info));
    }
    log::info!(
        "flash not initialised, detected {} ({} bytes): formatting",
        info.ic.name,
        info.ic.size
    );
    checked(s, &blobs.reset_blob)?;

    let key = generate_key(rng);
    let cmd = partition_flash_cmd(
        info.ic,
        &FLASH_LAYOUT,
        &blobs.partition_signature,
        &make_cert(&key.public_key()),
    );
    let host_cert = parse_partition_reply(&s.cmd(&cmd)?)?;

    RomInfo::get(s)?;

    let rsp = s.cmd(&[0x50]);
    let cleanup = call_cleanups(s);
    let rsp = rsp?;
    status(&rsp)?;
    cleanup?;
    let ecdh = parse_ecdh_reply(&rsp)?;

    let mut iv = [0u8; 16];
    rng.fill(&mut iv);
    let image = make_tls_flash(&encrypt_key(&key, psk, &iv), &host_cert, &ecdh)?;
    s.open_channel(&image)?;

    for p in ERASE_ORDER {
        erase_flash(s, blobs, p)?;
    }
    write_flash(s, blobs, 1, 0, &image)?;
    reboot(s)?;
    Ok(InitFlash::Paired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{TlsFlash, firmware_key};
    use crate::flash::write_flash_cmd;
    use crate::tables::flash_ic_lookup;
    use crate::testutil::{Script, Step, blobs};
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;

    struct Counter(u8);
    impl Entropy for Counter {
        fn fill(&mut self, b: &mut [u8]) {
            for x in b {
                self.0 = self.0.wrapping_add(1);
                *x = self.0;
            }
        }
    }

    #[test]
    fn curve_block_matches_p256() {
        let c = curve_block();
        assert_eq!(c.len(), 420);
        assert_eq!(&c[..12], [0x17, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0]);
        // Gx little-endian in the third slot.
        assert_eq!(&c[12 + 2 * 68..12 + 2 * 68 + 4], [0x96, 0xc2, 0x98, 0xd8]);
        assert!(c[12 + 32..12 + 68].iter().all(|&b| b == 0));
    }

    #[test]
    fn cert_is_signed_by_handshake_key() {
        let k = SecretKey::from_slice(&[7; 32]).unwrap();
        let c = make_cert(&k.public_key());
        assert_eq!(c.len(), CERT_LEN);
        let (x, y) = xy_le(&k.public_key());
        assert_eq!(&c[8..40], &x[..]);
        assert_eq!(&c[76..108], &y[..]);
        let l = u32::from_le_bytes(c[184..188].try_into().unwrap()) as usize;
        let sig = DerSignature::from_bytes(&c[188..188 + l]).unwrap();
        let hs = SigningKey::from_slice(&tls::hs_key()).unwrap();
        VerifyingKey::from(&hs).verify(&c[..184], &sig).unwrap();
        assert!(c[188 + l..].iter().all(|&b| b == 0));
    }

    #[test]
    fn sealed_key_opens_with_the_same_psk() {
        let psk = PskKeys::from_hw("Synthetic", "1");
        let k = SecretKey::from_slice(&[9; 32]).unwrap();
        let blob = encrypt_key(&k, &psk, &[3; 16]);
        assert_eq!(blob.len(), 161);
        assert_eq!(psk.open_priv_blob(&blob).unwrap().to_bytes(), k.to_bytes());
        assert!(matches!(
            PskKeys::from_hw("Synthetic", "2").open_priv_blob(&blob),
            Err(tls::Error::PairedElsewhere)
        ));
    }

    #[test]
    fn partition_cmd_layout() {
        let ic = flash_ic_lookup(0xef, 0x40, 0x100000).unwrap();
        assert_eq!(
            serialize_flash_params(ic),
            [0, 0, 0x10, 0, 0, 0x10, 0, 0, 0, 0, 0x20, 0]
        );
        let c = partition_flash_cmd(ic, &FLASH_LAYOUT, &[0x5a; 256], &[1; CERT_LEN]);
        assert_eq!(c.len(), 1393);
        assert_eq!(&c[..9], [0x4f, 0, 0, 0, 0, 0, 0, 12, 0]);
        let p = serialize_partition(&FLASH_LAYOUT[0]);
        assert_eq!(&c[21..25], [1, 0, 0xf0, 0x01]);
        assert_eq!(&c[25..73], &p[..]);
        assert_eq!(
            &p[..16],
            [1, 4, 7, 0, 0, 0x10, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn replies() {
        let mut r = vec![0, 0, 3, 0, 0, 0, 1, 2, 3, 4];
        assert_eq!(parse_partition_reply(&r).unwrap(), [1, 2, 3]);
        r[2] = 9;
        assert!(parse_partition_reply(&r).is_err());

        let mut e = vec![0, 0];
        e.extend_from_slice(&(4u32 + 8 + 400).to_le_bytes());
        e.extend_from_slice(&[0; 8]);
        e.extend((0..400).map(|i| i as u8));
        assert_eq!(parse_ecdh_reply(&e).unwrap()[..3], [0, 1, 2]);
        e[7] = 1;
        assert!(parse_ecdh_reply(&e).is_err());
        e[7] = 0;
        e[2] = 0;
        assert!(parse_ecdh_reply(&e).is_err());
    }

    /// A full pairing against a scripted sensor; the image handed to the channel
    /// parses with the same pre-shared keys and carries the sensor's blocks.
    #[test]
    fn init_flash_sequence() {
        let b = blobs();
        let psk = PskKeys::from_hw("Synthetic", "1");
        let mut info = vec![0, 0];
        for v in [0xefu16, 0x40, 0x100, 0, 0x1000, 0, 0] {
            info.extend_from_slice(&v.to_le_bytes());
        }
        // Sensor side: a firmware-signed ECDH key, as in the handshake tests.
        let fw = SigningKey::from_slice(&[5; 32]).unwrap();
        let sensor = SecretKey::from_slice(&[6; 32]).unwrap();
        let ecdh = {
            let (x, y) = xy_le(&sensor.public_key());
            let mut k = vec![0u8; 0x90];
            k[0x08..0x28].copy_from_slice(&x);
            k[0x4c..0x6c].copy_from_slice(&y);
            let sig: DerSignature = fw.sign(&k);
            k.extend_from_slice(&(sig.as_bytes().len() as u32).to_le_bytes());
            k.extend_from_slice(sig.as_bytes());
            k.resize(ECDH_BLOCK_LEN, 0);
            k
        };
        let mut ecdh_rsp = vec![0, 0];
        ecdh_rsp.extend_from_slice(&(4u32 + 20 + 400).to_le_bytes());
        ecdh_rsp.extend_from_slice(&[0; 20]);
        ecdh_rsp.extend(&ecdh);
        let host_cert: Vec<u8> = (0..184).map(|i| i as u8).collect();
        let mut part_rsp = vec![0, 0, 184, 0, 0, 0];
        part_rsp.extend(&host_cert);
        part_rsp.extend_from_slice(&[0xee; 10]);

        // Expected key and IV from the counter entropy.
        let mut rng = Counter(0);
        let key = generate_key(&mut rng);
        let mut iv = [0; 16];
        rng.fill(&mut iv);
        let ic = flash_ic_lookup(0xef, 0x40, 0x100000).unwrap();
        let image = make_tls_flash(&encrypt_key(&key, &psk, &iv), &host_cert, &ecdh).unwrap();
        let mut steps = vec![
            Step::Cmd(vec![0x3e], info),
            Step::Cmd(b.reset_blob.clone(), vec![0, 0]),
            Step::Cmd(
                partition_flash_cmd(
                    ic,
                    &FLASH_LAYOUT,
                    &b.partition_signature,
                    &make_cert(&key.public_key()),
                ),
                part_rsp,
            ),
            Step::Cmd(vec![1], [vec![0, 0], vec![0; 16]].concat()),
            Step::Cmd(vec![0x50], ecdh_rsp),
            Step::Cmd(vec![0x1a], vec![0, 0]),
            Step::Open(Some(image.clone())),
        ];
        for p in ERASE_ORDER {
            steps.push(Step::Cmd(b.db_write_enable.clone(), vec![0, 0]));
            steps.push(Step::Cmd(vec![0x3f, p], vec![0, 0]));
            steps.push(Step::Cmd(vec![0x1a], vec![0, 0]));
        }
        steps.push(Step::Cmd(b.db_write_enable.clone(), vec![0, 0]));
        steps.push(Step::Cmd(write_flash_cmd(1, 0, &image), vec![0, 0]));
        steps.push(Step::Cmd(vec![0x1a], vec![0, 0]));
        steps.push(Step::Cmd(vec![5, 2, 0], vec![0, 0]));
        let mut s = Script::steps(steps);
        let r = init_flash(&mut s, &b, &psk, &mut Counter(0)).unwrap();
        assert!(matches!(r, InitFlash::Paired));
        s.done();

        let fw_key = VerifyingKey::from(&fw);
        let flash = TlsFlash::parse(&image, &psk, &fw_key).unwrap();
        assert_eq!(flash.cert, host_cert);
        assert_eq!(flash.host_key.to_bytes(), key.to_bytes());
        let blocks = tls_flash_blocks(&image).unwrap();
        let ids: Vec<u16> = blocks.iter().map(|(i, _)| *i).collect();
        assert_eq!(ids, [0, 4, 3, 5, 1, 2, 6]);
        assert_eq!(blocks[3].1, &curve_block()[..]);
        // The real firmware key rejects our synthetic sensor key.
        assert!(TlsFlash::parse(&image, &psk, &firmware_key()).is_err());
    }
}
