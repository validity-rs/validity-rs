//! Vendor material that cannot be redistributed: the opaque command blobs live in
//! the Synaptics driver DLL shipped in Lenovo's package `nz3gf07w.exe`. Each blob is
//! the command byte 0x06 followed by a contiguous run of that DLL, so only offsets,
//! lengths and hashes are kept here (see `tools/oracle/blob_offsets.py`). The vendor
//! signature of the flash partition table is a raw run of the same DLL.

use sha2::{Digest, Sha256};

/// SHA-256 of `synaWudfBioUsb.dll` from `nz3gf07w.exe` (2160248 bytes).
pub const DLL_SHA256: &str = "aed9f4246bbaca28776c05c169c734cae9763322b03dc00e4319320e1aa2294d";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobRef {
    pub name: &'static str,
    pub offset: usize,
    pub len: usize,
    /// SHA-256 of the full blob, command byte included.
    pub sha256: &'static str,
}

/// 06cb:009a blobs.
pub const BLOBS_009A: [BlobRef; 4] = [
    BlobRef {
        name: "init_hardcoded",
        offset: 0x173890,
        len: 580,
        sha256: "3404634893ce32b7fca6b62846f665f41c9dedd5029f0daadc6d800f9567e65f",
    },
    BlobRef {
        name: "init_hardcoded_clean_slate",
        offset: 0x16a3b0,
        len: 740,
        sha256: "29d8b94221d850d1965e722d93223589dbff61c11182451a6a5b86dc5a3bc511",
    },
    BlobRef {
        name: "reset_blob",
        offset: 0x173ae0,
        len: 12036,
        sha256: "a2e7567075c126dca659bdb4c09c3ea4241508dfb32c7c9255f79090470f4013",
    },
    BlobRef {
        name: "db_write_enable",
        offset: 0x1769f0,
        len: 3620,
        sha256: "9c94e0f3d2ef89d625c91d04999cefa0a8d846ef0a1842825bcde3cc8f032517",
    },
];

/// RSA signature of the hardcoded partition layout (python-validity
/// `init_flash.partition_signature`), used by 06cb:009a, 138a:0097 and 138a:009d.
/// A raw run of the DLL, without command byte.
pub const PARTITION_SIGNATURE: BlobRef = BlobRef {
    name: "partition_signature",
    offset: 0x1b7100,
    len: 256,
    sha256: "aa67e62c9de7c7e9591fd449cc9594512c2494274f195a259350fc9f4d4cc108",
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    DllMismatch,
    OutOfRange(&'static str),
    BlobMismatch(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::DllMismatch => write!(f, "driver DLL does not match SHA-256 {DLL_SHA256}"),
            Error::OutOfRange(n) => write!(f, "blob {n} lies outside the DLL"),
            Error::BlobMismatch(n) => write!(f, "blob {n} has an unexpected SHA-256"),
        }
    }
}

impl std::error::Error for Error {}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Extracts and verifies blobs from a DLL image.
pub fn extract(dll: &[u8], refs: &[BlobRef]) -> Result<Vec<Vec<u8>>, Error> {
    refs.iter()
        .map(|r| {
            let run = dll
                .get(r.offset..r.offset + r.len)
                .ok_or(Error::OutOfRange(r.name))?;
            let mut blob = Vec::with_capacity(r.len + 1);
            blob.push(0x06);
            blob.extend_from_slice(run);
            if hex(&Sha256::digest(&blob)) != r.sha256 {
                return Err(Error::BlobMismatch(r.name));
            }
            Ok(blob)
        })
        .collect()
}

/// Extracts and verifies a raw run of the DLL (no command byte).
pub fn extract_raw(dll: &[u8], r: &BlobRef) -> Result<Vec<u8>, Error> {
    let run = dll
        .get(r.offset..r.offset + r.len)
        .ok_or(Error::OutOfRange(r.name))?;
    if hex(&Sha256::digest(run)) != r.sha256 {
        return Err(Error::BlobMismatch(r.name));
    }
    Ok(run.to_vec())
}

/// The 06cb:009a command blobs and the partition table signature.
pub struct Blobs {
    pub init_hardcoded: Vec<u8>,
    pub init_hardcoded_clean_slate: Vec<u8>,
    pub reset_blob: Vec<u8>,
    pub db_write_enable: Vec<u8>,
    pub partition_signature: Vec<u8>,
}

/// Lengths only: the blobs are vendor material, not something to log.
impl core::fmt::Debug for Blobs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Blobs")
            .field("init_hardcoded", &self.init_hardcoded.len())
            .field(
                "init_hardcoded_clean_slate",
                &self.init_hardcoded_clean_slate.len(),
            )
            .field("reset_blob", &self.reset_blob.len())
            .field("db_write_enable", &self.db_write_enable.len())
            .field("partition_signature", &self.partition_signature.len())
            .finish()
    }
}

impl Blobs {
    pub fn from_dll(dll: &[u8]) -> Result<Self, Error> {
        if hex(&Sha256::digest(dll)) != DLL_SHA256 {
            return Err(Error::DllMismatch);
        }
        let mut b = extract(dll, &BLOBS_009A)?.into_iter();
        let mut next = || b.next().expect("four blobs");
        Ok(Blobs {
            init_hardcoded: next(),
            init_hardcoded_clean_slate: next(),
            reset_blob: next(),
            db_write_enable: next(),
            partition_signature: extract_raw(dll, &PARTITION_SIGNATURE)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_checks_range_and_hash() {
        let dll: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let mut blob = vec![6];
        blob.extend_from_slice(&dll[100..140]);
        let good = hex(&Sha256::digest(&blob));
        let good: &'static str = Box::leak(good.into_boxed_str());
        let refs = [BlobRef {
            name: "t",
            offset: 100,
            len: 40,
            sha256: good,
        }];
        assert_eq!(extract(&dll, &refs).unwrap(), vec![blob]);

        let refs = [BlobRef {
            name: "t",
            offset: 101,
            len: 40,
            sha256: good,
        }];
        assert_eq!(extract(&dll, &refs), Err(Error::BlobMismatch("t")));
        let refs = [BlobRef {
            name: "t",
            offset: 4090,
            len: 40,
            sha256: good,
        }];
        assert_eq!(extract(&dll, &refs), Err(Error::OutOfRange("t")));
        assert!(matches!(Blobs::from_dll(&dll), Err(Error::DllMismatch)));

        let raw = hex(&Sha256::digest(&dll[100..140]));
        let raw: &'static str = Box::leak(raw.into_boxed_str());
        let r = BlobRef {
            name: "r",
            offset: 100,
            len: 40,
            sha256: raw,
        };
        assert_eq!(extract_raw(&dll, &r).unwrap(), &dll[100..140]);
        let r = BlobRef { offset: 99, ..r };
        assert_eq!(extract_raw(&dll, &r), Err(Error::BlobMismatch("r")));
        let r = BlobRef { offset: 4090, ..r };
        assert_eq!(extract_raw(&dll, &r), Err(Error::OutOfRange("r")));
    }

    /// Runs against the real DLL when `VALIDITY_DLL` points at it.
    #[test]
    fn real_dll_if_available() {
        let Ok(path) = std::env::var("VALIDITY_DLL") else {
            eprintln!("VALIDITY_DLL not set, skipped");
            return;
        };
        let b = Blobs::from_dll(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(b.reset_blob.len(), 12037);
        assert_eq!(b.partition_signature.len(), 256);
    }
}
