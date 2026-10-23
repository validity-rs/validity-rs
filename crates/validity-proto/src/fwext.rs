//! Firmware extension upload (python-validity `upload_fwext.py`).
//!
//! The extension (`*.xpfwext`) is vendor firmware: it is never shipped here but read
//! from the driver package at install time.

use crate::cmd::Error;
use crate::flash::{FirmwareInfo, get_fw_info, write_flash_all, write_fw_signature};
use crate::scanner::{identify_sensor, read_hw_reg32, reboot, write_hw_reg32};
use crate::session::Sensor;
use crate::vendor::Blobs;

/// SHA-256 of `6_07f_lenovo_mis_qm.xpfwext` from `nz3gf07w.exe` (06cb:009a,
/// 138a:0097, 138a:009d), 218482 bytes.
pub const FWEXT_MIS_QM_SHA256: &str =
    "ed2b1b5818c4072dd5c1a66e5d556888e81e3806ab0fc653164bea823ccfa2b1";

pub const SIGNATURE_LEN: usize = 0x100;

/// A parsed firmware extension file: a text header ended by 0x1a, the image, and
/// a 256-byte signature at the end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fwext {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Fwext {
    pub fn parse(file: &[u8]) -> Result<Self, Error> {
        let start = file
            .iter()
            .position(|&b| b == 0x1a)
            .ok_or(Error::Malformed(
                "firmware extension without header end (0x1a)",
            ))?;
        let body = &file[start + 1..];
        if body.len() <= SIGNATURE_LEN {
            return Err(Error::Malformed("firmware extension too short"));
        }
        let (payload, signature) = body.split_at(body.len() - SIGNATURE_LEN);
        Ok(Fwext {
            payload: payload.to_vec(),
            signature: signature.to_vec(),
        })
    }
}

#[derive(Debug)]
pub enum FwextUpload {
    /// Firmware was already present.
    Present(FirmwareInfo),
    /// Firmware was written; the sensor rebooted.
    Uploaded(FirmwareInfo),
}

/// Uploads the firmware extension to partition 2 unless one is present, then
/// reboots the sensor.
pub fn upload_fwext(
    s: &mut impl Sensor,
    blobs: &Blobs,
    fwext: Option<&Fwext>,
) -> Result<FwextUpload, Error> {
    if let Some(fwi) = get_fw_info(s, 2)? {
        log::info!("detected firmware version {}.{}", fwi.major, fwi.minor);
        return Ok(FwextUpload::Present(fwi));
    }
    // The reference only opens the file after touching the registers; failing
    // before any write is safer.
    let fwext = fwext.ok_or(Error::Unsupported(
        "no firmware on the sensor and no firmware extension file given",
    ))?;
    log::info!("no firmware detected, uploading");
    // Unknown register poke done by the vendor driver.
    write_hw_reg32(s, 0x8000_205c, 7)?;
    let r = read_hw_reg32(s, 0x8000_2080)?;
    if !matches!(r, 2 | 3) {
        return Err(Error::Protocol(format!("unexpected register value {r:#x}")));
    }
    let dev = identify_sensor(s)?;
    log::debug!("sensor: {}", dev.name.trim_end());
    write_flash_all(s, blobs, 2, 0, &fwext.payload)?;
    write_fw_signature(s, 2, &fwext.signature)?;
    let fwi =
        get_fw_info(s, 2)?.ok_or(Error::Protocol("no firmware detected after upload".into()))?;
    log::info!(
        "loaded firmware extension {}.{}, {} modules",
        fwi.major,
        fwi.minor,
        fwi.modules.len()
    );
    reboot(s)?;
    Ok(FwextUpload::Uploaded(fwi))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_file() {
        let mut f = b"header text\r\n".to_vec();
        f.push(0x1a);
        f.extend((0..300u32).map(|i| i as u8));
        let x = Fwext::parse(&f).unwrap();
        assert_eq!(x.payload, (0..44u32).map(|i| i as u8).collect::<Vec<_>>());
        assert_eq!(x.signature.len(), 256);
        assert_eq!(x.signature[0], 44);
        assert!(Fwext::parse(b"no marker").is_err());
        let mut short = vec![0x1a];
        short.extend([0; 256]);
        assert!(Fwext::parse(&short).is_err());
    }
}
