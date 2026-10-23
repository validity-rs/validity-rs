//! Bringing a sensor up (python-validity `init.py` `open_common`): pair if blank,
//! start the session, open the channel, upload the firmware extension if missing,
//! identify and calibrate, and create the user storage.
//!
//! Pairing and the firmware upload end in a sensor reboot: the caller reopens the
//! device once it reconnects and calls [`open`] again.

use crate::calibration::CalibrationFile;
use crate::cmd::{Error, read_tls_flash, send_init};
use crate::db::init_db;
use crate::fwext::{Fwext, FwextUpload, upload_fwext};
use crate::pairing::{InitFlash, init_flash};
use crate::scanner::{Scanner, reboot};
use crate::session::Sensor;
use crate::tls::PskKeys;
use crate::transport::Entropy;
use crate::vendor::Blobs;

/// Why the sensor rebooted during [`open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rebooted {
    Paired,
    FirmwareUploaded,
}

#[derive(Debug)]
pub enum Opened {
    Ready(Box<Scanner>),
    Rebooted(Rebooted),
}

/// Inputs of [`open`] besides the sensor.
pub struct Setup<'a> {
    pub blobs: &'a Blobs,
    /// Pre-shared keys of this host (must match the session's).
    pub psk: &'a PskKeys,
    /// Firmware extension, needed only when the sensor has none.
    pub fwext: Option<&'a Fwext>,
    /// Calibration saved by an earlier session.
    pub calibration: Option<&'a CalibrationFile>,
}

pub fn open(
    s: &mut impl Sensor,
    setup: &Setup<'_>,
    rng: &mut impl Entropy,
) -> Result<Opened, Error> {
    if let InitFlash::Paired = init_flash(s, setup.blobs, setup.psk, rng)? {
        return Ok(Opened::Rebooted(Rebooted::Paired));
    }
    send_init(s, setup.blobs)?;
    let flash = read_tls_flash(s)?;
    s.open_channel(&flash)?;
    if let FwextUpload::Uploaded(_) = upload_fwext(s, setup.blobs, setup.fwext)? {
        return Ok(Opened::Rebooted(Rebooted::FirmwareUploaded));
    }
    let scanner = Scanner::open(s, setup.blobs, setup.calibration)?;
    init_db(s, setup.blobs)?;
    Ok(Opened::Ready(Box::new(scanner)))
}

/// Ends a session: the reference reboots the sensor on exit, otherwise it keeps
/// TLS sessions around and eventually runs out of memory.
pub fn close(s: &mut impl Sensor) -> Result<(), Error> {
    reboot(s)
}
