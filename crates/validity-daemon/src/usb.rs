//! The real sensor: USB discovery, opening, port reset and hotplug
//! notifications, and the host keys the pairing was sealed with.

use std::future::poll_fn;
use std::path::Path;
use std::pin::Pin;

use futures_core::Stream;
use validity_proto::session::{Deadlines, UsbSession};
use validity_proto::tls::PskKeys;
use validity_proto::transport::OsEntropy;
use validity_proto::usb::{self, UsbSensor};
use validity_proto::vendor::{self, Blobs};

use crate::sensor::{Hardware, OpenFailure, Opened, UsbId};

/// The pre-shared keys of this host, from its DMI product name and serial, read
/// the way python-validity reads them (it paired the sensor). Like it, a host
/// without DMI data uses `VirtualBox` / `0`; unreadable data (not root) is an
/// error rather than silently wrong keys.
pub fn host_keys(dmi: &Path) -> Result<PskKeys, String> {
    let read = |f: &str| match std::fs::read_to_string(dmi.join(f)) {
        Ok(s) => Ok(Some(s.trim().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "cannot read the DMI {f} ({e}): the daemon must run as root"
        )),
    };
    match (read("product_name")?, read("product_serial")?) {
        (Some(name), Some(serial)) => Ok(PskKeys::from_hw(&name, &serial)),
        _ => Ok(PskKeys::from_hw("VirtualBox", "0")),
    }
}

/// Reads and checks the vendor DLL.
pub fn load_blobs(path: &Path) -> Result<Blobs, String> {
    let dll = std::fs::read(path).map_err(|e| {
        format!(
            "vendor driver DLL {} not readable ({e}): install it with `validity-vendor install` (as root)",
            path.display()
        )
    })?;
    Blobs::from_dll(&dll).map_err(|e| match e {
        vendor::Error::DllMismatch => format!(
            "{} is not the expected Synaptics driver DLL (SHA-256 {})",
            path.display(),
            vendor::DLL_SHA256
        ),
        e => format!("{}: {e}", path.display()),
    })
}

/// Where Linux lists USB devices (what nusb enumerates).
const SYSFS_USB: &str = "/sys/bus/usb/devices";

#[derive(Debug)]
pub struct UsbHardware {
    psk: Result<PskKeys, String>,
    deadlines: Deadlines,
}

impl UsbHardware {
    /// `deadlines` bound every wait of the sessions it opens.
    pub fn new(psk: Result<PskKeys, String>, deadlines: Deadlines) -> Self {
        UsbHardware { psk, deadlines }
    }
}

impl Hardware for UsbHardware {
    type Session = UsbSession<UsbSensor, OsEntropy>;

    fn probe(&mut self) -> Result<Option<UsbId>, String> {
        // No USB subsystem (some containers, USB-less machines): no sensor.
        if !Path::new(SYSFS_USB).exists() {
            return Ok(None);
        }
        usb::find_supported()
            .map(|v| v.first().copied())
            .map_err(|e| e.to_string())
    }

    fn open(&mut self) -> Result<Opened<Self::Session>, OpenFailure> {
        let psk = self.psk.clone().map_err(OpenFailure::Setup)?;
        let dev = UsbSensor::open().map_err(|e| OpenFailure::Io(e.to_string()))?;
        let id = (dev.vendor_id, dev.product_id);
        let session = UsbSession::new(dev, OsEntropy, psk).with_deadlines(self.deadlines);
        let cancel = session.cancel_handle();
        Ok(Opened {
            session,
            cancel,
            id,
        })
    }

    fn reset(&mut self, session: Self::Session) -> Result<(), String> {
        session.into_link().reset().map_err(|e| e.to_string())
    }

    fn watch(&mut self, notify: Box<dyn Fn() + Send + Sync>) -> bool {
        let mut watch = match nusb::watch_devices() {
            Ok(w) => w,
            Err(e) => {
                log::warn!("USB hotplug notifications unavailable: {e}");
                return false;
            }
        };
        let spawned = std::thread::Builder::new()
            .name("usb-hotplug".into())
            .spawn(move || {
                let rt = match zruntime::LocalRuntime::new() {
                    Ok(rt) => rt,
                    Err(e) => {
                        log::warn!("USB hotplug thread: {e}");
                        return;
                    }
                };
                rt.block_on(async {
                    while poll_fn(|cx| Pin::new(&mut watch).poll_next(cx))
                        .await
                        .is_some()
                    {
                        notify();
                    }
                });
            });
        spawned.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_keys_follow_python_validity() {
        let dir = std::env::temp_dir().join(format!("validity-dmi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // No DMI at all: python-validity's fallback.
        let none = host_keys(&dir).unwrap();
        assert_eq!(
            none.encryption,
            PskKeys::from_hw("VirtualBox", "0").encryption
        );
        std::fs::write(dir.join("product_name"), "Synthetic Laptop\n").unwrap();
        std::fs::write(dir.join("product_serial"), " SN-SYNTHETIC \n").unwrap();
        let k = host_keys(&dir).unwrap();
        assert_eq!(
            k.encryption,
            PskKeys::from_hw("Synthetic Laptop", "SN-SYNTHETIC").encryption
        );
        assert_ne!(k.encryption, none.encryption);
        // There but unreadable (here a directory): an error, never the
        // fallback keys.
        let bad = dir.join("unreadable");
        std::fs::create_dir_all(bad.join("product_name")).unwrap();
        let e = host_keys(&bad).expect_err("an error");
        assert!(e.starts_with("cannot read the DMI product_name ("), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Without a supported sensor, which is what the tests can count on: no
    /// sensor found, and hotplug notifications whenever nusb has them.
    #[test]
    fn probe_and_hotplug_without_a_sensor() {
        let mut hw = UsbHardware::new(Err("no keys".into()), Deadlines::DEFAULT);
        let expected = if Path::new(SYSFS_USB).exists() {
            usb::find_supported()
                .map(|v| v.first().copied())
                .map_err(|e| e.to_string())
        } else {
            Ok(None)
        };
        assert_eq!(hw.probe(), expected);
        // Opening needs the host keys first.
        assert!(matches!(hw.open(), Err(OpenFailure::Setup(m)) if m == "no keys"));
        let available = nusb::watch_devices().is_ok();
        assert_eq!(hw.watch(Box::new(|| {})), available);
    }

    #[test]
    fn blobs_need_the_right_dll() {
        let p = std::env::temp_dir().join(format!("validity-dll-{}", std::process::id()));
        let err = |p: &Path| load_blobs(p).expect_err("an error");
        assert!(err(&p).contains("not readable"));
        std::fs::write(&p, b"not a dll").unwrap();
        assert!(err(&p).contains("SHA-256"));
    }
}
