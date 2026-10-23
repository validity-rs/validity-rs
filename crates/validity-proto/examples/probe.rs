//! Hardware probe: opens the sensor, reads the pairing material and runs one command
//! over the encrypted channel. Read-only apart from the final sensor reboot.
//!
//! Usage (root): probe <path/to/synaWudfBioUsb.dll>

use std::time::Instant;

use validity_proto::channel::{Channel, TlsFlash, firmware_key};
use validity_proto::cmd::{self, GET_FLASH_INFO, REBOOT};
use validity_proto::tls::PskKeys;
use validity_proto::transport::OsEntropy;
use validity_proto::usb::UsbSensor;
use validity_proto::vendor::Blobs;

fn dmi(field: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/dmi/id/{field}"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|e| panic!("reading DMI {field} (needs root): {e}"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dll = std::env::args()
        .nth(1)
        .ok_or("usage: probe <synaWudfBioUsb.dll>")?;
    let blobs = Blobs::from_dll(&std::fs::read(dll)?)?;
    println!("blobs: extracted and verified from the vendor DLL");

    let t0 = Instant::now();
    let mut usb = UsbSensor::open()?;
    println!("usb: opened {:04x}:{:04x}", usb.vendor_id, usb.product_id);

    let fwext = cmd::send_init(&mut usb, &blobs)?;
    println!("init: ok, firmware extension {fwext:?}");

    let plain_info = cmd::checked(&mut usb, &GET_FLASH_INFO)?;
    println!("flash info (clear): {} bytes", plain_info.len());

    let flash = cmd::read_tls_flash(&mut usb)?;
    println!("tls flash: {} bytes read", flash.len());
    let psk = PskKeys::from_hw(&dmi("product_name"), &dmi("product_serial"));
    let flash = TlsFlash::parse(&flash, &psk, &firmware_key())?;
    println!(
        "tls flash: host key opened, certificate {} bytes, sensor ECDH key signed by firmware",
        flash.cert.len()
    );

    let mut rng = OsEntropy;
    let mut ch = Channel::new(flash);
    ch.open(&mut usb, &mut rng)?;
    println!(
        "channel: handshake complete in {:?} since start",
        t0.elapsed()
    );

    let enc_info = ch.app(&mut usb, &mut rng, &GET_FLASH_INFO)?;
    cmd::status(&enc_info)?;
    println!(
        "flash info (encrypted): {} bytes, identical to clear: {}",
        enc_info.len(),
        enc_info == plain_info
    );
    if enc_info != plain_info {
        println!(
            "  clear:     {}\n  encrypted: {}",
            hex(&plain_info),
            hex(&enc_info)
        );
    }

    // Like the reference: reboot so the sensor does not accumulate TLS sessions.
    match ch.app(&mut usb, &mut rng, &REBOOT) {
        Ok(r) => println!("reboot: status {}", hex(&r[..r.len().min(2)])),
        Err(e) => println!("reboot: sensor dropped the link as expected ({e})"),
    }
    Ok(())
}
