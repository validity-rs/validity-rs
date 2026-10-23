//! USB transport: commands on bulk endpoints 0x01/0x81, image data on bulk 0x82,
//! interrupts on 0x83.

use std::time::Duration;

use nusb::MaybeFuture;
use nusb::transfer::{Buffer, Bulk, In, Interrupt, Out, TransferError};

use crate::transport::{Transport, TransportError};

/// Devices handled by python-validity; only 06cb:009a is validated so far.
pub const SUPPORTED: [(u16, u16); 4] = [
    (0x06cb, 0x009a),
    (0x138a, 0x0090),
    (0x138a, 0x0097),
    (0x138a, 0x009d),
];

const CMD_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_REPLY: usize = 100 * 1024;
/// Image data (calibration frames) arrives in one transfer of up to 1 MiB.
const MAX_IMAGE: usize = 1024 * 1024;

pub struct UsbSensor {
    device: nusb::Device,
    out: nusb::Endpoint<Bulk, Out>,
    inp: nusb::Endpoint<Bulk, In>,
    img: nusb::Endpoint<Bulk, In>,
    int: nusb::Endpoint<Interrupt, In>,
    pub vendor_id: u16,
    pub product_id: u16,
}

fn map(e: TransferError) -> TransportError {
    match e {
        TransferError::Cancelled => TransportError::Timeout,
        TransferError::Disconnected => TransportError::Disconnected,
        e => TransportError::Other(e.to_string()),
    }
}

fn io(e: impl std::fmt::Display) -> TransportError {
    TransportError::Other(e.to_string())
}

impl UsbSensor {
    /// Opens the first supported sensor.
    pub fn open() -> Result<Self, TransportError> {
        let info = nusb::list_devices()
            .wait()
            .map_err(io)?
            .find(|d| SUPPORTED.contains(&(d.vendor_id(), d.product_id())))
            .ok_or_else(|| TransportError::Other("no supported sensor found".into()))?;
        let (vendor_id, product_id) = (info.vendor_id(), info.product_id());
        let device = info.open().wait().map_err(io)?;
        let iface = device.detach_and_claim_interface(0).wait().map_err(io)?;
        Ok(UsbSensor {
            out: iface.endpoint::<Bulk, Out>(0x01).map_err(io)?,
            inp: iface.endpoint::<Bulk, In>(0x81).map_err(io)?,
            img: iface.endpoint::<Bulk, In>(0x82).map_err(io)?,
            int: iface.endpoint::<Interrupt, In>(0x83).map_err(io)?,
            device,
            vendor_id,
            product_id,
        })
    }

    /// Waits up to `timeout` for an interrupt packet; `Ok(None)` on timeout.
    pub fn wait_int(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        let c = self.int.transfer_blocking(self.int.allocate(64), timeout);
        match c.status {
            Ok(()) => Ok(Some(c.buffer.into_vec())),
            Err(TransferError::Cancelled) => Ok(None),
            Err(e) => Err(map(e)),
        }
    }

    /// One bulk read of image data on endpoint 0x82.
    pub fn read_82(&mut self, timeout: Duration) -> Result<Vec<u8>, TransportError> {
        let c = self
            .img
            .transfer_blocking(self.img.allocate(MAX_IMAGE), timeout);
        c.status.map_err(map)?;
        let data = c.buffer.into_vec();
        log::trace!("<82< {} bytes", data.len());
        Ok(data)
    }

    /// USB port reset: recovers a sensor stuck after an interrupted exchange.
    pub fn reset(self) -> Result<(), TransportError> {
        self.device.reset().wait().map_err(io)
    }
}

impl Transport for UsbSensor {
    fn cmd(&mut self, out: &[u8]) -> Result<Vec<u8>, TransportError> {
        log::trace!(">cmd> {}", hex(out));
        self.out
            .transfer_blocking(Buffer::from(out.to_vec()), CMD_TIMEOUT)
            .status
            .map_err(map)?;
        let c = self
            .inp
            .transfer_blocking(self.inp.allocate(MAX_REPLY), CMD_TIMEOUT);
        c.status.map_err(map)?;
        let rsp = c.buffer.into_vec();
        log::trace!("<cmd< {}", hex(&rsp));
        Ok(rsp)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
