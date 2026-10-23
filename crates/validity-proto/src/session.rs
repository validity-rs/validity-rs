//! The application-level view of a sensor: python-validity's `tls.cmd` / `tls.app`
//! plus the interrupt and bulk reads that capture needs. Everything above this layer
//! (flash, database, capture, enrolment) is written against [`Sensor`], so the same
//! code drives real hardware ([`UsbSession`]) and recorded sessions
//! ([`crate::replay::ReplaySensor`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use p256::ecdsa::VerifyingKey;

use crate::channel::{self, Channel, TlsFlash, firmware_key};
use crate::cmd::Error;
use crate::tls::{self, PskKeys};
use crate::transport::{Entropy, Transport, TransportError};
use crate::usb::UsbSensor;

pub trait Sensor {
    /// `tls.cmd`: in the clear before the channel is open, encrypted afterwards.
    fn cmd(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error>;

    /// Whether the encrypted channel is open.
    fn is_open(&self) -> bool;

    /// `tls.app`: an application command that must go over the open channel.
    fn app(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.is_open() {
            return Err(channel::Error::Tls(tls::Error::NotSecure).into());
        }
        self.cmd(payload)
    }

    /// Opens the encrypted channel with the pairing material of a TLS flash image
    /// (partition 1 as read from, or about to be written to, the sensor).
    fn open_channel(&mut self, tls_flash: &[u8]) -> Result<(), Error>;

    /// `usb.wait_int`: blocks until the sensor raises an interrupt.
    /// Returns [`Error::Cancelled`] once [`CancelHandle::cancel`] was called.
    fn wait_int(&mut self) -> Result<Vec<u8>, Error>;

    /// `usb.read_82`: one bulk read of image data on endpoint 0x82.
    fn read_82(&mut self) -> Result<Vec<u8>, Error>;

    /// Clears a pending cancellation; called when a cancellable operation starts.
    fn clear_cancel(&mut self) {}

    /// Back-off between retries of a failed capture (a no-op when replaying).
    fn pause(&mut self, _d: Duration) {}
}

/// A bare transport is a sensor whose channel is never open: commands go in the
/// clear and there is no interrupt endpoint. Used before pairing material exists.
impl<T: Transport> Sensor for T {
    fn cmd(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(Transport::cmd(self, payload)?)
    }

    fn is_open(&self) -> bool {
        false
    }

    fn open_channel(&mut self, _tls_flash: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported("a bare transport has no channel"))
    }

    fn wait_int(&mut self) -> Result<Vec<u8>, Error> {
        Err(Error::Unsupported(
            "a bare transport has no interrupt endpoint",
        ))
    }

    fn read_82(&mut self) -> Result<Vec<u8>, Error> {
        Err(Error::Unsupported("a bare transport has no image endpoint"))
    }
}

/// What a real session needs from the USB device beyond command exchanges.
pub trait UsbLink: Transport {
    /// One interrupt packet, or `Ok(None)` after `timeout`.
    fn interrupt(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError>;
    /// One bulk read on endpoint 0x82 (up to 1 MiB).
    fn bulk_82(&mut self, timeout: Duration) -> Result<Vec<u8>, TransportError>;
}

impl UsbLink for UsbSensor {
    fn interrupt(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        self.wait_int(timeout)
    }

    fn bulk_82(&mut self, timeout: Duration) -> Result<Vec<u8>, TransportError> {
        self.read_82(timeout)
    }
}

/// Cancels a blocking [`Sensor::wait_int`] from another thread.
#[derive(Clone, Default)]
pub struct CancelHandle(Arc<AtomicBool>);

impl CancelHandle {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn take(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }

    fn clear(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Interrupt polling period: a cancellation is noticed within this delay.
const INT_POLL: Duration = Duration::from_millis(100);
/// python-validity reads image data with a 10 s timeout.
const BULK_82_TIMEOUT: Duration = Duration::from_secs(10);

/// A live session: the USB link, the channel once open, and the randomness source.
pub struct UsbSession<L: UsbLink, E: Entropy> {
    link: L,
    channel: Option<Channel>,
    rng: E,
    psk: PskKeys,
    fw_key: VerifyingKey,
    cancel: CancelHandle,
}

impl<L: UsbLink, E: Entropy> UsbSession<L, E> {
    /// `psk` are the host's pre-shared keys ([`PskKeys::from_hw`] of the DMI product
    /// name and serial), which seal the host key in the TLS flash.
    pub fn new(link: L, rng: E, psk: PskKeys) -> Self {
        UsbSession {
            link,
            channel: None,
            rng,
            psk,
            fw_key: firmware_key(),
            cancel: CancelHandle::default(),
        }
    }

    /// Replaces the firmware key that must have signed the sensor's ECDH key
    /// (hardcoded per firmware revision in the vendor driver; tests use their own).
    pub fn with_firmware_key(mut self, key: VerifyingKey) -> Self {
        self.fw_key = key;
        self
    }

    pub fn cancel_handle(&self) -> CancelHandle {
        self.cancel.clone()
    }

    pub fn psk(&self) -> &PskKeys {
        &self.psk
    }

    /// Gives the link back, e.g. to reset the device.
    pub fn into_link(self) -> L {
        self.link
    }
}

impl<L: UsbLink, E: Entropy> Sensor for UsbSession<L, E> {
    fn cmd(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        match &mut self.channel {
            Some(ch) => Ok(ch.app(&mut self.link, &mut self.rng, payload)?),
            None => Ok(self.link.cmd(payload)?),
        }
    }

    fn is_open(&self) -> bool {
        self.channel.as_ref().is_some_and(Channel::is_open)
    }

    fn open_channel(&mut self, tls_flash: &[u8]) -> Result<(), Error> {
        self.channel = None;
        let flash = TlsFlash::parse(tls_flash, &self.psk, &self.fw_key)?;
        let mut ch = Channel::new(flash);
        ch.open(&mut self.link, &mut self.rng)?;
        self.channel = Some(ch);
        Ok(())
    }

    // python-validity clears its cancel flag every time it starts waiting, so a
    // cancellation that arrives while a command is in flight is lost and the wait
    // never ends. Here the flag is only cleared when an operation starts
    // (`clear_cancel`) or when the cancellation is delivered.
    fn wait_int(&mut self) -> Result<Vec<u8>, Error> {
        loop {
            if let Some(b) = self.link.interrupt(INT_POLL)? {
                return Ok(b);
            }
            if self.cancel.take() {
                return Err(Error::Cancelled);
            }
        }
    }

    fn read_82(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.link.bulk_82(BULK_82_TIMEOUT)?)
    }

    fn clear_cancel(&mut self) {
        self.cancel.clear();
    }

    fn pause(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Link {
        replies: VecDeque<Vec<u8>>,
        ints: VecDeque<Option<Vec<u8>>>,
        cancel_after_polls: Option<(usize, CancelHandle)>,
    }

    impl Transport for Link {
        fn cmd(&mut self, _out: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.replies.pop_front().ok_or(TransportError::Disconnected)
        }
    }

    impl UsbLink for Link {
        fn interrupt(&mut self, _t: Duration) -> Result<Option<Vec<u8>>, TransportError> {
            if let Some((n, h)) = &mut self.cancel_after_polls {
                if *n == 0 {
                    h.cancel();
                } else {
                    *n -= 1;
                }
            }
            Ok(self.ints.pop_front().unwrap_or(None))
        }
        fn bulk_82(&mut self, _t: Duration) -> Result<Vec<u8>, TransportError> {
            Ok(vec![7; 3])
        }
    }

    struct Zero;
    impl Entropy for Zero {
        fn fill(&mut self, b: &mut [u8]) {
            b.fill(0);
        }
    }

    fn session(link: Link) -> UsbSession<Link, Zero> {
        UsbSession::new(link, Zero, PskKeys::from_hw("Synthetic", "0"))
    }

    #[test]
    fn plain_until_open_and_app_refused() {
        let mut s = session(Link {
            replies: VecDeque::from([vec![0, 0, 1]]),
            ints: VecDeque::new(),
            cancel_after_polls: None,
        });
        assert!(!s.is_open());
        assert_eq!(s.cmd(&[1]).unwrap(), [0, 0, 1]);
        assert!(matches!(
            s.app(&[1]),
            Err(Error::Channel(channel::Error::Tls(tls::Error::NotSecure)))
        ));
        assert!(s.open_channel(&[0xff; 64]).is_err());
        assert!(!s.is_open());
        assert_eq!(s.read_82().unwrap(), [7, 7, 7]);
    }

    #[test]
    fn wait_int_polls_until_data_or_cancel() {
        let mut s = session(Link {
            replies: VecDeque::new(),
            ints: VecDeque::from([None, None, Some(vec![2, 0])]),
            cancel_after_polls: None,
        });
        assert_eq!(s.wait_int().unwrap(), [2, 0]);

        let h = CancelHandle::default();
        let mut s = session(Link {
            replies: VecDeque::new(),
            ints: VecDeque::new(),
            cancel_after_polls: Some((3, h.clone())),
        });
        s.cancel = h;
        assert!(matches!(s.wait_int(), Err(Error::Cancelled)));
        // Delivered once: the flag is consumed.
        assert!(!s.cancel.take());

        // A cancellation requested before the wait is not lost.
        let mut s = session(Link {
            replies: VecDeque::new(),
            ints: VecDeque::from([None]),
            cancel_after_polls: None,
        });
        s.cancel_handle().cancel();
        assert!(matches!(s.wait_int(), Err(Error::Cancelled)));
        s.cancel_handle().cancel();
        s.clear_cancel();
        s.link.ints = VecDeque::from([Some(vec![3])]);
        assert_eq!(s.wait_int().unwrap(), [3]);
    }
}
