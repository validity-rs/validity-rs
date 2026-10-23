//! Protocol for Synaptics/Validity match-on-chip fingerprint sensors.

pub mod calibration;
pub mod channel;
pub mod cmd;
pub mod db;
pub mod flash;
pub mod fwext;
pub mod hex;
pub mod init;
pub mod pairing;
pub mod replay;
pub mod scanner;
pub mod session;
pub mod sid;
pub mod tables;
pub mod timeslot;
pub mod tls;
pub mod transport;
pub mod usb;
pub mod vendor;

#[cfg(test)]
mod testutil;

pub use cmd::Error;
pub use session::Sensor;
