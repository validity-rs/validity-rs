//! fprintd-compatible D-Bus service (`net.reactivated.Fprint`) for
//! Synaptics/Validity match-on-chip fingerprint sensors, on `validity-proto`.
//!
//! - [`service`]: the D-Bus objects (fprintd 1.94.5's Manager and Device).
//! - [`machine`]: claim and action rules, device state (pure, unit-tested).
//! - [`worker`]: the thread that owns the sensor.
//! - [`sensor`]: hardware abstraction, the non-destructive open sequence,
//!   cancellation and result decisions.
//! - [`fake`]: an emulated sensor for tests.

pub mod config;
pub mod errors;
pub mod fake;
pub mod logging;
pub mod machine;
pub mod polkit;
pub mod sensor;
pub mod service;
pub mod usb;
pub mod users;
pub mod worker;
