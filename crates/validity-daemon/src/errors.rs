//! The `net.reactivated.Fprint.Error.*` errors, and how sensor failures map to
//! fprintd's result strings.

use validity_proto::Error as ProtoError;
use validity_proto::transport::TransportError;

/// fprintd 1.94's D-Bus errors. The message is free text for humans.
#[derive(Debug, Clone, PartialEq, zbus::DBusError)]
#[zbus(prefix = "net.reactivated.Fprint.Error")]
pub enum FprintError {
    #[zbus(error)]
    ZBus(zbus::Error),
    ClaimDevice(String),
    AlreadyInUse(String),
    Internal(String),
    PermissionDenied(String),
    NoEnrolledPrints(String),
    FingerAlreadyEnrolled(String),
    NoActionInProgress(String),
    InvalidFingername(String),
    NoSuchDevice(String),
    PrintsNotDeleted(String),
    PrintsNotDeletedFromDevice(String),
}

impl FprintError {
    /// The D-Bus error name, for logs and tests.
    pub fn name(&self) -> &'static str {
        match self {
            FprintError::ZBus(_) => "org.freedesktop.DBus.Error.Failed",
            FprintError::ClaimDevice(_) => "net.reactivated.Fprint.Error.ClaimDevice",
            FprintError::AlreadyInUse(_) => "net.reactivated.Fprint.Error.AlreadyInUse",
            FprintError::Internal(_) => "net.reactivated.Fprint.Error.Internal",
            FprintError::PermissionDenied(_) => "net.reactivated.Fprint.Error.PermissionDenied",
            FprintError::NoEnrolledPrints(_) => "net.reactivated.Fprint.Error.NoEnrolledPrints",
            FprintError::FingerAlreadyEnrolled(_) => {
                "net.reactivated.Fprint.Error.FingerAlreadyEnrolled"
            }
            FprintError::NoActionInProgress(_) => "net.reactivated.Fprint.Error.NoActionInProgress",
            FprintError::InvalidFingername(_) => "net.reactivated.Fprint.Error.InvalidFingername",
            FprintError::NoSuchDevice(_) => "net.reactivated.Fprint.Error.NoSuchDevice",
            FprintError::PrintsNotDeleted(_) => "net.reactivated.Fprint.Error.PrintsNotDeleted",
            FprintError::PrintsNotDeletedFromDevice(_) => {
                "net.reactivated.Fprint.Error.PrintsNotDeletedFromDevice"
            }
        }
    }
}

/// What a failed sensor operation means for the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The client stopped the operation (or the system is going to sleep).
    Cancelled,
    /// The USB device is gone or unresponsive: drop the session and reconnect.
    Lost,
    /// The sensor's storage is full (status 0x04b5).
    DataFull,
    /// The record already exists (status 0x04c3).
    Duplicate,
    /// Anything else: the session is still usable.
    Other,
}

/// Status: template partition full.
pub const STATUS_DATA_FULL: u16 = 0x04b5;
/// Status: duplicate record.
pub const STATUS_DUPLICATE: u16 = 0x04c3;
/// Status: a cleartext command reached a sensor that still has a TLS session
/// (it resets the session).
pub const STATUS_TLS_RESET: u16 = 0x0315;
/// Status: cleartext reply where a TLS record was expected.
pub const STATUS_NO_SESSION: u16 = 0x0404;

pub fn classify(e: &ProtoError) -> Failure {
    match e {
        ProtoError::Cancelled => Failure::Cancelled,
        ProtoError::Transport(_) => Failure::Lost,
        ProtoError::Channel(validity_proto::channel::Error::Transport(_)) => Failure::Lost,
        // The sensor dropped its side of the channel: the session is unusable.
        ProtoError::Channel(_) => Failure::Lost,
        ProtoError::Status(STATUS_TLS_RESET | STATUS_NO_SESSION) => Failure::Lost,
        ProtoError::Status(STATUS_DATA_FULL) => Failure::DataFull,
        ProtoError::Status(STATUS_DUPLICATE) => Failure::Duplicate,
        _ => Failure::Other,
    }
}

/// Whether the transport error says the device itself went away (as opposed
/// to a timeout on a device that is still there).
pub fn is_disconnect(e: &ProtoError) -> bool {
    matches!(
        e,
        ProtoError::Transport(TransportError::Disconnected)
            | ProtoError::Channel(validity_proto::channel::Error::Transport(
                TransportError::Disconnected
            ))
    )
}

/// `VerifyStatus` result for a failed verification; `None` when nothing is to be
/// reported (the client cancelled).
pub fn verify_failure(f: Failure) -> Option<&'static str> {
    match f {
        Failure::Cancelled => None,
        Failure::Lost => Some("verify-disconnected"),
        Failure::DataFull | Failure::Duplicate | Failure::Other => Some("verify-unknown-error"),
    }
}

/// `EnrollStatus` result for a failed enrolment; `None` when the client cancelled.
pub fn enroll_failure(f: Failure) -> Option<&'static str> {
    match f {
        Failure::Cancelled => None,
        Failure::Lost => Some("enroll-disconnected"),
        Failure::DataFull => Some("enroll-data-full"),
        Failure::Duplicate => Some("enroll-duplicate"),
        Failure::Other => Some("enroll-unknown-error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use validity_proto::channel;
    use validity_proto::tls;
    use zbus::DBusError;

    #[test]
    fn dbus_error_names() {
        let all = [
            FprintError::ClaimDevice("x".into()),
            FprintError::AlreadyInUse("x".into()),
            FprintError::Internal("x".into()),
            FprintError::PermissionDenied("x".into()),
            FprintError::NoEnrolledPrints("x".into()),
            FprintError::FingerAlreadyEnrolled("x".into()),
            FprintError::NoActionInProgress("x".into()),
            FprintError::InvalidFingername("x".into()),
            FprintError::NoSuchDevice("x".into()),
            FprintError::PrintsNotDeleted("x".into()),
            FprintError::PrintsNotDeletedFromDevice("x".into()),
        ];
        for e in &all {
            assert_eq!(e.name(), DBusError::name(e).to_string(), "{e:?}");
            assert!(e.name().starts_with("net.reactivated.Fprint.Error."));
            assert_eq!(e.description(), Some("x"));
        }
        assert_eq!(
            FprintError::NoEnrolledPrints(String::new()).name(),
            "net.reactivated.Fprint.Error.NoEnrolledPrints"
        );
    }

    #[test]
    fn sensor_errors_map_to_fprintd_results() {
        let lost = ProtoError::Transport(TransportError::Disconnected);
        let timeout = ProtoError::Transport(TransportError::Timeout);
        assert_eq!(classify(&lost), Failure::Lost);
        assert!(is_disconnect(&lost));
        assert_eq!(classify(&timeout), Failure::Lost);
        assert!(!is_disconnect(&timeout));
        assert_eq!(classify(&ProtoError::Cancelled), Failure::Cancelled);
        assert_eq!(classify(&ProtoError::Status(0x04b5)), Failure::DataFull);
        assert_eq!(classify(&ProtoError::Status(0x04c3)), Failure::Duplicate);
        assert_eq!(classify(&ProtoError::Status(0x0315)), Failure::Lost);
        assert_eq!(classify(&ProtoError::Status(0x0404)), Failure::Lost);
        assert_eq!(classify(&ProtoError::Status(0x0007)), Failure::Other);
        assert_eq!(
            classify(&ProtoError::Channel(channel::Error::Tls(
                tls::Error::BadMac
            ))),
            Failure::Lost
        );
        assert_eq!(
            classify(&ProtoError::Protocol("scanning problem".into())),
            Failure::Other
        );

        assert_eq!(verify_failure(Failure::Cancelled), None);
        assert_eq!(verify_failure(Failure::Lost), Some("verify-disconnected"));
        assert_eq!(verify_failure(Failure::Other), Some("verify-unknown-error"));
        assert_eq!(enroll_failure(Failure::Cancelled), None);
        assert_eq!(enroll_failure(Failure::Lost), Some("enroll-disconnected"));
        assert_eq!(enroll_failure(Failure::DataFull), Some("enroll-data-full"));
        assert_eq!(enroll_failure(Failure::Duplicate), Some("enroll-duplicate"));
        assert_eq!(enroll_failure(Failure::Other), Some("enroll-unknown-error"));
    }
}
