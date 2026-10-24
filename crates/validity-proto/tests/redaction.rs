//! What the protocol types print. Debug output reaches logs, so the types that hold
//! key material, vendor blobs or long recordings print a redacted or summarised
//! form; error messages are what a user reads. Written from the survivors of a
//! mutation-testing run. All data is synthetic.

use std::time::Duration;

use p256::SecretKey;
use validity_proto::channel::{Channel, TlsFlash};
use validity_proto::replay::{Event, Mask, ReplaySensor, Stats, Trace};
use validity_proto::session::{Deadlines, UsbLink, UsbSession};
use validity_proto::tls::{PskKeys, SessionKeys};
use validity_proto::transport::{Entropy, Transport, TransportError};
use validity_proto::vendor::{self, Blobs};

fn key(n: u8) -> SecretKey {
    let mut b = [0u8; 32];
    b[31] = n;
    SecretKey::from_slice(&b).unwrap()
}

#[test]
fn key_material_is_redacted() {
    let psk = PskKeys::from_hw("Synthetic", "0");
    assert_eq!(format!("{psk:?}"), "PskKeys { .. }");
    let keys = SessionKeys {
        master_secret: [1; 48],
        sign: [2; 32],
        validation: [3; 32],
        encryption: [4; 32],
        decryption: [5; 32],
    };
    assert_eq!(format!("{keys:?}"), "SessionKeys { .. }");
}

#[test]
fn channel_shows_its_state_only() {
    let flash = TlsFlash {
        host_key: key(1),
        cert: vec![0xc3; 8],
        sensor_key: key(2).public_key(),
    };
    let ch = Channel::new(flash);
    assert_eq!(
        format!("{ch:?}"),
        "Channel { keys: false, secure_tx: false, secure_rx: false, .. }"
    );
}

#[test]
fn blobs_show_their_lengths_only() {
    let b = Blobs {
        init_hardcoded: vec![6; 3],
        init_hardcoded_clean_slate: vec![6; 4],
        reset_blob: vec![6; 5],
        db_write_enable: vec![6; 6],
        partition_signature: vec![0x5a; 256],
    };
    assert_eq!(
        format!("{b:?}"),
        "Blobs { init_hardcoded: 3, init_hardcoded_clean_slate: 4, reset_blob: 5, \
         db_write_enable: 6, partition_signature: 256 }"
    );
}

#[test]
fn error_messages() {
    assert_eq!(
        vendor::Error::DllMismatch.to_string(),
        format!("driver DLL does not match SHA-256 {}", vendor::DLL_SHA256)
    );
    assert_eq!(
        vendor::Error::OutOfRange("reset_blob").to_string(),
        "blob reset_blob lies outside the DLL"
    );
    assert_eq!(
        vendor::Error::BlobMismatch("reset_blob").to_string(),
        "blob reset_blob has an unexpected SHA-256"
    );
    assert_eq!(TransportError::Timeout.to_string(), "USB timeout");
    assert_eq!(
        TransportError::Disconnected.to_string(),
        "sensor disconnected"
    );
    assert_eq!(
        TransportError::Other("stall".into()).to_string(),
        "USB error: stall"
    );
}

#[test]
fn replay_sensor_summarises_the_recording() {
    let trace = Trace {
        events: vec![
            Event::Interrupt(vec![0]),
            Event::Bulk82(Some(4)),
            Event::Interrupt(vec![2]),
        ],
        results: vec![],
    };
    let r = ReplaySensor::new(&trace).with_mask(Mask {
        name: "synthetic",
        ranges: Box::new(|_| None),
    });
    assert_eq!(
        format!("{r:?}"),
        format!(
            "ReplaySensor {{ events: 3, pos: 0, open: false, \
             masks: [Mask {{ name: \"synthetic\", .. }}], failed: None, stats: {:?} }}",
            Stats::default()
        )
    );
}

struct Silent;

impl Transport for Silent {
    fn cmd(&mut self, _out: &[u8]) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::Disconnected)
    }
}

impl UsbLink for Silent {
    fn interrupt(&mut self, _timeout: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(None)
    }
    fn bulk_82(&mut self, _timeout: Duration) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::Timeout)
    }
}

struct Zero;

impl Entropy for Zero {
    fn fill(&mut self, b: &mut [u8]) {
        b.fill(0);
    }
}

#[test]
fn usb_session_shows_state_and_deadlines() {
    let s = UsbSession::new(Silent, Zero, PskKeys::from_hw("Synthetic", "0"));
    assert_eq!(
        format!("{s:?}"),
        format!(
            "UsbSession {{ open: false, deadlines: {:?}, .. }}",
            Deadlines::DEFAULT
        )
    );
}
