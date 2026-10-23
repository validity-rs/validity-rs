//! TLS record layer: splitting and opening records with fixed session keys.
#![no_main]

use libfuzzer_sys::fuzz_target;
use validity_proto::tls::{self, SessionKeys};

fuzz_target!(|data: &[u8]| {
    let keys = SessionKeys {
        master_secret: [1; 48],
        sign: [2; 32],
        validation: [3; 32],
        encryption: [4; 32],
        decryption: [5; 32],
    };
    if let Ok(recs) = tls::split_records(data) {
        for (t, body) in recs {
            assert!(body.len() <= data.len());
            drop(tls::open(&keys, t, body));
        }
    }
    // What we seal, we can open with the mirrored keys.
    let mirrored = SessionKeys { decryption: keys.encryption, validation: keys.sign, ..keys.clone() };
    let sealed = tls::seal(&keys, tls::CONTENT_APP_DATA, data, &[6; 16]);
    assert_eq!(tls::open(&mirrored, tls::CONTENT_APP_DATA, &sealed).unwrap(), data);
});
