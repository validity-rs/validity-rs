//! TLS flash partition and the sensor ECDH block, as read back from the chip.
#![no_main]

use libfuzzer_sys::fuzz_target;
use validity_proto::channel::{TlsFlash, firmware_key, parse_ecdh_block};
use validity_proto::tls::PskKeys;

fuzz_target!(|data: &[u8]| {
    let psk = PskKeys::from_hw("Fuzz Laptop", "FUZZ0");
    let fw = firmware_key();
    drop(TlsFlash::parse(data, &psk, &fw));
    drop(parse_ecdh_block(data, &fw));
    drop(psk.open_priv_blob(data));
});
