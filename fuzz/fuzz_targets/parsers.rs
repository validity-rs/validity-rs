//! Every reply parser: none may panic, hang or allocate unboundedly on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use validity_proto::{calibration, cmd, db, flash, fwext, pairing, scanner, sid, timeslot, tls};

fuzz_target!(|data: &[u8]| {
    let Some((&which, b)) = data.split_first() else { return };
    match which % 20 {
        0 => drop(cmd::status(b)),
        1 => drop(cmd::status_word(b)),
        2 => drop(cmd::RomInfo::parse(b)),
        3 => drop(cmd::parse_read_flash(b)),
        4 => drop(flash::PartitionInfo::parse(b)),
        5 => drop(flash::parse_flash_info(b)),
        6 => drop(flash::parse_fw_info(b)),
        7 => drop(db::parse_user_storage(b)),
        8 => drop(db::parse_identity(b)),
        9 => drop(db::parse_user(b)),
        10 => drop(db::parse_record_value(b)),
        11 => drop(db::parse_record_children(b)),
        12 => drop(db::parse_db_info(b)),
        13 => drop(pairing::parse_partition_reply(b)),
        14 => drop(pairing::parse_ecdh_reply(b)),
        15 => drop(scanner::parse_factory_bits(b)),
        16 => drop(scanner::parse_enrollment_update(b)),
        17 => drop(scanner::parse_dict(b)),
        18 => {
            drop(sid::Sid::from_bytes(b));
            drop(calibration::CalibrationFile::from_bytes(b));
            drop(fwext::Fwext::parse(b));
            drop(tls::unpad(b));
        }
        _ => {
            // A whole timeslot program: decoding must always make progress.
            let mut rest = b;
            while let Ok((_, n)) = timeslot::decode_insn(rest) {
                assert!(n > 0 && n <= rest.len(), "decode_insn must consume input");
                rest = &rest[n..];
            }
        }
    }
});
