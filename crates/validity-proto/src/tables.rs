//! Lookup tables: sensor models, flash chips, sensor geometry and the factory capture
//! programs (python-validity `hw_tables.py`, `table_types.py`, `generated_tables.py`,
//! `firmware_tables.py`, `fingerprint_constants.py`).
//!
//! The large tables live in `tables/generated.rs`, produced mechanically by
//! `tools/oracle/gen_tables.py`.

mod generated;

pub use generated::{CAPTURE_PROGRAMS, DEV_INFO, FLASH_IC, SENSOR_TYPES};

use crate::cmd::RomInfo;
use crate::hex;

/// A sensor model, identified by `cmd 0x75` (major, version).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInfo {
    pub major: u16,
    pub sensor_type: u16,
    pub version: u8,
    pub version_mask: u8,
    pub name: &'static str,
}

/// `dev_info_lookup`: an exact version match wins; otherwise the last entry of that
/// major whose (masked) version is a wildcard, or any entry when `ver` is 0.
pub fn dev_info_lookup(major: u16, ver: u16) -> Option<&'static DeviceInfo> {
    let mut fuzzy = None;
    for i in DEV_INFO.iter().filter(|i| i.major == major) {
        let masked = (i.version & i.version_mask) as u16;
        if ver == 0 || masked == 0 {
            fuzzy = Some(i);
        } else if ver == masked {
            return Some(i);
        }
    }
    fuzzy
}

/// A serial flash chip known to the firmware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashIcInfo {
    pub name: &'static str,
    pub size: u32,
    pub f18: u32,
    pub jid0: u16,
    pub jid1: u16,
    pub f1b: u32,
    pub f1c: u32,
    pub f1e: u32,
    pub sector_size: u32,
    pub sector_erase_cmd: u8,
    pub f25: u32,
    pub f26: u32,
}

pub fn flash_ic_lookup(jid0: u16, jid1: u16, size: u32) -> Option<&'static FlashIcInfo> {
    FLASH_IC
        .iter()
        .find(|i| i.jid0 == jid0 && i.jid1 == jid1 && i.size == size)
}

/// Sensor geometry for a sensor type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensorTypeInfo {
    pub sensor_type: u16,
    pub bytes_per_line: u16,
    pub repeat_multiplier: u8,
    pub lines_per_calibration_data: u16,
    pub line_width: u16,
    /// Hex; see [`SensorTypeInfo::calibration_blob`].
    pub calibration_blob: &'static str,
}

impl SensorTypeInfo {
    pub fn get(sensor_type: u16) -> Option<&'static SensorTypeInfo> {
        SENSOR_TYPES.iter().find(|i| i.sensor_type == sensor_type)
    }

    pub fn calibration_blob(&self) -> Vec<u8> {
        hex::decode(self.calibration_blob).expect("generated tables hold valid hex")
    }
}

/// A factory capture program for a ROM version and sensor type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensorCaptureProg {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub u1: u32,
    pub dev_type: u32,
    pub a0: u32,
    pub a1: u32,
    /// Hex; concatenated by [`SensorCaptureProg::program`].
    pub blobs: &'static [&'static str],
}

const ANY: u32 = 0xffff;

fn fuzzy(expected: u32, actual: u32) -> u32 {
    if expected == actual {
        2
    } else if expected == ANY {
        1
    } else {
        0
    }
}

impl SensorCaptureProg {
    fn metric(&self, rom: &RomInfo) -> u32 {
        let mut m = fuzzy(self.major, rom.major as u32);
        m = (m << 2) | fuzzy(self.minor, rom.minor as u32);
        m = (m << 2) | fuzzy(self.build, rom.build);
        (m << 2) | fuzzy(self.u1, rom.u1 as u32)
    }

    /// Best program for the ROM and sensor type (`SensorCaptureProg.get`): filter on
    /// major, sensor type and the two unknown selectors, then keep the first entry
    /// with the highest match metric.
    pub fn get(rom: &RomInfo, sensor_type: u16, a0: u32, a1: u32) -> Option<Vec<u8>> {
        let mut best: Option<(&SensorCaptureProg, u32)> = None;
        for p in CAPTURE_PROGRAMS {
            let ok = |want: u32, have: u32| want == ANY || want == have;
            if !ok(p.major, rom.major as u32)
                || !ok(p.dev_type, sensor_type as u32)
                || !ok(p.a0, a0)
                || !ok(p.a1, a1)
            {
                continue;
            }
            let m = p.metric(rom);
            if m > best.map_or(0, |(_, b)| b) {
                best = Some((p, m));
            }
        }
        best.map(|(p, _)| p.program())
    }

    pub fn program(&self) -> Vec<u8> {
        self.blobs
            .iter()
            .flat_map(|b| hex::decode(b).expect("generated tables hold valid hex"))
            .collect()
    }
}

/// USB devices handled by python-validity and the firmware extension each one needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareFile {
    pub vendor_id: u16,
    pub product_id: u16,
    /// Lenovo driver package holding the firmware extension.
    pub driver_url: &'static str,
    /// SHA-512 of the driver package.
    pub driver_sha512: &'static str,
    /// File name of the firmware extension inside the package.
    pub fwext_name: &'static str,
}

const NZ3GF07W: &str = "https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe";
const NZ3GF07W_SHA512: &str = "a4a4e6058b1ea8ab721953d2cfd775a1e7bc589863d160e5ebbb90344858f147d695103677a8df0b2de0c95345df108bda97196245b067f45630038fb7c807cd";

pub const FIRMWARE_FILES: [FirmwareFile; 4] = [
    FirmwareFile {
        vendor_id: 0x138a,
        product_id: 0x0090,
        driver_url: "https://download.lenovo.com/pccbbs/mobiles/n1cgn08w.exe",
        driver_sha512: "d839fa65adf4c952ecb4a5c4b2fc5b5bdedd8e02a421564bdc7fae1d281be4ea26fcde2333f2ab78d56cef0fdccce0a3cf429300b89544cdc9cfee6d0fe0db55",
        fwext_name: "6_07f_Lenovo.xpfwext",
    },
    FirmwareFile {
        vendor_id: 0x138a,
        product_id: 0x0097,
        driver_url: NZ3GF07W,
        driver_sha512: NZ3GF07W_SHA512,
        fwext_name: "6_07f_lenovo_mis_qm.xpfwext",
    },
    FirmwareFile {
        vendor_id: 0x06cb,
        product_id: 0x009a,
        driver_url: NZ3GF07W,
        driver_sha512: NZ3GF07W_SHA512,
        fwext_name: "6_07f_lenovo_mis_qm.xpfwext",
    },
    FirmwareFile {
        vendor_id: 0x138a,
        product_id: 0x009d,
        driver_url: NZ3GF07W,
        driver_sha512: NZ3GF07W_SHA512,
        fwext_name: "6_07f_lenovo_mis_qm.xpfwext",
    },
];

pub fn firmware_file(vendor_id: u16, product_id: u16) -> Option<&'static FirmwareFile> {
    FIRMWARE_FILES
        .iter()
        .find(|f| f.vendor_id == vendor_id && f.product_id == product_id)
}

/// Finger positions: fprintd names, then ANSI 381 and Windows extensions.
pub const FINGERS: [(&str, u16); 24] = [
    ("right-thumb", 1),
    ("right-index-finger", 2),
    ("right-middle-finger", 3),
    ("right-ring-finger", 4),
    ("right-little-finger", 5),
    ("left-thumb", 6),
    ("left-index-finger", 7),
    ("left-middle-finger", 8),
    ("left-ring-finger", 9),
    ("left-little-finger", 10),
    ("WINBIO_ANSI_381_POS_UNKNOWN", 0),
    ("WINBIO_ANSI_381_POS_RH_FOUR_FINGERS", 13),
    ("WINBIO_ANSI_381_POS_LH_FOUR_FINGERS", 14),
    ("WINBIO_ANSI_381_POS_TWO_THUMBS", 15),
    ("WINBIO_FINGER_UNSPECIFIED_POS_01", 0xf5),
    ("WINBIO_FINGER_UNSPECIFIED_POS_02", 0xf6),
    ("WINBIO_FINGER_UNSPECIFIED_POS_03", 0xf7),
    ("WINBIO_FINGER_UNSPECIFIED_POS_04", 0xf8),
    ("WINBIO_FINGER_UNSPECIFIED_POS_05", 0xf9),
    ("WINBIO_FINGER_UNSPECIFIED_POS_06", 0xfa),
    ("WINBIO_FINGER_UNSPECIFIED_POS_07", 0xfb),
    ("WINBIO_FINGER_UNSPECIFIED_POS_08", 0xfc),
    ("WINBIO_FINGER_UNSPECIFIED_POS_09", 0xfd),
    ("WINBIO_FINGER_UNSPECIFIED_POS_10", 0xfe),
];

pub fn finger_id(name: &str) -> Option<u16> {
    FINGERS.iter().find(|(n, _)| *n == name).map(|(_, i)| *i)
}

pub fn finger_name(id: u16) -> Option<&'static str> {
    FINGERS.iter().find(|(_, i)| *i == id).map(|(n, _)| *n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeslot;

    #[test]
    fn generated_tables_are_well_formed() {
        assert_eq!(DEV_INFO.len(), 417);
        assert_eq!(FLASH_IC.len(), 20);
        assert_eq!(SENSOR_TYPES.len(), 27);
        assert_eq!(CAPTURE_PROGRAMS.len(), 42);
        for t in SENSOR_TYPES {
            assert!(!t.calibration_blob().is_empty());
        }
        for p in CAPTURE_PROGRAMS {
            let chunks = timeslot::split_chunks(&p.program()).unwrap();
            for c in chunks
                .iter()
                .filter(|c| c.kind == timeslot::CHUNK_TIMESLOT_TABLE_2D)
            {
                timeslot::disassemble(&c.value, 0).unwrap();
            }
        }
    }

    #[test]
    fn lookups() {
        let d = dev_info_lookup(0x190, 0x59).unwrap();
        assert_eq!((d.sensor_type, d.name.trim()), (0x199, "57K0 FM-3367-002"));
        // Unknown version of a known major: falls back to the last wildcard entry.
        let d = dev_info_lookup(0x190, 0xfe).unwrap();
        assert_eq!(d.name.trim(), "109A_FM-3302-001");
        // Version 0 matches every entry of the major: the last one wins.
        assert_eq!(
            dev_info_lookup(0x190, 0).unwrap().name.trim(),
            "86C  TM-P3569-001"
        );
        assert!(dev_info_lookup(0x1234, 1).is_none());

        let f = flash_ic_lookup(0xef, 0x40, 0x10_0000).unwrap();
        assert_eq!(
            (f.name, f.sector_size, f.sector_erase_cmd),
            ("W25Q80B", 0x1000, 0x20)
        );
        assert!(flash_ic_lookup(0xef, 0x40, 0x20_0000).is_none());

        let t = SensorTypeInfo::get(0x199).unwrap();
        assert_eq!((t.bytes_per_line, t.repeat_multiplier), (0x78, 2));
        assert_eq!(t.calibration_blob().len(), 112);

        let rom = RomInfo {
            timestamp: 0,
            build: 0,
            major: 6,
            minor: 7,
            product: 0x30,
            u1: 0,
        };
        let p = SensorCaptureProg::get(&rom, 0x199, 0x18, 0x19).unwrap();
        assert_eq!(p.len(), 228 + 420);
        assert!(SensorCaptureProg::get(&rom, 0x4321, 0x18, 0x19).is_none());
        // Minor 7 has a dedicated 0x1825 program; minor 9 falls back to the minor-0 one.
        let p7 = SensorCaptureProg::get(&rom, 0x1825, 0x18, 0x19).unwrap();
        let rom9 = RomInfo { minor: 9, ..rom };
        let p9 = SensorCaptureProg::get(&rom9, 0x1825, 0x18, 0x19).unwrap();
        assert_ne!(p7, p9);

        assert_eq!(finger_id("left-index-finger"), Some(7));
        assert_eq!(finger_name(0xf5), Some("WINBIO_FINGER_UNSPECIFIED_POS_01"));
        assert_eq!(finger_name(11), None);
        assert_eq!(
            firmware_file(0x06cb, 0x009a).unwrap().fwext_name,
            "6_07f_lenovo_mis_qm.xpfwext"
        );
    }
}
