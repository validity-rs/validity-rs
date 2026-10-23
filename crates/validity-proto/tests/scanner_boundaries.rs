//! Scanner behaviour pinned from the survivors of a mutation-testing run: the
//! validation of a stored calibration file in `Scanner::open`, the geometry `probe`
//! derives from the capture program, the timeslot-table patching, the line-update
//! padding, the interrupt checks of a capture and the capture-program polling.
//! All data is synthetic.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::Once;
use std::time::Duration;

use validity_proto::Error;
use validity_proto::calibration::{self, CalibrationFile};
use validity_proto::cmd::read_flash_cmd;
use validity_proto::scanner::{
    CaptureInfo, CaptureMode, Scanner, patch_timeslot_again, patch_timeslot_table,
    wait_till_finished,
};
use validity_proto::session::{Deadlines, Sensor, Wait};
use validity_proto::tables::SensorTypeInfo;
use validity_proto::timeslot::{self, CHUNK_LINE_UPDATE, CHUNK_LINE_UPDATE_TRANSFORM};
use validity_proto::vendor::Blobs;

fn blobs() -> Blobs {
    Blobs {
        init_hardcoded: vec![6, 1, 1],
        init_hardcoded_clean_slate: vec![6, 2, 2],
        reset_blob: vec![6, 3, 3],
        db_write_enable: vec![6, 4, 4],
        partition_signature: vec![0x5a; 256],
    }
}

/// A made-up sensor of type 0x199 (`cmd 0x75` major 0x190, version 0x59) with ROM
/// 6.8 build 0x56: it answers the probe, serves partition 6 from `flash6`, answers
/// capture programs with `capture_status` and plays `ints` as interrupts. Every
/// command is recorded.
struct Device {
    flash6: Vec<u8>,
    factory_values: Vec<u8>,
    capture_status: u16,
    ints: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}

const SENSOR_TYPE: u16 = 0x199;

impl Device {
    fn new() -> Self {
        Device {
            flash6: calibration::clean_slate(&(0..100u8).collect::<Vec<_>>()),
            factory_values: (0..112).map(|i| 0x70 + (i % 9) as u8).collect(),
            capture_status: 0,
            ints: VecDeque::new(),
            sent: Vec::new(),
        }
    }

    fn sent_capture_program(&self) -> bool {
        self.sent.iter().any(|c| c[0] == 0x02)
    }
}

fn u32_at(b: &[u8], o: usize) -> usize {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize
}

impl Sensor for Device {
    fn cmd(&mut self, p: &[u8]) -> Result<Vec<u8>, Error> {
        self.sent.push(p.to_vec());
        Ok(match p[0] {
            0x75 => vec![0, 0, 0, 0, 0, 0, 0x59, 0, 0x90, 1],
            0x01 => {
                let mut r = vec![0, 0];
                r.extend([0, 0, 0, 0, 0x56, 0, 0, 0, 6, 8, 0, 0x30, 0, 0, 0, 0]);
                r
            }
            0x6f => {
                assert_eq!(p, [0x6f, 0, 0x0e, 0, 0, 0, 0, 0, 0]);
                let mut value = vec![0xee; 4];
                value.extend(&self.factory_values);
                let mut r = vec![0, 0];
                r.extend(0u32.to_le_bytes()); // unknown
                r.extend(1u32.to_le_bytes()); // entries
                r.extend(0u32.to_le_bytes()); // ptr
                r.extend((value.len() as u16).to_le_bytes());
                r.extend(0x0e00u16.to_le_bytes()); // tag
                r.extend(3u16.to_le_bytes()); // subtag
                r.extend(0u16.to_le_bytes()); // flags
                r.extend(value);
                r
            }
            0x40 => {
                assert_eq!(p[1], 6, "only partition 6 is read");
                let (addr, size) = (u32_at(p, 5), u32_at(p, 9));
                let mut data: Vec<u8> = self.flash6.iter().skip(addr).take(size).copied().collect();
                data.resize(size, 0xff);
                let mut r = vec![0, 0];
                r.extend((size as u32).to_le_bytes());
                r.extend([0, 0]);
                r.extend(data);
                r
            }
            0x02 => self.capture_status.to_le_bytes().to_vec(),
            0x51 => {
                assert_eq!(p, [0x51, 0, 0x20, 0, 0]);
                let mut r = vec![0, 0, 12, 0, 0, 0];
                r.extend([0x60, 0, 0x50, 0, 0x20, 1, 4, 0, 0, 0, 0, 0]);
                r
            }
            0x04 => vec![0x34, 0x12],
            c => panic!("unexpected command {c:#04x}"),
        })
    }

    fn is_open(&self) -> bool {
        true
    }

    fn open_channel(&mut self, _: &[u8]) -> Result<(), Error> {
        unreachable!("the channel is already open")
    }

    fn wait_int(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.ints.pop_front().expect("an interrupt is scripted"))
    }

    fn read_82(&mut self) -> Result<Vec<u8>, Error> {
        unreachable!("no image is read in these tests")
    }
}

// Records log messages per thread, so tests running in parallel do not mix.
thread_local! {
    static LOGS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

struct ThreadLog;

impl log::Log for ThreadLog {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, r: &log::Record<'_>) {
        LOGS.with(|l| l.borrow_mut().push(format!("{} {}", r.level(), r.args())));
    }
    fn flush(&self) {}
}

static LOGGER: ThreadLog = ThreadLog;

/// Installs the logger once and returns (and clears) this thread's messages.
fn take_logs() -> Vec<String> {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
    });
    LOGS.with(|l| std::mem::take(&mut *l.borrow_mut()))
}

const IGNORED: &str = "WARN calibration file does not match this sensor, ignored";

fn type_info() -> &'static SensorTypeInfo {
    SensorTypeInfo::get(SENSOR_TYPE).unwrap()
}

fn good_file() -> CalibrationFile {
    let lines = type_info().lines_per_calibration_data;
    let bpl = 0x78u16;
    CalibrationFile {
        sensor_type: SENSOR_TYPE,
        bytes_per_line: bpl,
        lines,
        data: (0..bpl as usize * lines as usize)
            .map(|i| (i * 13) as u8)
            .collect(),
    }
}

/// Opens with `file`; `Ok` with the stored data in use when the file was accepted.
/// A rejected file means calibrating from scratch, which this device refuses
/// (status 0x0bad on the capture program).
fn open_with(file: &CalibrationFile) -> (Result<Scanner, Error>, Device, Vec<String>) {
    take_logs();
    let mut d = Device::new();
    d.capture_status = 0x0bad;
    let r = Scanner::open(&mut d, &blobs(), Some(file));
    (r, d, take_logs())
}

fn assert_rejected(file: &CalibrationFile) {
    let (r, d, logs) = open_with(file);
    assert!(matches!(r, Err(Error::Status(0x0bad))), "{r:?}");
    assert!(d.sent_capture_program());
    assert!(logs.iter().any(|l| l == IGNORED), "{logs:?}");
}

#[test]
fn a_matching_calibration_file_is_used() {
    let f = good_file();
    let (r, d, logs) = open_with(&f);
    let sc = r.unwrap();
    assert_eq!(sc.calib_data, f.data);
    assert!(!sc.calibrated);
    assert!(!d.sent_capture_program());
    assert!(!logs.iter().any(|l| l == IGNORED), "{logs:?}");
}

#[test]
fn a_calibration_file_for_another_sensor_type_is_ignored() {
    let mut f = good_file();
    f.sensor_type = 0xdb;
    assert_rejected(&f);
}

#[test]
fn a_calibration_file_with_another_line_count_is_ignored() {
    // Self-consistent (bytes per line x lines = data length), but not this sensor's.
    let mut f = good_file();
    f.lines = 0x70 * 2;
    f.bytes_per_line = 0x3c;
    assert_eq!(f.bytes_per_line as usize * f.lines as usize, f.data.len());
    assert_rejected(&f);
}

#[test]
fn a_calibration_file_with_inconsistent_geometry_is_ignored() {
    let mut f = good_file();
    f.bytes_per_line += 1;
    assert_rejected(&f);
    let mut f = good_file();
    f.data.pop();
    assert_rejected(&f);
}

#[test]
fn without_a_calibration_file_the_sensor_is_calibrated() {
    take_logs();
    let mut d = Device::new();
    d.capture_status = 0x0bad;
    let r = Scanner::open(&mut d, &blobs(), None);
    assert!(matches!(r, Err(Error::Status(0x0bad))), "{r:?}");
    assert!(!take_logs().iter().any(|l| l == IGNORED));
}

#[test]
fn probe_derives_the_frame_geometry_from_the_2d_chunk() {
    let mut d = Device::new();
    let sc = Scanner::probe(&mut d).unwrap();
    assert_eq!(sc.device.sensor_type, SENSOR_TYPE);
    // The program's 2D chunk holds 0x70 lines; type 0x199 repeats each twice.
    assert_eq!(type_info().repeat_multiplier, 2);
    assert_eq!(sc.lines_per_frame, 0xe0);
    assert_eq!(sc.bytes_per_line, 0x78);
    assert_eq!(sc.factory_calibration_values, d.factory_values);
    assert_eq!(sc.factory_calib_data, None);
    assert_eq!(
        (
            sc.key_calibration_line,
            sc.calibration_frames,
            sc.calibration_iterations
        ),
        (0x38, 3, 3)
    );
}

#[test]
fn calibration_file_bytes_per_line() {
    let mut d = Device::new();
    let mut sc = Scanner::probe(&mut d).unwrap();
    sc.calib_data = good_file().data;
    let f = sc.calibration_file();
    assert_eq!(f, good_file());
    // Round trip through the on-disk format.
    assert_eq!(CalibrationFile::from_bytes(&f.to_bytes()).unwrap(), f);
}

#[test]
fn timeslot_table_patch_stops_three_bytes_before_the_end() {
    // A Call needs i + 3 < len, as in the reference: a trailing 3-byte Call is kept.
    assert_eq!(
        patch_timeslot_table(&[0x10, 1, 2], true, 2).unwrap(),
        [0x10, 1, 2]
    );
    assert_eq!(
        patch_timeslot_table(&[0x10, 1, 2, 0], true, 2).unwrap(),
        [0x10, 2, 4, 0]
    );
    // After Noops and an Idle Rx.
    assert_eq!(
        patch_timeslot_table(&[0, 0, 0x10, 1, 2, 0], true, 3).unwrap(),
        [0, 0, 0x10, 2, 6, 0]
    );
    assert_eq!(
        patch_timeslot_table(&[7, 9, 0x11, 1, 2, 0x12, 4, 5, 0], false, 2).unwrap(),
        [7, 9, 0x11, 1, 4, 0x12, 4, 10, 0]
    );
    // Any other instruction stops the patching.
    assert_eq!(
        patch_timeslot_table(&[0x01, 0x10, 1, 2, 0], true, 2).unwrap(),
        [0x01, 0x10, 1, 2, 0]
    );
}

#[test]
fn timeslot_table_patch_keeps_single_repeats() {
    assert_eq!(
        patch_timeslot_table(&[0x10, 5, 1, 0], true, 2).unwrap(),
        [0x10, 5, 1, 0]
    );
    assert_eq!(
        patch_timeslot_table(&[0x10, 5, 0, 0], true, 2).unwrap(),
        [0x10, 5, 0, 0]
    );
}

#[test]
fn timeslot_patch_again_without_terminators() {
    // The table ends right after its Call: nothing to patch, and no read past the end.
    assert_eq!(
        patch_timeslot_again(&[0x10, 1, 2], 9).unwrap(),
        [0x10, 1, 2]
    );
    // Call to 4, End of Table, then a routine running to the end of the buffer
    // with a write to 0x8000203c (opcode 0x40 | 0x0f).
    assert_eq!(
        patch_timeslot_again(&[0x10, 1, 2, 1, 0x4f, 0xaa, 0xbb], 9).unwrap(),
        [0x10, 1, 2, 1, 0x4f, 9, 0xbb]
    );
    // The last write wins; writes to other registers are left alone.
    assert_eq!(
        patch_timeslot_again(
            &[
                0x10, 1, 2, 2, 0x4f, 1, 1, 0x4e, 2, 2, 0x4f, 3, 3, 2, 0x4f, 4, 4
            ],
            9
        )
        .unwrap(),
        [
            0x10, 1, 2, 2, 0x4f, 1, 1, 0x4e, 2, 2, 0x4f, 9, 3, 2, 0x4f, 4, 4
        ]
    );
}

/// Chunks of a capture command (after `02 || bytes per line || lines`).
fn chunks_of(cmd: &[u8]) -> Vec<timeslot::Chunk> {
    assert_eq!(cmd[0], 0x02);
    timeslot::split_chunks(&cmd[5..]).unwrap()
}

#[test]
fn line_update_data_is_padded_to_four_bytes() {
    let mut d = Device::new();
    let mut sc = Scanner::probe(&mut d).unwrap();
    // Eight values of 0 and 1: one bit each, packed into a single byte (0xaa).
    sc.factory_calibration_values = vec![0, 1, 0, 1, 0, 1, 0, 1];
    let cmd = sc.build_cmd_02(CaptureMode::Calibrate).unwrap();
    let chunks = chunks_of(&cmd);
    let transform = &chunks
        .iter()
        .find(|c| c.kind == CHUNK_LINE_UPDATE_TRANSFORM)
        .unwrap()
        .value;
    // Calibration blob line (v0 = 0xf), then the packed values: v0 = (bits - 1) | 8,
    // v1 = minimum, v2 = 0, then the data padded with zeros to 4 bytes.
    let mut want = vec![0x0f, 0, 0, 0];
    want.extend(type_info().calibration_blob());
    want.extend([8, 0, 0, 0, 0xaa, 0, 0, 0]);
    assert_eq!(*transform, want);
    // Both lines are transformed: the line-update chunk holds their headers only.
    let lu = &chunks
        .iter()
        .find(|c| c.kind == CHUNK_LINE_UPDATE)
        .unwrap()
        .value;
    assert_eq!(lu.len(), 4 + 2 * 8);
    assert_eq!(lu[..4], 2u32.to_le_bytes());
    for k in 0..2 {
        let flags = u32_at(lu, 4 + 8 * k + 4) as u32;
        assert_eq!(flags >> 20, 0x70 | (2 + k as u32), "count {}", 2 + k);
    }
}

fn capture_with(ints: &[&[u8]]) -> (Result<CaptureInfo, Error>, Device) {
    let mut d = Device::new();
    let sc = Scanner::probe(&mut d).unwrap();
    d.sent.clear();
    d.ints = ints.iter().map(|i| i.to_vec()).collect();
    let r = sc.capture(&mut d, CaptureMode::Identify);
    assert_eq!(
        d.sent.last().unwrap(),
        &[0x04],
        "the capture is always stopped"
    );
    assert!(d.ints.is_empty());
    (r, d)
}

#[test]
fn capture_completion_interrupt_needs_three_bytes() {
    let start: &[u8] = &[0, 1, 2, 3, 4];
    let finger: &[u8] = &[2, 9, 9, 9, 9];
    let (r, _) = capture_with(&[start, finger, &[3, 0, 4]]);
    assert_eq!(
        r.unwrap(),
        CaptureInfo {
            x: 0x60,
            y: 0x50,
            w1: 0x120,
            w2: 4
        }
    );
    // Progress (bit 2 clear), then done.
    let (r, _) = capture_with(&[start, finger, &[3, 0, 1], &[3, 0, 6, 0]]);
    assert!(r.is_ok());
    for short in [&[3u8][..], &[3, 0]] {
        let (r, d) = capture_with(&[start, finger, short]);
        assert!(matches!(r, Err(Error::Protocol(_))), "{r:?}");
        assert!(!d.sent.iter().any(|c| c[0] == 0x51));
    }
    // Any other interrupt while waiting for completion.
    let (r, _) = capture_with(&[start, finger, &[4, 0, 4]]);
    assert!(matches!(r, Err(Error::Protocol(_))), "{r:?}");
}

#[test]
fn stored_calibration_reaches_the_flash_check() {
    // The accepted file's data is what the flash check compares against: a clean
    // slate whose body does not hash right makes the sensor recalibrate.
    let mut d = Device::new();
    d.capture_status = 0x0bad;
    let last = d.flash6.len() - 1;
    d.flash6[last] ^= 1;
    let r = Scanner::open(&mut d, &blobs(), Some(&good_file()));
    assert!(matches!(r, Err(Error::Status(0x0bad))), "{r:?}");
    assert!(
        d.sent
            .iter()
            .any(|c| *c == read_flash_cmd(6, 0, calibration::CLEAN_SLATE_HDR as u32))
    );
}

/// Answers the capture-program status (`0x51`) with `busy` replies, then idle,
/// and records the pauses between polls.
struct Poller {
    busy: usize,
    polls: usize,
    pauses: Vec<Duration>,
}

impl Sensor for Poller {
    fn cmd(&mut self, p: &[u8]) -> Result<Vec<u8>, Error> {
        assert_eq!(p, [0x51, 0, 0, 0, 0]);
        self.polls += 1;
        Ok(if self.polls > self.busy {
            vec![0]
        } else {
            vec![1]
        })
    }
    fn is_open(&self) -> bool {
        true
    }
    fn open_channel(&mut self, _: &[u8]) -> Result<(), Error> {
        unreachable!()
    }
    fn wait_int(&mut self) -> Result<Vec<u8>, Error> {
        unreachable!()
    }
    fn read_82(&mut self) -> Result<Vec<u8>, Error> {
        unreachable!()
    }
    fn pause(&mut self, d: Duration) {
        self.pauses.push(d);
    }
}

#[test]
fn capture_program_polling_pauses_between_polls_only() {
    let poll = Duration::from_millis(200);
    // Idle on the third poll: two pauses.
    let mut s = Poller {
        busy: 2,
        polls: 0,
        pauses: vec![],
    };
    wait_till_finished(&mut s).unwrap();
    assert_eq!((s.polls, s.pauses.clone()), (3, vec![poll; 2]));
    // Never idle: polls every 200 ms for the capture deadline (5 s), with no
    // pause after the last poll.
    let limit = Deadlines::DEFAULT.capture;
    let n = (limit.as_millis() / poll.as_millis()) as usize;
    let mut s = Poller {
        busy: usize::MAX,
        polls: 0,
        pauses: vec![],
    };
    let e = wait_till_finished(&mut s).unwrap_err();
    assert!(
        matches!(e, Error::Timeout { waiting_for: Wait::Capture, after } if after == limit),
        "{e:?}"
    );
    assert_eq!(s.polls, n + 1);
    assert_eq!(s.pauses, vec![poll; n]);
    assert_eq!(s.pauses.iter().sum::<Duration>(), limit);
    // Idle on the very last poll: no pause after it either.
    let mut s = Poller {
        busy: n,
        polls: 0,
        pauses: vec![],
    };
    wait_till_finished(&mut s).unwrap();
    assert_eq!((s.polls, s.pauses.len()), (n + 1, n));
}
