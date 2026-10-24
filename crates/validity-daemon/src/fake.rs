//! An emulated sensor for tests (the daemon's integration tests, the container
//! end-to-end test): a [`Sensor`] that answers the 06cb:009a command set the way
//! `validity-proto` expects, with an in-memory flash and record database, and
//! finger touches scripted by the test through [`FakeSensor`].
//!
//! It plays the sensor's side of the protocol below the channel: commands
//! arrive in the clear (the channel itself is covered by `validity-proto`'s
//! tests against python-validity). Everything above it is the production code
//! path: the daemon's open sequence, `Scanner::{identify, enroll}`, the
//! database helpers, cancellation, reconnection.
//!
//! Its waits behave like `UsbSession`'s: a finger wait ends with
//! `Error::Timeout` after the finger deadline ([`FakeSensor::set_finger_deadline`],
//! 30 s by default), and a wait for an interrupt the emulated sensor will not
//! raise ([`FakeSensor::hang_next_capture`]) fails at once with the timeout the
//! sensor deadline would give.
//!
//! Fingers are identified by a number chosen by the test. An enrolled record
//! remembers the finger it was enrolled with (in its template id), and an
//! identification matches the touched finger against every record, of every
//! user, as the real sensor does.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use validity_proto::Error as ProtoError;
use validity_proto::db;
use validity_proto::pairing::FLASH_LAYOUT;
use validity_proto::session::{CancelHandle, Deadlines, Sensor, Wait};
use validity_proto::sid::Sid;
use validity_proto::transport::TransportError;
use validity_proto::vendor::Blobs;
use validity_proto::{channel, tls};

use crate::sensor::{Hardware, OpenFailure, Opened, UsbId, VALIDATED};

/// One finger placement, consumed by one capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Touch {
    /// A good image of finger `n`.
    Finger(u32),
    /// A good image of finger `n` that adds nothing to an enrolment (the same
    /// area again).
    Redundant(u32),
    /// A failed capture (finger moved, partial...).
    ScanError,
}

/// The synthetic stand-ins for the vendor blobs the emulator recognises.
pub fn blobs() -> Blobs {
    Blobs {
        init_hardcoded: vec![6, 0xf1, 1],
        init_hardcoded_clean_slate: vec![6, 0xf2, 2],
        reset_blob: vec![6, 0xf3, 3],
        db_write_enable: vec![6, 0xf4, 4],
        partition_signature: vec![0x5a; 256],
    }
}

const OK: [u8; 2] = [0, 0];
const NOT_FOUND: u16 = db::STATUS_NOT_FOUND;
const STORAGE_ID: u16 = 3;
/// Images an enrolment needs (the accepted-image mask reaches 0x1f).
const IMAGES: u32 = 5;

#[derive(Debug, Clone)]
struct Finger {
    dbid: u16,
    subtype: u16,
    id: u32,
}

#[derive(Debug, Clone)]
struct User {
    dbid: u16,
    identity: Vec<u8>,
    fingers: Vec<Finger>,
}

/// Counters for assertions.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    /// Looks for the sensor on the bus.
    pub probes: u32,
    pub opens: u32,
    pub resets: u32,
    pub reboots: u32,
    pub matches: u32,
}

struct State {
    present: bool,
    id: UsbId,
    /// Bumped by unplug and reboot: older sessions are dead.
    generation: u64,
    paired: bool,
    paired_elsewhere: bool,
    firmware: bool,
    db_full: bool,
    stuck: bool,
    /// Captures still to hang: accepted, but the scan never starts.
    hang_captures: u32,
    /// The reboot command times out (until a USB reset).
    refuse_reboot: bool,
    deadlines: Deadlines,
    /// How long a reboot or a USB reset takes the device off the bus.
    reboot_absence: Duration,
    fail_opens: u32,
    touches: VecDeque<Touch>,
    waiting: bool,
    storage: bool,
    users: Vec<User>,
    next_dbid: u16,
    flash6: Vec<u8>,
    counters: Counters,
    notify: Option<Arc<dyn Fn() + Send + Sync>>,
}

struct Shared {
    state: Mutex<State>,
    cond: Condvar,
}

/// The test's handle on the emulated sensor.
#[derive(Clone)]
pub struct FakeSensor(Arc<Shared>);

impl std::fmt::Debug for FakeSensor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = self.lock();
        f.debug_struct("FakeSensor")
            .field("present", &st.present)
            .field("users", &st.users.len())
            .field("touches", &st.touches.len())
            .field("counters", &st.counters)
            .finish_non_exhaustive()
    }
}

impl Default for FakeSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeSensor {
    /// A paired sensor with its firmware extension and an empty database.
    pub fn new() -> Self {
        FakeSensor(Arc::new(Shared {
            state: Mutex::new(State {
                present: true,
                id: VALIDATED,
                generation: 0,
                paired: true,
                paired_elsewhere: false,
                firmware: true,
                db_full: false,
                stuck: false,
                hang_captures: 0,
                refuse_reboot: false,
                deadlines: Deadlines::DEFAULT,
                reboot_absence: Duration::ZERO,
                fail_opens: 0,
                touches: VecDeque::new(),
                waiting: false,
                storage: false,
                users: Vec::new(),
                next_dbid: 0x10,
                flash6: vec![0xff; 0x8000],
                counters: Counters::default(),
                notify: None,
            }),
            cond: Condvar::new(),
        }))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.state.lock().expect("fake sensor lock")
    }

    fn changed(&self) {
        self.0.cond.notify_all();
    }

    fn hotplug(&self) {
        let n = self.lock().notify.clone();
        if let Some(n) = n {
            n();
        }
    }

    /// The hardware to hand to the daemon.
    pub fn hardware(&self) -> FakeHardware {
        FakeHardware(self.clone())
    }

    /// Queues finger placements.
    pub fn touch(&self, t: impl IntoIterator<Item = Touch>) {
        self.lock().touches.extend(t);
        self.changed();
    }

    /// Whether the device is on the bus now (what a USB enumeration would say).
    pub fn hardware_probe(&self) -> Option<UsbId> {
        let st = self.lock();
        st.present.then_some(st.id)
    }

    /// Placements not consumed yet.
    pub fn pending_touches(&self) -> usize {
        self.lock().touches.len()
    }

    /// Whether a capture is waiting for a finger right now.
    pub fn waiting_for_finger(&self) -> bool {
        self.lock().waiting
    }

    /// Waits until a capture waits for a finger (or `timeout`).
    pub fn wait_for_capture(&self, timeout: Duration) -> bool {
        let end = Instant::now() + timeout;
        let mut st = self.lock();
        while !st.waiting {
            let now = Instant::now();
            if now >= end {
                return false;
            }
            st = self
                .0
                .cond
                .wait_timeout(st, end - now)
                .expect("fake sensor lock")
                .0;
        }
        true
    }

    /// The device leaves the bus (sessions die, hotplug is signalled).
    pub fn unplug(&self) {
        {
            let mut st = self.lock();
            st.present = false;
            st.generation += 1;
        }
        self.changed();
        self.hotplug();
    }

    /// The device comes back (at a "new address": old sessions stay dead).
    pub fn plug(&self) {
        self.lock().present = true;
        self.changed();
        self.hotplug();
    }

    /// A reboot or a USB reset takes the device off the bus for `d` (about
    /// 0.5 s on a T480), after which it comes back at a new address.
    pub fn set_reboot_absence(&self, d: Duration) {
        self.lock().reboot_absence = d;
    }

    /// Leaves the bus (old sessions die) and comes back after the configured
    /// absence, with hotplug notifications both ways.
    fn re_enumerate(&self) {
        let absence = {
            let mut st = self.lock();
            st.generation += 1;
            if !st.reboot_absence.is_zero() {
                st.present = false;
            }
            st.reboot_absence
        };
        self.changed();
        if absence.is_zero() {
            return;
        }
        self.hotplug();
        let me = self.clone();
        std::thread::spawn(move || {
            std::thread::sleep(absence);
            me.plug();
        });
    }

    /// Every command times out until a USB port reset.
    pub fn set_stuck(&self, stuck: bool) {
        self.lock().stuck = stuck;
        self.changed();
    }

    /// The next finger capture is accepted but its scan never starts: the
    /// sensor stops raising interrupts until it is rebooted (issue #2).
    pub fn hang_next_capture(&self) {
        self.lock().hang_captures += 1;
    }

    /// The reboot command times out, until a USB port reset.
    pub fn refuse_reboot(&self, v: bool) {
        self.lock().refuse_reboot = v;
    }

    /// How long a capture waits for a finger before its deadline passes.
    pub fn set_finger_deadline(&self, d: Duration) {
        self.lock().deadlines.finger = d;
    }

    /// The next `n` USB opens fail.
    pub fn fail_opens(&self, n: u32) {
        self.lock().fail_opens = n;
    }

    pub fn set_paired(&self, paired: bool) {
        self.lock().paired = paired;
    }

    pub fn set_paired_elsewhere(&self, v: bool) {
        self.lock().paired_elsewhere = v;
    }

    pub fn set_firmware(&self, v: bool) {
        self.lock().firmware = v;
    }

    pub fn set_db_full(&self, v: bool) {
        self.lock().db_full = v;
    }

    pub fn set_usb_id(&self, id: UsbId) {
        self.lock().id = id;
    }

    pub fn counters(&self) -> Counters {
        self.lock().counters
    }

    /// Adds an enrolled finger directly (another user, a Windows account...).
    pub fn enroll_directly(&self, sid: &Sid, subtype: u16, finger: u32) {
        let mut st = self.lock();
        st.storage = true;
        let identity = db::identity_to_bytes(sid);
        let dbid = match st.users.iter().position(|u| u.identity == identity) {
            Some(i) => i,
            None => {
                let dbid = st.alloc();
                st.users.push(User {
                    dbid,
                    identity,
                    fingers: Vec::new(),
                });
                st.users.len() - 1
            }
        };
        let fdbid = st.alloc();
        st.users[dbid].fingers.push(Finger {
            dbid: fdbid,
            subtype,
            id: finger,
        });
    }

    /// `(SID, subtype, finger)` of every enrolled record.
    pub fn records(&self) -> Vec<(Sid, u16, u32)> {
        let st = self.lock();
        st.users
            .iter()
            .flat_map(|u| {
                let sid = db::parse_identity(&u.identity).expect("valid identity");
                u.fingers
                    .iter()
                    .map(move |f| (sid.clone(), f.subtype, f.id))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

impl State {
    fn alloc(&mut self) -> u16 {
        let id = self.next_dbid;
        self.next_dbid += 1;
        id
    }

    fn finger_record_owner(&self, finger: u32) -> Option<(&User, &Finger)> {
        self.users
            .iter()
            .find_map(|u| u.fingers.iter().find(|f| f.id == finger).map(|f| (u, f)))
    }
}

/// The emulator as [`Hardware`].
#[derive(Debug)]
pub struct FakeHardware(FakeSensor);

impl Hardware for FakeHardware {
    type Session = FakeChip;

    fn probe(&mut self) -> Result<Option<UsbId>, String> {
        let mut st = self.0.lock();
        st.counters.probes += 1;
        Ok(st.present.then_some(st.id))
    }

    fn open(&mut self) -> Result<Opened<FakeChip>, OpenFailure> {
        let mut st = self.0.lock();
        if !st.present {
            return Err(OpenFailure::Io("no such device".into()));
        }
        if st.fail_opens > 0 {
            st.fail_opens -= 1;
            return Err(OpenFailure::Io("permission denied (emulated)".into()));
        }
        st.counters.opens += 1;
        let cancel = CancelHandle::default();
        let chip = FakeChip {
            shared: self.0.clone(),
            generation: st.generation,
            cancel: cancel.clone(),
            open: false,
            ints: VecDeque::new(),
            capture: Capture::Idle,
            last_finger: None,
            enrol: None,
            update_second: false,
        };
        Ok(Opened {
            session: chip,
            cancel,
            id: st.id,
        })
    }

    fn reset(&mut self, session: FakeChip) -> Result<(), String> {
        drop(session);
        {
            let mut st = self.0.lock();
            st.counters.resets += 1;
            st.stuck = false;
            st.refuse_reboot = false;
        }
        self.0.re_enumerate();
        Ok(())
    }

    fn watch(&mut self, notify: Box<dyn Fn() + Send + Sync>) -> bool {
        self.0.lock().notify = Some(Arc::from(notify));
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Capture {
    Idle,
    /// Program loaded: the next interrupt says "armed".
    Armed,
    /// Program accepted, but the sensor never says "armed".
    Hung,
    /// Waiting for a touch.
    Waiting,
    /// Finger seen: the next interrupt says "done".
    Done(Touch),
    Finished(Touch),
}

struct Enrolment {
    mask: u16,
    finger: Option<u32>,
    images: u32,
}

/// One session with the emulated sensor.
pub struct FakeChip {
    shared: FakeSensor,
    generation: u64,
    cancel: CancelHandle,
    open: bool,
    ints: VecDeque<Vec<u8>>,
    capture: Capture,
    last_finger: Option<u32>,
    enrol: Option<Enrolment>,
    /// The enrolment update is sent twice; the second carries the result.
    update_second: bool,
}

impl std::fmt::Debug for FakeChip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeChip")
            .field("generation", &self.generation)
            .field("open", &self.open)
            .field("capture", &self.capture)
            .finish_non_exhaustive()
    }
}

fn status(s: u16) -> Vec<u8> {
    s.to_le_bytes().to_vec()
}

fn u16s(v: &[u16]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

/// Template id of an enrolled finger: it names the finger.
fn tid_for(finger: u32) -> Vec<u8> {
    let mut t = b"FAKE-TID".to_vec();
    t.extend(finger.to_le_bytes());
    t.resize(32, 0);
    t
}

fn finger_of_tid(tid: &[u8]) -> Option<u32> {
    (tid.len() >= 12 && &tid[..8] == b"FAKE-TID").then(|| le32(tid, 8))
}

/// An enrolment update record: tag, length, 0x34 header bytes, value.
fn record(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut r = u16s(&[tag, value.len() as u16]);
    r.extend([0; 0x34]);
    r.extend(value);
    r
}

impl FakeChip {
    fn alive(&self) -> Result<(), ProtoError> {
        let st = self.shared.lock();
        if st.generation != self.generation {
            return Err(TransportError::Disconnected.into());
        }
        if st.stuck {
            return Err(TransportError::Timeout.into());
        }
        Ok(())
    }

    fn user_reply(u: &User) -> Vec<u8> {
        let mut r = status(0);
        r.extend(u16s(&[
            u.dbid,
            u.fingers.len() as u16,
            0,
            u.identity.len() as u16,
        ]));
        for f in &u.fingers {
            r.extend(u16s(&[f.dbid, f.subtype, STORAGE_ID, 0x100]));
        }
        r.extend(&u.identity);
        r
    }

    fn storage_reply(st: &State) -> Vec<u8> {
        if !st.storage {
            return status(NOT_FOUND);
        }
        let name = b"StgWindsor\0";
        let mut r = status(0);
        r.extend(u16s(&[
            STORAGE_ID,
            st.users.len() as u16,
            name.len() as u16,
            0,
        ]));
        for u in &st.users {
            r.extend(u16s(&[u.dbid, u.identity.len() as u16]));
        }
        r.extend(name);
        r
    }

    fn new_record(&mut self, p: &[u8]) -> Vec<u8> {
        let (parent, kind, _storage, len) = (le16(p, 1), le16(p, 3), le16(p, 5), le16(p, 7));
        let data = &p[9..9 + len as usize];
        let mut st = self.shared.lock();
        match kind {
            db::TYPE_STORAGE => {
                st.storage = true;
                [status(0), u16s(&[STORAGE_ID])].concat()
            }
            db::TYPE_USER if parent == STORAGE_ID && st.storage => {
                let dbid = st.alloc();
                st.users.push(User {
                    dbid,
                    identity: data.to_vec(),
                    fingers: Vec::new(),
                });
                [status(0), u16s(&[dbid])].concat()
            }
            db::TYPE_FINGER_NEW => {
                if st.db_full {
                    return status(crate::errors::STATUS_DATA_FULL);
                }
                let subtype = le16(data, 0);
                // Tagged values after the 8-byte header: 1 template, 2 template id.
                let mut tinfo = &data[8..8 + le16(data, 4) as usize];
                let mut tid = Vec::new();
                while tinfo.len() >= 4 {
                    let (t, l) = (le16(tinfo, 0), le16(tinfo, 2) as usize);
                    if t == 2 {
                        tid = tinfo[4..4 + l].to_vec();
                    }
                    tinfo = &tinfo[4 + l..];
                }
                let Some(finger) = finger_of_tid(&tid) else {
                    return status(0x0401);
                };
                let dbid = st.alloc();
                let Some(u) = st.users.iter_mut().find(|u| u.dbid == parent) else {
                    return status(NOT_FOUND);
                };
                if u.fingers.iter().any(|f| f.subtype == subtype) {
                    return status(crate::errors::STATUS_DUPLICATE);
                }
                u.fingers.push(Finger {
                    dbid,
                    subtype,
                    id: finger,
                });
                drop(st);
                // The sensor raises an interrupt once the record is stored.
                self.ints.push_back(vec![6, 0, 0, 0, 0]);
                [status(0), u16s(&[dbid])].concat()
            }
            _ => status(0x0401),
        }
    }

    fn enrollment_update(&mut self) -> Vec<u8> {
        if !self.update_second {
            self.update_second = true;
            self.ints.push_back(vec![5, 0, 0, 0, 0]);
            return status(0);
        }
        self.update_second = false;
        let touch = match self.capture {
            Capture::Finished(t) => t,
            _ => return status(0x0401),
        };
        let e = self.enrol.get_or_insert(Enrolment {
            mask: 0,
            finger: None,
            images: 0,
        });
        match touch {
            Touch::Finger(f) => {
                e.finger.get_or_insert(f);
                e.mask = (e.mask << 1) | 1;
            }
            Touch::Redundant(f) => {
                e.finger.get_or_insert(f);
            }
            Touch::ScanError => {}
        }
        e.images += 1;
        let accepted = e.mask.count_ones();
        let mut header = e.mask.to_le_bytes().to_vec();
        header.extend((accepted as u16 * 0x14).to_le_bytes());
        header.resize(0x3c, 0);
        let mut body = record(0, format!("TEMPLATE-{}", e.images).as_bytes());
        body.extend(record(1, &header));
        if accepted >= IMAGES {
            body.extend(record(3, &tid_for(e.finger.unwrap_or(0))));
        }
        let mut r = status(0);
        r.extend((body.len() as u16).to_le_bytes());
        r.extend(body);
        r
    }

    fn match_result(&mut self) -> Vec<u8> {
        let st = self.shared.lock();
        let Some((u, f)) = self.last_finger.and_then(|f| st.finger_record_owner(f)) else {
            return status(NOT_FOUND);
        };
        let mut d = Vec::new();
        d.extend(u16s(&[1, 4]));
        d.extend(u32::from(u.dbid).to_le_bytes());
        d.extend(u16s(&[3, 2, f.subtype]));
        d.extend(u16s(&[4, 32]));
        d.extend([0xab; 32]);
        let mut r = status(0);
        r.extend((d.len() as u16).to_le_bytes());
        r.extend(d);
        r
    }

    fn reply(&mut self, p: &[u8], blobs: &Blobs) -> Result<Vec<u8>, ProtoError> {
        if p == blobs.init_hardcoded
            || p == blobs.init_hardcoded_clean_slate
            || p == blobs.db_write_enable
        {
            return Ok(OK.to_vec());
        }
        let Some(&c) = p.first() else {
            return Ok(status(0x0401));
        };
        let st = || self.shared.lock();
        Ok(match c {
            // ROM info: build 0x56, version 6.8, product 0x30.
            0x01 => {
                let mut r = status(0);
                r.extend([
                    0x44, 0x33, 0x22, 0x11, 0x56, 0, 0, 0, 6, 8, 0, 0x30, 0, 0, 0, 0,
                ]);
                r
            }
            0x19 => OK.to_vec(),
            // Firmware info.
            0x43 => {
                if st().firmware {
                    [status(0), u16s(&[1, 2, 0]), vec![0; 4]].concat()
                } else {
                    status(validity_proto::flash::STATUS_NO_FIRMWARE)
                }
            }
            // Flash info: W25Q80B, the Windows partition layout once paired.
            0x3e => {
                let parts: Vec<u8> = if st().paired {
                    FLASH_LAYOUT.iter().flat_map(|p| p.to_bytes()).collect()
                } else {
                    Vec::new()
                };
                let n = parts.len() / 12;
                [
                    status(0),
                    u16s(&[0xef, 0x40, 0x100, 0, 0x1000, 0, n as u16]),
                    parts,
                ]
                .concat()
            }
            // Flash read: partition 6 is emulated, the rest reads erased.
            0x40 => {
                let (part, addr, size) = (p[1], le32(p, 5) as usize, le32(p, 9) as usize);
                let data = if part == 6 {
                    let f = &st().flash6;
                    let mut d = f
                        .get(addr..(addr + size).min(f.len()))
                        .unwrap_or(&[])
                        .to_vec();
                    d.resize(size, 0xff);
                    d
                } else {
                    vec![0xff; size]
                };
                [
                    status(0),
                    (size as u32).to_le_bytes().to_vec(),
                    vec![0, 0],
                    data,
                ]
                .concat()
            }
            0x41 => {
                let (part, addr, len) = (p[1], le32(p, 5) as usize, le32(p, 9) as usize);
                if part == 6 {
                    let data = &p[13..13 + len];
                    let mut s = self.shared.lock();
                    if addr + len > s.flash6.len() {
                        return Ok(status(0x0401));
                    }
                    s.flash6[addr..addr + len].copy_from_slice(data);
                }
                OK.to_vec()
            }
            0x3f => {
                if p[1] == 6 {
                    self.shared.lock().flash6.fill(0xff);
                }
                OK.to_vec()
            }
            0x1a => OK.to_vec(),
            // Reboot: the device leaves the bus and comes back.
            0x05 => {
                if self.shared.lock().refuse_reboot {
                    return Err(TransportError::Timeout.into());
                }
                self.shared.lock().counters.reboots += 1;
                self.shared.re_enumerate();
                OK.to_vec()
            }
            // Sensor id: 0x0190:0x0059, a 0x199-type sensor.
            0x75 => [status(0), vec![0; 4], u16s(&[0x59, 0x190])].concat(),
            // Factory bits: subtag 3 holds the calibration values.
            0x6f => {
                let values: Vec<u8> = (0..112).map(|i| 0x70 + (i % 9) as u8).collect();
                let mut entry = vec![0; 4];
                entry.extend(values);
                let mut r = status(0);
                r.extend(0u32.to_le_bytes());
                r.extend(1u32.to_le_bytes());
                r.extend(0u32.to_le_bytes());
                r.extend(u16s(&[entry.len() as u16, 0x0e00, 3, 0]));
                r.extend(entry);
                r
            }
            // Capture program; calibration captures ask for lines and read
            // image data, finger captures (no lines) raise interrupts.
            0x02 => {
                if le16(p, 3) == 0 {
                    let mut s = self.shared.lock();
                    self.capture = if s.hang_captures > 0 {
                        s.hang_captures -= 1;
                        Capture::Hung
                    } else {
                        Capture::Armed
                    };
                }
                OK.to_vec()
            }
            0x51 => match self.capture {
                Capture::Finished(t) => {
                    let error: u32 = if t == Touch::ScanError { 0x5b } else { 0 };
                    let mut r = status(0);
                    r.extend(12u32.to_le_bytes());
                    r.extend(u16s(&[0x60, 0x50, 0x120, 4]));
                    r.extend(error.to_le_bytes());
                    r
                }
                _ => [status(0), vec![0; 4]].concat(),
            },
            0x04 => {
                if self.capture != Capture::Idle && !matches!(self.capture, Capture::Finished(_)) {
                    self.capture = Capture::Idle;
                }
                OK.to_vec()
            }
            0x39 => OK.to_vec(),
            // Match against every record; the interrupt says whether it matched.
            0x5e => {
                let matched = self
                    .last_finger
                    .is_some_and(|f| st().finger_record_owner(f).is_some());
                if matched {
                    st().counters.matches += 1;
                }
                self.ints.push_back(if matched {
                    vec![3, 0, 0, 0, 0]
                } else {
                    vec![4, 0, 0, 0xdb, 0]
                });
                OK.to_vec()
            }
            0x60 => self.match_result(),
            0x62 => OK.to_vec(),
            // Enrolment session start / end.
            0x69 => {
                if p.get(1) == Some(&1) {
                    self.enrol = Some(Enrolment {
                        mask: 0,
                        finger: None,
                        images: 0,
                    });
                    self.update_second = false;
                }
                OK.to_vec()
            }
            0x68 => {
                self.ints.push_back(vec![3, 0, 0, 0, 0]);
                [status(0), 0x1234_5678u32.to_le_bytes().to_vec()].concat()
            }
            0x6b => self.enrollment_update(),
            // Database.
            0x45 => [
                status(0),
                [1u32, 0, 0x80000, 0x1000, 0x70000]
                    .iter()
                    .flat_map(|v| v.to_le_bytes())
                    .collect(),
                u16s(&[3, 0]),
            ]
            .concat(),
            0x4b => {
                let (dbid, len) = (le16(p, 1), le16(p, 3) as usize);
                let name = &p[5..5 + len];
                if name == b"StgWindsor\0" || dbid == STORAGE_ID {
                    Self::storage_reply(&st())
                } else {
                    status(NOT_FOUND)
                }
            }
            0x4a => {
                let (dbid, len) = (le16(p, 1), le16(p, 5) as usize);
                let s = st();
                let u = if dbid != 0 {
                    s.users.iter().find(|u| u.dbid == dbid)
                } else {
                    let identity = &p[7..7 + len];
                    s.users.iter().find(|u| u.identity == identity)
                };
                match u {
                    Some(u) => Self::user_reply(u),
                    None => status(NOT_FOUND),
                }
            }
            0x47 => self.new_record(p),
            0x48 => {
                let dbid = le16(p, 1);
                let mut s = self.shared.lock();
                if let Some(i) = s.users.iter().position(|u| u.dbid == dbid) {
                    s.users.remove(i);
                    OK.to_vec()
                } else if let Some(u) = s
                    .users
                    .iter_mut()
                    .find(|u| u.fingers.iter().any(|f| f.dbid == dbid))
                {
                    u.fingers.retain(|f| f.dbid != dbid);
                    OK.to_vec()
                } else {
                    status(NOT_FOUND)
                }
            }
            _ => status(0x0401),
        })
    }
}

impl Sensor for FakeChip {
    fn cmd(&mut self, payload: &[u8]) -> Result<Vec<u8>, ProtoError> {
        self.alive()?;
        self.reply(payload, &blobs())
    }

    fn is_open(&self) -> bool {
        self.open
    }

    fn open_channel(&mut self, _tls_flash: &[u8]) -> Result<(), ProtoError> {
        self.alive()?;
        if self.shared.lock().paired_elsewhere {
            return Err(ProtoError::Channel(channel::Error::Tls(
                tls::Error::PairedElsewhere,
            )));
        }
        self.open = true;
        Ok(())
    }

    fn wait_int(&mut self) -> Result<Vec<u8>, ProtoError> {
        self.wait_for(Wait::Interrupt)
    }

    fn wait_for(&mut self, what: Wait) -> Result<Vec<u8>, ProtoError> {
        self.alive()?;
        if let Some(b) = self.ints.pop_front() {
            return Ok(b);
        }
        let timeout = |deadlines: &Deadlines| ProtoError::Timeout {
            waiting_for: what,
            after: deadlines.get(what),
        };
        match self.capture {
            Capture::Armed => {
                self.capture = Capture::Waiting;
                return Ok(vec![0, 1, 2, 3, 4]);
            }
            Capture::Done(t) => {
                self.capture = Capture::Finished(t);
                return Ok(vec![3, 0, 6, 0, 0]);
            }
            _ => {}
        }
        if what != Wait::Finger || self.capture != Capture::Waiting {
            // Nothing will come: the sensor deadline passes (at once, here).
            return Err(timeout(&self.shared.lock().deadlines));
        }
        // Block until a touch, a cancellation, a disconnection or the finger
        // deadline, like the real session (which polls every 100 ms).
        let mut st = self.shared.lock();
        let deadline = Instant::now() + st.deadlines.finger;
        loop {
            if st.generation != self.generation {
                st.waiting = false;
                return Err(TransportError::Disconnected.into());
            }
            if self.cancel.take() {
                st.waiting = false;
                self.shared.changed();
                return Err(ProtoError::Cancelled);
            }
            if self.capture == Capture::Waiting
                && let Some(t) = st.touches.pop_front()
            {
                st.waiting = false;
                self.shared.changed();
                self.last_finger = match t {
                    Touch::Finger(f) | Touch::Redundant(f) => Some(f),
                    Touch::ScanError => None,
                };
                self.capture = Capture::Done(t);
                return Ok(vec![2, 0, 0, 0, 0]);
            }
            if Instant::now() >= deadline {
                st.waiting = false;
                self.shared.changed();
                return Err(timeout(&st.deadlines));
            }
            if !st.waiting && self.capture == Capture::Waiting {
                st.waiting = true;
                self.shared.0.cond.notify_all();
            }
            st = self
                .shared
                .0
                .cond
                .wait_timeout(st, Duration::from_millis(10))
                .expect("fake sensor lock")
                .0;
        }
    }

    fn read_82(&mut self) -> Result<Vec<u8>, ProtoError> {
        self.alive()?;
        // Calibration frames: any content averages to a valid calibration.
        Ok((0..256 * 1024u32).map(|i| 0x70 + (i % 31) as u8).collect())
    }

    fn clear_cancel(&mut self) {
        self.cancel.take();
    }

    fn pause(&mut self, d: Duration) {
        // A tenth of real time keeps retry tests fast.
        std::thread::sleep(d / 10);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensor::{Canceller, Guarded, open_session};
    use crate::users::sid_for_uid;
    use std::ops::ControlFlow;
    use validity_proto::scanner::{EnrollProgress, Identified};

    fn session(f: &FakeSensor) -> (Guarded<FakeChip>, validity_proto::scanner::Scanner) {
        let o = f.hardware().open().unwrap();
        let mut g = Guarded::new(o.session, o.cancel, Canceller::new(), Arc::new(|_| {}));
        let dir = std::env::temp_dir().join(format!("vd-fake-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sc = open_session(&mut g, &blobs(), &dir.join("calibration.bin")).unwrap();
        (g, sc)
    }

    #[test]
    fn production_code_enrols_and_identifies_against_the_emulator() {
        let f = FakeSensor::new();
        let (mut s, sc) = session(&f);
        let alice = sid_for_uid(1000);
        f.touch([
            Touch::Finger(1),
            Touch::Redundant(1),
            Touch::ScanError,
            Touch::Finger(1),
            Touch::Finger(1),
            Touch::Finger(1),
            Touch::Finger(1),
        ]);
        let mut seen = Vec::new();
        let rec = sc
            .enroll(&mut s, &blobs(), &alice, 7, |p| {
                seen.push(match p {
                    EnrollProgress::Image(h) => format!("{:?}", crate::sensor::progress_mask(h)),
                    EnrollProgress::Retry(_) => "retry".into(),
                });
                ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(
            seen,
            [
                "Some(1)", "Some(1)", "retry", "Some(3)", "Some(7)", "Some(15)", "Some(31)"
            ]
        );
        assert_eq!(f.records(), [(alice.clone(), 7, 1)]);
        let users = db::list_users(&mut s).unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].identity, alice);
        assert_eq!(users[0].fingers[0].subtype, 7);
        assert_eq!(users[0].fingers[0].dbid, rec);

        f.touch([Touch::Finger(1)]);
        match sc.identify(&mut s, |_| ControlFlow::Continue(())).unwrap() {
            Identified::Match { user, subtype, .. } => {
                assert_eq!((user, subtype), (u32::from(users[0].dbid), 7));
            }
            other => panic!("{other:?}"),
        }
        f.touch([Touch::Finger(2)]);
        assert!(matches!(
            sc.identify(&mut s, |_| ControlFlow::Continue(())).unwrap(),
            Identified::NoMatch(_)
        ));
        // The same finger again for the same user: the sensor refuses it.
        assert_eq!(
            db::new_finger(
                &mut s,
                &blobs(),
                users[0].dbid,
                &db::make_finger_data(7, b"x", &tid_for(1))
            )
            .unwrap_err()
            .to_string(),
            "sensor status 04c3"
        );
        db::del_record(&mut s, users[0].dbid).unwrap();
        assert!(f.records().is_empty());
    }

    #[test]
    fn open_reports_setup_problems_and_disconnects() {
        let f = FakeSensor::new();
        f.set_paired(false);
        let o = f.hardware().open().unwrap();
        let mut g = Guarded::new(o.session, o.cancel, Canceller::new(), Arc::new(|_| {}));
        let p = std::env::temp_dir().join("vd-fake-none.bin");
        assert!(matches!(
            open_session(&mut g, &blobs(), &p),
            Err(crate::sensor::SessionError::Setup(m)) if m.contains("blank")
        ));
        f.set_paired(true);
        f.set_paired_elsewhere(true);
        assert!(matches!(
            open_session(&mut g, &blobs(), &p),
            Err(crate::sensor::SessionError::Setup(m)) if m.contains("another computer")
        ));
        f.set_paired_elsewhere(false);
        f.set_firmware(false);
        assert!(matches!(
            open_session(&mut g, &blobs(), &p),
            Err(crate::sensor::SessionError::Setup(m)) if m.contains("firmware")
        ));
        f.unplug();
        assert!(matches!(
            open_session(&mut g, &blobs(), &p),
            Err(crate::sensor::SessionError::Sensor(ProtoError::Transport(
                TransportError::Disconnected
            )))
        ));
        assert!(f.hardware().probe().unwrap().is_none());
    }

    // ------------------------------------------------ the emulator itself

    fn chip(f: &FakeSensor) -> (FakeChip, CancelHandle) {
        let o = f.hardware().open().unwrap();
        (o.session, o.cancel)
    }

    fn cmd(c: &mut FakeChip, p: &[u8]) -> Vec<u8> {
        c.reply(p, &blobs()).unwrap()
    }

    /// A flash command: `op part 0 0 0 addr(le32) n(le32) data`.
    fn flash_cmd(op: u8, part: u8, addr: u32, n: u32, data: &[u8]) -> Vec<u8> {
        let mut c = vec![op, part, 0, 0, 0];
        c.extend(addr.to_le_bytes());
        c.extend(n.to_le_bytes());
        c.extend(data);
        c
    }

    #[test]
    fn handles_and_debug_output() {
        let f = FakeSensor::new();
        assert_eq!(
            format!("{f:?}"),
            format!(
                "FakeSensor {{ present: true, users: 0, touches: 0, counters: {:?}, .. }}",
                Counters::default()
            )
        );
        assert_eq!(f.hardware_probe(), Some(VALIDATED));
        f.touch([Touch::Finger(1), Touch::ScanError]);
        assert_eq!(f.pending_touches(), 2);
        // No capture is waiting.
        assert!(!f.waiting_for_finger());
        assert!(!f.wait_for_capture(Duration::from_millis(50)));
        let (mut c, _) = chip(&f);
        assert_eq!(
            format!("{c:?}"),
            "FakeChip { generation: 0, open: false, capture: Idle, .. }"
        );
        assert!(!c.is_open());
        c.open_channel(&[]).unwrap();
        assert!(c.is_open());
        f.unplug();
        assert_eq!(f.hardware_probe(), None);
    }

    #[test]
    fn a_waiting_capture_is_visible_and_takes_only_finger_waits() {
        let f = FakeSensor::new();
        f.set_finger_deadline(Duration::from_secs(10));
        let (mut c, _) = chip(&f);
        // Capture program without calibration lines: armed, then waiting.
        cmd(&mut c, &[0x02, 0, 0, 0, 0]);
        assert_eq!(c.wait_for(Wait::CaptureStart).unwrap(), [0, 1, 2, 3, 4]);
        f.touch([Touch::Finger(3)]);
        // Only the finger wait takes the touch: any other fails at once.
        let t = Instant::now();
        assert!(matches!(
            c.wait_for(Wait::Capture),
            Err(ProtoError::Timeout {
                waiting_for: Wait::Capture,
                ..
            })
        ));
        assert!(t.elapsed() < Duration::from_secs(5));
        assert_eq!(f.pending_touches(), 1);
        assert_eq!(c.wait_for(Wait::Finger).unwrap(), [2, 0, 0, 0, 0]);
        assert_eq!(f.pending_touches(), 0);
        // wait_int is an interrupt wait: the capture's completion.
        assert_eq!(c.wait_int().unwrap(), [3, 0, 6, 0, 0]);
        // Nothing else will come.
        assert!(matches!(
            c.wait_int(),
            Err(ProtoError::Timeout {
                waiting_for: Wait::Interrupt,
                ..
            })
        ));

        // A finger wait is visible to the test while it lasts.
        let (mut c, _) = chip(&f);
        cmd(&mut c, &[0x02, 0, 0, 0, 0]);
        c.wait_for(Wait::CaptureStart).unwrap();
        let waiter = std::thread::spawn(move || c.wait_for(Wait::Finger).map(|_| ()));
        assert!(f.wait_for_capture(Duration::from_secs(5)));
        assert!(f.waiting_for_finger());
        f.touch([Touch::Finger(4)]);
        waiter.join().unwrap().unwrap();
        assert!(!f.waiting_for_finger());
    }

    #[test]
    fn cancellation_pause_and_reboot() {
        let f = FakeSensor::new();
        let (mut c, cancel) = chip(&f);
        // clear_cancel consumes a pending cancellation.
        cancel.cancel();
        c.clear_cancel();
        assert!(!cancel.take());
        // A tenth of the asked pause, really slept.
        let t = Instant::now();
        c.pause(Duration::from_millis(300));
        assert!(t.elapsed() >= Duration::from_millis(30));
        // A reboot ends the session: the next one is a new device.
        assert_eq!(cmd(&mut c, &[0x05, 2, 0]), OK);
        assert_eq!(f.counters().reboots, 1);
        assert!(matches!(
            c.cmd(&[0x01]),
            Err(ProtoError::Transport(TransportError::Disconnected))
        ));
        let (mut c2, _) = chip(&f);
        assert!(c2.cmd(&[0x01]).is_ok());
    }

    #[test]
    fn records_get_increasing_ids() {
        let f = FakeSensor::new();
        f.enroll_directly(&sid_for_uid(1000), 7, 1);
        f.enroll_directly(&sid_for_uid(1001), 2, 2);
        let (mut c, _) = chip(&f);
        c.open_channel(&[]).unwrap();
        let users = db::list_users(&mut c).unwrap();
        let ids: Vec<(u16, u16)> = users.iter().map(|u| (u.dbid, u.fingers[0].dbid)).collect();
        assert_eq!(ids, [(0x10, 0x11), (0x12, 0x13)]);
    }

    #[test]
    fn flash_partition_6_reads_writes_and_erases() {
        let f = FakeSensor::new();
        let (mut c, _) = chip(&f);
        let read = |c: &mut FakeChip, part, addr, n| {
            let r = cmd(c, &flash_cmd(0x40, part, addr, n, &[]));
            assert_eq!(&r[..8], [&[0u8, 0][..], &n.to_le_bytes(), &[0, 0]].concat());
            r[8..].to_vec()
        };
        // Writes reach partition 6 only, up to its very end.
        let end = 0x8000 - 4;
        assert_eq!(cmd(&mut c, &flash_cmd(0x41, 6, end, 4, &[1, 2, 3, 4])), OK);
        assert_eq!(cmd(&mut c, &flash_cmd(0x41, 6, 0x10, 2, &[9, 8])), OK);
        assert_eq!(cmd(&mut c, &flash_cmd(0x41, 5, 0x20, 2, &[7, 7])), OK);
        assert_eq!(
            cmd(&mut c, &flash_cmd(0x41, 6, end + 1, 4, &[1, 2, 3, 4])),
            status(0x0401)
        );
        assert_eq!(cmd(&mut c, &flash_cmd(0x41, 6, 0, 2, &[5, 6])), OK);
        assert_eq!(read(&mut c, 6, 0, 2), [5, 6]);
        assert_eq!(read(&mut c, 6, 0x10, 1), [9]);
        assert_eq!(read(&mut c, 6, end, 4), [1, 2, 3, 4]);
        assert_eq!(read(&mut c, 6, 0x0f, 4), [0xff, 9, 8, 0xff]);
        assert_eq!(read(&mut c, 6, 0x20, 2), [0xff, 0xff]);
        // Other partitions, and past the end, read erased.
        assert_eq!(read(&mut c, 5, 0x10, 2), [0xff, 0xff]);
        assert_eq!(read(&mut c, 6, 0x8000 - 2, 4), [3, 4, 0xff, 0xff]);
        // Erasing another partition leaves 6 alone; erasing 6 clears it.
        assert_eq!(cmd(&mut c, &[0x3f, 5]), OK);
        assert_eq!(read(&mut c, 6, 0x10, 2), [9, 8]);
        assert_eq!(cmd(&mut c, &[0x3f, 6]), OK);
        assert_eq!(read(&mut c, 6, 0x10, 2), [0xff, 0xff]);
    }

    #[test]
    fn calibration_data() {
        let f = FakeSensor::new();
        let (mut c, _) = chip(&f);
        let r = cmd(&mut c, &[0x6f]);
        let values = &r[26..];
        assert_eq!(values.len(), 112);
        for (i, v) in values.iter().enumerate() {
            assert_eq!(*v, 0x70 + (i % 9) as u8, "value {i}");
        }
        let frame = c.read_82().unwrap();
        assert_eq!(frame.len(), 256 * 1024);
        assert_eq!(&frame[..3], [0x70, 0x71, 0x72]);
        assert_eq!(frame[31], 0x70);
    }

    #[test]
    fn capture_stop_and_the_other_plain_commands() {
        let f = FakeSensor::new();
        let (mut c, _) = chip(&f);
        // A stop ends a capture in progress, not a finished one.
        cmd(&mut c, &[0x02, 0, 0, 0, 0]);
        assert_eq!(c.capture, Capture::Armed);
        assert_eq!(cmd(&mut c, &[0x04]), OK);
        assert_eq!(c.capture, Capture::Idle);
        c.capture = Capture::Finished(Touch::Finger(1));
        assert_eq!(cmd(&mut c, &[0x04]), OK);
        assert_eq!(c.capture, Capture::Finished(Touch::Finger(1)));
        for op in [0x19, 0x1a, 0x39, 0x62] {
            assert_eq!(cmd(&mut c, &[op]), OK, "{op:02x}");
        }
        assert_eq!(cmd(&mut c, &[0x99]), status(0x0401));
    }

    #[test]
    fn storage_lookup_by_name_or_id() {
        let f = FakeSensor::new();
        f.enroll_directly(&sid_for_uid(1000), 7, 1);
        let (mut c, _) = chip(&f);
        let lookup = |c: &mut FakeChip, dbid: u16, name: &[u8]| {
            let mut p = vec![0x4b];
            p.extend(dbid.to_le_bytes());
            p.extend((name.len() as u16).to_le_bytes());
            p.extend(name);
            u16::from_le_bytes(cmd(c, &p)[..2].try_into().unwrap())
        };
        assert_eq!(lookup(&mut c, 0, b"StgWindsor\0"), 0);
        assert_eq!(lookup(&mut c, STORAGE_ID, b""), 0);
        assert_eq!(lookup(&mut c, 0, b"Other\0"), NOT_FOUND);
        assert_eq!(lookup(&mut c, 0, b""), NOT_FOUND);
    }

    #[test]
    fn user_records_need_the_storage_as_parent() {
        let f = FakeSensor::new();
        let (mut c, _) = chip(&f);
        let new = |c: &mut FakeChip, parent: u16, kind: u16| {
            let identity = db::identity_to_bytes(&sid_for_uid(1000));
            let mut p = vec![0x47];
            for v in [parent, kind, STORAGE_ID, identity.len() as u16] {
                p.extend(v.to_le_bytes());
            }
            p.extend(identity);
            u16::from_le_bytes(cmd(c, &p)[..2].try_into().unwrap())
        };
        // No storage yet.
        assert_eq!(new(&mut c, STORAGE_ID, db::TYPE_USER), 0x0401);
        assert_eq!(new(&mut c, 0, db::TYPE_STORAGE), 0);
        // Not under the storage.
        assert_eq!(new(&mut c, 0x99, db::TYPE_USER), 0x0401);
        assert_eq!(new(&mut c, STORAGE_ID, db::TYPE_USER), 0);
        assert_eq!(f.lock().users.len(), 1);
    }

    #[test]
    fn template_ids_name_their_finger() {
        assert_eq!(finger_of_tid(&tid_for(42)), Some(42));
        assert_eq!(finger_of_tid(b"OTHERTID\x2a\0\0\0"), None);
        assert_eq!(finger_of_tid(b"FAKE-TI"), None);
    }

    #[test]
    fn enrolment_updates_count_images_and_accepted_ones() {
        let f = FakeSensor::new();
        let (mut c, _) = chip(&f);
        let update = |c: &mut FakeChip, t: Touch| {
            // The first of the pair only acknowledges.
            assert_eq!(c.enrollment_update(), OK);
            c.capture = Capture::Finished(t);
            let r = c.enrollment_update();
            let body = &r[4..];
            // Tag 0: the template, numbered by image.
            let tlen = u16::from_le_bytes([body[2], body[3]]) as usize;
            let template = String::from_utf8(body[4 + 0x34..4 + 0x34 + tlen].to_vec()).unwrap();
            // Tag 1: accepted-image mask, then 0x14 per accepted image.
            let h = &body[4 + 0x34 + tlen + 4 + 0x34..];
            (
                template,
                u16::from_le_bytes([h[0], h[1]]),
                u16::from_le_bytes([h[2], h[3]]),
            )
        };
        assert_eq!(
            update(&mut c, Touch::Finger(1)),
            ("TEMPLATE-1".into(), 1, 0x14)
        );
        assert_eq!(
            update(&mut c, Touch::Redundant(1)),
            ("TEMPLATE-2".into(), 1, 0x14)
        );
        assert_eq!(
            update(&mut c, Touch::Finger(1)),
            ("TEMPLATE-3".into(), 3, 0x28)
        );
        assert_eq!(
            update(&mut c, Touch::ScanError),
            ("TEMPLATE-4".into(), 3, 0x28)
        );
    }
}
