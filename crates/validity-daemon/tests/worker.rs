//! The sensor thread on its own: a `Worker` over the emulated sensor, driven
//! with `Command`s the way the D-Bus side drives it, its `Event`s and log lines
//! recorded. Covers the connection cycle (backoff, requests answered while the
//! sensor is unavailable, absent-sensor polling, the reappear window), runs
//! interrupted by a suspend or a shutdown, and the capture-failure bounds.
//! Written from the survivors of a mutation-testing run.

use std::path::PathBuf;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use validity_daemon::fake::{FakeSensor, Touch, blobs};
use validity_daemon::machine::{ActionKind, DeviceState, Event};
use validity_daemon::sensor::Canceller;
use validity_daemon::users::sid_for_uid;
use validity_daemon::worker::{Command, DeleteError, REBOOT_MARKER, Timing, Worker};
use validity_proto::sid::Sid;

// ------------------------------------------------------------- log capture

/// Log records, with the name of the thread that logged them: each test
/// runs its worker in a thread named after it.
struct Capture(Mutex<Vec<(String, log::Level, String)>>);

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, r: &log::Record<'_>) {
        let thread = std::thread::current().name().unwrap_or("").to_string();
        self.0
            .lock()
            .unwrap()
            .push((thread, r.level(), r.args().to_string()));
    }
    fn flush(&self) {}
}

fn capture() -> &'static Capture {
    static C: OnceLock<&'static Capture> = OnceLock::new();
    C.get_or_init(|| {
        let c: &'static Capture = Box::leak(Box::new(Capture(Mutex::new(Vec::new()))));
        log::set_logger(c).expect("the only logger of this test binary");
        log::set_max_level(log::LevelFilter::Trace);
        c
    })
}

// ----------------------------------------------------------------- harness

fn timing() -> Timing {
    Timing {
        attempts: [0, 20, 40, 80, 160]
            .into_iter()
            .map(Duration::from_millis)
            .collect(),
        absent_first: Duration::from_millis(20),
        absent_max: Duration::from_millis(200),
        failed_cooldown: Duration::from_secs(1),
        max_capture_failures: 10,
        reappear: Duration::from_secs(1),
        reappear_poll: Duration::from_millis(20),
    }
}

fn alice() -> Sid {
    sid_for_uid(1000)
}

/// An event, and whether the emulated device was on the bus when it came.
type Seen = (Event, bool);

struct Run {
    name: String,
    fake: FakeSensor,
    tx: Sender<Command>,
    canceller: Arc<Canceller>,
    events: Arc<(Mutex<Vec<Seen>>, Condvar)>,
    started: Instant,
    thread: Option<std::thread::JoinHandle<()>>,
    dir: PathBuf,
}

impl Run {
    /// Starts a worker over a fresh emulated sensor; `queued` are sent before
    /// the thread starts.
    fn start(
        name: &str,
        prepare: impl FnOnce(&FakeSensor),
        timing: Timing,
        queued: Vec<Command>,
    ) -> Self {
        capture();
        let fake = FakeSensor::new();
        prepare(&fake);
        let dir =
            std::env::temp_dir().join(format!("validity-worker-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (tx, rx) = channel();
        for c in queued {
            tx.send(c).unwrap();
        }
        let canceller = Canceller::new();
        let events: Arc<(Mutex<Vec<Seen>>, Condvar)> = Arc::default();
        let (ev, f2) = (events.clone(), fake.clone());
        let sink = Arc::new(move |e: Event| {
            let present = f2.hardware_probe().is_some();
            ev.0.lock().unwrap().push((e, present));
            ev.1.notify_all();
        });
        let worker = Worker::new(
            fake.hardware(),
            Ok(Arc::new(blobs())),
            dir.join("calibration.bin"),
            rx,
            tx.clone(),
            sink,
            canceller.clone(),
            timing,
        );
        assert_eq!(
            format!("{worker:?}"),
            "Worker { state: Opening, id: None, live: false, .. }"
        );
        let started = Instant::now();
        let thread = std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || worker.run())
            .unwrap();
        Run {
            name: name.to_string(),
            fake,
            tx,
            canceller,
            events,
            started,
            thread: Some(thread),
            dir,
        }
    }

    fn send(&self, c: Command) {
        self.tx.send(c).unwrap();
    }

    fn events(&self) -> Vec<Seen> {
        self.events.0.lock().unwrap().clone()
    }

    /// Waits up to `d` for an event `f` accepts; its index.
    fn wait_for(&self, d: Duration, f: impl Fn(&Event) -> bool) -> Option<usize> {
        let end = Instant::now() + d;
        let mut ev = self.events.0.lock().unwrap();
        loop {
            if let Some(i) = ev.iter().position(|(e, _)| f(e)) {
                return Some(i);
            }
            let now = Instant::now();
            if now >= end {
                return None;
            }
            ev = self.events.1.wait_timeout(ev, end - now).unwrap().0;
        }
    }

    fn ready(&self) {
        assert!(
            self.wait_for(Duration::from_secs(10), |e| matches!(
                e,
                Event::Device {
                    state: DeviceState::Ready,
                    ..
                }
            ))
            .is_some(),
            "{}: never ready: {:?}",
            self.name,
            self.events()
        );
    }

    fn ended(&self, op: u64, d: Duration) -> bool {
        self.wait_for(d, |e| *e == Event::OpEnded { op }).is_some()
    }

    /// The statuses of run `op`, once it ended (or after 10 s).
    fn statuses(&self, op: u64) -> Vec<&'static str> {
        assert!(
            self.ended(op, Duration::from_secs(10)),
            "{}: run {op} did not end: {:?}",
            self.name,
            self.events()
        );
        self.statuses_so_far(op)
    }

    fn statuses_so_far(&self, op: u64) -> Vec<&'static str> {
        self.events()
            .into_iter()
            .filter_map(|(e, _)| match e {
                Event::Status { op: o, result, .. } if o == op => Some(result),
                _ => None,
            })
            .collect()
    }

    /// What this test's worker logged.
    fn logs(&self) -> Vec<(log::Level, String)> {
        capture()
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|(t, _, _)| *t == self.name)
            .map(|(_, l, m)| (*l, m.clone()))
            .collect()
    }

    fn logged(&self, level: log::Level, prefix: &str) -> usize {
        self.logs()
            .iter()
            .filter(|(l, m)| *l == level && m.starts_with(prefix))
            .count()
    }

    fn shutdown(&mut self) {
        let (reply, done) = zruntime::mpmc::bounded(std::num::NonZeroUsize::MIN);
        self.canceller.start_shutdown();
        self.send(Command::Shutdown { reply });
        zbus::block_on(done.recv()).expect("the worker answers Shutdown");
        self.thread.take().unwrap().join().unwrap();
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        if self.thread.is_some() && !std::thread::panicking() {
            self.shutdown();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Polls `f` every 10 ms for up to `d`.
fn poll(d: Duration, f: impl Fn() -> bool) -> bool {
    let end = Instant::now() + d;
    loop {
        if f() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn verify(op: u64) -> Command {
    Command::Verify {
        op,
        sid: alice(),
        finger: None,
    }
}

fn enroll(op: u64) -> Command {
    Command::Enroll {
        op,
        sid: alice(),
        finger: 7,
        replace: false,
    }
}

fn status(op: u64, result: &'static str, done: bool, kind: ActionKind) -> Event {
    Event::Status {
        op,
        kind,
        result,
        done,
    }
}

// ------------------------------------------------------------------- tests

#[test]
fn start_and_stop_are_logged_and_the_reboot_recorded() {
    let mut r = Run::start("start-stop", |_| {}, timing(), vec![]);
    r.ready();
    r.shutdown();
    // One line per state change, none for a state set again.
    assert_eq!(
        r.logged(log::Level::Info, "sensor ready"),
        1,
        "{:?}",
        r.logs()
    );
    // The emulator has hotplug notifications: no polling notice.
    assert_eq!(
        r.logged(log::Level::Info, "no USB hotplug notifications"),
        0
    );
    // Closing rebooted the sensor: the time is recorded for the next instance.
    let at: u128 = std::fs::read_to_string(r.dir.join(REBOOT_MARKER))
        .unwrap()
        .parse()
        .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    assert!(now >= at && now - at < 60_000, "marker {at}, now {now}");
}

#[test]
fn an_absent_sensor_is_polled_less_and_less_often() {
    let r = Run::start("absent", |f| f.unplug(), timing(), vec![]);
    assert!(
        r.wait_for(Duration::from_secs(5), |e| matches!(
            e,
            Event::Device {
                state: DeviceState::Absent,
                ..
            }
        ))
        .is_some()
    );
    let first = r.fake.counters().probes;
    std::thread::sleep(Duration::from_millis(1200));
    // 20 ms, doubling at every poll: at most a handful in 1.2 s (every 20 ms
    // would be 60).
    let polls = r.fake.counters().probes - first;
    assert!((2..=10).contains(&polls), "{polls} polls in 1.2 s");
}

#[test]
fn a_burst_of_usb_events_keeps_the_requests_in_it() {
    let r = Run::start(
        "burst",
        |f| {
            f.enroll_directly(&alice(), 2, 1);
            f.touch([Touch::Finger(1)]);
        },
        timing(),
        vec![Command::Hotplug, Command::Hotplug, verify(1)],
    );
    assert_eq!(r.statuses(1), ["verify-match"]);
}

#[test]
fn attempts_wait_their_backoff_delay() {
    let mut t = timing();
    t.attempts = vec![Duration::ZERO, Duration::from_millis(400)];
    let r = Run::start("backoff", |f| f.fail_opens(1), t, vec![]);
    r.ready();
    let took = r.started.elapsed();
    assert!(took >= Duration::from_millis(400), "ready after {took:?}");
    assert_eq!(r.fake.counters().opens, 1);
}

#[test]
fn requests_during_a_connection_cycle_are_answered_at_once() {
    let mut t = timing();
    t.attempts = vec![Duration::ZERO, Duration::from_secs(3)];
    let r = Run::start("cycle", |f| f.fail_opens(1), t, vec![]);
    // The first open failed: the worker waits 3 s for the second attempt.
    std::thread::sleep(Duration::from_millis(200));
    r.send(verify(3));
    r.send(enroll(4));
    let (reply, rx) = zruntime::mpmc::bounded(std::num::NonZeroUsize::MIN);
    r.send(Command::Delete {
        sid: alice(),
        finger: None,
        reply,
    });
    let quick = Duration::from_secs(1);
    assert!(r.ended(3, quick), "{:?}", r.events());
    assert!(r.ended(4, quick), "{:?}", r.events());
    assert_eq!(r.statuses_so_far(3), ["verify-disconnected"]);
    assert_eq!(r.statuses_so_far(4), ["enroll-disconnected"]);
    assert_eq!(
        zbus::block_on(rx.recv()).unwrap(),
        Err(DeleteError::Unavailable(
            "the sensor is not available".into()
        ))
    );
    // Then the cycle goes on.
    r.ready();
}

#[test]
fn a_sensor_expected_back_is_opening_while_off_the_bus() {
    let r = Run::start(
        "reappear",
        |f| f.set_reboot_absence(Duration::from_millis(600)),
        timing(),
        vec![],
    );
    r.ready();
    let n = r.events().len();
    let (reply, done) = zruntime::mpmc::bounded(std::num::NonZeroUsize::MIN);
    r.canceller.start_sleep();
    r.send(Command::Sleep { reply });
    zbus::block_on(done.recv()).unwrap();
    // The reboot of the close took it off the bus; it is back 600 ms later.
    r.send(Command::Wake);
    let opening = r
        .wait_for(Duration::from_secs(5), |e| {
            matches!(
                e,
                Event::Device {
                    state: DeviceState::Opening,
                    ..
                }
            )
        })
        .unwrap();
    assert!(opening >= n);
    assert!(
        !r.events()[opening].1,
        "opening reported only once the device was back: {:?}",
        r.events()
    );
    r.ready();
}

#[test]
fn repeated_capture_failures_end_the_verify_and_reset_the_sensor() {
    let mut t = timing();
    t.max_capture_failures = 3;
    let r = Run::start(
        "stuck",
        |f| {
            f.enroll_directly(&alice(), 2, 1);
            f.set_finger_deadline(Duration::from_millis(200));
            f.touch([Touch::ScanError; 3]);
        },
        t,
        vec![verify(5)],
    );
    assert_eq!(
        r.statuses(5),
        [
            "verify-retry-scan",
            "verify-retry-scan",
            "verify-retry-scan",
            "verify-unknown-error"
        ]
    );
    assert!(poll(Duration::from_secs(5), || r.fake.counters().resets == 1));
}

#[test]
fn a_verify_that_arrives_while_suspending_runs_after_the_wake_up() {
    let r = Run::start(
        "verify-sleep",
        |f| f.enroll_directly(&alice(), 2, 1),
        timing(),
        vec![],
    );
    r.ready();
    r.canceller.start_sleep();
    r.send(verify(6));
    assert!(!r.ended(6, Duration::from_millis(300)), "{:?}", r.events());
    r.fake.touch([Touch::Finger(1)]);
    r.send(Command::Wake);
    assert_eq!(r.statuses(6), ["verify-match"]);
}

#[test]
fn a_cancelled_run_ends_at_once_even_while_suspending() {
    let r = Run::start("cancel-sleep", |_| {}, timing(), vec![]);
    r.ready();
    r.canceller.cancel(8);
    r.canceller.start_sleep();
    r.send(verify(7));
    r.send(enroll(8));
    let quick = Duration::from_secs(1);
    assert!(r.ended(7, quick) && r.ended(8, quick), "{:?}", r.events());
    assert!(r.statuses_so_far(8).is_empty());
    r.send(Command::Wake);
}

#[test]
fn runs_arriving_during_shutdown_end_at_once() {
    let r = Run::start("shutdown-start", |_| {}, timing(), vec![]);
    r.ready();
    r.canceller.start_shutdown();
    r.send(verify(9));
    r.send(enroll(10));
    let quick = Duration::from_secs(1);
    assert!(r.ended(9, quick) && r.ended(10, quick), "{:?}", r.events());
    assert!(r.statuses_so_far(9).is_empty());
    assert!(r.statuses_so_far(10).is_empty());
}

#[test]
fn a_shutdown_ends_a_running_verify_without_a_status() {
    let r = Run::start(
        "shutdown-verify",
        |f| f.enroll_directly(&alice(), 2, 1),
        timing(),
        vec![],
    );
    r.ready();
    r.send(verify(11));
    assert!(r.fake.wait_for_capture(Duration::from_secs(5)));
    r.canceller.start_shutdown();
    assert!(r.ended(11, Duration::from_secs(2)), "{:?}", r.events());
    assert!(r.statuses_so_far(11).is_empty());
}

#[test]
fn a_shutdown_ends_a_running_enrolment_without_a_status() {
    let r = Run::start("shutdown-enroll", |_| {}, timing(), vec![]);
    r.ready();
    r.send(enroll(12));
    assert!(r.fake.wait_for_capture(Duration::from_secs(5)));
    r.canceller.start_shutdown();
    assert!(r.ended(12, Duration::from_secs(2)), "{:?}", r.events());
    assert!(r.statuses_so_far(12).is_empty());
}

#[test]
fn an_enrolment_interrupted_by_a_suspend_is_reported_after_it() {
    let r = Run::start("enroll-sleep", |_| {}, timing(), vec![]);
    r.ready();
    r.send(enroll(13));
    assert!(r.fake.wait_for_capture(Duration::from_secs(5)));
    r.canceller.start_sleep();
    let (reply, done) = zruntime::mpmc::bounded(std::num::NonZeroUsize::MIN);
    r.send(Command::Sleep { reply });
    zbus::block_on(done.recv()).unwrap();
    assert!(!r.ended(13, Duration::from_millis(300)), "{:?}", r.events());
    r.send(Command::Wake);
    // The enrolment's progress was in the closed session: it is lost.
    assert_eq!(r.statuses(13), ["enroll-disconnected"]);
}

#[test]
fn an_enrolment_that_arrives_while_suspending_is_reported_after_it() {
    let r = Run::start("enroll-before-sleep", |_| {}, timing(), vec![]);
    r.ready();
    r.canceller.start_sleep();
    r.send(enroll(14));
    assert!(!r.ended(14, Duration::from_millis(300)), "{:?}", r.events());
    r.send(Command::Wake);
    assert_eq!(r.statuses(14), ["enroll-disconnected"]);
}

#[test]
fn verify_results_are_logged_as_what_they_are() {
    let bob = sid_for_uid(1001);
    let r = Run::start(
        "verify-logs",
        |f| {
            f.enroll_directly(&alice(), 2, 1);
            f.enroll_directly(&bob, 2, 5);
            f.set_finger_deadline(Duration::from_millis(200));
        },
        timing(),
        vec![],
    );
    r.ready();
    // Bob's finger, for Alice: no match, and the log says whose it was.
    r.fake.touch([Touch::Finger(5)]);
    r.send(verify(15));
    assert_eq!(r.statuses(15), ["verify-no-match"]);
    assert_eq!(
        r.logged(log::Level::Info, "the finger matched database record"),
        1,
        "{:?}",
        r.logs()
    );
    // Her own finger: no such line.
    r.fake.touch([Touch::Finger(1)]);
    r.send(verify(16));
    assert_eq!(r.statuses(16), ["verify-match"]);
    assert_eq!(
        r.logged(log::Level::Info, "the finger matched database record"),
        1
    );
    // No finger in time: an ordinary end, not a failure.
    r.send(verify(17));
    assert_eq!(r.statuses(17), ["verify-no-match"]);
    assert_eq!(r.logged(log::Level::Info, "verification ended:"), 1);
    assert_eq!(r.logged(log::Level::Warn, "verification failed:"), 0);
}

#[test]
fn a_session_that_stops_answering_is_logged_a_vanished_one_is_not() {
    let r = Run::start(
        "lost-logs",
        |f| f.enroll_directly(&alice(), 2, 1),
        timing(),
        vec![],
    );
    r.ready();
    let not_responding = "sensor not responding (";
    // Unplugged: the session is gone, nothing more to say. The worker logs
    // (or not) before it looks for the sensor again, which finds none.
    r.fake.unplug();
    r.send(verify(18));
    assert_eq!(r.statuses(18), ["verify-disconnected"]);
    assert!(poll(Duration::from_secs(10), || {
        r.events().iter().any(|(e, _)| {
            matches!(
                e,
                Event::Device {
                    state: DeviceState::Absent,
                    ..
                }
            )
        })
    }));
    assert_eq!(
        r.logged(log::Level::Info, not_responding),
        0,
        "{:?}",
        r.logs()
    );
    r.fake.plug();
    r.send(Command::Hotplug);
    let n = r.events().len();
    assert!(poll(Duration::from_secs(10), || {
        r.events()[n..].iter().any(|(e, _)| {
            matches!(
                e,
                Event::Device {
                    state: DeviceState::Ready,
                    ..
                }
            )
        })
    }));
    // Commands time out: the session is dropped, and that is worth a line
    // (logged after the run ended).
    r.fake.set_stuck(true);
    r.send(verify(19));
    assert_eq!(r.statuses(19), ["verify-disconnected"]);
    assert!(
        poll(Duration::from_secs(5), || r
            .logged(log::Level::Info, not_responding)
            == 1),
        "{:?}",
        r.logs()
    );
}

#[test]
fn no_finger_in_time_does_not_count_as_a_capture_failure() {
    let mut t = timing();
    t.max_capture_failures = 2;
    let r = Run::start(
        "enroll-nofinger",
        |f| {
            f.set_finger_deadline(Duration::from_millis(100));
            // The duplicate check.
            f.touch([Touch::Finger(1)]);
        },
        t,
        vec![enroll(20)],
    );
    // More finger timeouts than the failure bound: still enrolling.
    let retries = |r: &Run| {
        r.statuses_so_far(20)
            .iter()
            .filter(|s| **s == "enroll-retry-scan")
            .count()
    };
    assert!(poll(Duration::from_secs(10), || retries(&r) >= 3));
    r.fake.touch([Touch::Finger(1); 5]);
    let s = r.statuses(20);
    assert_eq!(s.last(), Some(&"enroll-completed"), "{s:?}");
}

#[test]
fn repeated_capture_failures_end_the_enrolment() {
    let mut t = timing();
    t.max_capture_failures = 2;
    let r = Run::start(
        "enroll-stuck",
        |f| {
            f.set_finger_deadline(Duration::from_millis(100));
            f.touch([Touch::Finger(1), Touch::ScanError, Touch::ScanError]);
        },
        t,
        vec![enroll(21)],
    );
    assert_eq!(
        r.statuses(21),
        [
            "enroll-stage-passed",
            "enroll-retry-scan",
            "enroll-retry-scan",
            "enroll-unknown-error"
        ]
    );
}

#[test]
fn a_full_database_fails_the_enrolment_and_rereads_the_prints() {
    let r = Run::start(
        "enroll-full",
        |f| {
            f.set_db_full(true);
            f.touch([Touch::Finger(1); 6]);
        },
        timing(),
        vec![],
    );
    r.ready();
    let prints = |r: &Run| {
        r.events()
            .iter()
            .filter(|(e, _)| matches!(e, Event::Prints(_)))
            .count()
    };
    let before = prints(&r);
    r.send(enroll(22));
    let s = r.statuses(22);
    assert_eq!(s.last(), Some(&"enroll-data-full"), "{s:?}");
    assert!(r.events().contains(&(
        status(22, "enroll-data-full", true, ActionKind::Enroll),
        true
    )));
    // Records may have been written before the failure: read again.
    assert_eq!(prints(&r), before + 1);
    assert!(r.fake.records().is_empty());
}
