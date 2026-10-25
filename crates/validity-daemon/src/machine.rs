//! The state the D-Bus side keeps: the sensor's availability, the cached list of
//! enrolled prints, and fprintd's claim/action rules. Pure and synchronous, so
//! every rule is unit-tested without a bus or a sensor.
//!
//! The rules follow fprintd 1.94.5's documented behaviour: a client claims the
//! device for a user, runs one action at a time (verify, enroll, delete), stops a
//! verify or enroll with the matching Stop call once it reported a final status,
//! and releases the device (or disconnects from the bus, which releases it too).

use validity_proto::sid::Sid;

use crate::errors::FprintError;
use crate::users::{User, finger_name, finger_subtype};

/// Identifies one verify or enroll run, so that late events of an earlier run
/// are never mistaken for the current one.
pub type OpId = u64;

/// Where the sensor is. The D-Bus device object exists in every state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceState {
    /// Looking for, opening or re-opening the sensor (start, resume, recovery).
    Opening,
    Ready,
    /// No supported sensor on the USB bus.
    Absent,
    /// Unusable until an administrator acts: not paired, paired with another
    /// computer, no firmware extension, vendor files missing.
    NeedsSetup(String),
    /// Opening failed repeatedly; the daemon retries later on its own.
    Failed(String),
    /// Between logind's PrepareForSleep(true) and PrepareForSleep(false).
    Suspended,
}

/// What a client asking for the sensor gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    Ready,
    /// Coming up (or back): worth a short bounded wait.
    Soon,
    /// Fail fast, so that PAM moves on to the password.
    Unavailable(String),
}

impl DeviceState {
    pub fn availability(&self) -> Availability {
        match self {
            DeviceState::Ready => Availability::Ready,
            DeviceState::Opening | DeviceState::Suspended => Availability::Soon,
            DeviceState::Absent => Availability::Unavailable("no fingerprint sensor found".into()),
            DeviceState::NeedsSetup(why) => {
                Availability::Unavailable(format!("fingerprint sensor needs setup: {why}"))
            }
            DeviceState::Failed(why) => {
                Availability::Unavailable(format!("fingerprint sensor unavailable: {why}"))
            }
        }
    }

    /// Short name for logs.
    pub fn label(&self) -> &'static str {
        match self {
            DeviceState::Opening => "opening",
            DeviceState::Ready => "ready",
            DeviceState::Absent => "absent",
            DeviceState::NeedsSetup(_) => "needs-setup",
            DeviceState::Failed(_) => "failed",
            DeviceState::Suspended => "suspended",
        }
    }
}

/// The enrolled fingers of one database user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPrints {
    pub sid: Sid,
    /// Sensor subtypes (1..=10 for the fprintd fingers; others are Windows positions).
    pub fingers: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    Verify,
    Enroll,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    /// The sensor thread runs it.
    Running {
        kind: ActionKind,
        op: OpId,
    },
    /// A final status was reported; the client still has to call Stop.
    Finished {
        kind: ActionKind,
        op: OpId,
    },
    /// Stop was called; waiting for the sensor thread to let go.
    Stopping {
        kind: ActionKind,
        op: OpId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// Unique bus name of the claiming connection.
    pub sender: String,
    pub user: User,
    pub sid: Sid,
    pub action: Action,
    /// Distinguishes successive claims by the same connection.
    pub id: u64,
}

/// A signal for the claiming client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Emit {
    VerifyStatus {
        dest: String,
        result: &'static str,
        done: bool,
    },
    EnrollStatus {
        dest: String,
        result: &'static str,
        done: bool,
    },
    VerifyFingerSelected {
        dest: String,
        finger: &'static str,
    },
    FingerPresent(bool),
    FingerNeeded(bool),
    /// The `name` property changed.
    Name,
}

/// What the sensor thread reports (see `worker`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Device {
        state: DeviceState,
        name: Option<String>,
    },
    Prints(Vec<UserPrints>),
    Status {
        op: OpId,
        kind: ActionKind,
        result: &'static str,
        done: bool,
    },
    /// The run is over on the sensor side (after its final status, after a
    /// cancellation, or without a status when it never started).
    OpEnded {
        op: OpId,
    },
    Finger {
        present: bool,
        needed: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyStart {
    pub op: OpId,
    pub sid: Sid,
    /// `None`: any enrolled finger of the user.
    pub finger: Option<u16>,
    /// For VerifyFingerSelected.
    pub selected: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollStart {
    pub op: OpId,
    pub sid: Sid,
    pub finger: u16,
    /// The finger is enrolled already: its print is deleted first (as fprintd does).
    pub replace: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// Nothing left to wait for.
    Done,
    /// Cancel this run and wait for the sensor thread to end it.
    Cancel(OpId),
}

#[derive(Debug)]
pub struct Machine {
    pub device: DeviceState,
    pub name: String,
    /// The database as last read; `None` while the sensor is not ready.
    pub prints: Option<Vec<UserPrints>>,
    pub claim: Option<Claim>,
    pub finger_present: bool,
    pub finger_needed: bool,
    /// The highest run the sensor thread said it ended.
    pub last_ended: OpId,
    next_op: OpId,
    next_claim: u64,
}

/// The device name in the daemon's language (POSIX order: `LC_ALL`, then
/// `LC_MESSAGES`, then `LANG`); English unless that is French.
pub fn default_name() -> &'static str {
    name_for(|v| std::env::var(v).ok())
}

fn name_for(var: impl Fn(&str) -> Option<String>) -> &'static str {
    let lang = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|v| var(v).filter(|s| !s.is_empty()));
    match lang.as_deref() {
        Some(l) if l.starts_with("fr") => "le lecteur d'empreintes",
        _ => "the fingerprint reader",
    }
}

fn kind_busy(kind: ActionKind) -> &'static str {
    match kind {
        ActionKind::Verify => "Verification already in progress",
        ActionKind::Enroll => "Enrollment already in progress",
        ActionKind::Delete => "Delete already in progress",
    }
}

impl Default for Machine {
    fn default() -> Self {
        Self::new()
    }
}

impl Machine {
    pub fn new() -> Self {
        Machine {
            device: DeviceState::Opening,
            name: default_name().to_string(),
            prints: None,
            claim: None,
            finger_present: false,
            finger_needed: false,
            last_ended: 0,
            next_op: 1,
            next_claim: 1,
        }
    }

    fn new_op(&mut self) -> OpId {
        let op = self.next_op;
        self.next_op += 1;
        op
    }

    /// Fails unless the sensor can be used right now.
    pub fn require_ready(&self) -> Result<(), FprintError> {
        match self.device.availability() {
            Availability::Ready => Ok(()),
            Availability::Soon => Err(FprintError::Internal(format!(
                "fingerprint sensor not ready ({})",
                self.device.label()
            ))),
            Availability::Unavailable(why) => Err(FprintError::Internal(why)),
        }
    }

    pub fn check_unclaimed(&self) -> Result<(), FprintError> {
        match self.claim {
            Some(_) => Err(FprintError::AlreadyInUse(
                "Device was already claimed".into(),
            )),
            None => Ok(()),
        }
    }

    /// The claim, if `sender` holds it.
    pub fn claimant(&self, sender: &str) -> Result<&Claim, FprintError> {
        match &self.claim {
            None => Err(FprintError::ClaimDevice(
                "Device was not claimed before use".into(),
            )),
            Some(c) if c.sender != sender => Err(FprintError::AlreadyInUse(
                "Device already in use by another user".into(),
            )),
            Some(c) => Ok(c),
        }
    }

    fn claimant_mut(&mut self, sender: &str) -> Result<&mut Claim, FprintError> {
        self.claimant(sender)?;
        Ok(self.claim.as_mut().expect("checked above"))
    }

    fn can_start(action: Action) -> Result<(), FprintError> {
        match action {
            Action::None => Ok(()),
            Action::Running { kind, .. } | Action::Finished { kind, .. } => {
                Err(FprintError::AlreadyInUse(kind_busy(kind).into()))
            }
            Action::Stopping { .. } => Err(FprintError::AlreadyInUse(
                "Another operation is already in progress".into(),
            )),
        }
    }

    /// The fprintd-named fingers enrolled for `sid` (empty when none).
    pub fn fingers_of(&self, sid: &Sid) -> Result<Vec<u16>, FprintError> {
        let prints = self
            .prints
            .as_ref()
            .ok_or_else(|| FprintError::Internal("fingerprint database not available".into()))?;
        let mut f: Vec<u16> = prints
            .iter()
            .filter(|u| &u.sid == sid)
            .flat_map(|u| u.fingers.iter().copied())
            .filter(|s| finger_name(*s).is_some())
            .collect();
        crate::users::sort_fingers(&mut f);
        f.dedup();
        Ok(f)
    }

    /// ListEnrolledFingers: the names, or NoEnrolledPrints.
    pub fn list(&self, sid: &Sid) -> Result<Vec<String>, FprintError> {
        self.require_ready()?;
        let f = self.fingers_of(sid)?;
        if f.is_empty() {
            return Err(FprintError::NoEnrolledPrints(
                "Failed to discover prints".into(),
            ));
        }
        Ok(f.iter()
            .filter_map(|s| finger_name(*s))
            .map(str::to_string)
            .collect())
    }

    pub fn claim(&mut self, sender: &str, user: User, sid: Sid) -> Result<u64, FprintError> {
        self.check_unclaimed()?;
        self.require_ready()?;
        let id = self.next_claim;
        self.next_claim += 1;
        self.claim = Some(Claim {
            sender: sender.to_string(),
            user,
            sid,
            action: Action::None,
            id,
        });
        Ok(id)
    }

    pub fn start_verify(
        &mut self,
        sender: &str,
        finger_name_arg: &str,
    ) -> Result<VerifyStart, FprintError> {
        let c = self.claimant(sender)?;
        Self::can_start(c.action)?;
        let sid = c.sid.clone();
        self.require_ready()?;
        let fingers = self.fingers_of(&sid)?;
        // fprintd treats an unknown name like "any".
        let requested = finger_subtype(finger_name_arg);
        let finger = match requested {
            Some(f) if !fingers.contains(&f) => {
                return Err(FprintError::NoEnrolledPrints(format!(
                    "No such print {finger_name_arg}"
                )));
            }
            Some(f) => Some(f),
            None if fingers.is_empty() => {
                return Err(FprintError::NoEnrolledPrints(
                    "No fingerprints enrolled".into(),
                ));
            }
            // A single print: verify that finger, and say so.
            None if fingers.len() == 1 => Some(fingers[0]),
            None => None,
        };
        let selected = finger.and_then(finger_name).unwrap_or("any");
        let op = self.new_op();
        self.claimant_mut(sender)?.action = Action::Running {
            kind: ActionKind::Verify,
            op,
        };
        Ok(VerifyStart {
            op,
            sid,
            finger,
            selected,
        })
    }

    pub fn start_enroll(
        &mut self,
        sender: &str,
        finger_name_arg: &str,
    ) -> Result<EnrollStart, FprintError> {
        let c = self.claimant(sender)?;
        let finger = finger_subtype(finger_name_arg)
            .ok_or_else(|| FprintError::InvalidFingername("Invalid finger name".into()))?;
        Self::can_start(c.action)?;
        let sid = c.sid.clone();
        self.require_ready()?;
        let replace = self.fingers_of(&sid)?.contains(&finger);
        let op = self.new_op();
        self.claimant_mut(sender)?.action = Action::Running {
            kind: ActionKind::Enroll,
            op,
        };
        Ok(EnrollStart {
            op,
            sid,
            finger,
            replace,
        })
    }

    /// VerifyStop / EnrollStop.
    pub fn stop(&mut self, sender: &str, kind: ActionKind) -> Result<Stop, FprintError> {
        let c = self.claimant_mut(sender)?;
        match c.action {
            Action::Finished { kind: k, .. } if k == kind => {
                c.action = Action::None;
                Ok(Stop::Done)
            }
            Action::Running { kind: k, op } if k == kind => {
                c.action = Action::Stopping { kind, op };
                Ok(Stop::Cancel(op))
            }
            Action::None => Err(FprintError::NoActionInProgress(
                match kind {
                    ActionKind::Verify => "No verification in progress",
                    ActionKind::Enroll => "No enrollment in progress",
                    ActionKind::Delete => "No action in progress",
                }
                .into(),
            )),
            _ => Err(FprintError::AlreadyInUse(
                "Another operation is already in progress".into(),
            )),
        }
    }

    /// Whether `op` is still being stopped (the sensor thread has not let go).
    pub fn stopping(&self, op: OpId) -> bool {
        matches!(
            self.claim.as_ref().map(|c| c.action),
            Some(Action::Stopping { op: o, .. }) if o == op
        )
    }

    /// DeleteEnrolledFingers2 (`None`) and DeleteEnrolledFinger (`Some`): claims
    /// the action and returns the user and the delete's id.
    pub fn start_delete(
        &mut self,
        sender: &str,
        finger: Option<u16>,
    ) -> Result<(Sid, OpId), FprintError> {
        let c = self.claimant(sender)?;
        Self::can_start(c.action)?;
        let sid = c.sid.clone();
        self.check_has_prints(&sid, finger)?;
        let op = self.new_op();
        self.claimant_mut(sender)?.action = Action::Running {
            kind: ActionKind::Delete,
            op,
        };
        Ok((sid, op))
    }

    /// The legacy DeleteEnrolledFingers: allowed unclaimed, or by the claimant
    /// when idle.
    pub fn check_legacy_delete(&self, sender: &str, sid: &Sid) -> Result<(), FprintError> {
        if self.claim.is_some() {
            Self::can_start(self.claimant(sender)?.action)?;
        }
        self.check_has_prints(sid, None)
    }

    fn check_has_prints(&self, sid: &Sid, finger: Option<u16>) -> Result<(), FprintError> {
        self.require_ready()?;
        let f = self.fingers_of(sid)?;
        match finger {
            Some(x) if !f.contains(&x) => Err(FprintError::NoEnrolledPrints(format!(
                "Fingerprint for finger {} is not enrolled",
                finger_name(x).unwrap_or("?")
            ))),
            None if f.is_empty() => Err(FprintError::NoEnrolledPrints(
                "No fingerprint enrolled".into(),
            )),
            _ => Ok(()),
        }
    }

    pub fn finish_delete(&mut self, op: OpId) {
        if let Some(c) = &mut self.claim
            && c.action
                == (Action::Running {
                    kind: ActionKind::Delete,
                    op,
                })
        {
            c.action = Action::None;
        }
    }

    /// The run to cancel when the claim goes away.
    fn running_op(c: &Claim) -> Option<OpId> {
        match c.action {
            Action::Running { op, kind } if kind != ActionKind::Delete => Some(op),
            Action::Stopping { op, .. } => Some(op),
            _ => None,
        }
    }

    /// Release: returns the run to cancel, if any.
    pub fn release(&mut self, sender: &str) -> Result<Option<OpId>, FprintError> {
        let c = self.claimant(sender)?;
        let op = Self::running_op(c);
        self.claim = None;
        Ok(op)
    }

    /// A connection left the bus: `Some(run to cancel)` if it held the claim.
    pub fn vanished(&mut self, name: &str) -> Option<Option<OpId>> {
        match &self.claim {
            Some(c) if c.sender == name => {
                let op = Self::running_op(c);
                self.claim = None;
                Some(op)
            }
            _ => None,
        }
    }

    /// Applies an event of the sensor thread; returns the signals to send.
    pub fn on_event(&mut self, ev: Event) -> Vec<Emit> {
        let mut out = Vec::new();
        match ev {
            Event::Device { state, name } => {
                if state != DeviceState::Ready {
                    self.prints = None;
                }
                if let Some(n) = name
                    && n != self.name
                {
                    self.name = n;
                    out.push(Emit::Name);
                }
                self.device = state;
            }
            Event::Prints(p) => self.prints = Some(p),
            Event::Status {
                op,
                kind,
                result,
                done,
            } => {
                if let Some(c) = &mut self.claim
                    && c.action == (Action::Running { kind, op })
                {
                    let dest = c.sender.clone();
                    if done {
                        c.action = Action::Finished { kind, op };
                    }
                    out.push(match kind {
                        ActionKind::Enroll => Emit::EnrollStatus { dest, result, done },
                        _ => Emit::VerifyStatus { dest, result, done },
                    });
                }
            }
            Event::OpEnded { op } => {
                self.last_ended = self.last_ended.max(op);
                if let Some(c) = &mut self.claim {
                    match c.action {
                        Action::Running { kind, op: o } if o == op => {
                            c.action = Action::Finished { kind, op }
                        }
                        Action::Stopping { op: o, .. } if o == op => c.action = Action::None,
                        _ => {}
                    }
                }
            }
            Event::Finger { present, needed } => {
                if present != self.finger_present {
                    self.finger_present = present;
                    out.push(Emit::FingerPresent(present));
                }
                if needed != self.finger_needed {
                    self.finger_needed = needed;
                    out.push(Emit::FingerNeeded(needed));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::sid_for_uid;

    #[test]
    fn the_name_is_a_plain_phrase_in_the_daemons_language() {
        fn env(vars: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
            move |v| {
                vars.iter()
                    .find(|(k, _)| *k == v)
                    .map(|(_, x)| x.to_string())
            }
        }
        let fr = "le lecteur d'empreintes";
        let en = "the fingerprint reader";
        assert_eq!(name_for(env(&[("LANG", "fr_FR.UTF-8")])), fr);
        assert_eq!(name_for(env(&[("LANG", "fr_BE.UTF-8")])), fr);
        assert_eq!(name_for(env(&[("LANG", "en_US.UTF-8")])), en);
        assert_eq!(name_for(env(&[("LANG", "C")])), en);
        assert_eq!(name_for(env(&[])), en);
        // POSIX order, and an empty variable does not count.
        assert_eq!(
            name_for(env(&[("LC_ALL", "en_US.UTF-8"), ("LANG", "fr_FR.UTF-8")])),
            en
        );
        assert_eq!(
            name_for(env(&[("LC_ALL", ""), ("LC_MESSAGES", "fr_FR.UTF-8")])),
            fr
        );
    }

    fn alice() -> (User, Sid) {
        (
            User {
                name: "alice".into(),
                uid: 1000,
            },
            sid_for_uid(1000),
        )
    }

    fn ready(prints: Vec<(u32, Vec<u16>)>) -> Machine {
        let mut m = Machine::new();
        m.on_event(Event::Device {
            state: DeviceState::Ready,
            name: Some("test sensor".into()),
        });
        m.on_event(Event::Prints(
            prints
                .into_iter()
                .map(|(uid, fingers)| UserPrints {
                    sid: sid_for_uid(uid),
                    fingers,
                })
                .collect(),
        ));
        m
    }

    fn err_name<T: std::fmt::Debug>(r: Result<T, FprintError>) -> &'static str {
        r.expect_err("an error").name()
    }

    #[test]
    fn availability_fails_fast_except_while_opening() {
        let mut m = Machine::new();
        assert_eq!(m.device.availability(), Availability::Soon);
        assert_eq!(
            err_name(m.claim(":1.1", alice().0, alice().1)),
            "net.reactivated.Fprint.Error.Internal"
        );
        for (s, a) in [
            (DeviceState::Absent, false),
            (DeviceState::NeedsSetup("not paired".into()), false),
            (DeviceState::Failed("timeout".into()), false),
            (DeviceState::Suspended, true),
            (DeviceState::Opening, true),
        ] {
            m.on_event(Event::Device {
                state: s.clone(),
                name: None,
            });
            assert_eq!(
                matches!(m.device.availability(), Availability::Soon),
                a,
                "{s:?}"
            );
            assert!(m.claim(":1.1", alice().0, alice().1).is_err());
            assert!(m.list(&alice().1).is_err());
        }
        assert!(matches!(
            DeviceState::NeedsSetup("x".into()).availability(),
            Availability::Unavailable(m) if m.contains("needs setup: x")
        ));
    }

    #[test]
    fn claim_rules() {
        let mut m = ready(vec![(1000, vec![7])]);
        let (u, s) = alice();
        assert_eq!(
            err_name(m.claimant(":1.1")),
            "net.reactivated.Fprint.Error.ClaimDevice"
        );
        m.claim(":1.1", u.clone(), s.clone()).unwrap();
        assert_eq!(
            err_name(m.claim(":1.2", u.clone(), s.clone())),
            "net.reactivated.Fprint.Error.AlreadyInUse"
        );
        assert_eq!(
            err_name(m.claim(":1.1", u.clone(), s.clone())),
            "net.reactivated.Fprint.Error.AlreadyInUse"
        );
        assert_eq!(
            err_name(m.start_verify(":1.2", "any")),
            "net.reactivated.Fprint.Error.AlreadyInUse"
        );
        assert_eq!(
            err_name(m.release(":1.2")),
            "net.reactivated.Fprint.Error.AlreadyInUse"
        );
        assert_eq!(m.release(":1.1").unwrap(), None);
        assert_eq!(
            err_name(m.release(":1.1")),
            "net.reactivated.Fprint.Error.ClaimDevice"
        );
        // A new claim gets a new id.
        let a = m.claim(":1.1", u.clone(), s.clone()).unwrap();
        m.release(":1.1").unwrap();
        let b = m.claim(":1.1", u, s).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn list_and_finger_selection() {
        let mut m = ready(vec![(1000, vec![2, 7, 0xf5]), (1001, vec![1])]);
        let (u, s) = alice();
        assert_eq!(
            m.list(&s).unwrap(),
            ["left-index-finger", "right-index-finger"]
        );
        assert_eq!(
            err_name(m.list(&sid_for_uid(4242))),
            "net.reactivated.Fprint.Error.NoEnrolledPrints"
        );
        m.claim(":1.1", u, s.clone()).unwrap();
        // Two prints: any of them.
        let v = m.start_verify(":1.1", "any").unwrap();
        assert_eq!((v.finger, v.selected, &v.sid), (None, "any", &s));
        // A final status, then Stop.
        m.on_event(Event::Status {
            op: v.op,
            kind: ActionKind::Verify,
            result: "verify-no-match",
            done: true,
        });
        assert_eq!(
            err_name(m.start_verify(":1.1", "any")),
            "net.reactivated.Fprint.Error.AlreadyInUse"
        );
        assert_eq!(m.stop(":1.1", ActionKind::Verify).unwrap(), Stop::Done);
        // A named finger that is enrolled.
        let v = m.start_verify(":1.1", "right-index-finger").unwrap();
        assert_eq!((v.finger, v.selected), (Some(2), "right-index-finger"));
        assert_eq!(
            m.stop(":1.1", ActionKind::Verify).unwrap(),
            Stop::Cancel(v.op)
        );
        assert!(m.stopping(v.op));
        m.on_event(Event::OpEnded { op: v.op });
        assert!(!m.stopping(v.op));
        // Not enrolled.
        assert_eq!(
            err_name(m.start_verify(":1.1", "right-thumb")),
            "net.reactivated.Fprint.Error.NoEnrolledPrints"
        );
        // An unknown name means "any", as in fprintd.
        let v = m.start_verify(":1.1", "nonsense").unwrap();
        assert_eq!(v.finger, None);
    }

    #[test]
    fn single_print_is_selected() {
        let mut m = ready(vec![(1000, vec![7])]);
        m.claim(":1.1", alice().0, alice().1).unwrap();
        let v = m.start_verify(":1.1", "any").unwrap();
        assert_eq!((v.finger, v.selected), (Some(7), "left-index-finger"));
    }

    #[test]
    fn verify_without_prints() {
        let mut m = ready(vec![(1001, vec![7])]);
        m.claim(":1.1", alice().0, alice().1).unwrap();
        assert_eq!(
            err_name(m.start_verify(":1.1", "any")),
            "net.reactivated.Fprint.Error.NoEnrolledPrints"
        );
        // Device gone after the claim: fail fast.
        m.on_event(Event::Device {
            state: DeviceState::Absent,
            name: None,
        });
        assert_eq!(m.prints, None);
        assert_eq!(
            err_name(m.start_verify(":1.1", "any")),
            "net.reactivated.Fprint.Error.Internal"
        );
    }

    #[test]
    fn statuses_reach_only_the_current_run() {
        let mut m = ready(vec![(1000, vec![7, 8])]);
        m.claim(":1.1", alice().0, alice().1).unwrap();
        let v = m.start_verify(":1.1", "any").unwrap();
        // A retry status: not done.
        assert_eq!(
            m.on_event(Event::Status {
                op: v.op,
                kind: ActionKind::Verify,
                result: "verify-retry-scan",
                done: false
            }),
            [Emit::VerifyStatus {
                dest: ":1.1".into(),
                result: "verify-retry-scan",
                done: false
            }]
        );
        // An earlier run's status is dropped.
        assert!(
            m.on_event(Event::Status {
                op: v.op - 1,
                kind: ActionKind::Verify,
                result: "verify-match",
                done: true
            })
            .is_empty()
        );
        // Stop requested: whatever the sensor says next is not reported.
        assert_eq!(
            m.stop(":1.1", ActionKind::Verify).unwrap(),
            Stop::Cancel(v.op)
        );
        assert!(
            m.on_event(Event::Status {
                op: v.op,
                kind: ActionKind::Verify,
                result: "verify-match",
                done: true
            })
            .is_empty()
        );
        assert_eq!(
            err_name(m.stop(":1.1", ActionKind::Verify)),
            "net.reactivated.Fprint.Error.AlreadyInUse"
        );
        m.on_event(Event::OpEnded { op: v.op });
        assert_eq!(
            err_name(m.stop(":1.1", ActionKind::Verify)),
            "net.reactivated.Fprint.Error.NoActionInProgress"
        );
        // Released: statuses of the next claimant's runs only.
        let v2 = m.start_verify(":1.1", "any").unwrap();
        assert_eq!(m.release(":1.1").unwrap(), Some(v2.op));
        assert!(
            m.on_event(Event::Status {
                op: v2.op,
                kind: ActionKind::Verify,
                result: "verify-match",
                done: true
            })
            .is_empty()
        );
    }

    #[test]
    fn run_ended_without_status_still_needs_stop() {
        let mut m = ready(vec![(1000, vec![7])]);
        m.claim(":1.1", alice().0, alice().1).unwrap();
        let v = m.start_verify(":1.1", "any").unwrap();
        m.on_event(Event::OpEnded { op: v.op });
        assert_eq!(
            err_name(m.start_verify(":1.1", "any")),
            "net.reactivated.Fprint.Error.AlreadyInUse"
        );
        assert_eq!(m.stop(":1.1", ActionKind::Verify).unwrap(), Stop::Done);
        m.start_verify(":1.1", "any").unwrap();
    }

    #[test]
    fn enroll_rules() {
        let mut m = ready(vec![(1000, vec![7])]);
        m.claim(":1.1", alice().0, alice().1).unwrap();
        assert_eq!(
            err_name(m.start_enroll(":1.1", "any")),
            "net.reactivated.Fprint.Error.InvalidFingername"
        );
        assert_eq!(
            err_name(m.start_enroll(":1.1", "WINBIO_FINGER_UNSPECIFIED_POS_01")),
            "net.reactivated.Fprint.Error.InvalidFingername"
        );
        let e = m.start_enroll(":1.1", "left-index-finger").unwrap();
        assert_eq!((e.finger, e.replace), (7, true));
        assert_eq!(
            err_name(m.start_verify(":1.1", "any")),
            "net.reactivated.Fprint.Error.AlreadyInUse"
        );
        assert_eq!(
            err_name(m.stop(":1.1", ActionKind::Verify)),
            "net.reactivated.Fprint.Error.AlreadyInUse"
        );
        assert_eq!(
            m.on_event(Event::Status {
                op: e.op,
                kind: ActionKind::Enroll,
                result: "enroll-completed",
                done: true
            }),
            [Emit::EnrollStatus {
                dest: ":1.1".into(),
                result: "enroll-completed",
                done: true
            }]
        );
        assert_eq!(m.stop(":1.1", ActionKind::Enroll).unwrap(), Stop::Done);
        let e = m.start_enroll(":1.1", "right-thumb").unwrap();
        assert_eq!((e.finger, e.replace), (1, false));
    }

    #[test]
    fn delete_rules() {
        let mut m = ready(vec![(1000, vec![7])]);
        let (u, s) = alice();
        // Legacy delete works unclaimed.
        m.check_legacy_delete(":1.9", &s).unwrap();
        assert_eq!(
            err_name(m.check_legacy_delete(":1.9", &sid_for_uid(1))),
            "net.reactivated.Fprint.Error.NoEnrolledPrints"
        );
        m.claim(":1.1", u, s.clone()).unwrap();
        assert_eq!(
            err_name(m.check_legacy_delete(":1.9", &s)),
            "net.reactivated.Fprint.Error.AlreadyInUse"
        );
        m.check_legacy_delete(":1.1", &s).unwrap();
        assert_eq!(
            err_name(m.start_delete(":1.1", Some(1))),
            "net.reactivated.Fprint.Error.NoEnrolledPrints"
        );
        let (sid, op) = m.start_delete(":1.1", Some(7)).unwrap();
        assert_eq!(sid, s);
        assert_eq!(
            err_name(m.start_delete(":1.1", None)),
            "net.reactivated.Fprint.Error.AlreadyInUse"
        );
        m.finish_delete(op);
        m.start_delete(":1.1", None).unwrap();
    }

    #[test]
    fn vanished_client_releases() {
        let mut m = ready(vec![(1000, vec![7, 8])]);
        m.claim(":1.1", alice().0, alice().1).unwrap();
        assert_eq!(m.vanished(":1.2"), None);
        let v = m.start_verify(":1.1", "any").unwrap();
        assert_eq!(m.vanished(":1.1"), Some(Some(v.op)));
        assert!(m.claim.is_none());
        m.claim(":1.3", alice().0, alice().1).unwrap();
        assert_eq!(m.vanished(":1.3"), Some(None));
    }

    fn busy_message<T: std::fmt::Debug>(r: Result<T, FprintError>) -> String {
        match r {
            Err(FprintError::AlreadyInUse(m)) => m,
            other => panic!("expected AlreadyInUse, got {other:?}"),
        }
    }

    #[test]
    fn state_labels() {
        for (s, l) in [
            (DeviceState::Opening, "opening"),
            (DeviceState::Ready, "ready"),
            (DeviceState::Absent, "absent"),
            (DeviceState::NeedsSetup("x".into()), "needs-setup"),
            (DeviceState::Failed("x".into()), "failed"),
            (DeviceState::Suspended, "suspended"),
        ] {
            assert_eq!(s.label(), l);
        }
    }

    #[test]
    fn busy_messages_name_the_running_action() {
        let mut m = ready(vec![(1000, vec![7, 8])]);
        m.claim(":1.1", alice().0, alice().1).unwrap();
        let v = m.start_verify(":1.1", "any").unwrap();
        assert_eq!(
            busy_message(m.start_enroll(":1.1", "right-thumb")),
            "Verification already in progress"
        );
        m.stop(":1.1", ActionKind::Verify).unwrap();
        assert_eq!(
            busy_message(m.start_verify(":1.1", "any")),
            "Another operation is already in progress"
        );
        m.on_event(Event::OpEnded { op: v.op });
        let e = m.start_enroll(":1.1", "right-thumb").unwrap();
        assert_eq!(
            busy_message(m.start_verify(":1.1", "any")),
            "Enrollment already in progress"
        );
        m.on_event(Event::OpEnded { op: e.op });
        m.stop(":1.1", ActionKind::Enroll).unwrap();
        let (_, d) = m.start_delete(":1.1", Some(7)).unwrap();
        assert_eq!(
            busy_message(m.start_verify(":1.1", "any")),
            "Delete already in progress"
        );
        m.finish_delete(d);
    }

    #[test]
    fn stop_must_match_the_finished_action() {
        let mut m = ready(vec![(1000, vec![7])]);
        m.claim(":1.1", alice().0, alice().1).unwrap();
        let v = m.start_verify(":1.1", "any").unwrap();
        m.on_event(Event::Status {
            op: v.op,
            kind: ActionKind::Verify,
            result: "verify-match",
            done: true,
        });
        // A finished verification is not ended by EnrollStop.
        assert_eq!(
            err_name(m.stop(":1.1", ActionKind::Enroll)),
            "net.reactivated.Fprint.Error.AlreadyInUse"
        );
        assert_eq!(m.stop(":1.1", ActionKind::Verify).unwrap(), Stop::Done);
    }

    #[test]
    fn release_cancels_verify_and_enroll_runs_but_not_deletes() {
        let mut m = ready(vec![(1000, vec![7])]);
        let (u, s) = alice();
        // A delete runs to its end: nothing to cancel.
        m.claim(":1.1", u.clone(), s.clone()).unwrap();
        m.start_delete(":1.1", Some(7)).unwrap();
        assert_eq!(m.release(":1.1").unwrap(), None);
        // A run being stopped is still cancelled by a release.
        m.claim(":1.1", u.clone(), s.clone()).unwrap();
        let e = m.start_enroll(":1.1", "right-thumb").unwrap();
        assert_eq!(
            m.stop(":1.1", ActionKind::Enroll).unwrap(),
            Stop::Cancel(e.op)
        );
        assert_eq!(m.release(":1.1").unwrap(), Some(e.op));
        // And by the client leaving the bus.
        m.claim(":1.1", u, s).unwrap();
        let e = m.start_enroll(":1.1", "right-thumb").unwrap();
        m.stop(":1.1", ActionKind::Enroll).unwrap();
        assert_eq!(m.vanished(":1.1"), Some(Some(e.op)));
    }

    #[test]
    fn only_the_current_run_ends() {
        let mut m = ready(vec![(1000, vec![7])]);
        m.claim(":1.1", alice().0, alice().1).unwrap();
        let v = m.start_verify(":1.1", "any").unwrap();
        // An earlier run ending leaves the current one running.
        m.on_event(Event::OpEnded { op: v.op - 1 });
        assert_eq!(
            m.stop(":1.1", ActionKind::Verify).unwrap(),
            Stop::Cancel(v.op)
        );
        // ... and being stopped.
        m.on_event(Event::OpEnded { op: v.op - 1 });
        assert!(m.stopping(v.op));
        assert_eq!(
            err_name(m.start_verify(":1.1", "any")),
            "net.reactivated.Fprint.Error.AlreadyInUse"
        );
        m.on_event(Event::OpEnded { op: v.op });
        assert!(!m.stopping(v.op));
        m.start_verify(":1.1", "any").unwrap();
    }

    #[test]
    fn finger_properties_change_once() {
        let mut m = Machine::new();
        assert_eq!(
            m.on_event(Event::Finger {
                present: false,
                needed: true
            }),
            [Emit::FingerNeeded(true)]
        );
        assert!(
            m.on_event(Event::Finger {
                present: false,
                needed: true
            })
            .is_empty()
        );
        assert_eq!(
            m.on_event(Event::Finger {
                present: true,
                needed: false
            }),
            [Emit::FingerPresent(true), Emit::FingerNeeded(false)]
        );
    }
}
