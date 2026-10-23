//! Scripted sensor for unit tests: every command must match the script exactly.

use std::collections::VecDeque;

use crate::cmd::Error;
use crate::hex;
use crate::session::Sensor;
use crate::vendor::Blobs;

pub enum Step {
    Cmd(Vec<u8>, Vec<u8>),
    Int(Vec<u8>),
    Bulk(Vec<u8>),
    /// `open_channel`, with the TLS flash image it must receive (if checked).
    Open(Option<Vec<u8>>),
}

pub struct Script {
    steps: VecDeque<Step>,
    open: bool,
    pub opened_with: Option<Vec<u8>>,
}

impl Script {
    pub fn new(cmds: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        Self::steps(cmds.into_iter().map(|(t, r)| Step::Cmd(t, r)).collect())
    }

    pub fn steps(steps: Vec<Step>) -> Self {
        Script {
            steps: steps.into(),
            open: false,
            opened_with: None,
        }
    }

    pub fn opened(mut self) -> Self {
        self.open = true;
        self
    }

    pub fn done(&self) {
        assert!(self.steps.is_empty(), "{} steps left", self.steps.len());
    }
}

impl Sensor for Script {
    fn cmd(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        match self.steps.pop_front() {
            Some(Step::Cmd(tx, rx)) => {
                assert_eq!(hex::encode(payload), hex::encode(&tx), "command mismatch");
                Ok(rx)
            }
            _ => panic!("unexpected command {}", hex::encode(payload)),
        }
    }

    fn is_open(&self) -> bool {
        self.open
    }

    fn open_channel(&mut self, tls_flash: &[u8]) -> Result<(), Error> {
        match self.steps.pop_front() {
            Some(Step::Open(want)) => {
                if let Some(w) = want {
                    assert_eq!(hex::encode(tls_flash), hex::encode(&w));
                }
                self.opened_with = Some(tls_flash.to_vec());
                self.open = true;
                Ok(())
            }
            _ => panic!("unexpected open_channel"),
        }
    }

    fn wait_int(&mut self) -> Result<Vec<u8>, Error> {
        match self.steps.pop_front() {
            Some(Step::Int(b)) => Ok(b),
            _ => panic!("unexpected wait_int"),
        }
    }

    fn read_82(&mut self) -> Result<Vec<u8>, Error> {
        match self.steps.pop_front() {
            Some(Step::Bulk(b)) => Ok(b),
            _ => panic!("unexpected read_82"),
        }
    }
}

/// Synthetic stand-ins for the vendor blobs.
pub fn blobs() -> Blobs {
    Blobs {
        init_hardcoded: vec![6, 1, 1],
        init_hardcoded_clean_slate: vec![6, 2, 2],
        reset_blob: vec![6, 3, 3],
        db_write_enable: vec![6, 4, 4],
        partition_signature: vec![0x5a; 256],
    }
}
