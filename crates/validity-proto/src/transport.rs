//! What the protocol layers need from the outside world: a command pipe to the
//! sensor and a source of randomness. Both are traits so that sessions can be
//! replayed byte-exact in tests.

/// One command/response exchange with the sensor (bulk OUT, then bulk IN).
pub trait Transport {
    fn cmd(&mut self, out: &[u8]) -> Result<Vec<u8>, TransportError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Timeout,
    Disconnected,
    Other(String),
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransportError::Timeout => f.write_str("USB timeout"),
            TransportError::Disconnected => f.write_str("sensor disconnected"),
            TransportError::Other(s) => write!(f, "USB error: {s}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Source of randomness for client randoms, ephemeral keys and CBC IVs.
pub trait Entropy {
    fn fill(&mut self, buf: &mut [u8]);
}

/// The operating system's CSPRNG.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("the OS random source is available");
    }
}
