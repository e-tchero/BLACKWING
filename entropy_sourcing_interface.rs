use crate::error::{CryptoError, Result};

/// A thread-safe, cryptographically secure random number generator interface.
pub trait SecureRandom: Send + Sync {
    /// Fills the provided destination buffer with raw, cryptographically secure random bytes.
    fn fill(&mut self, bytes: &mut [u8]) -> Result<()>;
}

/// Production implementation of SecureRandom backed entirely by the OS entropy source.
pub struct OsRandom;

impl SecureRandom for OsRandom {
    #[inline]
    fn fill(&mut self, bytes: &mut [u8]) -> Result<()> {
        getrandom::getrandom(bytes).map_err(|_| CryptoError::EntropyUnavailable)
    }
}