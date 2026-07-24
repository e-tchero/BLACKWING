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

/// Fills a buffer with cryptographically secure random bytes from the OS entropy source.
///
/// This is a convenience wrapper around `OsRandom` that can be called without
/// instantiating an RNG. Useful for generating nonces, salts, and other
/// protocol-level random values.
///
/// # Errors
///
/// Returns [`CryptoError::EntropyUnavailable`] if the OS entropy source is
/// unavailable (extremely rare outside of early boot or sandboxed environments).
#[inline]
pub fn secure_random_bytes(buf: &mut [u8]) -> Result<()> {
    let mut rng = OsRandom;
    rng.fill(buf)
}
