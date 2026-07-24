use thiserror::Error;

/// Unified, backend-independent error model for Blackwing Cryptographic Primitives.
#[non_exhaustive]
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    #[error("System entropy source is unavailable or returned failure")]
    EntropyUnavailable,

    #[error("Invalid cryptographic key format, length, or mathematical structure")]
    InvalidKey,

    #[error("Asymmetric signature verification failed")]
    VerificationFailed,

    #[error("Internal hardware security module (TPM) or library backend failure")]
    Backend,

    #[error("The requested cryptographic operation is unsupported on this platform")]
    Unsupported,

    #[error("Invalid protocol, parsing, or operational state transition")]
    InvalidState,

    #[error("A critical resource (such as key slots or TPM sessions) is exhausted")]
    ResourceExhausted,
}

/// Standarized Result alias using our backend-agnostic error mapping.
pub type Result<T> = std::result::Result<T, CryptoError>;
