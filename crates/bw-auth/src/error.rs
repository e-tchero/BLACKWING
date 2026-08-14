//! Error types for the OPAQUE authentication flows.

use opaque_ke::errors::ProtocolError;
use thiserror::Error;

/// Errors that can occur during OPAQUE registration or login.
#[derive(Debug, Error)]
pub enum AuthError {
    /// The OPAQUE protocol reported an error.
    ///
    /// This includes `ProtocolError::InvalidLoginError`, which is returned
    /// when the client or server detects a wrong password during login.
    #[error("OPAQUE protocol error: {0:?}")]
    Protocol(#[from] ProtocolError),
    /// Failed to serialize or deserialize protocol state.
    #[error("OPAQUE state serialization failed")]
    Serialization,
}
