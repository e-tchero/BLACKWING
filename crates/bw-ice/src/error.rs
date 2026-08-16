//! Error types for the ICE layer.

use thiserror::Error;

/// Errors produced by the ICE manager.
#[derive(Debug, Error)]
pub enum IceError {
    /// A STUN/TURN server URL could not be parsed.
    #[error("invalid ICE server URL `{0}`: {1}")]
    InvalidUrl(String, String),

    /// The underlying [`webrtc_ice::Agent`] reported an error.
    #[error("ICE agent error: {0}")]
    Agent(String),

    /// A remote candidate string could not be parsed.
    #[error("invalid remote candidate `{0}`: {1}")]
    InvalidCandidate(String, String),

    /// Connectivity checks did not establish a connection.
    #[error("ICE connection failed: {0}")]
    ConnectFailed(String),

    /// [`crate::IceManager::gather_candidates`] was called more than once.
    #[error("ICE candidates have already been gathered")]
    AlreadyGathered,

    /// Remote credentials were not set before establishing a connection.
    #[error("remote ICE credentials have not been set")]
    MissingRemoteCredentials,

    /// A signaling channel closed unexpectedly.
    #[error("ICE signaling channel closed")]
    ChannelClosed,
}
