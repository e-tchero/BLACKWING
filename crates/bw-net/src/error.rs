//! Error types for the `bw-net` crate.
//!
//! `NetError` is the single error type propagated from `bw-net` to callers.
//! Protocol errors crossing the `bw-net` → `bw-protocol` boundary are wrapped
//! in [`NetError::Protocol`] so the transport layer remains decoupled from
//! protocol semantics.

use thiserror::Error;

/// All errors that can originate within `bw-net`.
#[derive(Debug, Error)]
pub enum NetError {
    /// A raw OS-level I/O error (socket bind, send, recv, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The receive buffer contains fewer bytes than the minimum frame header.
    #[error("Datagram is too small to contain a valid frame header")]
    DatagramTooSmall,

    /// A datagram exceeded the maximum allowed size and was discarded.
    #[error("Datagram size {actual} exceeds maximum {max}")]
    DatagramTooLarge {
        /// Actual byte count received.
        actual: usize,
        /// Maximum permitted byte count.
        max: usize,
    },

    /// The underlying protocol layer rejected the decoded frame or envelope.
    ///
    /// This variant bridges `bw-protocol` errors to `bw-net` callers without
    /// introducing a circular dependency. `bw-net` wraps but does not
    /// interpret these errors.
    #[error("Protocol error: {0}")]
    Protocol(#[from] bw_protocol::error::ProtocolError),

    /// The transport connection was closed by the remote peer.
    #[error("Connection closed by remote peer")]
    ConnectionClosed,

    /// A shutdown signal was received; the receive loop was stopped cleanly.
    #[error("Transport shut down cleanly")]
    Shutdown,
}
