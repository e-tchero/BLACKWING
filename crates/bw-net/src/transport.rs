//! Transport abstraction layer.
//!
//! Defines [`Transport`], the single async interface that all network backends
//! (UDP, TCP, QUIC, relay) must implement. `bw-protocol` receives only this
//! trait object — it never observes the concrete socket type.
//!
//! ## Design Contract
//!
//! - `send` and `receive` operate on raw byte frames, not parsed protocol types.
//! - `disconnect` is always non-blocking and idempotent.
//! - Implementors must be `Send + Sync` to cross Tokio task boundaries.

use crate::error::NetError;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

/// A type alias for a boxed, pinned, `Send`-safe async future.
///
/// Used as the return type for all `Transport` methods to allow them to be
/// object-safe while remaining fully async.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The core network abstraction for `bw-net`.
///
/// Each concrete transport (UDP, TCP, QUIC) implements this trait. The
/// protocol layer accepts `Arc<dyn Transport>` and never depends on the
/// underlying socket type.
pub trait Transport: Send + Sync {
    /// Sends raw frame bytes to the remote peer.
    ///
    /// The caller is responsible for providing a fully serialized frame
    /// (header + payload). The transport does not inspect the contents.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Io`] on OS-level socket failures.
    /// Returns [`NetError::ConnectionClosed`] if the peer has disconnected.
    fn send<'a>(&'a self, frame_bytes: &'a [u8]) -> BoxFuture<'a, Result<(), NetError>>;

    /// Receives the next available datagram from the remote peer.
    ///
    /// Blocks asynchronously until data arrives or an error occurs.
    ///
    /// # Returns
    ///
    /// A tuple of `(bytes, peer_addr)` on success.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Io`] on OS-level socket failures.
    /// Returns [`NetError::DatagramTooSmall`] if the datagram is malformed.
    /// Returns [`NetError::Shutdown`] if the transport was cleanly stopped.
    fn receive(&self) -> BoxFuture<'_, Result<(Vec<u8>, SocketAddr), NetError>>;

    /// Gracefully terminates the transport connection.
    ///
    /// After this completes, subsequent `send` or `receive` calls will return
    /// [`NetError::ConnectionClosed`]. This method is idempotent.
    fn disconnect(&self) -> BoxFuture<'_, Result<(), NetError>>;

    /// Returns the local address the transport is bound to.
    fn local_addr(&self) -> Result<SocketAddr, NetError>;
}
