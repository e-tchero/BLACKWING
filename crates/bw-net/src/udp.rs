//! UDP transport implementation and receive loop.
//!
//! [`UdpTransport`] implements [`Transport`] over a Tokio `UdpSocket`.
//! [`run_receive_loop`] drives the vertical slice: it reads raw datagrams,
//! hands them to `bw-protocol`'s codec, and passes decoded frames to the
//! protocol dispatcher.
//!
//! ## Maximum Datagram Size
//!
//! A single UDP datagram payload is limited to 65,507 bytes (IPv4) or
//! 65,527 bytes (IPv6). We enforce a tighter application-level maximum of
//! 65,536 bytes, which comfortably covers the largest Blackwing frame while
//! staying within OS limits.

use crate::error::NetError;
use crate::transport::{BoxFuture, Transport};
use bw_protocol::codec::decode_frame;
use bw_protocol::dispatcher::MessageDispatcher;
use bw_protocol::routing::MessageEnvelope;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, error, warn};

/// Maximum byte size accepted for a single incoming datagram.
///
/// Datagrams exceeding this limit are discarded and a warning is emitted.
/// This prevents oversized packets from triggering heap allocations above
/// our expected working set.
pub const MAX_DATAGRAM_SIZE: usize = 65_536;

/// A UDP-backed implementation of the [`Transport`] trait.
///
/// Wraps a Tokio `UdpSocket` behind an `Arc` so it can be shared between
/// the sender and receiver tasks without cloning the socket itself.
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
}

impl UdpTransport {
    /// Binds a new UDP socket to the given local address and wraps it.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Io`] if the OS rejects the bind request (e.g.
    /// address already in use, insufficient permissions).
    pub async fn bind(addr: SocketAddr) -> Result<Self, NetError> {
        let socket = UdpSocket::bind(addr).await?;
        debug!(local_addr = %addr, "UDP socket bound");
        Ok(Self {
            socket: Arc::new(socket),
        })
    }

    /// Binds a UDP socket locally and connects it to a specific remote peer.
    ///
    /// Connecting the socket allows the use of `Transport::send` (which uses
    /// `try_send` under the hood) without specifying a destination address
    /// per packet.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Io`] if binding or connecting fails.
    pub async fn connect(local_addr: SocketAddr, peer_addr: SocketAddr) -> Result<Self, NetError> {
        let socket = UdpSocket::bind(local_addr).await?;
        socket.connect(peer_addr).await?;
        debug!(local_addr = %local_addr, peer = %peer_addr, "UDP socket bound and connected");
        Ok(Self {
            socket: Arc::new(socket),
        })
    }

    /// Returns a cloned `Arc` reference to the underlying socket.
    ///
    /// Intended for use when a second task needs shared access to the same
    /// socket (e.g. a dedicated sender task).
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }
}

impl Transport for UdpTransport {
    fn send<'a>(&'a self, frame_bytes: &'a [u8]) -> BoxFuture<'a, Result<(), NetError>> {
        Box::pin(async move {
            self.socket.send(frame_bytes).await?;
            Ok(())
        })
    }

    fn receive(&self) -> BoxFuture<'_, Result<(Vec<u8>, SocketAddr), NetError>> {
        Box::pin(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
            let (len, peer_addr) = self.socket.recv_from(&mut buf).await?;
            if len == 0 {
                return Err(NetError::DatagramTooSmall);
            }
            buf.truncate(len);
            debug!(bytes = len, peer = %peer_addr, "Datagram received");
            Ok((buf, peer_addr))
        })
    }

    fn disconnect(&self) -> BoxFuture<'_, Result<(), NetError>> {
        // UDP is connectionless; "disconnecting" is a no-op at the socket
        // level. Callers use the shutdown channel in `run_receive_loop` to
        // stop the receive loop cleanly.
        Box::pin(async move { Ok(()) })
    }

    fn local_addr(&self) -> Result<SocketAddr, NetError> {
        self.socket.local_addr().map_err(NetError::Io)
    }
}

/// Drives the network → protocol vertical slice.
///
/// This is the core receive loop. It:
/// 1. Reads a raw datagram from the `transport`.
/// 2. Passes the bytes to `bw-protocol`'s `decode_frame` codec.
/// 3. Deserializes the payload into a [`MessageEnvelope`].
/// 4. Calls [`MessageDispatcher::dispatch`] to hand the envelope to the
///    protocol layer for validation (and, once WP-4.11 is complete, routing).
///
/// The loop runs until the `shutdown` receiver observes a `true` signal, at
/// which point it exits cleanly with [`NetError::Shutdown`].
///
/// # Architecture Note
///
/// `bw-net` passes raw bytes into `bw-protocol`. It does not interpret the
/// frame contents. All state associated with the session (encryption context,
/// sequence numbers, routing) lives inside `bw-protocol` and is not visible
/// here. This enforces the ownership boundary mandated by the Phase 0
/// Architecture Freeze (Sections 1 and 5).
///
/// # Errors
///
/// - [`NetError::Io`]: OS-level socket failure. The loop exits immediately.
/// - [`NetError::DatagramTooLarge`]: Oversized datagram discarded; loop continues.
/// - [`NetError::Protocol`]: Codec or dispatcher error. The bad frame is
///   discarded and a warning is emitted; the loop continues.
/// - [`NetError::Shutdown`]: Clean exit on shutdown signal.
pub async fn run_receive_loop(
    transport: Arc<dyn Transport>,
    dispatcher: Arc<MessageDispatcher>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), NetError> {
    loop {
        tokio::select! {
            // Biased poll: check shutdown first so a pending datagram cannot
            // starve a shutdown signal under sustained traffic.
            biased;

            // Shutdown path — exits cleanly without error logging.
            result = shutdown.changed() => {
                if result.is_ok() && *shutdown.borrow() {
                    debug!("Receive loop received shutdown signal; exiting cleanly");
                    return Err(NetError::Shutdown);
                }
            }

            // Happy path — receive and process one datagram per iteration.
            recv_result = transport.receive() => {
                match recv_result {
                    Err(NetError::Io(e)) => {
                        error!(error = %e, "Fatal I/O error in receive loop");
                        return Err(NetError::Io(e));
                    }
                    Err(NetError::DatagramTooSmall) => {
                        warn!("Discarding empty datagram");
                        continue;
                    }
                    Err(other) => {
                        warn!(error = %other, "Non-fatal receive error; continuing");
                        continue;
                    }
                    Ok((bytes, peer_addr)) => {
                        if bytes.len() > MAX_DATAGRAM_SIZE {
                            warn!(
                                actual = bytes.len(),
                                max = MAX_DATAGRAM_SIZE,
                                peer = %peer_addr,
                                "Discarding oversized datagram"
                            );
                            continue;
                        }

                        // ── Boundary: bw-net → bw-protocol ──────────────────
                        // From this point forward, all logic lives in bw-protocol.
                        // bw-net does not interpret the bytes; it only forwards.

                        let frame = match decode_frame(&bytes) {
                            Ok(f) => f,
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    peer = %peer_addr,
                                    "Frame decode failed; discarding datagram"
                                );
                                continue;
                            }
                        };

                        let envelope = match MessageEnvelope::deserialize(frame.payload) {
                            Ok(env) => env,
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    peer = %peer_addr,
                                    "Envelope deserialization failed; discarding frame"
                                );
                                continue;
                            }
                        };

                        if let Err(e) = dispatcher.dispatch(envelope) {
                            warn!(
                                error = %e,
                                peer = %peer_addr,
                                "Dispatcher rejected envelope"
                            );
                        }
                    }
                }
            }
        }
    }
}
