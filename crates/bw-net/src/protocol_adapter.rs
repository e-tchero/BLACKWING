//! Adapter bridging `bw-net::Transport` to `bw-protocol::Transport`.
//!
//! # Architecture
//!
//! `bw-net` owns sockets and raw byte I/O. `bw-protocol` owns frame decoding,
//! session state, encryption, and dispatch. This adapter lives in `bw-net`
//! (which depends on `bw-protocol`) and wraps any `bw-net::Transport` to
//! implement `bw-protocol::transport::Transport`.
//!
//! | bw-net::Transport            | bw-protocol::Transport               |
//! |------------------------------|---------------------------------------|
//! | `send(&[u8]) → NetError`     | `send(ProtocolFrame) → ProtocolError` |
//! | `receive() → (Vec, Addr)`    | `receive() → OwnedProtocolFrame`      |
//! | `disconnect() → NetError`    | `close() → ProtocolError`             |
//! | `local_addr() → SocketAddr`  | `state() → ConnectionState` (tracked) |

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use bw_protocol::codec::{decode_frame, encode_frame};
use bw_protocol::error::ProtocolError;
use bw_protocol::frame::{OwnedProtocolFrame, ProtocolFrame};
use bw_protocol::transport::{ConnectionState, Transport as ProtocolTransport};

use crate::transport::BoxFuture;

use crate::error::NetError;
use crate::transport::Transport as NetTransport;

/// Wraps a `bw-net::Transport` so it can be used where a
/// `bw-protocol::Transport` is expected.
///
/// The adapter performs on-the-fly frame encoding/decoding and tracks
/// connection state internally via an atomic.
///
/// # Example
///
/// ```ignore
/// use bw_net::protocol_adapter::ProtocolTransportAdapter;
/// use bw_net::transport::Transport as NetTransport;
/// use bw_protocol::transport::Transport as ProtocolTransport;
///
/// let udp = UdpTransport::bind(...).await?;
/// let adapter = ProtocolTransportAdapter::new(udp);
/// // adapter implements bw_protocol::transport::Transport
/// ```
pub struct ProtocolTransportAdapter {
    inner: Arc<dyn NetTransport>,
    state: AtomicU32,
}

impl ProtocolTransportAdapter {
    /// Wraps a `bw-net::Transport` behind an `Arc` and initialises state to
    /// [`Connected`](ConnectionState::Connected).
    pub fn new<T: NetTransport + 'static>(inner: T) -> Self {
        Self {
            inner: Arc::new(inner),
            state: AtomicU32::new(ConnectionState::Connected as u32),
        }
    }

    /// Wraps an already-`Arc`-wrapped `bw-net::Transport`.
    pub fn from_arc(inner: Arc<dyn NetTransport>) -> Self {
        Self {
            inner,
            state: AtomicU32::new(ConnectionState::Connected as u32),
        }
    }

    /// Returns a reference to the inner `bw-net::Transport`.
    pub fn inner(&self) -> &dyn NetTransport {
        &*self.inner
    }

    fn set_state(&self, s: ConnectionState) {
        self.state.store(s as u32, Ordering::Release);
    }
}

impl std::fmt::Debug for ProtocolTransportAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolTransportAdapter")
            .field("state", &self.state())
            .finish()
    }
}

// ─── Error mapping ──────────────────────────────────────────────────

/// Maps [`NetError`] to [`ProtocolError`] at the adapter boundary.
fn map_net_error(e: NetError) -> ProtocolError {
    match e {
        NetError::Io(_) => ProtocolError::InvalidHandshake,
        NetError::DatagramTooSmall => ProtocolError::BufferTooSmall,
        NetError::DatagramTooLarge { .. } => ProtocolError::InvalidPayloadLength,
        NetError::Protocol(p) => p,
        NetError::ConnectionClosed | NetError::Shutdown => ProtocolError::InvalidRoute,
    }
}

// ─── ProtocolTransport impl ─────────────────────────────────────────

impl ProtocolTransport for ProtocolTransportAdapter {
    fn send<'a>(&'a self, frame: ProtocolFrame<'a>) -> BoxFuture<'a, Result<(), ProtocolError>> {
        Box::pin(async move {
            if self.state.load(Ordering::Acquire) != ConnectionState::Connected as u32 {
                return Err(ProtocolError::InvalidRoute);
            }
            let bytes = encode_frame(&frame);
            self.inner.send(&bytes).await.map_err(map_net_error)
        })
    }

    fn receive(&self) -> BoxFuture<'_, Result<OwnedProtocolFrame, ProtocolError>> {
        Box::pin(async move {
            if self.state.load(Ordering::Acquire) != ConnectionState::Connected as u32 {
                return Err(ProtocolError::InvalidRoute);
            }
            let (bytes, _peer_addr) = self.inner.receive().await.map_err(map_net_error)?;
            let borrowed = decode_frame(&bytes)?;
            Ok(OwnedProtocolFrame {
                header: borrowed.header,
                payload: borrowed.payload.to_vec(),
            })
        })
    }

    fn state(&self) -> ConnectionState {
        match self.state.load(Ordering::Acquire) {
            0 => ConnectionState::Disconnected,
            1 => ConnectionState::Connecting,
            2 => ConnectionState::Connected,
            3 => ConnectionState::Disconnecting,
            _ => ConnectionState::Failed,
        }
    }

    fn close<'a>(&'a self) -> BoxFuture<'a, Result<(), ProtocolError>> {
        Box::pin(async move {
            self.set_state(ConnectionState::Disconnected);
            self.inner.disconnect().await.map_err(map_net_error)
        })
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::BoxFuture as NetBoxFuture;
    use bw_protocol::header::{PacketHeader, PROTOCOL_MAGIC};
    use bw_protocol::version::CURRENT_VERSION;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicBool;
    use tokio::sync::mpsc;

    /// A minimal `bw-net::Transport` implementation backed by mpsc channels
    /// so we can test the adapter without real UDP sockets.
    struct MockNetTransport {
        tx: mpsc::Sender<Vec<u8>>,
        rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
        disconnected: AtomicBool,
    }

    impl MockNetTransport {
        fn new_pair(cap: usize) -> (Arc<Self>, Arc<Self>) {
            let (tx1, rx1) = mpsc::channel(cap);
            let (tx2, rx2) = mpsc::channel(cap);

            let a = Arc::new(Self {
                tx: tx1,
                rx: tokio::sync::Mutex::new(rx2),
                disconnected: AtomicBool::new(false),
            });
            let b = Arc::new(Self {
                tx: tx2,
                rx: tokio::sync::Mutex::new(rx1),
                disconnected: AtomicBool::new(false),
            });
            (a, b)
        }
    }

    impl NetTransport for MockNetTransport {
        fn send<'a>(&'a self, bytes: &'a [u8]) -> NetBoxFuture<'a, Result<(), NetError>> {
            Box::pin(async move {
                if self.disconnected.load(Ordering::Acquire) {
                    return Err(NetError::ConnectionClosed);
                }
                self.tx
                    .send(bytes.to_vec())
                    .await
                    .map_err(|_| NetError::ConnectionClosed)
            })
        }

        fn receive(&self) -> NetBoxFuture<'_, Result<(Vec<u8>, SocketAddr), NetError>> {
            Box::pin(async move {
                if self.disconnected.load(Ordering::Acquire) {
                    return Err(NetError::ConnectionClosed);
                }
                let mut rx = self.rx.lock().await;
                let bytes = rx.recv().await.ok_or(NetError::ConnectionClosed)?;
                Ok((bytes, "127.0.0.1:0".parse().unwrap()))
            })
        }

        fn disconnect(&self) -> NetBoxFuture<'_, Result<(), NetError>> {
            Box::pin(async move {
                self.disconnected.store(true, Ordering::Release);
                Ok(())
            })
        }

        fn local_addr(&self) -> Result<SocketAddr, NetError> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
    }

    /// Builds a minimal `ProtocolFrame` for testing.
    fn test_frame(payload: &[u8]) -> ProtocolFrame<'_> {
        let header = PacketHeader {
            magic: PROTOCOL_MAGIC,
            schema_version: u16::from(CURRENT_VERSION),
            flags: 0,
            packet_type: 0,
            payload_length: payload.len() as u16,
            sequence_number: 0,
            session_epoch: 0,
            monotonic_timestamp: 0,
        };
        ProtocolFrame { header, payload }
    }

    // ─── Happy path ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_roundtrip() {
        let (net_a, net_b) = MockNetTransport::new_pair(16);
        let proto_a = ProtocolTransportAdapter::from_arc(net_a);
        let proto_b = ProtocolTransportAdapter::from_arc(net_b);

        let payload = b"hello from adapter";
        let frame = test_frame(payload);

        // Send from A, receive on B
        proto_a.send(frame).await.unwrap();
        let received = proto_b.receive().await.unwrap();

        assert_eq!(received.payload, payload);
        assert_eq!(received.header.payload_length, payload.len() as u16);
    }

    #[tokio::test]
    async fn test_close_sets_state() {
        let (net_a, _net_b) = MockNetTransport::new_pair(16);
        let proto = ProtocolTransportAdapter::from_arc(net_a);

        assert_eq!(proto.state(), ConnectionState::Connected);

        proto.close().await.unwrap();
        assert_eq!(proto.state(), ConnectionState::Disconnected);

        // Send after close should fail
        let frame = test_frame(b"drop");
        let result = proto.send(frame).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_send_receive_multiple_frames() {
        let (net_a, net_b) = MockNetTransport::new_pair(16);
        let proto_a = ProtocolTransportAdapter::from_arc(net_a);
        let proto_b = ProtocolTransportAdapter::from_arc(net_b);

        for i in 0..5 {
            let payload = vec![i as u8; 64];
            let frame = test_frame(&payload);
            proto_a.send(frame).await.unwrap();
        }

        for i in 0..5 {
            let received = proto_b.receive().await.unwrap();
            let expected = vec![i as u8; 64];
            assert_eq!(received.payload, expected);
        }
    }

    #[tokio::test]
    async fn test_error_on_closed_transport() {
        let (net_a, _net_b) = MockNetTransport::new_pair(16);
        let proto = ProtocolTransportAdapter::from_arc(net_a);

        // Close the underlying net transport directly
        proto.inner.disconnect().await.unwrap();

        // The adapter doesn't know about the inner disconnect, but send/receive
        // should still fail because the inner transport returns ConnectionClosed.
        let frame = test_frame(b"fail");
        let result = proto.send(frame).await;
        assert!(result.is_err(), "send after inner disconnect should fail");

        let result = proto.receive().await;
        assert!(
            result.is_err(),
            "receive after inner disconnect should fail"
        );
    }

    #[tokio::test]
    async fn test_from_arc() {
        let (net_a, _net_b) = MockNetTransport::new_pair(16);
        let arc: Arc<dyn NetTransport> = net_a;
        let proto = ProtocolTransportAdapter::from_arc(arc);

        assert_eq!(proto.state(), ConnectionState::Connected);
    }
}
