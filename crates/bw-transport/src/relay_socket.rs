//! RelayUdpSocket: a Quinn `AsyncUdpSocket` wrapper that prepends/strips a 32-byte
//! relay routing header when communicating via the relay data plane.
//!
//! # Protocol format
//!
//! When the destination is the relay address, every outgoing QUIC UDP packet is
//! wrapped as:
//!
//!   `[relay_token: 32 bytes][opaque QUIC payload: ≤ MAX_RELAY_PAYLOAD bytes]`
//!
//! The relay uses the first 32 bytes to look up the forwarding context and
//! forwards the remaining bytes verbatim to the remote endpoint.  On receipt
//! from the relay, the 32-byte prefix is stripped before the payload is handed
//! to Quinn.
//!
//! # MTU
//!
//! The maximum QUIC payload is limited to 1168 bytes (1200 - 32) to avoid
//! IP fragmentation across the relay hop.  The relay drops any packet whose
//! total size (header + payload) exceeds 1200 bytes.

use quinn::{AsyncUdpSocket, UdpPoller};
use quinn::udp::{RecvMeta, Transmit};
use std::{
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::net::UdpSocket;

/// Maximum allowed QUIC payload size when relaying (1200 - 32-byte header).
pub const MAX_RELAY_PAYLOAD: usize = 1168;
/// Total maximum wire size: relay header + QUIC payload.
pub const MAX_RELAY_PACKET: usize = 1200;
/// Size of the relay routing header.
pub const RELAY_HEADER_LEN: usize = 32;

/// A Quinn `AsyncUdpSocket` implementation that transparently injects and strips
/// a 32-byte relay routing token on the data plane.
///
/// When the peer address equals `relay_addr`, outgoing QUIC packets are
/// prefixed with `relay_token` and packets received from `relay_addr` have
/// the first 32 bytes stripped before being passed to Quinn.
///
/// All other traffic (direct peers) bypasses the relay header entirely.
pub struct RelayUdpSocket {
    inner: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    relay_token: [u8; RELAY_HEADER_LEN],
}

impl fmt::Debug for RelayUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayUdpSocket")
            .field("relay_addr", &self.relay_addr)
            .finish()
    }
}

impl RelayUdpSocket {
    /// Wraps an existing async UDP socket for relay-routed communication.
    ///
    /// `relay_addr`  – the address of the relay data plane.
    /// `relay_token` – the 32-byte token assigned during `CandidateExchange`.
    pub fn new(
        inner: Arc<UdpSocket>,
        relay_addr: SocketAddr,
        relay_token: [u8; RELAY_HEADER_LEN],
    ) -> Arc<Self> {
        Arc::new(Self {
            inner,
            relay_addr,
            relay_token,
        })
    }

    /// Returns the relay routing token.
    pub fn relay_token(&self) -> &[u8; RELAY_HEADER_LEN] {
        &self.relay_token
    }
}

// ── UdpPoller implementation for RelayUdpSocket ──────────────────────────────

struct RelayPoller {
    socket: Arc<UdpSocket>,
}

impl fmt::Debug for RelayPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelayPoller")
    }
}

impl UdpPoller for RelayPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx).map_err(io::Error::from)
    }
}

// ── AsyncUdpSocket implementation ────────────────────────────────────────────

impl AsyncUdpSocket for RelayUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(RelayPoller {
            socket: self.inner.clone(),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let dest = transmit.destination;

        if dest == self.relay_addr {
            // Relay path: prepend the 32-byte token.
            let payload_len = transmit.contents.len();
            if payload_len > MAX_RELAY_PAYLOAD {
                // Packet too large; drop silently (consistent with relay policy).
                return Ok(());
            }
            let mut buf = Vec::with_capacity(RELAY_HEADER_LEN + payload_len);
            buf.extend_from_slice(&self.relay_token);
            buf.extend_from_slice(transmit.contents);

            // Blocking send on the async socket — permitted on Tokio because
            // try_send is called only when the socket is already write-ready.
            match self.inner.try_send_to(&buf, dest) {
                Ok(_) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    Err(io::Error::new(io::ErrorKind::WouldBlock, e))
                }
                Err(e) => Err(e),
            }
        } else {
            // Direct path: no relay header.
            match self.inner.try_send_to(transmit.contents, dest) {
                Ok(_) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    Err(io::Error::new(io::ErrorKind::WouldBlock, e))
                }
                Err(e) => Err(e),
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // We handle one datagram at a time (max_receive_segments = 1).
        let buf = match bufs.first_mut() {
            Some(b) => b,
            None => return Poll::Ready(Ok(0)),
        };

        // We need a temporary buffer large enough for a max relay packet
        // so we can inspect/strip the header before handing data to Quinn.
        let mut tmp = [0u8; MAX_RELAY_PACKET];
        let mut read_buf = tokio::io::ReadBuf::new(&mut tmp);

        // Use Tokio's ReadBuf-based poll_recv_from.
        match self.inner.poll_recv_from(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(addr)) => {
                let n = read_buf.filled().len();

                if addr == self.relay_addr {
                    // Relay path: strip the 32-byte header.
                    if n < RELAY_HEADER_LEN {
                        // Malformed: too short to contain the header — drop.
                        meta[0] = RecvMeta {
                            addr,
                            len: 0,
                            stride: 0,
                            ecn: None,
                            dst_ip: None,
                        };
                        return Poll::Ready(Ok(1));
                    }
                    let payload = &tmp[RELAY_HEADER_LEN..n];
                    let payload_len = payload.len();
                    // Copy stripped payload into Quinn's buffer.
                    buf[..payload_len].copy_from_slice(payload);
                    meta[0] = RecvMeta {
                        addr,
                        len: payload_len,
                        stride: payload_len,
                        ecn: None,
                        dst_ip: None,
                    };
                } else {
                    // Direct path: copy as-is.
                    buf[..n].copy_from_slice(&tmp[..n]);
                    meta[0] = RecvMeta {
                        addr,
                        len: n,
                        stride: n,
                        ecn: None,
                        dst_ip: None,
                    };
                }
                Poll::Ready(Ok(1))
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

