//! IceUdpSocket: a Quinn `AsyncUdpSocket` adapter that routes QUIC datagrams
//! through an established ICE connection (`bw_ice::IceConnection`).
//!
//! The ICE connection (`webrtc-util`'s `Conn`) exposes an async
//! send/recv datagram API, while Quinn polls a synchronous
//! `AsyncUdpSocket`. A background task bridges the two: it drains an
//! unbounded outgoing queue into `Conn::send` and forwards received datagrams
//! into an internal queue that `poll_recv` drains. The destination address on
//! a `Transmit` is ignored — the ICE connection is already bound to the
//! negotiated candidate pair, so all datagrams travel over the P2P path.

use bw_ice::IceConnection;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::sync::mpsc;

/// The queue of datagrams received from the remote peer, awaiting Quinn.
type RecvQueue = Arc<Mutex<VecDeque<(SocketAddr, Vec<u8>)>>>;

/// A Quinn `AsyncUdpSocket` backed by an established ICE connection.
///
/// The socket reports the ICE connection's local address and routes every
/// datagram through the negotiated candidate pair, providing Quinn with a
/// direct P2P transport.
pub struct IceUdpSocket {
    local: SocketAddr,
    /// Datagrams received from the remote peer, queued for Quinn.
    recv_queue: RecvQueue,
    /// The task currently waiting in `poll_recv`, woken on new datagrams.
    recv_waker: Arc<Mutex<Option<Waker>>>,
    /// Outgoing datagrams from Quinn, drained by the background task.
    send_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl fmt::Debug for IceUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IceUdpSocket")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl IceUdpSocket {
    /// Wraps an established ICE connection, spawning the background bridge
    /// task that moves datagrams between Quinn and the ICE socket.
    pub fn new(ice: IceConnection) -> io::Result<Arc<Self>> {
        let conn = ice.inner();
        let local = conn
            .local_addr()
            .map_err(|e| io::Error::other(e.to_string()))?;
        // The ICE connection is bound to a single remote peer (the selected
        // candidate pair), so all received datagrams share that source.
        let remote = conn.remote_addr().unwrap_or(local);

        let (send_tx, mut send_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let recv_queue: RecvQueue = Arc::new(Mutex::new(VecDeque::new()));
        let recv_waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));

        let queue_clone = Arc::clone(&recv_queue);
        let waker_clone = Arc::clone(&recv_waker);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                tokio::select! {
                    maybe_data = send_rx.recv() => {
                        match maybe_data {
                            Some(data) => {
                                // The ICE connection is gone if this fails.
                                if conn.send(&data).await.is_err() {
                                    break;
                                }
                            }
                            // All senders dropped — shutdown.
                            None => break,
                        }
                    }
                    result = conn.recv(&mut buf) => {
                        match result {
                            Ok(n) if n > 0 => {
                                let mut queue = lock_poisoned(&queue_clone);
                                queue.push_back((remote, buf[..n].to_vec()));
                                drop(queue);
                                if let Some(waker) =
                                    lock_poisoned(&waker_clone).take()
                                {
                                    waker.wake();
                                }
                            }
                            Ok(_) => continue,
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        Ok(Arc::new(Self {
            local,
            recv_queue,
            recv_waker,
            send_tx,
        }))
    }
}

/// Locks a poisoned `std::sync::Mutex` by recovering its contents.
fn lock_poisoned<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A poller that always reports the socket as writable: `try_send` buffers
/// into an unbounded channel, so sends never block.
#[derive(Debug)]
struct IcePoller;

impl UdpPoller for IcePoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for IceUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(IcePoller)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.send_tx
            .send(transmit.contents.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionReset, "ICE connection closed"))
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let buf = match bufs.first_mut() {
            Some(b) => b,
            None => return Poll::Ready(Ok(0)),
        };

        // Register the waker *before* checking the queue to avoid a lost
        // wakeup: a datagram pushed after this point wakes us.
        *lock_poisoned(&self.recv_waker) = Some(cx.waker().clone());

        let mut queue = lock_poisoned(&self.recv_queue);
        if let Some((addr, data)) = queue.pop_front() {
            if data.len() > buf.len() {
                // Datagram too large for Quinn's buffer — drop it.
                meta[0] = RecvMeta {
                    addr,
                    len: 0,
                    stride: 0,
                    ecn: None,
                    dst_ip: None,
                };
                return Poll::Ready(Ok(1));
            }
            buf[..data.len()].copy_from_slice(&data);
            meta[0] = RecvMeta {
                addr,
                len: data.len(),
                stride: data.len(),
                ecn: None,
                dst_ip: None,
            };
            Poll::Ready(Ok(1))
        } else {
            Poll::Pending
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}
