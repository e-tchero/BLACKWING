//! Connection management and task lifecycle.
//!
//! Provides the `ConnectionManager` runtime and the opaque `ConnectionHandle`.
//! These structs own the raw sockets and Tokio tasks but are completely decoupled
//! from protocol logic.

use crate::error::NetError;
use crate::transport::Transport;
use crate::udp::{run_receive_loop, UdpTransport};
use bw_protocol::dispatcher::MessageDispatcher;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// A unique identifier for a network connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u64);

impl ConnectionId {
    fn next() -> Self {
        Self(NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed))
    }
}

/// An opaque handle representing an active connection.
///
/// **Drop Semantics**: Dropping this handle automatically fires the cancellation
/// token, which instructs the underlying Tokio receiver/sender tasks to exit
/// cleanly, release their sockets, and terminate.
#[derive(Debug)]
pub struct ConnectionHandle {
    id: ConnectionId,
    peer_addr: SocketAddr,
    cancel_token: CancellationToken,
    // Fires token cancellation automatically when dropped.
    _guard: DropGuard,
}

impl ConnectionHandle {
    /// Returns the connection's unique ID.
    pub fn id(&self) -> ConnectionId {
        self.id
    }

    /// Returns the resolved peer address of this connection.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Checks if the connection has been cancelled/closed.
    pub fn is_closed(&self) -> bool {
        self.cancel_token.is_cancelled()
    }
}

/// Internal state tracked by the manager for an active connection.
pub struct ConnectionState {
    /// Token used to cancel/close the connection task.
    pub cancel_token: CancellationToken,
    /// Handle to the connection's receiver task.
    pub receiver_handle: JoinHandle<Result<(), NetError>>,
}

/// The networking runtime.
///
/// Owns the active connection registry and spawns task lifecycles.
pub struct ConnectionManager {
    dispatcher: Arc<MessageDispatcher>,
    active_connections: Arc<Mutex<HashMap<ConnectionId, ConnectionState>>>,
}

impl ConnectionManager {
    /// Creates a new `ConnectionManager`.
    pub fn new(dispatcher: Arc<MessageDispatcher>) -> Self {
        Self {
            dispatcher,
            active_connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Connects to a remote UDP peer and spawns the receive loop.
    ///
    /// # Returns
    ///
    /// Returns a `ConnectionHandle` which manages the lifecycle of the connection.
    pub async fn connect_udp(
        &self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    ) -> Result<ConnectionHandle, NetError> {
        let transport = Arc::new(UdpTransport::connect(local_addr, peer_addr).await?);
        let id = ConnectionId::next();

        let cancel_token = CancellationToken::new();
        // Create a DropGuard that cancels the token when the Handle is dropped.
        let guard = cancel_token.clone().drop_guard();

        // Convert the cancellation token into a watch channel for the legacy loop API
        // (In a full refactor, run_receive_loop should accept CancellationToken directly,
        // but bridging it here keeps changes localized).
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let token_clone = cancel_token.clone();
        // Bridging task: fires the watch channel when token is cancelled
        tokio::spawn(async move {
            token_clone.cancelled().await;
            let _ = shutdown_tx.send(true);
        });

        let t = Arc::clone(&transport) as Arc<dyn Transport>;
        let d = Arc::clone(&self.dispatcher);

        let receiver_handle = tokio::spawn(run_receive_loop(t, d, shutdown_rx));

        let state = ConnectionState {
            cancel_token: cancel_token.clone(),
            receiver_handle,
        };

        self.active_connections.lock().await.insert(id, state);

        Ok(ConnectionHandle {
            id,
            peer_addr,
            cancel_token,
            _guard: guard,
        })
    }

    /// Internal test hook: awaits the termination of the receiver task for a given connection
    /// and removes it from the registry.
    pub async fn wait_for_shutdown(&self, id: ConnectionId) -> Result<(), NetError> {
        let state = self.active_connections.lock().await.remove(&id);
        if let Some(s) = state {
            match s.receiver_handle.await {
                Ok(res) => return res,
                Err(e) => {
                    if e.is_cancelled() {
                        return Ok(());
                    } else {
                        return Err(NetError::Shutdown);
                    }
                }
            }
        }
        Ok(())
    }
}
