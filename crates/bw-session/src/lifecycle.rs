//! Connection lifecycle state machine.

use std::sync::atomic::{AtomicU8, Ordering};

/// The lifecycle states of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionState {
    /// The connection is established at the transport level.
    Connected = 0,
    /// The connection is performing the secure handshake.
    Handshaking = 1,
    /// The connection is active and carrying traffic.
    Active = 2,
    /// The connection is shutting down.
    Closing = 3,
    /// The connection is fully closed.
    Closed = 4,
}

impl From<u8> for ConnectionState {
    fn from(value: u8) -> Self {
        match value {
            0 => ConnectionState::Connected,
            1 => ConnectionState::Handshaking,
            2 => ConnectionState::Active,
            3 => ConnectionState::Closing,
            _ => ConnectionState::Closed,
        }
    }
}

/// Thread-safe state tracking for a connection lifecycle.
pub struct Lifecycle {
    state: AtomicU8,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifecycle {
    /// Creates a lifecycle starting in the `Connected` state.
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(ConnectionState::Connected as u8),
        }
    }

    /// Returns the current state.
    pub fn get_state(&self) -> ConnectionState {
        self.state.load(Ordering::Acquire).into()
    }

    /// Atomically transitions from `expected` to `new`, failing if the
    /// current state does not match `expected`.
    #[allow(clippy::result_unit_err)]
    pub fn transition(&self, expected: ConnectionState, new: ConnectionState) -> Result<(), ()> {
        self.state
            .compare_exchange(
                expected as u8,
                new as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map(|_| ())
            .map_err(|_| ())
    }

    /// Unconditionally sets the state (used during teardown).
    pub fn force_state(&self, new: ConnectionState) {
        self.state.store(new as u8, Ordering::Release);
    }
}
