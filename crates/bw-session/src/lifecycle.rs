use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionState {
    Connected = 0,
    Handshaking = 1,
    Active = 2,
    Closing = 3,
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

pub struct Lifecycle {
    state: AtomicU8,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifecycle {
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(ConnectionState::Connected as u8),
        }
    }

    pub fn get_state(&self) -> ConnectionState {
        self.state.load(Ordering::Acquire).into()
    }

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

    pub fn force_state(&self, new: ConnectionState) {
        self.state.store(new as u8, Ordering::Release);
    }
}
