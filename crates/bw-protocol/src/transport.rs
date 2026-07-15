//! Transport abstraction layer.

use crate::error::ProtocolError;
use crate::frame::ProtocolFrame;
use futures::future::BoxFuture;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

/// Lifecycle connection states of a transport connection.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum ConnectionState {
    /// The transport is disconnected.
    Disconnected = 0,
    /// The transport is actively establishing a connection.
    Connecting = 1,
    /// The transport is connected and ready to transmit data.
    Connected = 2,
    /// The transport is actively closing.
    Disconnecting = 3,
    /// The transport has failed.
    Failed = 4,
}

/// Abstract, dyn-compatible representation of a transport connection.
pub trait Transport: Send + Sync {
    /// Sends a protocol frame over the transport.
    fn send<'a>(&'a self, frame: ProtocolFrame<'a>) -> BoxFuture<'a, Result<(), ProtocolError>>;

    /// Receives a protocol frame from the transport.
    fn receive<'a>(&'a self) -> BoxFuture<'a, Result<ProtocolFrame<'a>, ProtocolError>>;

    /// Returns the current connection state.
    fn state(&self) -> ConnectionState;

    /// Closes the connection.
    fn close<'a>(&'a self) -> BoxFuture<'a, Result<(), ProtocolError>>;
}

/// A mock implementation of the `Transport` trait for unit testing.
pub struct MockTransport {
    state: AtomicU32,
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    // Holds the last received frame raw buffer.
    read_buf: Mutex<Vec<u8>>,
}

impl MockTransport {
    /// Creates a new `MockTransport` pair for testing.
    pub fn new_pair(channel_capacity: usize) -> (Arc<Self>, Arc<Self>) {
        let (tx1, rx1) = mpsc::channel(channel_capacity);
        let (tx2, rx2) = mpsc::channel(channel_capacity);

        let t1 = Arc::new(Self {
            state: AtomicU32::new(ConnectionState::Connected as u32),
            tx: tx1,
            rx: Mutex::new(rx2),
            read_buf: Mutex::new(Vec::new()),
        });

        let t2 = Arc::new(Self {
            state: AtomicU32::new(ConnectionState::Connected as u32),
            tx: tx2,
            rx: Mutex::new(rx1),
            read_buf: Mutex::new(Vec::new()),
        });

        (t1, t2)
    }

    /// Sets the state of this mock transport.
    pub fn set_state(&self, new_state: ConnectionState) {
        self.state.store(new_state as u32, Ordering::SeqCst);
    }
}

impl Transport for MockTransport {
    fn send<'a>(&'a self, frame: ProtocolFrame<'a>) -> BoxFuture<'a, Result<(), ProtocolError>> {
        Box::pin(async move {
            if self.state() != ConnectionState::Connected {
                return Err(ProtocolError::InvalidRoute);
            }
            let bytes = crate::codec::encode_frame(&frame);
            self.tx
                .send(bytes)
                .await
                .map_err(|_| ProtocolError::SerializationError)?;
            Ok(())
        })
    }

    fn receive<'a>(&'a self) -> BoxFuture<'a, Result<ProtocolFrame<'a>, ProtocolError>> {
        Box::pin(async move {
            if self.state() != ConnectionState::Connected {
                return Err(ProtocolError::InvalidRoute);
            }
            let mut rx = self.rx.lock().await;
            let bytes = rx.recv().await.ok_or(ProtocolError::BufferTooSmall)?;

            let mut read_buf = self.read_buf.lock().await;
            *read_buf = bytes;

            // We safely extend the slice lifetime to 'a since read_buf is owned by self,
            // and self outlives the return future 'a.
            let ptr = read_buf.as_ptr();
            let len = read_buf.len();
            let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

            let decoded = crate::codec::decode_frame(slice)?;
            Ok(decoded)
        })
    }

    fn state(&self) -> ConnectionState {
        match self.state.load(Ordering::SeqCst) {
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
            Ok(())
        })
    }
}
