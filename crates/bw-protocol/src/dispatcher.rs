//! Packet dispatcher with route handler registry.
//!
//! [`MessageDispatcher`] validates incoming [`MessageEnvelope`]s and routes
//! them to registered [`MessageHandler`] implementations keyed by
//! [`MessageType`]. This is the central message routing hub of the protocol
//! layer.
//!
//! # Handler registration
//!
//! External code (e.g. `bw-agent`, `bw-console`) registers handlers at
//! startup:
//!
//! ```ignore
//! dispatcher.register_handler(MessageType::Ping, MyPingHandler)?;
//! ```
//!
//! Multiple handlers can be registered for the same [`MessageType`]; they are
//! invoked in registration order. If a handler returns
//! [`ProtocolError`], the remaining handlers for that type are skipped and
//! the error propagates to the caller of [`dispatch`](MessageDispatcher::dispatch).

use crate::error::ProtocolError;
use crate::message::MessageType;
use crate::routing::MessageEnvelope;
use crate::transport::Transport;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

/// Processes a routed message envelope.
///
/// Implementations must be [`Send`] + [`Sync`] so they can be registered
/// on a dispatcher shared across Tokio task boundaries.
pub trait MessageHandler: Send + Sync {
    /// Process a dispatched message envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if processing fails. The error propagates
    /// back to the caller of [`MessageDispatcher::dispatch`] and prevents
    /// any remaining handlers for this message type from being invoked.
    fn handle(&self, envelope: &MessageEnvelope) -> Result<(), ProtocolError>;
}

/// Coordinates the reception and routing of incoming message envelopes.
pub struct MessageDispatcher {
    handlers: RwLock<HashMap<MessageType, Vec<Box<dyn MessageHandler>>>>,
}

impl std::fmt::Debug for MessageDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let handler_count = self
            .handlers
            .read()
            .map(|map| map.values().map(|v| v.len()).sum::<usize>())
            .unwrap_or(0);
        f.debug_struct("MessageDispatcher")
            .field("registered_handlers", &handler_count)
            .finish()
    }
}

impl Default for MessageDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageDispatcher {
    /// Creates a new empty `MessageDispatcher`.
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a handler for a specific message type.
    ///
    /// Multiple handlers can be registered for the same [`MessageType`].
    /// They will be invoked in registration order during
    /// [`dispatch`](MessageDispatcher::dispatch).
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidHandshake`] if the internal handler
    /// lock is poisoned (unrecoverable).
    pub fn register_handler<H: MessageHandler + 'static>(
        &self,
        message_type: MessageType,
        handler: H,
    ) -> Result<(), ProtocolError> {
        let mut handlers = self
            .handlers
            .write()
            .map_err(|_| ProtocolError::InvalidHandshake)?;
        handlers
            .entry(message_type)
            .or_default()
            .push(Box::new(handler));
        Ok(())
    }

    /// Removes all handlers for a given message type.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidHandshake`] if the internal handler
    /// lock is poisoned (unrecoverable).
    pub fn unregister_handlers(&self, message_type: &MessageType) -> Result<(), ProtocolError> {
        let mut handlers = self
            .handlers
            .write()
            .map_err(|_| ProtocolError::InvalidHandshake)?;
        handlers.remove(message_type);
        Ok(())
    }

    /// Dispatches a single message envelope to registered handlers.
    ///
    /// 1. Validates the envelope's routing coordinates and structural
    ///    invariants via [`MessageEnvelope::validate`].
    /// 2. Looks up handlers registered for the message's type.
    /// 3. Invokes each handler in registration order.
    ///
    /// If any handler returns an error, the remaining handlers for that
    /// message type are skipped and the error propagates immediately.
    ///
    /// If no handler is registered for the message type, the message is
    /// silently dropped after validation. This is the expected behaviour
    /// for unhandled or unsolicited message types.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if envelope validation fails or any
    /// registered handler returns an error.
    pub fn dispatch(&self, envelope: MessageEnvelope) -> Result<(), ProtocolError> {
        // Enforce validation checks before any handler is invoked
        envelope.validate()?;

        let msg_type = envelope.message.message_type;
        let handlers = self
            .handlers
            .read()
            .map_err(|_| ProtocolError::InvalidHandshake)?;

        if let Some(entry_handlers) = handlers.get(&msg_type) {
            for handler in entry_handlers {
                handler.handle(&envelope)?;
            }
        }

        Ok(())
    }

    /// Listens to a transport source, decoding and dispatching incoming frames.
    ///
    /// Loops indefinitely, receiving frames from the transport, decoding
    /// them into [`MessageEnvelope`]s, and dispatching to registered handlers.
    /// The loop exits when the transport returns an error (e.g. connection
    /// closed).
    pub async fn run(&self, transport: Arc<dyn Transport>) -> Result<(), ProtocolError> {
        loop {
            let frame = transport.receive().await?;
            let envelope = MessageEnvelope::deserialize(&frame.payload)?;
            self.dispatch(envelope)?;
        }
    }
}
