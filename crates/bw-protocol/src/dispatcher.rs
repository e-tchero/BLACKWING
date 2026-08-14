//! Packet dispatcher: routes incoming message envelopes to registered handlers.

use crate::error::ProtocolError;
use crate::message::MessageType;
use crate::routing::MessageEnvelope;
use crate::transport::Transport;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;

/// A handler for a specific message type.
///
/// Handlers receive the full envelope and return `Ok(())` on success or a
/// [`DispatchError`] on failure. Handlers must be `Send + Sync` so the
/// dispatcher can be shared across tasks.
pub type MessageHandler = Arc<dyn Fn(MessageEnvelope) -> Result<(), DispatchError> + Send + Sync>;

/// Errors produced while dispatching a [`MessageEnvelope`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DispatchError {
    /// The envelope failed protocol validation.
    #[error("Envelope validation failed: {0}")]
    Validation(#[from] ProtocolError),
    /// No handler is registered for the envelope's message type.
    #[error("No handler registered for message type: {0:?}")]
    NoHandler(MessageType),
    /// The registered handler reported a failure while processing the message.
    ///
    /// This is a protocol-generic carrier (e.g. an OS input-injection failure
    /// in the server) — the payload is a human-readable description so the
    /// protocol layer stays independent of specific handler implementations.
    #[error("Message handler failed: {0}")]
    Handler(String),
}

/// Coordinates the reception and routing of incoming message envelopes.
///
/// Handlers are registered per [`MessageType`]. Each dispatched envelope is
/// validated first and then delivered to the handler registered for its
/// message type, if any.
pub struct MessageDispatcher {
    handlers: RwLock<HashMap<MessageType, MessageHandler>>,
}

impl Default for MessageDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MessageDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self
            .handlers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        f.debug_struct("MessageDispatcher")
            .field("registered_handlers", &count)
            .finish()
    }
}

impl MessageDispatcher {
    /// Creates a new `MessageDispatcher`.
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a handler for the given message type.
    ///
    /// Registering a second handler for the same type replaces the first.
    pub fn register_handler(&self, message_type: MessageType, handler: MessageHandler) {
        self.handlers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(message_type, handler);
    }

    /// Dispatches a single message envelope.
    ///
    /// The envelope is validated first; validation errors are returned as
    /// [`DispatchError::Validation`] before any handler lookup. If no handler
    /// is registered for the envelope's message type,
    /// [`DispatchError::NoHandler`] is returned. Otherwise the registered
    /// handler is invoked with the envelope.
    pub fn dispatch(&self, envelope: MessageEnvelope) -> Result<(), DispatchError> {
        self.validate(&envelope)?;

        let handlers = self.handlers.read().unwrap_or_else(|e| e.into_inner());
        let handler = handlers
            .get(&envelope.message.message_type)
            .ok_or(DispatchError::NoHandler(envelope.message.message_type))?
            .clone();

        handler(envelope)
    }

    /// Validates the routing coordinates and envelope properties.
    fn validate(&self, envelope: &MessageEnvelope) -> Result<(), DispatchError> {
        envelope.validate()?;
        Ok(())
    }

    /// Listens to a transport source, decoding and dispatching incoming frames.
    pub async fn run(&self, transport: Arc<dyn Transport>) -> Result<(), DispatchError> {
        loop {
            let frame = transport.receive().await?;
            let envelope = MessageEnvelope::deserialize(&frame.payload)?;
            self.dispatch(envelope)?;
        }
    }
}
