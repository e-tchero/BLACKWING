//! Packet dispatcher skeleton.

use crate::error::ProtocolError;
use crate::routing::MessageEnvelope;
use crate::transport::Transport;
use std::sync::Arc;

/// Coordinates the reception and routing of incoming message envelopes.
#[derive(Debug)]
pub struct MessageDispatcher {}

impl Default for MessageDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageDispatcher {
    /// Creates a new `MessageDispatcher`.
    pub fn new() -> Self {
        Self {}
    }

    /// Dispatches a single message envelope.
    ///
    /// # Returns
    ///
    /// `Ok(())` if successfully routed, or `ProtocolError` on validation or routing failure.
    pub fn dispatch(&self, envelope: MessageEnvelope) -> Result<(), ProtocolError> {
        // Enforce validation checks before processing
        envelope.validate()?;

        // Routing/dispatching hooks can be registered here in future iterations
        Ok(())
    }

    /// Listens to a transport source, decoding and dispatching incoming frames.
    pub async fn run(&self, transport: Arc<dyn Transport>) -> Result<(), ProtocolError> {
        loop {
            let frame = transport.receive().await?;
            let envelope = MessageEnvelope::deserialize(&frame.payload)?;
            self.dispatch(envelope)?;
        }
    }
}
