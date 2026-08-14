//! Protocol messages layer.

use crate::error::ProtocolError;
use serde::{Deserialize, Serialize};

/// The type classification of a protocol message.
#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    /// Keep-alive ping query.
    Ping = 0,
    /// Keep-alive pong response.
    Pong = 1,
    /// Init connection handshake start.
    Hello = 2,
    /// Disconnection termination signal.
    Goodbye = 3,
    /// Periodic health/liveness heartbeat.
    Heartbeat = 4,
    /// Raw application payload carrier.
    Data = 5,
    /// Handshake negotiation or runtime connection controls.
    Control = 6,
    /// Failure reports or protocol error notifications.
    Error = 7,
    /// Remote keyboard input event (key press/release).
    InputKeyboard = 8,
    /// Remote mouse input event (movement and/or button state).
    InputMouse = 9,
}

/// A remote keyboard event (key press or release).
///
/// Carried in the payload of a [`ProtocolMessage`] with
/// [`MessageType::InputKeyboard`].
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyboardEvent {
    /// Win32 virtual-key code (e.g. `0x41` = `VK_A`).
    pub keycode: u16,
    /// `true` presses the key, `false` releases it.
    pub is_down: bool,
}

/// A remote mouse event (relative movement and/or button state).
///
/// Carried in the payload of a [`ProtocolMessage`] with
/// [`MessageType::InputMouse`].
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseEvent {
    /// Relative horizontal cursor movement in pixels.
    pub dx: i32,
    /// Relative vertical cursor movement in pixels.
    pub dy: i32,
    /// Bitmask of mouse button states: bit 0 = left, bit 1 = right,
    /// bit 2 = middle. `0` means no buttons pressed.
    pub buttons_mask: u8,
}

/// A structured protocol message with metadata and an owned payload.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProtocolMessage {
    /// The classification type of the message.
    pub message_type: MessageType,
    /// Unique identifier for matching queries and responses.
    pub message_id: u32,
    /// Operation-specific flag bitmask.
    pub flags: u16,
    /// The owned inner message payload.
    pub payload: Vec<u8>,
}

impl ProtocolMessage {
    /// Serializes the protocol message into a compact binary representation (CBOR).
    ///
    /// # Returns
    ///
    /// The serialized byte vector, or `ProtocolError` on serialization failure.
    pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(self, &mut buffer)
            .map_err(|_| ProtocolError::SerializationError)?;
        Ok(buffer)
    }

    /// Deserializes a byte slice into a structured `ProtocolMessage`.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte slice to deserialize from.
    ///
    /// # Returns
    ///
    /// The deserialized `ProtocolMessage`, or `ProtocolError` on failure.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        ciborium::de::from_reader(bytes).map_err(|_| ProtocolError::DeserializationError)
    }

    /// Builds an [`MessageType::InputKeyboard`] message carrying a [`KeyboardEvent`].
    ///
    /// # Returns
    ///
    /// The constructed message, or `ProtocolError` if the event cannot be
    /// serialized into the payload.
    pub fn keyboard_event(keycode: u16, is_down: bool) -> Result<Self, ProtocolError> {
        let event = KeyboardEvent { keycode, is_down };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload)
            .map_err(|_| ProtocolError::SerializationError)?;
        Ok(Self {
            message_type: MessageType::InputKeyboard,
            message_id: 0,
            flags: 0,
            payload,
        })
    }

    /// Builds an [`MessageType::InputMouse`] message carrying a [`MouseEvent`].
    ///
    /// # Returns
    ///
    /// The constructed message, or `ProtocolError` if the event cannot be
    /// serialized into the payload.
    pub fn mouse_event(dx: i32, dy: i32, buttons_mask: u8) -> Result<Self, ProtocolError> {
        let event = MouseEvent {
            dx,
            dy,
            buttons_mask,
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload)
            .map_err(|_| ProtocolError::SerializationError)?;
        Ok(Self {
            message_type: MessageType::InputMouse,
            message_id: 0,
            flags: 0,
            payload,
        })
    }

    /// Returns the decoded [`KeyboardEvent`] if this message is an input-keyboard
    /// message.
    ///
    /// Returns `None` when the message type is not [`MessageType::InputKeyboard`]
    /// or the payload cannot be decoded.
    pub fn as_keyboard_event(&self) -> Option<KeyboardEvent> {
        if self.message_type != MessageType::InputKeyboard {
            return None;
        }
        ciborium::de::from_reader(&self.payload[..]).ok()
    }

    /// Returns the decoded [`MouseEvent`] if this message is an input-mouse
    /// message.
    ///
    /// Returns `None` when the message type is not [`MessageType::InputMouse`]
    /// or the payload cannot be decoded.
    pub fn as_mouse_event(&self) -> Option<MouseEvent> {
        if self.message_type != MessageType::InputMouse {
            return None;
        }
        ciborium::de::from_reader(&self.payload[..]).ok()
    }

    /// Validates protocol constraints on the message fields.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        // Data messages must not have empty payload if flags indicate data presence
        if self.message_type == MessageType::Data && self.payload.is_empty() && self.flags != 0 {
            return Err(ProtocolError::InvalidPayloadLength);
        }

        // Input messages must carry a serialized event payload.
        if matches!(
            self.message_type,
            MessageType::InputKeyboard | MessageType::InputMouse
        ) && self.payload.is_empty()
        {
            return Err(ProtocolError::InvalidPayloadLength);
        }

        Ok(())
    }
}
