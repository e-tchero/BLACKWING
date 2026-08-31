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
    /// Remote clipboard content (text or image).
    ClipboardData = 10,
    /// Encoded audio packet (Opus).
    AudioData = 11,
    /// ICE candidate for P2P NAT traversal signaling.
    IceCandidate = 12,
    /// Encoded video frame (H.264) from the agent to the client.
    VideoData = 13,
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

/// A remote mouse event (movement and/or button state).
///
/// Carried in the payload of a [`ProtocolMessage`] with
/// [`MessageType::InputMouse`].
///
/// When `is_absolute` is `false` (default), `dx`/`dy` are relative pixel
/// deltas from the cursor's current position. When `is_absolute` is `true`,
/// `dx`/`dy` are absolute coordinates in the MOUSEEVENTF_ABSOLUTE normalized
/// space (0–65535 mapped to the full screen), which bypasses Windows pointer
/// ballistics and eliminates cursor jitter.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseEvent {
    /// Horizontal cursor position: relative delta (pixels) or absolute
    /// (normalized 0–65535) depending on `is_absolute`.
    pub dx: i32,
    /// Vertical cursor position: relative delta (pixels) or absolute
    /// (normalized 0–65535) depending on `is_absolute`.
    pub dy: i32,
    /// Bitmask of mouse button states: bit 0 = left, bit 1 = right,
    /// bit 2 = middle. `0` means no buttons pressed.
    pub buttons_mask: u8,
    /// When `true`, `dx`/`dy` are absolute normalized coordinates
    /// (0–65535) for MOUSEEVENTF_ABSOLUTE injection. When `false`,
    /// they are relative pixel deltas.
    #[serde(default)]
    pub is_absolute: bool,
}

/// The format of a clipboard payload.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ClipboardFormat {
    /// Plain-text clipboard content (UTF-8 bytes).
    Text,
    /// RGBA8 image with explicit pixel dimensions.
    ImageRgba8 {
        /// Image width in pixels.
        width: usize,
        /// Image height in pixels.
        height: usize,
    },
}

/// A remote clipboard change (text or image).
///
/// Carried in the payload of a [`ProtocolMessage`] with
/// [`MessageType::ClipboardData`]. `data` holds raw UTF-8 string bytes for
/// [`ClipboardFormat::Text`] or tightly-packed RGBA8 pixels for
/// [`ClipboardFormat::ImageRgba8`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClipboardEvent {
    /// The format and (for images) dimensions of the payload.
    pub format: ClipboardFormat,
    /// Raw string bytes or RGBA pixels.
    pub data: Vec<u8>,
}

/// An encoded audio packet.
///
/// Carried in the payload of a [`ProtocolMessage`] with
/// [`MessageType::AudioData`]. `opus_data` holds a single Opus-encoded frame
/// (typically 20 ms of audio); the format metadata (channels, sample rate)
/// lets the receiver configure its decoder.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AudioPayload {
    /// Number of interleaved PCM channels the frame was encoded from.
    pub channels: u16,
    /// Sample rate in Hz the frame was encoded at.
    pub sample_rate: u32,
    /// One Opus-encoded audio frame.
    pub opus_data: Vec<u8>,
}

/// An ICE candidate for P2P NAT traversal.
///
/// Carried in the payload of a [`ProtocolMessage`] with
/// [`MessageType::IceCandidate`]. `candidate_str` is the SDP-formatted
/// candidate line exchanged between peers during connectivity checks; the
/// optional `sdp_mid`/`sdp_mline_index` fields disambiguate which media
/// stream the candidate belongs to.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct IceCandidatePayload {
    /// SDP-formatted ICE candidate line (e.g. `candidate:1 1 UDP 2130706431 192.168.1.10 54321 typ host`).
    pub candidate_str: String,
    /// Media stream identification the candidate belongs to (when known).
    pub sdp_mid: Option<String>,
    /// 0-based media line index the candidate belongs to (when known).
    pub sdp_mline_index: Option<u16>,
}

/// Payload of a [`MessageType::VideoData`] message.
///
/// `encoded_frame` holds a serialized [`bw_encoder::EncodedFrame`]
/// (`EncodedFrame::to_bytes()`), which carries the codec, dimensions, frame
/// type, sequence number and the encoded NAL payload. The client reconstructs
/// the frame with `EncodedFrame::from_bytes()` before decoding.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VideoPayload {
    /// Serialized [`bw_encoder::EncodedFrame`] bytes.
    pub encoded_frame: Vec<u8>,
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
    /// Maximum serialized size of a ProtocolMessage (4 MiB).
    /// Must match MAX_REASSEMBLED_SIZE in bw-session to prevent
    /// allocation through CBOR deserialization.
    pub const MAX_DESER_SIZE: usize = 4 * 1024 * 1024;

    /// Maximum length of clipboard text data in bytes (1 MiB).
    /// Prevents unbounded allocation from malicious clipboard payloads.
    pub const MAX_CLIPBOARD_TEXT_LEN: usize = 1024 * 1024;

    /// Maximum dimension (width or height) for clipboard images in pixels.
    /// Combined with MAX_CLIPBOARD_TEXT_LEN this bounds the maximum
    /// allocation from a single clipboard event to ~16 GiB (the RGBA
    /// payload), but the 4 MiB ProtocolMessage::MAX_DESER_SIZE limits
    /// the actual serialized size to 4 MiB. This dimension check
    /// prevents integer overflow in width * height * 4 before the
    /// deserialized payload is even allocated.
    pub const MAX_CLIPBOARD_IMAGE_DIM: usize = 4096;

    /// Deserializes a byte slice into a structured `ProtocolMessage`.
    ///
    /// Rejects payloads exceeding `MAX_DESER_SIZE` before CBOR allocation.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        // C3 FIX: reject oversized payloads before CBOR allocation.
        if bytes.len() > Self::MAX_DESER_SIZE {
            return Err(ProtocolError::OversizedPayload(
                bytes.len(),
                Self::MAX_DESER_SIZE,
            ));
        }
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
        Self::mouse_event_abs(dx, dy, buttons_mask, false)
    }

    /// Builds an [`MessageType::InputMouse`] message carrying a [`MouseEvent`]
    /// with absolute or relative coordinates.
    pub fn mouse_event_abs(
        dx: i32,
        dy: i32,
        buttons_mask: u8,
        is_absolute: bool,
    ) -> Result<Self, ProtocolError> {
        let event = MouseEvent {
            dx,
            dy,
            buttons_mask,
            is_absolute,
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

    /// Builds a [`MessageType::ClipboardData`] message carrying a
    /// [`ClipboardEvent`].
    ///
    /// # Returns
    ///
    /// The constructed message, or `ProtocolError` if the event cannot be
    /// serialized into the payload.
    pub fn clipboard_event(event: ClipboardEvent) -> Result<Self, ProtocolError> {
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload)
            .map_err(|_| ProtocolError::SerializationError)?;
        Ok(Self {
            message_type: MessageType::ClipboardData,
            message_id: 0,
            flags: 0,
            payload,
        })
    }

    /// Returns the decoded [`ClipboardEvent`] if this message is a clipboard
    /// message.
    ///
    /// Returns `None` when the message type is not
    /// [`MessageType::ClipboardData`] or the payload cannot be decoded.
    pub fn as_clipboard_event(&self) -> Option<ClipboardEvent> {
        if self.message_type != MessageType::ClipboardData {
            return None;
        }
        let event: ClipboardEvent = ciborium::de::from_reader(&self.payload[..]).ok()?;

        // M1 FIX: validate clipboard payload size before accepting.
        match &event.format {
            ClipboardFormat::Text => {
                if event.data.len() > Self::MAX_CLIPBOARD_TEXT_LEN {
                    return None;
                }
            }
            ClipboardFormat::ImageRgba8 { width, height } => {
                // Reject if dimensions exceed maximum or if width*height*4 overflows.
                if *width > Self::MAX_CLIPBOARD_IMAGE_DIM || *height > Self::MAX_CLIPBOARD_IMAGE_DIM
                {
                    return None;
                }
                let expected = width.checked_mul(*height).and_then(|a| a.checked_mul(4));
                match expected {
                    Some(exp) if exp == event.data.len() => {}
                    _ => return None,
                }
            }
        }
        Some(event)
    }

    /// Builds a [`MessageType::AudioData`] message carrying an [`AudioPayload`].
    ///
    /// # Returns
    ///
    /// The constructed message, or `ProtocolError` if the payload cannot be
    /// serialized.
    pub fn audio_data(payload: AudioPayload) -> Result<Self, ProtocolError> {
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)
            .map_err(|_| ProtocolError::SerializationError)?;
        Ok(Self {
            message_type: MessageType::AudioData,
            message_id: 0,
            flags: 0,
            payload: payload_bytes,
        })
    }

    /// Returns the decoded [`AudioPayload`] if this message is an audio
    /// message.
    ///
    /// Returns `None` when the message type is not [`MessageType::AudioData`]
    /// or the payload cannot be decoded.
    pub fn as_audio_data(&self) -> Option<AudioPayload> {
        if self.message_type != MessageType::AudioData {
            return None;
        }
        ciborium::de::from_reader(&self.payload[..]).ok()
    }

    /// Builds a [`MessageType::IceCandidate`] message carrying an
    /// [`IceCandidatePayload`].
    ///
    /// # Returns
    ///
    /// The constructed message, or `ProtocolError` if the payload cannot be
    /// serialized.
    pub fn ice_candidate(payload: IceCandidatePayload) -> Result<Self, ProtocolError> {
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)
            .map_err(|_| ProtocolError::SerializationError)?;
        Ok(Self {
            message_type: MessageType::IceCandidate,
            message_id: 0,
            flags: 0,
            payload: payload_bytes,
        })
    }

    /// Returns the decoded [`IceCandidatePayload`] if this message is an ICE
    /// candidate message.
    ///
    /// Returns `None` when the message type is not
    /// [`MessageType::IceCandidate`] or the payload cannot be decoded.
    pub fn as_ice_candidate(&self) -> Option<IceCandidatePayload> {
        if self.message_type != MessageType::IceCandidate {
            return None;
        }
        ciborium::de::from_reader(&self.payload[..]).ok()
    }

    /// Builds a [`MessageType::VideoData`] message carrying a [`VideoPayload`].
    ///
    /// # Returns
    ///
    /// The constructed message, or `ProtocolError` if the payload cannot be
    /// serialized.
    pub fn video_data(payload: VideoPayload) -> Result<Self, ProtocolError> {
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)
            .map_err(|_| ProtocolError::SerializationError)?;
        Ok(Self {
            message_type: MessageType::VideoData,
            message_id: 0,
            flags: 0,
            payload: payload_bytes,
        })
    }

    /// Returns the decoded [`VideoPayload`] if this message is a video
    /// message.
    ///
    /// Returns `None` when the message type is not [`MessageType::VideoData`]
    /// or the payload cannot be decoded.
    pub fn as_video_data(&self) -> Option<VideoPayload> {
        if self.message_type != MessageType::VideoData {
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

        // Input, clipboard and audio messages must carry a serialized payload.
        if matches!(
            self.message_type,
            MessageType::InputKeyboard
                | MessageType::InputMouse
                | MessageType::ClipboardData
                | MessageType::AudioData
                | MessageType::IceCandidate
                | MessageType::VideoData
        ) && self.payload.is_empty()
        {
            return Err(ProtocolError::InvalidPayloadLength);
        }

        Ok(())
    }
}
