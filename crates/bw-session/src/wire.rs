//! Wire protocol for the session layer.
//!
//! Two concerns live here:
//!
//! 1. **Authentication exchange** — the OPAQUE (RFC 9381) login flow carried
//!    over the QUIC stream *before* the secure session is established. Three
//!    plaintext frames on a dedicated packet type: credential request
//!    (client → server), credential response (server → client), finalization
//!    (client → server). On success both sides derive the same session key.
//! 2. **Message framing** — [`MessageSession`] sends and receives encrypted
//!    [`ProtocolMessage`]s over an established [`SecureConnection`], wrapping
//!    the CBOR message bytes in an [`OwnedProtocolFrame`] with the message
//!    packet type.

use std::sync::Arc;

use bw_auth::{client, SessionKey};
use bw_protocol::error::ProtocolError;
use bw_protocol::frame::OwnedProtocolFrame;
use bw_protocol::header::{PacketHeader, PROTOCOL_MAGIC};
use bw_protocol::message::ProtocolMessage;
use bw_protocol::routing::SessionId;
use bw_protocol::session::SessionManager;
use bw_protocol::version::CURRENT_VERSION;
use bw_transport::adapter::QuicProtocolAdapter;
use thiserror::Error;

use crate::secure_conn::{SecureConnError, SecureConnection, SecureReceiver, SecureSender};

/// Packet type for OPAQUE authentication frames (pre-session, plaintext).
const PACKET_TYPE_AUTH: u16 = 0x03;
/// Packet type for encrypted application-message frames.
const PACKET_TYPE_MESSAGE: u16 = 0x02;

/// Maximum payload of a single protocol frame. Kept comfortably below
/// `u16::MAX` so the header's 16-bit `payload_length` field stays accurate
/// for large application messages (e.g. a full H.264 IDR video frame) even
/// after the encryption/CBOR overhead is added on the wire.
const MESSAGE_FRAGMENT_SIZE: usize = 60_000;

/// Header `flags` bit meaning "more fragments follow this one".
const FLAG_FRAGMENT_MORE: u16 = 0x0001;

/// This bounds memory allocation during fragment reassembly. The largest
/// legitimate BLACKWING message is a 4K H.264 IDR keyframe (under 1 MiB).
/// 4 MiB provides generous headroom while preventing OOM from fragment floods.
const MAX_REASSEMBLED_SIZE: usize = 4 * 1024 * 1024;

/// Encodes fragment metadata into the header `flags` field:
/// bit 0 = "more fragments follow", bits 1..=15 = fragment index.
fn fragment_flags(index: u16, more: bool) -> u16 {
    (index << 1) | u16::from(more)
}

/// Errors produced by the session wire protocol.
#[derive(Debug, Error)]
pub enum WireError {
    /// The QUIC adapter reported an error.
    #[error("transport adapter error: {0}")]
    Adapter(#[from] bw_transport::AdapterError),
    /// An OPAQUE step failed.
    #[error("authentication error: {0}")]
    Auth(#[from] bw_auth::AuthError),
    /// The server's enrollment store reported an error.
    #[error("enrollment store error: {0}")]
    Store(#[from] bw_auth::store::StoreError),
    /// The secure session reported an error.
    #[error("secure session error: {0}")]
    Session(#[from] SecureConnError),
    /// A protocol message could not be serialized or deserialized.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    /// The peer sent a frame of the wrong type during the exchange.
    #[error("unexpected frame during exchange")]
    UnexpectedFrame,
    /// The peer's credential request was malformed.
    #[error("malformed credential request")]
    MalformedRequest,
    /// The peer closed the stream mid-exchange.
    #[error("connection closed during exchange")]
    Closed,
    /// Fragments of a large message arrived out of order or with a gap.
    #[error("fragmented message out of order")]
    FragmentOutOfOrder,
    /// The reassembled message exceeds the maximum allowed size.
    #[error("reassembled message too large ({0} bytes, max 4 MiB)")]
    OversizedMessage(usize),
}

/// An authenticated, encrypted message channel over a QUIC connection.
///
/// Wraps a [`SecureConnection`] and adds the [`ProtocolMessage`] serialization
/// layer: [`MessageSession::send_message`] encrypts a CBOR message and
/// [`MessageSession::recv_message`] decrypts and decodes the next one.
pub struct MessageSession {
    secure: SecureConnection,
}

impl MessageSession {
    /// Wraps an established secure connection.
    pub fn new(secure: SecureConnection) -> Self {
        Self { secure }
    }

    /// Sends one encrypted protocol message.
    pub async fn send_message(&mut self, message: &ProtocolMessage) -> Result<(), WireError> {
        let payload = message.serialize()?;
        self.send_fragmented(payload).await
    }

    /// Receives and decrypts the next protocol message.
    pub async fn recv_message(&mut self) -> Result<ProtocolMessage, WireError> {
        let payload = self.recv_reassembled().await?;
        Ok(ProtocolMessage::deserialize(&payload)?)
    }

    /// Sends the serialized message bytes, splitting them into multiple
    /// protocol frames when they exceed [`MESSAGE_FRAGMENT_SIZE`].
    async fn send_fragmented(&mut self, payload: Vec<u8>) -> Result<(), WireError> {
        if payload.len() <= MESSAGE_FRAGMENT_SIZE {
            let frame = OwnedProtocolFrame {
                header: PacketHeader {
                    magic: PROTOCOL_MAGIC,
                    schema_version: CURRENT_VERSION.into(),
                    packet_type: PACKET_TYPE_MESSAGE,
                    flags: 0,
                    payload_length: payload.len() as u16,
                    ..Default::default()
                },
                payload,
            };
            self.secure.send_secure_frame(frame).await?;
            return Ok(());
        }
        let total = payload.len();
        let mut index: u16 = 0;
        let mut offset = 0;
        while offset < total {
            let end = (offset + MESSAGE_FRAGMENT_SIZE).min(total);
            let more = end < total;
            let frame = OwnedProtocolFrame {
                header: PacketHeader {
                    magic: PROTOCOL_MAGIC,
                    schema_version: CURRENT_VERSION.into(),
                    packet_type: PACKET_TYPE_MESSAGE,
                    flags: fragment_flags(index, more),
                    payload_length: (end - offset) as u16,
                    ..Default::default()
                },
                payload: payload[offset..end].to_vec(),
            };
            self.secure.send_secure_frame(frame).await?;
            index += 1;
            offset = end;
        }
        Ok(())
    }

    /// Reads protocol frames until one complete (possibly fragmented)
    /// message is reassembled, returning the serialized message bytes.
    async fn recv_reassembled(&mut self) -> Result<Vec<u8>, WireError> {
        let frame = self.secure.recv_secure_frame().await?;
        let index = frame.header.flags >> 1;
        let mut more = (frame.header.flags & FLAG_FRAGMENT_MORE) != 0;
        if index == 0 && !more {
            return Ok(frame.payload);
        }
        let mut payload = Vec::with_capacity(MESSAGE_FRAGMENT_SIZE * 2);
        payload.extend_from_slice(&frame.payload);
        let mut expected = u32::from(index) + 1;
        while more {
            let fragment = self.secure.recv_secure_frame().await?;
            let frag_index = fragment.header.flags >> 1;
            more = (fragment.header.flags & FLAG_FRAGMENT_MORE) != 0;
            if u32::from(frag_index) != expected {
                return Err(WireError::FragmentOutOfOrder);
            }
            // C2 FIX: enforce reassembly size limit.
            let new_len = payload.len() + fragment.payload.len();
            if new_len > MAX_REASSEMBLED_SIZE {
                return Err(WireError::OversizedMessage(new_len));
            }
            payload.extend_from_slice(&fragment.payload);
            expected += 1;
        }
        Ok(payload)
    }

    /// Gracefully closes the secure connection.
    pub async fn close(&mut self) {
        self.secure.close().await;
    }
}

/// Send half of a [`MessageSession`], for a dedicated sender task.
///
/// Produced by [`MessageSession::into_split`]; shares the session's encryption
/// context with the receive half through the [`SessionManager`].
pub struct MessageSender {
    secure: SecureSender,
}

/// Receive half of a [`MessageSession`], for a dedicated receiver task.
pub struct MessageReceiver {
    secure: SecureReceiver,
}

impl MessageSender {
    /// Sends one encrypted protocol message.
    pub async fn send_message(&mut self, message: &ProtocolMessage) -> Result<(), WireError> {
        let payload = message.serialize()?;
        self.send_fragmented(payload).await
    }

    /// Sends the serialized message bytes, splitting them into multiple
    /// protocol frames when they exceed [`MESSAGE_FRAGMENT_SIZE`].
    async fn send_fragmented(&mut self, payload: Vec<u8>) -> Result<(), WireError> {
        if payload.len() <= MESSAGE_FRAGMENT_SIZE {
            let frame = OwnedProtocolFrame {
                header: PacketHeader {
                    magic: PROTOCOL_MAGIC,
                    schema_version: CURRENT_VERSION.into(),
                    packet_type: PACKET_TYPE_MESSAGE,
                    flags: 0,
                    payload_length: payload.len() as u16,
                    ..Default::default()
                },
                payload,
            };
            self.secure.send_secure_frame(frame).await?;
            return Ok(());
        }
        let total = payload.len();
        let mut index: u16 = 0;
        let mut offset = 0;
        while offset < total {
            let end = (offset + MESSAGE_FRAGMENT_SIZE).min(total);
            let more = end < total;
            let frame = OwnedProtocolFrame {
                header: PacketHeader {
                    magic: PROTOCOL_MAGIC,
                    schema_version: CURRENT_VERSION.into(),
                    packet_type: PACKET_TYPE_MESSAGE,
                    flags: fragment_flags(index, more),
                    payload_length: (end - offset) as u16,
                    ..Default::default()
                },
                payload: payload[offset..end].to_vec(),
            };
            self.secure.send_secure_frame(frame).await?;
            index += 1;
            offset = end;
        }
        Ok(())
    }

    /// Gracefully finishes the underlying send stream.
    pub async fn close(&mut self) {
        self.secure.close().await;
    }
}

impl MessageReceiver {
    /// Receives and decrypts the next protocol message.
    pub async fn recv_message(&mut self) -> Result<ProtocolMessage, WireError> {
        let payload = self.recv_reassembled().await?;
        Ok(ProtocolMessage::deserialize(&payload)?)
    }

    /// Reads protocol frames until one complete (possibly fragmented)
    /// message is reassembled, returning the serialized message bytes.
    async fn recv_reassembled(&mut self) -> Result<Vec<u8>, WireError> {
        let frame = self.secure.recv_secure_frame().await?;
        let index = frame.header.flags >> 1;
        let mut more = (frame.header.flags & FLAG_FRAGMENT_MORE) != 0;
        if index == 0 && !more {
            return Ok(frame.payload);
        }
        let mut payload = Vec::with_capacity(MESSAGE_FRAGMENT_SIZE * 2);
        payload.extend_from_slice(&frame.payload);
        let mut expected = u32::from(index) + 1;
        while more {
            let fragment = self.secure.recv_secure_frame().await?;
            let frag_index = fragment.header.flags >> 1;
            more = (fragment.header.flags & FLAG_FRAGMENT_MORE) != 0;
            if u32::from(frag_index) != expected {
                return Err(WireError::FragmentOutOfOrder);
            }
            // C2 FIX: enforce reassembly size limit.
            let new_len = payload.len() + fragment.payload.len();
            if new_len > MAX_REASSEMBLED_SIZE {
                return Err(WireError::OversizedMessage(new_len));
            }
            payload.extend_from_slice(&fragment.payload);
            expected += 1;
        }
        Ok(payload)
    }
}

impl MessageSession {
    /// Splits the session into independent sender and receiver halves.
    ///
    /// After splitting, one task can own the sender (streaming video/audio)
    /// while another owns the receiver (dispatching inbound control messages).
    pub fn into_split(self) -> (MessageSender, MessageReceiver) {
        let (sender, receiver) = self.secure.into_split();
        (
            MessageSender { secure: sender },
            MessageReceiver { secure: receiver },
        )
    }
}

/// Builds a plaintext frame on the auth packet type.
fn auth_frame(payload: &[u8]) -> bw_protocol::frame::ProtocolFrame<'_> {
    bw_protocol::frame::ProtocolFrame {
        header: PacketHeader {
            magic: PROTOCOL_MAGIC,
            schema_version: CURRENT_VERSION.into(),
            packet_type: PACKET_TYPE_AUTH,
            payload_length: payload.len() as u16,
            ..Default::default()
        },
        payload,
    }
}

/// Derives the session ID for a login from the shared session key.
pub fn session_id_from_key(key: &SessionKey) -> SessionId {
    let bytes = key.as_bytes();
    let mut id = [0u8; 16];
    let n = bytes.len().min(16);
    id[..n].copy_from_slice(&bytes[..n]);
    SessionId(id)
}

/// Client side of a full session: OPAQUE login + secure handshake.
///
/// Consumes the adapter (the QUIC bidi stream), performs the three-frame auth
/// exchange, then upgrades to a [`MessageSession`].
pub async fn client_establish(
    adapter: QuicProtocolAdapter,
    session_manager: Arc<SessionManager>,
    identifier: &[u8],
    password: &[u8],
) -> Result<MessageSession, WireError> {
    let mut adapter = adapter;

    // 1. OPAQUE login: credential request (identifier-prefixed).
    let login_start = client::start_login(password)?;
    let request_bytes = login_start.request.serialize();
    let mut payload = Vec::with_capacity(2 + identifier.len() + request_bytes.len());
    payload.extend_from_slice(&(identifier.len() as u16).to_be_bytes());
    payload.extend_from_slice(identifier);
    payload.extend_from_slice(&request_bytes);
    adapter.send_frame(&auth_frame(&payload)).await?;

    // 2. Credential response.
    let mut buffer = Vec::new();
    let response_frame = adapter.recv_frame(&mut buffer).await?;
    if response_frame.header.packet_type != PACKET_TYPE_AUTH {
        return Err(WireError::UnexpectedFrame);
    }
    let credential_response = client::deserialize_credential_response(response_frame.payload)?;

    // 3. Finalization.
    let login_finish = client::finish_login(login_start.state, credential_response, password)?;
    adapter
        .send_frame(&auth_frame(&login_finish.finalization.serialize()))
        .await?;

    let session_key = login_finish.session_key;
    let session_id = session_id_from_key(&session_key);
    let mut secure = SecureConnection::new(adapter, session_manager, session_id);
    secure.client_handshake(session_key.as_bytes()).await?;

    Ok(MessageSession::new(secure))
}

/// Server side of a full session: OPAQUE login + secure handshake.
///
/// Returns the [`MessageSession`] and the authenticated identifier.
pub async fn server_establish(
    adapter: QuicProtocolAdapter,
    session_manager: Arc<SessionManager>,
    store: &bw_auth::store::EnrollmentStore,
) -> Result<(MessageSession, Vec<u8>), WireError> {
    let mut adapter = adapter;

    // 1. Credential request (identifier-prefixed).
    let mut buffer = Vec::new();
    let request_frame = adapter.recv_frame(&mut buffer).await?;
    if request_frame.header.packet_type != PACKET_TYPE_AUTH {
        return Err(WireError::UnexpectedFrame);
    }
    if request_frame.payload.len() < 2 {
        return Err(WireError::MalformedRequest);
    }
    let id_len = u16::from_be_bytes([request_frame.payload[0], request_frame.payload[1]]) as usize;
    if request_frame.payload.len() < 2 + id_len {
        return Err(WireError::MalformedRequest);
    }
    let identifier = request_frame.payload[2..2 + id_len].to_vec();

    // 2. Credential response (looked up from the enrollment store).
    let (login, response_bytes) =
        store.start_login(&identifier, &request_frame.payload[2 + id_len..])?;
    adapter.send_frame(&auth_frame(&response_bytes)).await?;

    // 3. Finalization.
    let finalization_frame = adapter.recv_frame(&mut buffer).await?;
    if finalization_frame.header.packet_type != PACKET_TYPE_AUTH {
        return Err(WireError::UnexpectedFrame);
    }
    let session_key = store.finish_login(login, finalization_frame.payload)?;

    let session_id = session_id_from_key(&session_key);
    let mut secure = SecureConnection::new(adapter, session_manager, session_id);
    secure.server_handshake(session_key.as_bytes()).await?;

    Ok((MessageSession::new(secure), identifier))
}
