//! Secure connection layer: authenticated handshake and encrypted frames.

use crate::lifecycle::{ConnectionState, Lifecycle};
use bw_crypto::random::{OsRandom, SecureRandom};
use bw_protocol::encryption::{EncryptionContext, KeyRotationPolicy, SessionKeys};
use bw_protocol::frame::ProtocolFrame;
use bw_protocol::handshake::derive_session_keys;
use bw_protocol::header::{PacketHeader, PROTOCOL_MAGIC};
use bw_protocol::routing::SessionId;
use bw_protocol::session::SessionManager;
use bw_protocol::version::CURRENT_VERSION;
use bw_transport::adapter::{AdapterError, QuicProtocolAdapter};
use std::sync::Arc;
use thiserror::Error;

const PACKET_TYPE_HANDSHAKE: u16 = 0x01;
const PACKET_TYPE_MESSAGE: u16 = 0x02;

/// Maximum payload carried in a single wire frame. Kept well below
/// `u16::MAX` so the 32-byte header's `payload_length` field cannot
/// overflow even for large encrypted application payloads (e.g. video).
const FRAGMENT_SIZE: usize = 60_000;

/// Header `flags` bit meaning "more fragments follow this one".
const FLAG_FRAGMENT_MORE: u16 = 0x0001;

/// Encodes fragment metadata into the header `flags` field:
/// bit 0 = "more fragments follow", bits 1..=15 = fragment index.
fn fragment_flags(index: u16, more: bool) -> u16 {
    (index << 1) | u16::from(more)
}

/// Errors that can occur during secure connection setup or use.
#[derive(Debug, Error)]
pub enum SecureConnError {
    /// The underlying transport adapter reported an error.
    #[error("Adapter error: {0}")]
    Adapter(#[from] AdapterError),
    /// The protocol layer reported an error.
    #[error("Protocol error: {0}")]
    Protocol(#[from] bw_protocol::error::ProtocolError),
    /// The lifecycle state machine rejected a transition.
    #[error("Invalid lifecycle transition")]
    LifecycleError,
    /// The handshake exchange did not complete successfully.
    #[error("Handshake failed")]
    HandshakeFailed,
    /// Failed to generate a cryptographic nonce.
    #[error("Failed to generate cryptographic nonce")]
    NonceFailed,
    /// The crypto layer reported an error.
    #[error("Crypto error: {0}")]
    Crypto(#[from] bw_crypto::error::CryptoError),
    /// Fragments of a large message arrived out of order or with a gap.
    #[error("fragmented message out of order")]
    FragmentOutOfOrder,
}

/// A secure, encrypted session built on a QUIC protocol adapter.
pub struct SecureConnection {
    adapter: QuicProtocolAdapter,
    session_id: SessionId,
    session_manager: Arc<SessionManager>,
    lifecycle: Lifecycle,
}

impl SecureConnection {
    /// Creates a new secure connection around the given adapter and session.
    pub fn new(
        adapter: QuicProtocolAdapter,
        session_manager: Arc<SessionManager>,
        session_id: SessionId,
    ) -> Self {
        Self {
            adapter,
            session_id,
            session_manager,
            lifecycle: Lifecycle::new(),
        }
    }

    /// Returns the current connection lifecycle state.
    pub fn state(&self) -> ConnectionState {
        self.lifecycle.get_state()
    }

    /// Performs the client-side handshake to establish the secure session.
    ///
    /// `session_key` is the key material produced by a successful OPAQUE login
    /// (see `bw-auth`); it is expanded to a 32-byte channel master secret via
    /// HKDF before the nonce-based session key derivation.
    pub async fn client_handshake(&mut self, session_key: &[u8]) -> Result<(), SecureConnError> {
        self.lifecycle
            .transition(ConnectionState::Connected, ConnectionState::Handshaking)
            .map_err(|_| SecureConnError::LifecycleError)?;

        // 1. Client generates a fresh nonce and sends HandshakeRequest
        let mut client_nonce = [0u8; 16];
        let mut rng = OsRandom;
        rng.fill(&mut client_nonce)
            .map_err(|_| SecureConnError::NonceFailed)?;

        let req_frame = ProtocolFrame {
            header: PacketHeader {
                magic: PROTOCOL_MAGIC,
                schema_version: CURRENT_VERSION.into(),
                packet_type: PACKET_TYPE_HANDSHAKE,
                payload_length: 16,
                ..Default::default()
            },
            payload: &client_nonce,
        };
        self.adapter.send_frame(&req_frame).await?;

        // 2. Client receives HandshakeResponse
        let mut buffer = Vec::new();
        let resp_frame = self.adapter.recv_frame(&mut buffer).await?;
        if resp_frame.header.packet_type != PACKET_TYPE_HANDSHAKE || resp_frame.payload.len() != 16
        {
            return Err(SecureConnError::HandshakeFailed);
        }

        let mut server_nonce = [0u8; 16];
        server_nonce.copy_from_slice(resp_frame.payload);

        // 3. Derive the 32-byte channel master secret from the OPAQUE session
        //    key, then derive per-role keys and register the session.
        let master_secret = bw_crypto::hkdf_derive(None, session_key, Some(b"opaque-session"))?;
        self.session_manager.create_session_from_handshake(
            self.session_id,
            &master_secret,
            &client_nonce,
            &server_nonce,
            KeyRotationPolicy::Manual,
        )?;

        self.lifecycle
            .transition(ConnectionState::Handshaking, ConnectionState::Active)
            .map_err(|_| SecureConnError::LifecycleError)?;
        Ok(())
    }

    /// Performs the server-side handshake to establish the secure session.
    ///
    /// `session_key` is the key material produced by a successful OPAQUE login
    /// (see `bw-auth`); it is expanded to a 32-byte channel master secret via
    /// HKDF before the nonce-based session key derivation.
    pub async fn server_handshake(&mut self, session_key: &[u8]) -> Result<(), SecureConnError> {
        self.lifecycle
            .transition(ConnectionState::Connected, ConnectionState::Handshaking)
            .map_err(|_| SecureConnError::LifecycleError)?;

        // 1. Server receives HandshakeRequest
        let mut buffer = Vec::new();
        let req_frame = self.adapter.recv_frame(&mut buffer).await?;
        if req_frame.header.packet_type != PACKET_TYPE_HANDSHAKE || req_frame.payload.len() != 16 {
            return Err(SecureConnError::HandshakeFailed);
        }

        let mut client_nonce = [0u8; 16];
        client_nonce.copy_from_slice(req_frame.payload);

        // 2. Server generates a fresh nonce and sends HandshakeResponse
        let mut server_nonce = [0u8; 16];
        let mut rng = OsRandom;
        rng.fill(&mut server_nonce)
            .map_err(|_| SecureConnError::NonceFailed)?;

        let resp_frame = ProtocolFrame {
            header: PacketHeader {
                magic: PROTOCOL_MAGIC,
                schema_version: CURRENT_VERSION.into(),
                packet_type: PACKET_TYPE_HANDSHAKE,
                payload_length: 16,
                ..Default::default()
            },
            payload: &server_nonce,
        };
        self.adapter.send_frame(&resp_frame).await?;

        // 3. Derive keys and register session.
        // CRITICAL: The server derives keys using the SAME nonce order as the client
        // (client_nonce first, server_nonce second) so the HKDF salt is identical on both sides.
        // derive_session_keys labels:
        //   send_key = HKDF(salt, "client-key")  → client encrypts with this
        //   recv_key = HKDF(salt, "server-key")  → server encrypts with this
        // The server therefore SWAPS the roles: its send_key = "server-key", recv_key = "client-key".
        let master_secret = bw_crypto::hkdf_derive(None, session_key, Some(b"opaque-session"))?;
        let client_keys = derive_session_keys(&master_secret, &client_nonce, &server_nonce)
            .map_err(SecureConnError::Protocol)?;

        // Swap send/recv so the server encrypts outbound with "server-key"
        // and decrypts inbound with "client-key".
        let server_keys = SessionKeys {
            send_key: client_keys.recv_key.clone(),
            recv_key: client_keys.send_key.clone(),
            epoch: client_keys.epoch,
        };
        let context = EncryptionContext::new(server_keys, KeyRotationPolicy::Manual);
        self.session_manager
            .create_session_with_context(self.session_id, context)
            .map_err(SecureConnError::Protocol)?;

        self.lifecycle
            .transition(ConnectionState::Handshaking, ConnectionState::Active)
            .map_err(|_| SecureConnError::LifecycleError)?;
        Ok(())
    }

    /// Sends an authenticated and encrypted frame over the secure connection.
    pub async fn send_secure_frame(
        &mut self,
        frame: bw_protocol::frame::OwnedProtocolFrame,
    ) -> Result<(), SecureConnError> {
        if self.state() != ConnectionState::Active {
            return Err(SecureConnError::LifecycleError);
        }

        let encrypted_frame = self
            .session_manager
            .with_session_context(&self.session_id, |ctx| ctx.encrypt_frame(&frame))??;
        let cbor_bytes = encrypted_frame.serialize()?;
        self.send_fragments(&cbor_bytes).await
    }

    /// Sends the encrypted message bytes, splitting them into multiple wire
    /// frames when they exceed [`FRAGMENT_SIZE`].
    async fn send_fragments(&mut self, cbor_bytes: &[u8]) -> Result<(), SecureConnError> {
        if cbor_bytes.len() <= FRAGMENT_SIZE {
            return self.send_one_fragment(0, false, cbor_bytes).await;
        }
        let total = cbor_bytes.len();
        let mut index: u16 = 0;
        let mut offset = 0;
        while offset < total {
            let end = (offset + FRAGMENT_SIZE).min(total);
            let more = end < total;
            self.send_one_fragment(index, more, &cbor_bytes[offset..end])
                .await?;
            index += 1;
            offset = end;
        }
        Ok(())
    }

    /// Writes a single wire frame carrying one fragment of the message.
    async fn send_one_fragment(
        &mut self,
        index: u16,
        more: bool,
        payload: &[u8],
    ) -> Result<(), SecureConnError> {
        let secure_frame = ProtocolFrame {
            header: PacketHeader {
                magic: PROTOCOL_MAGIC,
                schema_version: CURRENT_VERSION.into(),
                packet_type: PACKET_TYPE_MESSAGE,
                flags: fragment_flags(index, more),
                payload_length: payload.len() as u16,
                ..Default::default()
            },
            payload,
        };
        self.adapter.send_frame(&secure_frame).await?;
        Ok(())
    }

    /// Receives and decrypts an authenticated frame from the secure connection.
    pub async fn recv_secure_frame(
        &mut self,
    ) -> Result<bw_protocol::frame::OwnedProtocolFrame, SecureConnError> {
        if self.state() != ConnectionState::Active {
            return Err(SecureConnError::LifecycleError);
        }
        let cbor_bytes = self.recv_fragments().await?;
        let encrypted_frame = bw_protocol::encryption::EncryptedFrame::deserialize(&cbor_bytes)?;
        let decrypted_frame = self
            .session_manager
            .with_session_context(&self.session_id, |ctx| ctx.decrypt_frame(&encrypted_frame))??;
        Ok(decrypted_frame)
    }

    /// Reads wire frames until one complete (possibly fragmented) message is
    /// reassembled, returning the raw encrypted message bytes.
    async fn recv_fragments(&mut self) -> Result<Vec<u8>, SecureConnError> {
        let mut buffer = Vec::new();
        let first = self.adapter.recv_frame(&mut buffer).await?;
        let index = first.header.flags >> 1;
        let mut more = (first.header.flags & FLAG_FRAGMENT_MORE) != 0;
        if index == 0 && !more {
            // Unfragmented fast path (the common case).
            return Ok(first.payload.to_vec());
        }
        let mut payload = Vec::with_capacity(FRAGMENT_SIZE * 2);
        payload.extend_from_slice(first.payload);
        let mut expected = u32::from(index) + 1;
        while more {
            let mut buf = Vec::new();
            let fragment = self.adapter.recv_frame(&mut buf).await?;
            let frag_index = fragment.header.flags >> 1;
            more = (fragment.header.flags & FLAG_FRAGMENT_MORE) != 0;
            if u32::from(frag_index) != expected {
                return Err(SecureConnError::FragmentOutOfOrder);
            }
            payload.extend_from_slice(fragment.payload);
            expected += 1;
        }
        Ok(payload)
    }

    /// Closes the secure connection, releasing the session.
    pub async fn close(&mut self) {
        self.lifecycle.force_state(ConnectionState::Closing);
        let _ = self.session_manager.close_session(&self.session_id);
        self.adapter.close().await;
        self.lifecycle.force_state(ConnectionState::Closed);
    }
}

/// Send half of an established [`SecureConnection`].
///
/// Produced by [`SecureConnection::into_split`]; owns the QUIC send stream and
/// shares the session's encryption context through the [`SessionManager`], so a
/// sender task and a receiver task can drive the same session concurrently.
pub struct SecureSender {
    adapter: bw_transport::adapter::QuicSendAdapter,
    session_id: SessionId,
    session_manager: Arc<SessionManager>,
}

/// Receive half of an established [`SecureConnection`].
pub struct SecureReceiver {
    adapter: bw_transport::adapter::QuicRecvAdapter,
    session_id: SessionId,
    session_manager: Arc<SessionManager>,
}

impl SecureSender {
    /// Sends an authenticated and encrypted frame over the secure connection.
    pub async fn send_secure_frame(
        &mut self,
        frame: bw_protocol::frame::OwnedProtocolFrame,
    ) -> Result<(), SecureConnError> {
        let encrypted_frame = self
            .session_manager
            .with_session_context(&self.session_id, |ctx| ctx.encrypt_frame(&frame))??;
        let cbor_bytes = encrypted_frame.serialize()?;
        self.send_fragments(&cbor_bytes).await
    }

    /// Sends the encrypted message bytes, fragmenting into multiple wire
    /// frames when they exceed [`FRAGMENT_SIZE`].
    async fn send_fragments(&mut self, cbor_bytes: &[u8]) -> Result<(), SecureConnError> {
        if cbor_bytes.len() <= FRAGMENT_SIZE {
            return self.send_one_fragment(0, false, cbor_bytes).await;
        }
        let total = cbor_bytes.len();
        let mut index: u16 = 0;
        let mut offset = 0;
        while offset < total {
            let end = (offset + FRAGMENT_SIZE).min(total);
            let more = end < total;
            self.send_one_fragment(index, more, &cbor_bytes[offset..end])
                .await?;
            index += 1;
            offset = end;
        }
        Ok(())
    }

    /// Writes a single wire frame carrying one fragment of the message.
    async fn send_one_fragment(
        &mut self,
        index: u16,
        more: bool,
        payload: &[u8],
    ) -> Result<(), SecureConnError> {
        let secure_frame = ProtocolFrame {
            header: PacketHeader {
                magic: PROTOCOL_MAGIC,
                schema_version: CURRENT_VERSION.into(),
                packet_type: PACKET_TYPE_MESSAGE,
                flags: fragment_flags(index, more),
                payload_length: payload.len() as u16,
                ..Default::default()
            },
            payload,
        };
        self.adapter.send_frame(&secure_frame).await?;
        Ok(())
    }

    /// Gracefully finishes the underlying send stream.
    pub async fn close(&mut self) {
        self.adapter.close().await;
    }
}

impl SecureReceiver {
    /// Receives and decrypts an authenticated frame from the secure connection.
    pub async fn recv_secure_frame(
        &mut self,
    ) -> Result<bw_protocol::frame::OwnedProtocolFrame, SecureConnError> {
        let cbor_bytes = self.recv_fragments().await?;
        let encrypted_frame = bw_protocol::encryption::EncryptedFrame::deserialize(&cbor_bytes)?;
        let decrypted_frame = self
            .session_manager
            .with_session_context(&self.session_id, |ctx| ctx.decrypt_frame(&encrypted_frame))??;
        Ok(decrypted_frame)
    }

    /// Reads wire frames until one complete (possibly fragmented) message is
    /// reassembled, returning the raw encrypted message bytes.
    async fn recv_fragments(&mut self) -> Result<Vec<u8>, SecureConnError> {
        let mut buffer = Vec::new();
        let first = self.adapter.recv_frame(&mut buffer).await?;
        let index = first.header.flags >> 1;
        let mut more = (first.header.flags & FLAG_FRAGMENT_MORE) != 0;
        if index == 0 && !more {
            // Unfragmented fast path (the common case).
            return Ok(first.payload.to_vec());
        }
        let mut payload = Vec::with_capacity(FRAGMENT_SIZE * 2);
        payload.extend_from_slice(first.payload);
        let mut expected = u32::from(index) + 1;
        while more {
            let mut buf = Vec::new();
            let fragment = self.adapter.recv_frame(&mut buf).await?;
            let frag_index = fragment.header.flags >> 1;
            more = (fragment.header.flags & FLAG_FRAGMENT_MORE) != 0;
            if u32::from(frag_index) != expected {
                return Err(SecureConnError::FragmentOutOfOrder);
            }
            payload.extend_from_slice(fragment.payload);
            expected += 1;
        }
        Ok(payload)
    }
}

impl SecureConnection {
    /// Splits an established secure connection into independent sender and
    /// receiver halves.
    ///
    /// Both halves share the session's encryption context (via the
    /// [`SessionManager`]), so sends and receives can run concurrently in
    /// separate tasks. Only call after the handshake completes.
    pub fn into_split(self) -> (SecureSender, SecureReceiver) {
        let (send_adapter, recv_adapter) = self.adapter.into_split();
        let sender = SecureSender {
            adapter: send_adapter,
            session_id: self.session_id,
            session_manager: Arc::clone(&self.session_manager),
        };
        let receiver = SecureReceiver {
            adapter: recv_adapter,
            session_id: self.session_id,
            session_manager: self.session_manager,
        };
        (sender, receiver)
    }
}
