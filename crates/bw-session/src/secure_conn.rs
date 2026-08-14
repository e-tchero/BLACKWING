//! Secure connection layer: authenticated handshake and encrypted frames.

use crate::lifecycle::{ConnectionState, Lifecycle};
use bw_crypto::random::{OsRandom, SecureRandom};
use bw_crypto::SymmetricKey;
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
    pub async fn client_handshake(
        &mut self,
        master_secret: &SymmetricKey,
    ) -> Result<(), SecureConnError> {
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

        // 3. Derive keys and register session
        self.session_manager.create_session_from_handshake(
            self.session_id,
            master_secret,
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
    pub async fn server_handshake(
        &mut self,
        master_secret: &SymmetricKey,
    ) -> Result<(), SecureConnError> {
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
        let client_keys = derive_session_keys(master_secret, &client_nonce, &server_nonce)
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

        let secure_frame = ProtocolFrame {
            header: PacketHeader {
                magic: PROTOCOL_MAGIC,
                schema_version: CURRENT_VERSION.into(),
                packet_type: PACKET_TYPE_MESSAGE,
                payload_length: cbor_bytes.len() as u16,
                ..Default::default()
            },
            payload: &cbor_bytes,
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

        let mut buffer = Vec::new();
        let secure_frame = self.adapter.recv_frame(&mut buffer).await?;

        let encrypted_frame =
            bw_protocol::encryption::EncryptedFrame::deserialize(secure_frame.payload)?;

        let decrypted_frame = self
            .session_manager
            .with_session_context(&self.session_id, |ctx| ctx.decrypt_frame(&encrypted_frame))??;
        Ok(decrypted_frame)
    }

    /// Closes the secure connection, releasing the session.
    pub async fn close(&mut self) {
        self.lifecycle.force_state(ConnectionState::Closing);
        let _ = self.session_manager.close_session(&self.session_id);
        self.adapter.close().await;
        self.lifecycle.force_state(ConnectionState::Closed);
    }
}
