//! Integration tests for handshake I/O over [`Transport`].
//!
//! These tests verify the full WP-6 handshake flow using `MockTransport`
//! pairs, exercising `client_handshake` and `server_handshake` end-to-end.

use std::collections::HashSet;

use bw_crypto::{hkdf_derive, SymmetricKey};
use bw_protocol::encryption::KeyRotationPolicy;
use bw_protocol::handshake::{
    build_handshake_frame, client_handshake, server_handshake, Capabilities, HandshakeRequest,
    HandshakeResponse, HandshakeStatus, DEFAULT_HANDSHAKE_TIMEOUT,
};
use bw_protocol::message::MessageType;
use bw_protocol::routing::{MessageEnvelope, SessionId};
use bw_protocol::session::SessionManager;
use bw_protocol::transport::{MockTransport, Transport};
use bw_protocol::version::{ProtocolVersion, CURRENT_VERSION};
use std::sync::Arc;

/// Creates a deterministic master secret for testing.
fn make_master_secret() -> SymmetricKey {
    hkdf_derive(None, b"test-master-secret", None).unwrap()
}

/// Client capabilities: encryption + streaming + heartbeat.
fn client_capabilities() -> Capabilities {
    Capabilities(Capabilities::ENCRYPTION | Capabilities::STREAMING | Capabilities::HEARTBEAT)
}

/// Server capabilities: encryption + streaming + authentication.
fn server_capabilities() -> Capabilities {
    Capabilities(Capabilities::ENCRYPTION | Capabilities::STREAMING | Capabilities::AUTHENTICATION)
}

fn make_client_device_id() -> bw_crypto::DeviceId {
    bw_crypto::DeviceId::from_digest([1u8; 32])
}

/// Helper: convert an `Arc<MockTransport>` to `&dyn Transport`.
fn as_transport(t: &Arc<MockTransport>) -> &dyn Transport {
    let mock: &MockTransport = &*t;
    mock
}

// ─── Happy Path ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_handshake_full_roundtrip() {
    let master = make_master_secret();
    let (client_transport, server_transport) = MockTransport::new_pair(16);
    let session_manager = Arc::new(SessionManager::new());

    // Clone values that will be moved into the async server task
    let server_master = master.clone();
    let server_transport = Arc::new(server_transport);
    let sm = Arc::clone(&session_manager);

    let server_handle = {
        let transport = Arc::clone(&server_transport);
        let sm = Arc::clone(&sm);
        tokio::spawn(async move {
            let t = as_transport(&transport);
            server_handshake(
                t,
                &sm,
                server_capabilities(),
                &server_master,
                KeyRotationPolicy::Manual,
                DEFAULT_HANDSHAKE_TIMEOUT,
            )
            .await
        })
    };

    // Client performs handshake (uses original master, not moved)
    let result = client_handshake(
        as_transport(&client_transport),
        make_client_device_id(),
        client_capabilities(),
        &master,
        KeyRotationPolicy::Manual,
        DEFAULT_HANDSHAKE_TIMEOUT,
    )
    .await;

    let (session_id, context) = result.expect("Client handshake should succeed");
    assert_ne!(session_id.0, [0u8; 16], "Session ID must be non-zero");
    assert_eq!(context.current_key_epoch(), 0);

    // Server result
    let server_session_id = server_handle
        .await
        .expect("Server task panicked")
        .expect("Server handshake should succeed");
    assert_eq!(
        server_session_id, session_id,
        "Both sides must agree on session ID"
    );

    // Verify session is registered on server
    assert!(
        sm.validate_session(&session_id).unwrap(),
        "Session must be active on server"
    );
}

// ─── Rejection Cases ─────────────────────────────────────────────────

#[tokio::test]
async fn test_handshake_version_mismatch_rejected() {
    let master = make_master_secret();
    let (client_transport, server_transport) = MockTransport::new_pair(16);
    let session_manager = Arc::new(SessionManager::new());

    // Clone values for the async server task
    let server_master = master.clone();
    let server_transport = Arc::new(server_transport);
    let sm_for_server = Arc::clone(&session_manager);

    let server_handle = {
        let transport = Arc::clone(&server_transport);
        tokio::spawn(async move {
            let t = as_transport(&transport);
            server_handshake(
                t,
                &sm_for_server,
                server_capabilities(),
                &server_master,
                KeyRotationPolicy::Manual,
                DEFAULT_HANDSHAKE_TIMEOUT,
            )
            .await
        })
    };

    // Send a crafted HandshakeRequest with incompatible version
    let incompatible_version = ProtocolVersion::new(CURRENT_VERSION.major + 1, 0);
    let request = HandshakeRequest {
        client_version: incompatible_version,
        supported_capabilities: client_capabilities(),
        device_id: make_client_device_id(),
        nonce: [0u8; 16],
        timestamp: 1,
    };

    let frame = build_handshake_frame(
        MessageType::Hello,
        &request,
        make_client_device_id(),
        SessionId([0u8; 16]),
    )
    .unwrap();
    client_transport
        .as_ref()
        .send(frame.borrow())
        .await
        .unwrap();

    // Client should receive a rejection response
    let response_frame = client_transport.as_ref().receive().await.unwrap();

    // Parse the nested serialization: frame.payload → MessageEnvelope → HandshakeResponse
    let envelope: MessageEnvelope = ciborium::de::from_reader(&response_frame.payload[..]).unwrap();
    let hs_response: HandshakeResponse =
        ciborium::de::from_reader(&envelope.message.payload[..]).unwrap();

    assert_eq!(
        hs_response.status,
        HandshakeStatus::RejectedVersionMismatch,
        "Server must reject incompatible version"
    );

    // Server should have errored (rejection)
    let server_result = server_handle.await.expect("Server task panicked");
    assert!(
        server_result.is_err(),
        "Server handshake must return error on version mismatch"
    );
}

// ─── Transport Errors ─────────────────────────────────────────────────

#[tokio::test]
async fn test_handshake_transport_disconnect_returns_error() {
    let master = make_master_secret();
    let (client_transport, server_transport) = MockTransport::new_pair(16);

    // Close both sides so send() fails immediately
    client_transport.as_ref().close().await.unwrap();
    server_transport.as_ref().close().await.unwrap();

    let result = client_handshake(
        as_transport(&client_transport),
        make_client_device_id(),
        client_capabilities(),
        &master,
        KeyRotationPolicy::Manual,
        DEFAULT_HANDSHAKE_TIMEOUT,
    )
    .await;

    assert!(
        result.is_err(),
        "Client handshake should fail on disconnected transport"
    );
}

// ─── Multiple Concurrent Handshakes ───────────────────────────────────

#[tokio::test]
async fn test_handshake_multiple_sessions_independent() {
    let master = make_master_secret();
    let session_manager = Arc::new(SessionManager::new());
    let mut session_ids = Vec::new();

    for i in 0..3 {
        let (client_transport, server_transport) = MockTransport::new_pair(16);

        // Clone values for the async server task — each iteration gets fresh clones
        let server_master = master.clone();
        let sm_for_server = Arc::clone(&session_manager);
        let server_transport = Arc::new(server_transport);

        let server_handle = {
            let transport = Arc::clone(&server_transport);
            tokio::spawn(async move {
                let t = as_transport(&transport);
                server_handshake(
                    t,
                    &sm_for_server,
                    server_capabilities(),
                    &server_master,
                    KeyRotationPolicy::Manual,
                    DEFAULT_HANDSHAKE_TIMEOUT,
                )
                .await
            })
        };

        // Client uses separate clones — not moved into the server task
        let client_master = master.clone();
        let result = client_handshake(
            as_transport(&client_transport),
            make_client_device_id(),
            client_capabilities(),
            &client_master,
            KeyRotationPolicy::Manual,
            DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .await;

        let (sid, _ctx) =
            result.unwrap_or_else(|_| panic!("Client handshake {} should succeed", i));
        let server_sid = server_handle
            .await
            .expect("Server task panicked")
            .unwrap_or_else(|_| panic!("Server handshake {} should succeed", i));

        assert_eq!(
            sid, server_sid,
            "Both sides must agree on session ID for handshake {}",
            i
        );
        assert!(
            session_manager.validate_session(&sid).unwrap(),
            "Session {} must be active",
            i
        );
        session_ids.push(sid);
    }

    // All session IDs must be distinct
    let unique: HashSet<SessionId> = session_ids.into_iter().collect();
    assert_eq!(unique.len(), 3, "All 3 sessions must have unique IDs");
}
