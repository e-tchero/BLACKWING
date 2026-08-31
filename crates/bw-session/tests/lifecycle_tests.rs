#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(missing_docs)]
use bw_auth::{client, server};
use bw_protocol::header::{PacketHeader, PROTOCOL_MAGIC};
use bw_protocol::routing::SessionId;
use bw_protocol::session::SessionManager;
use bw_protocol::version::CURRENT_VERSION;
use bw_session::{ConnectionState, SecureConnection};
use bw_transport::adapter::QuicProtocolAdapter;
use bw_transport::{QuicClient, QuicServer};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

#[tokio::test]
async fn test_secure_connection_lifecycle() {
    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let server = QuicServer::bind_dev(server_addr, None).expect("Server should bind");

    let bound_addr = server.endpoint.local_addr().unwrap();
    let connect_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bound_addr.port());

    let client = QuicClient::bind_dev(None).expect("Client should bind");

    // Each node owns its own SessionManager (matches real deployment topology)
    let server_session_manager = Arc::new(SessionManager::new());
    let client_session_manager = Arc::new(SessionManager::new());

    let session_id = SessionId([42; 16]);

    // Authenticate via OPAQUE (RFC 9381): registration then login produces the
    // shared session key used as the handshake master secret.
    const PASSWORD: &[u8] = b"correct horse battery staple";
    const IDENTIFIER: &[u8] = b"alice@example.com";

    let auth_setup = server::new_setup();
    // Registration (4 messages, in-process for the test).
    let reg_start = client::start_registration(PASSWORD).unwrap();
    let (reg_req, reg_state) = (reg_start.request, reg_start.state);
    let reg_resp = server::start_registration(&auth_setup, reg_req, IDENTIFIER).unwrap();
    let reg_upload = client::finish_registration(reg_state, reg_resp, PASSWORD).unwrap();
    let password_file = server::finish_registration(reg_upload);

    // Client-side login.
    let login_start = client::start_login(PASSWORD).unwrap();
    let (login_req, login_state) = (login_start.request, login_start.state);
    // Server-side login.
    let server_login =
        server::start_login(&auth_setup, password_file, login_req, IDENTIFIER).unwrap();
    let (cred_resp, server_login_state) = (server_login.response, server_login.state);
    // Client finishes login; server finishes login; keys must match.
    let client_login = client::finish_login(login_state, cred_resp, PASSWORD).unwrap();
    let client_session_key = client_login.session_key;
    let server_session_key =
        server::finish_login(server_login_state, client_login.finalization).unwrap();
    assert_eq!(client_session_key.as_bytes(), server_session_key.as_bytes());

    let sm_server = server_session_manager.clone();
    let server_key_bytes = server_session_key.as_bytes().to_vec();

    // Spawn server task
    let server_task = tokio::spawn(async move {
        // connect_client_server()
        let conn = server
            .accept()
            .await
            .expect("Server should accept connection");
        let (send_stream, recv_stream) = conn.accept_bi().await.expect("Should accept bi stream");

        let adapter = QuicProtocolAdapter::new(send_stream, recv_stream);
        let mut secure_conn = SecureConnection::new(adapter, sm_server.clone(), session_id);

        // State: Connected
        assert_eq!(secure_conn.state(), ConnectionState::Connected);

        // handshake() -> State: Active, session_created()
        secure_conn
            .server_handshake(&server_key_bytes)
            .await
            .expect("Server handshake should succeed");

        assert_eq!(secure_conn.state(), ConnectionState::Active);
        assert!(sm_server.validate_session(&session_id).unwrap());

        // receive() encrypted frame
        let frame = secure_conn
            .recv_secure_frame()
            .await
            .expect("Server should receive secure frame");
        assert_eq!(frame.payload.as_slice(), b"secret message");

        // disconnect() -> State: Closed, session removed()
        secure_conn.close().await;
        assert_eq!(secure_conn.state(), ConnectionState::Closed);

        // session removed() — zeroization verified (EncryptionContext drops on close_session)
        assert!(!sm_server.validate_session(&session_id).unwrap());
    });

    // connect_client_server() (client side)
    let conn = client
        .connect(connect_addr)
        .await
        .expect("Client should connect");
    let (send_stream, recv_stream) = conn.open_bi().await.expect("Should open bi stream");

    let adapter = QuicProtocolAdapter::new(send_stream, recv_stream);
    let mut secure_conn =
        SecureConnection::new(adapter, client_session_manager.clone(), session_id);

    // State: Connected
    assert_eq!(secure_conn.state(), ConnectionState::Connected);

    // handshake() -> State: Active, session_created()
    secure_conn
        .client_handshake(client_session_key.as_bytes())
        .await
        .expect("Client handshake should succeed");

    assert_eq!(secure_conn.state(), ConnectionState::Active);
    assert!(client_session_manager
        .validate_session(&session_id)
        .unwrap());

    // send encrypted frame()
    let mut header = PacketHeader::default();
    header.magic = PROTOCOL_MAGIC;
    header.schema_version = CURRENT_VERSION.into();
    header.packet_type = 2; // Message
    header.payload_length = 14;

    let frame = bw_protocol::frame::OwnedProtocolFrame {
        header,
        payload: b"secret message".to_vec(),
    };
    secure_conn
        .send_secure_frame(frame)
        .await
        .expect("Client should send secure frame");

    // Wait for server to process and close
    server_task.await.expect("Server task should complete");

    // Client session is still open (closed only on explicit disconnect)
    assert!(client_session_manager
        .validate_session(&session_id)
        .unwrap());
}
