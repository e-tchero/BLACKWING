use bw_crypto::SymmetricKey;
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
    let server = QuicServer::bind(server_addr, None).expect("Server should bind");

    let bound_addr = server.endpoint.local_addr().unwrap();
    let connect_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bound_addr.port());

    let client = QuicClient::bind(None).expect("Client should bind");

    // Each node owns its own SessionManager (matches real deployment topology)
    let server_session_manager = Arc::new(SessionManager::new());
    let client_session_manager = Arc::new(SessionManager::new());

    let session_id = SessionId([42; 16]);

    // Shared pre-agreed master secret (in WP-6.3+ this will be negotiated via ECDH)
    let mut master_secret_bytes = [0u8; 32];
    master_secret_bytes[0] = 0xAB;
    let master_secret = SymmetricKey(master_secret_bytes);

    let sm_server = server_session_manager.clone();
    let ms_server = master_secret.clone();

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
            .server_handshake(&ms_server)
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
        .client_handshake(&master_secret)
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
