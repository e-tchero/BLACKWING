//! End-to-end test of the session wire protocol over a real QUIC connection.
//!
//! Proves the full path the binaries use:
//!
//! ```text
//! client: QuicClient → connect → open_bi → OPAQUE login → MessageSession
//! server: QuicServer → accept → accept_bi → OPAQUE login → MessageSession
//! then: client sends an input message, server receives and dispatches it.
//! ```
#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use bw_auth::store::EnrollmentStore;
use bw_crypto::DeviceId;
use bw_protocol::dispatcher::{DispatchError, MessageDispatcher};
use bw_protocol::message::{MessageType, ProtocolMessage};
use bw_protocol::routing::{MessageEnvelope, NodeId, Route, SessionId};
use bw_protocol::session::SessionManager;
use bw_session::wire;
use bw_transport::adapter::QuicProtocolAdapter;
use bw_transport::{QuicClient, QuicServer};
use tokio::time::{timeout, Duration};

const DEVICE_ID: &str = "test-device";
const PASSWORD: &str = "correct horse battery staple";

/// A dispatcher handler that records the messages it receives.
#[derive(Default)]
struct RecordingHandler {
    messages: std::sync::Mutex<Vec<MessageType>>,
}

impl RecordingHandler {
    fn record(&self, envelope: MessageEnvelope) -> Result<(), DispatchError> {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(envelope.message.message_type);
        Ok(())
    }

    fn received(&self) -> Vec<MessageType> {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

fn make_node_id(val: u8) -> NodeId {
    NodeId(DeviceId::from_digest([val; 32]))
}

/// Wraps a message in a directly-routed envelope, matching what the client
/// binary produces.
fn wrap(message: ProtocolMessage) -> MessageEnvelope {
    MessageEnvelope {
        source: make_node_id(1),
        destination: make_node_id(2),
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message,
        routing_flags: 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_full_session_wire_exchange() {
    // ── Server side ────────────────────────────────────────────────────────
    let mut store = EnrollmentStore::new();
    store
        .register(DEVICE_ID.as_bytes(), PASSWORD.as_bytes())
        .unwrap();
    let store = Arc::new(store);
    let server_manager = Arc::new(SessionManager::new());

    let server_addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let quic_server = QuicServer::bind_dev(server_addr, None).unwrap();
    let bound_addr = quic_server.endpoint.local_addr().unwrap();

    let server_dispatcher = Arc::new(MessageDispatcher::new());
    let recorder = Arc::new(RecordingHandler::default());
    server_dispatcher.register_handler(
        MessageType::InputKeyboard,
        Arc::new({
            let recorder = Arc::clone(&recorder);
            move |envelope| recorder.record(envelope)
        }),
    );

    let accept_handle = tokio::spawn(async move {
        let conn = quic_server.accept().await.expect("connection accepted");
        let (send, recv) = conn.accept_bi().await.expect("bidi stream");
        let adapter = QuicProtocolAdapter::new(send, recv);
        let (session, identifier) =
            wire::server_establish(adapter, Arc::clone(&server_manager), &store)
                .await
                .expect("server establish");
        assert_eq!(
            String::from_utf8_lossy(&identifier),
            DEVICE_ID,
            "server sees the client's identifier"
        );

        let (mut sender, mut receiver) = session.into_split();

        // Serve one inbound message then exit.
        let message = receiver.recv_message().await.expect("client message");
        let envelope = wrap(message);
        server_dispatcher
            .dispatch(envelope)
            .expect("dispatch succeeds");

        // Echo a clipboard event back to prove the return path works.
        let reply = ProtocolMessage::clipboard_event(bw_protocol::message::ClipboardEvent {
            format: bw_protocol::message::ClipboardFormat::Text,
            data: b"hello from server".to_vec(),
        })
        .unwrap();
        sender.send_message(&reply).await.expect("send reply");
        sender.close().await;

        // Keep the connection alive until the client closes it, so the reply
        // is guaranteed to be flushed and acknowledged before we drop it.
        conn.closed().await;
    });

    // ── Client side ────────────────────────────────────────────────────────
    let quic_client = QuicClient::bind_dev(None).unwrap();
    let conn = timeout(Duration::from_secs(10), quic_client.connect(bound_addr))
        .await
        .expect("connect within timeout")
        .expect("connect succeeds");

    let (send, recv) = conn.open_bi().await.expect("open bidi stream");
    let adapter = QuicProtocolAdapter::new(send, recv);
    let client_manager = Arc::new(SessionManager::new());
    let mut session = wire::client_establish(
        adapter,
        Arc::clone(&client_manager),
        DEVICE_ID.as_bytes(),
        PASSWORD.as_bytes(),
    )
    .await
    .expect("client establish");

    // Send an input message (as the real client would on a key press).
    let message = ProtocolMessage::keyboard_event(0x41, true).unwrap();
    session.send_message(&message).await.expect("send message");

    // Receive the server's clipboard reply.
    let reply = timeout(Duration::from_secs(10), session.recv_message())
        .await
        .expect("reply within timeout")
        .expect("recv message");
    assert_eq!(reply.message_type, MessageType::ClipboardData);

    session.close().await;

    // Signal the server that the session is over by closing the QUIC
    // connection; the server waits on `conn.closed()` before dropping it.
    conn.close(0u32.into(), b"session complete");
    timeout(Duration::from_secs(10), accept_handle)
        .await
        .expect("server task within timeout")
        .expect("server task finished");

    // The server must have dispatched exactly the keyboard message.
    let received = recorder.received();
    assert_eq!(received, vec![MessageType::InputKeyboard]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_wrong_password_rejected() {
    let mut store = EnrollmentStore::new();
    store
        .register(DEVICE_ID.as_bytes(), PASSWORD.as_bytes())
        .unwrap();
    let store = Arc::new(store);
    let server_manager = Arc::new(SessionManager::new());

    let server_addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let quic_server = QuicServer::bind_dev(server_addr, None).unwrap();
    let bound_addr = quic_server.endpoint.local_addr().unwrap();

    let accept_handle = tokio::spawn(async move {
        let conn = quic_server.accept().await.expect("connection accepted");
        let (send, recv) = conn.accept_bi().await.expect("bidi stream");
        let adapter = QuicProtocolAdapter::new(send, recv);
        // The server-side login fails when the client's password is wrong.
        let result = wire::server_establish(adapter, Arc::clone(&server_manager), &store).await;
        assert!(result.is_err(), "server must reject a wrong-password login");
    });

    let quic_client = QuicClient::bind_dev(None).unwrap();
    let conn = timeout(Duration::from_secs(10), quic_client.connect(bound_addr))
        .await
        .expect("connect within timeout")
        .expect("connect succeeds");

    let (send, recv) = conn.open_bi().await.expect("open bidi stream");
    let adapter = QuicProtocolAdapter::new(send, recv);
    let client_manager = Arc::new(SessionManager::new());
    let result = wire::client_establish(
        adapter,
        Arc::clone(&client_manager),
        DEVICE_ID.as_bytes(),
        b"wrong password",
    )
    .await;
    assert!(
        result.is_err(),
        "client establish must fail on wrong password"
    );

    accept_handle.await.expect("server task finished");
}

/// Proves that a message whose encrypted form exceeds the 16-bit wire
/// `payload_length` limit (a 200 KB payload -> 4 fragments of 60 KB) survives
/// a full round-trip through the session layer over a real QUIC connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_large_message_fragmentation_roundtrip() {
    const BIG_SIZE: usize = 200_000; // > 3 x FRAGMENT_SIZE, far over u16::MAX

    let mut store = EnrollmentStore::new();
    store
        .register(DEVICE_ID.as_bytes(), PASSWORD.as_bytes())
        .unwrap();
    let store = Arc::new(store);
    let server_manager = Arc::new(SessionManager::new());

    let server_addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let quic_server = QuicServer::bind_dev(server_addr, None).unwrap();
    let bound_addr = quic_server.endpoint.local_addr().unwrap();

    let accept_handle = tokio::spawn(async move {
        let conn = quic_server.accept().await.expect("connection accepted");
        let (send, recv) = conn.accept_bi().await.expect("bidi stream");
        let adapter = QuicProtocolAdapter::new(send, recv);
        let (session, _identifier) =
            wire::server_establish(adapter, Arc::clone(&server_manager), &store)
                .await
                .expect("server establish");

        let (mut sender, mut receiver) = session.into_split();

        // Receive the big fragmented message and echo it back unchanged.
        let message = receiver
            .recv_message()
            .await
            .expect("receive fragmented message");
        assert_eq!(message.message_type, MessageType::Data);
        assert_eq!(message.payload.len(), BIG_SIZE);
        assert!(message.payload.iter().all(|&b| b == 0x42));

        sender
            .send_message(&message)
            .await
            .expect("echo fragmented message");
        sender.close().await;

        conn.closed().await;
    });

    let quic_client = QuicClient::bind_dev(None).unwrap();
    let conn = timeout(Duration::from_secs(10), quic_client.connect(bound_addr))
        .await
        .expect("connect within timeout")
        .expect("connect succeeds");

    let (send, recv) = conn.open_bi().await.expect("open bidi stream");
    let adapter = QuicProtocolAdapter::new(send, recv);
    let client_manager = Arc::new(SessionManager::new());
    let mut session = wire::client_establish(
        adapter,
        Arc::clone(&client_manager),
        DEVICE_ID.as_bytes(),
        PASSWORD.as_bytes(),
    )
    .await
    .expect("client establish");

    let big = ProtocolMessage {
        message_type: MessageType::Data,
        message_id: 42,
        flags: 0,
        payload: vec![0x42u8; BIG_SIZE],
    };
    session.send_message(&big).await.expect("send big message");

    let echo = timeout(Duration::from_secs(10), session.recv_message())
        .await
        .expect("echo within timeout")
        .expect("recv echo");
    assert_eq!(echo.message_type, MessageType::Data);
    assert_eq!(echo.payload.len(), BIG_SIZE);
    assert_eq!(echo.payload, big.payload, "round-trip byte integrity");

    session.close().await;
    conn.close(0u32.into(), b"session complete");
    timeout(Duration::from_secs(10), accept_handle)
        .await
        .expect("server task within timeout")
        .expect("server task finished");
}
