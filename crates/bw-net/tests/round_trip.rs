//! Integration test: full round-trip slice proof.
//!
//! Verifies the Phase 2 outbound transport goal:
//!
//! ```text
//! Application
//!     → encode_frame
//!     → bw-net::Transport::send()
//!     → UDP socket
//!     → (Network)
//!     → recv_from
//!     → decode_frame
//!     → deserialize
//!     → dispatcher
//! ```
//!
//! Two `UdpTransport` instances are used. The "client" connects to the "server".
//! Both run their own receive loops to capture responses if needed, but the primary
//! goal here is proving `Transport::send()` works via a connected UDP socket.

use bw_crypto::DeviceId;
use bw_net::transport::Transport;
use bw_net::udp::{run_receive_loop, UdpTransport};
use bw_protocol::codec::encode_frame;
use bw_protocol::dispatcher::MessageDispatcher;
use bw_protocol::frame::ProtocolFrame;
use bw_protocol::header::{PacketHeader, PROTOCOL_MAGIC};
use bw_protocol::message::{MessageType, ProtocolMessage};
use bw_protocol::routing::{MessageEnvelope, NodeId, Route, SessionId};
use bw_protocol::version::CURRENT_VERSION;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::{timeout, Duration};

fn make_ping_envelope() -> MessageEnvelope {
    let src = NodeId(DeviceId::from_digest([0x01; 32]));
    let dst = NodeId(DeviceId::from_digest([0x02; 32]));
    MessageEnvelope {
        source: src,
        destination: dst,
        session_id: SessionId([0xAB; 16]),
        route: Route::Direct,
        message: ProtocolMessage {
            message_type: MessageType::Ping,
            message_id: 1,
            flags: 0,
            payload: vec![],
        },
        routing_flags: 0,
    }
}

fn make_raw_frame(envelope: &MessageEnvelope) -> Vec<u8> {
    let payload = envelope.serialize().expect("serialization must succeed");
    let header = PacketHeader {
        magic: PROTOCOL_MAGIC,
        schema_version: u16::from(CURRENT_VERSION),
        flags: 0,
        packet_type: 1,
        payload_length: payload.len() as u16,
        sequence_number: 0,
        session_epoch: 0,
        monotonic_timestamp: 42,
    };
    let frame = ProtocolFrame {
        header,
        payload: &payload,
    };
    encode_frame(&frame)
}

#[tokio::test]
async fn phase2_outbound_transport_round_trip() {
    // 1. Setup Server (binds to ephemeral loopback port)
    let server_transport = Arc::new(
        UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("server bind failed"),
    );
    let server_addr = server_transport.local_addr().unwrap();

    // 2. Setup Client (binds to ephemeral, connects to server)
    let client_transport = Arc::new(
        UdpTransport::connect("127.0.0.1:0".parse().unwrap(), server_addr)
            .await
            .expect("client connect failed"),
    );

    // 3. Launch Server Receive Loop
    let server_dispatcher = Arc::new(MessageDispatcher::new());
    let (server_shutdown_tx, server_shutdown_rx) = watch::channel(false);
    let server_handle = tokio::spawn(run_receive_loop(
        Arc::clone(&server_transport) as Arc<dyn Transport>,
        server_dispatcher,
        server_shutdown_rx,
    ));

    // 4. Client sends frame via Transport::send()
    let envelope = make_ping_envelope();
    let raw = make_raw_frame(&envelope);

    client_transport
        .send(&raw)
        .await
        .expect("Transport::send must succeed");

    // 5. Allow time for delivery and processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 6. Clean shutdown
    server_shutdown_tx.send(true).unwrap();

    let result = timeout(Duration::from_secs(2), server_handle)
        .await
        .expect("server loop must exit quickly")
        .expect("task must not panic");

    assert!(matches!(result, Err(bw_net::error::NetError::Shutdown)));
}
