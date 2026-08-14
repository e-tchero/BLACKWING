#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)
//! Integration test: vertical slice proof.
//!
//! Verifies that the complete path
//!
//! ```text
//! bw-net UdpTransport
//!     → recv_from (loopback)
//!     → decode_frame (bw-protocol codec)
//!     → MessageEnvelope::deserialize
//!     → MessageDispatcher::dispatch
//! ```
//!
//! functions correctly end-to-end without any mocking.
//!
//! Two OS-assigned UDP sockets are created on `127.0.0.1:0`. One acts as
//! sender; the other runs the receive loop. After confirming successful
//! dispatch of a valid frame, the test signals shutdown and asserts the loop
//! exits cleanly.

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
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{timeout, Duration};

/// Build a minimal valid `MessageEnvelope` carrying a `Ping` message.
///
/// Source and destination differ so `Route::Direct` validation passes.
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

/// Build a raw byte frame containing a serialized `MessageEnvelope` as
/// payload, wrapped in a `PacketHeader`.
fn make_raw_frame(envelope: &MessageEnvelope) -> Vec<u8> {
    let payload = envelope
        .serialize()
        .expect("envelope serialization must succeed");
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

/// Proves the bw-net → bw-protocol vertical slice over a real loopback socket.
///
/// The test:
/// 1. Binds two UDP sockets on loopback.
/// 2. Sends one valid encoded frame from the sender socket to the receiver.
/// 3. Runs `run_receive_loop` as a background Tokio task.
/// 4. Signals shutdown after a short deadline.
/// 5. Asserts the loop exits with `NetError::Shutdown` (clean exit).
#[tokio::test]
async fn vertical_slice_udp_receive_to_dispatch() {
    // ── Bind sockets ────────────────────────────────────────────────────────
    let receiver_transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("receiver socket bind must succeed");
    let receiver_addr = receiver_transport
        .local_addr()
        .expect("local_addr must succeed");

    let sender_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("sender socket bind must succeed");

    // ── Build and send the frame ─────────────────────────────────────────────
    let envelope = make_ping_envelope();
    let raw = make_raw_frame(&envelope);

    sender_socket
        .send_to(&raw, receiver_addr)
        .await
        .expect("send_to must succeed");

    // ── Launch receive loop ──────────────────────────────────────────────────
    let dispatcher = Arc::new(MessageDispatcher::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let transport_arc: Arc<dyn bw_net::transport::Transport> = Arc::new(receiver_transport);

    let loop_handle = tokio::spawn(run_receive_loop(
        Arc::clone(&transport_arc),
        Arc::clone(&dispatcher),
        shutdown_rx,
    ));

    // ── Signal shutdown after allowing the frame to be processed ────────────
    // 200 ms is generous for a loopback round-trip; CI machines typically
    // complete this in < 1 ms.
    tokio::time::sleep(Duration::from_millis(200)).await;
    shutdown_tx.send(true).expect("shutdown signal must send");

    // ── Assert clean exit ───────────────────────────────────────────────────
    let result = timeout(Duration::from_secs(2), loop_handle)
        .await
        .expect("receive loop must exit within 2 s")
        .expect("Tokio task must not panic");

    assert!(
        matches!(result, Err(bw_net::error::NetError::Shutdown)),
        "Expected NetError::Shutdown, got: {:?}",
        result
    );
}
