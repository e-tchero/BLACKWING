//! Integration tests: Resilience and Edge Cases
//!
//! Verifies that the receive loop correctly handles hostile or accidental
//! network noise without panicking or deadlocking.
//!
//! Test matrix:
//! - empty datagrams
//! - random binary garbage
//! - truncated frames
//! - invalid protocol magic
//! - invalid protocol version
//! - valid header / truncated payload
//! - valid frame / garbage CBOR envelope payload
//! - rapid-fire malformed packets
//! - large valid frames (near MTU limit)

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
use tokio::time::{sleep, timeout, Duration};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Build a valid ping-bound `MessageEnvelope` with a configurable payload.
fn make_ping_envelope(payload: Vec<u8>) -> MessageEnvelope {
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
            payload,
        },
        routing_flags: 0,
    }
}

/// Build a raw byte frame from a header and payload slice.
fn make_raw_frame(header: PacketHeader, payload: &[u8]) -> Vec<u8> {
    let frame = ProtocolFrame { header, payload };
    encode_frame(&frame)
}

/// Spawn a `run_receive_loop` task and return handles for sending packets
/// and cleanly shutting it down.
async fn spawn_receiver() -> (
    tokio::net::UdpSocket, // sender socket
    std::net::SocketAddr,  // receiver address
    watch::Sender<bool>,   // shutdown signal
    tokio::task::JoinHandle<Result<(), bw_net::error::NetError>>,
) {
    use tokio::net::UdpSocket;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("receiver bind");
    let receiver_addr = transport.local_addr().expect("local_addr");

    let dispatcher = Arc::new(MessageDispatcher::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let loop_handle = tokio::spawn(run_receive_loop(
        Arc::new(transport) as Arc<dyn Transport>,
        dispatcher,
        shutdown_rx,
    ));

    let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender bind");

    (sender, receiver_addr, shutdown_tx, loop_handle)
}

/// Assert that the receive loop is still running (hasn't panicked).
fn assert_loop_alive(handle: &tokio::task::JoinHandle<Result<(), bw_net::error::NetError>>) {
    assert!(
        !handle.is_finished(),
        "Receive loop crashed (task finished unexpectedly)"
    );
}

// ── Malformed & Truncated Packet Tests ──────────────────────────────────────

#[tokio::test]
async fn phase4_resilience_malformed_and_truncated() {
    let (sender, receiver_addr, shutdown_tx, loop_handle) = spawn_receiver().await;

    // ── Test 1: Empty datagram (0 bytes) ──────────────────────────────────
    sender
        .send_to(&[], receiver_addr)
        .await
        .expect("send empty");
    sleep(Duration::from_millis(50)).await;
    assert_loop_alive(&loop_handle);

    // ── Test 2: Random binary garbage (256 bytes) ─────────────────────────
    let garbage: Vec<u8> = (0..256).map(|i| (i ^ 0xAB) as u8).collect();
    sender
        .send_to(&garbage, receiver_addr)
        .await
        .expect("send garbage");
    sleep(Duration::from_millis(50)).await;
    assert_loop_alive(&loop_handle);

    // ── Test 3: Truncated header (4 bytes where 32 are expected) ─────────
    sender
        .send_to(b"BWPG", receiver_addr)
        .await
        .expect("send truncated header");
    sleep(Duration::from_millis(50)).await;
    assert_loop_alive(&loop_handle);

    // ── Test 4: Full 32-byte header, invalid magic bytes ──────────────────
    let bad_magic_header = PacketHeader {
        magic: [0xDE, 0xAD, 0xBE, 0xEF],
        schema_version: u16::from(CURRENT_VERSION),
        flags: 0,
        packet_type: 0,
        payload_length: 0,
        sequence_number: 0,
        session_epoch: 0,
        monotonic_timestamp: 0,
    };
    sender
        .send_to(bad_magic_header.as_bytes(), receiver_addr)
        .await
        .expect("send bad magic");
    sleep(Duration::from_millis(50)).await;
    assert_loop_alive(&loop_handle);

    // ── Test 5: Valid header, unsupported version ──────────────────────────
    let bad_version_header = PacketHeader {
        magic: PROTOCOL_MAGIC,
        schema_version: 0xFFFF, // version 255.255 — definitely unsupported
        flags: 0,
        packet_type: 0,
        payload_length: 0,
        sequence_number: 0,
        session_epoch: 0,
        monotonic_timestamp: 0,
    };
    sender
        .send_to(bad_version_header.as_bytes(), receiver_addr)
        .await
        .expect("send bad version");
    sleep(Duration::from_millis(50)).await;
    assert_loop_alive(&loop_handle);

    // ── Test 6: Valid header, claims large payload but truncated ───────────
    let truncated_header = PacketHeader {
        magic: PROTOCOL_MAGIC,
        schema_version: u16::from(CURRENT_VERSION),
        flags: 0,
        packet_type: 1,
        payload_length: 1000, // claims 1000 bytes
        sequence_number: 0,
        session_epoch: 0,
        monotonic_timestamp: 42,
    };
    let mut truncated_bytes = truncated_header.as_bytes().to_vec();
    truncated_bytes.extend_from_slice(b"short"); // only 5 bytes where 1000 expected
    sender
        .send_to(&truncated_bytes, receiver_addr)
        .await
        .expect("send truncated payload");
    sleep(Duration::from_millis(50)).await;
    assert_loop_alive(&loop_handle);

    // ── Test 7: Correct frame structure, garbage CBOR in payload ──────────
    let garbage_payload: Vec<u8> = (0..64).map(|i| (i ^ 0xFF) as u8).collect();
    let garbage_envelope_header = PacketHeader {
        magic: PROTOCOL_MAGIC,
        schema_version: u16::from(CURRENT_VERSION),
        flags: 0,
        packet_type: 1,
        payload_length: garbage_payload.len() as u16,
        sequence_number: 0,
        session_epoch: 0,
        monotonic_timestamp: 42,
    };
    let bad_envelope_frame = make_raw_frame(garbage_envelope_header, &garbage_payload);
    sender
        .send_to(&bad_envelope_frame, receiver_addr)
        .await
        .expect("send garbage envelope");
    sleep(Duration::from_millis(50)).await;
    assert_loop_alive(&loop_handle);

    // ── Test 8: Ten rapid-fire garbage packets ────────────────────────────
    for _ in 0..10 {
        let rapid_garbage: Vec<u8> = (0..128).map(|i| (i ^ 0x42) as u8).collect();
        sender
            .send_to(&rapid_garbage, receiver_addr)
            .await
            .expect("send rapid garbage");
    }
    sleep(Duration::from_millis(150)).await;
    assert_loop_alive(&loop_handle);

    // ── Clean shutdown ───────────────────────────────────────────────────
    shutdown_tx.send(true).expect("shutdown signal");
    let result = timeout(Duration::from_secs(2), loop_handle)
        .await
        .expect("loop must exit within 2s")
        .expect("task must not panic");
    assert!(
        matches!(result, Err(bw_net::error::NetError::Shutdown)),
        "Expected Shutdown, got {:?}",
        result
    );
}

// ── Near-MTU-Sized Frame Test ────────────────────────────────────────────────
//
// NOTE: The `bytes.len() > MAX_DATAGRAM_SIZE` defensive check in
// `run_receive_loop` (MAX_DATAGRAM_SIZE = 65536) cannot be triggered via
// real UDP because the maximum IPv4 datagram payload is 65507 bytes.
//
// Instead, this test proves that the loop correctly handles a large but
// valid frame, which exercises the codec, envelope deserializer, and
// dispatcher on near-MTU-sized data without crashing or deadlocking.
//
// CBOR note: `Vec<u8>` is serialized as an array of unsigned integers, not
// as a compact byte string. Each byte value >= 24 takes 2 CBOR bytes, so
// a payload of N bytes expands to ~1.9 N CBOR bytes. The total frame must
// stay below the IPv4 UDP payload limit of 65507 bytes.

#[tokio::test]
async fn phase4_resilience_oversized() {
    let (sender, receiver_addr, shutdown_tx, loop_handle) = spawn_receiver().await;

    // Build a valid envelope with a ~10,000 byte payload.
    // CBOR serializes Vec<u8> as an array of integers (~1.9x expansion),
    // so the total frame will be approximately 19,000 + 300 = 19,300 bytes,
    // well within the 65,507 byte UDP limit.
    let large_payload: Vec<u8> = (0..10_000).map(|i| (i & 0xFF) as u8).collect();
    let envelope = make_ping_envelope(large_payload);
    let payload = envelope.serialize().expect("envelope serialization");

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
    let frame = make_raw_frame(header, &payload);

    // Verify the frame fits within a single IPv4 UDP datagram
    assert!(
        frame.len() <= 65_507,
        "Test frame ({} bytes) exceeds IPv4 UDP max payload (65507). \
         CBOR Vec<u8> expansion is ~1.9x — consider reducing payload size.",
        frame.len()
    );

    sender
        .send_to(&frame, receiver_addr)
        .await
        .expect("send large frame");
    sleep(Duration::from_millis(200)).await;
    assert_loop_alive(&loop_handle);

    // ── Clean shutdown ───────────────────────────────────────────────────
    shutdown_tx.send(true).expect("shutdown signal");
    let result = timeout(Duration::from_secs(2), loop_handle)
        .await
        .expect("loop must exit within 2s")
        .expect("task must not panic");
    assert!(
        matches!(result, Err(bw_net::error::NetError::Shutdown)),
        "Expected Shutdown, got {:?}",
        result
    );
}
