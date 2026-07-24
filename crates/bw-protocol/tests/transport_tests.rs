use bw_crypto::DeviceId;
use bw_protocol::dispatcher::MessageDispatcher;
use bw_protocol::frame::ProtocolFrame;
use bw_protocol::header::{PacketHeader, PROTOCOL_MAGIC};
use bw_protocol::message::{MessageType, ProtocolMessage};
use bw_protocol::routing::{MessageEnvelope, NodeId, Route, SessionId};
use bw_protocol::transport::{ConnectionState, MockTransport, Transport};
use bw_protocol::version::CURRENT_VERSION;

fn make_node_id(val: u8) -> NodeId {
    NodeId(DeviceId::from_digest([val; 32]))
}

fn make_envelope() -> MessageEnvelope {
    let msg = ProtocolMessage {
        message_type: MessageType::Ping,
        message_id: 1,
        flags: 0,
        payload: vec![],
    };
    MessageEnvelope {
        source: make_node_id(1),
        destination: make_node_id(2),
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message: msg,
        routing_flags: 0,
    }
}

#[tokio::test]
async fn test_mock_transport_send_receive() {
    let (t1, t2) = MockTransport::new_pair(10);
    assert_eq!(t1.state(), ConnectionState::Connected);
    assert_eq!(t2.state(), ConnectionState::Connected);

    let envelope = make_envelope();
    let payload = envelope.serialize().unwrap();

    let header = PacketHeader {
        magic: PROTOCOL_MAGIC,
        schema_version: u16::from(CURRENT_VERSION),
        flags: 0,
        packet_type: 1,
        payload_length: payload.len() as u16,
        sequence_number: 1,
        session_epoch: 12345,
        monotonic_timestamp: 67890,
    };

    let frame = ProtocolFrame {
        header,
        payload: &payload,
    };

    t1.send(frame).await.unwrap();

    let received = t2.receive().await.unwrap();
    assert_eq!(received.header, header);
    assert_eq!(received.payload, payload);

    t1.close().await.unwrap();
    assert_eq!(t1.state(), ConnectionState::Disconnected);
}

#[tokio::test]
async fn test_dispatcher_run() {
    let (t1, t2) = MockTransport::new_pair(10);
    let dispatcher = MessageDispatcher::new();

    let envelope = make_envelope();
    let payload = envelope.serialize().unwrap();
    let header = PacketHeader {
        magic: PROTOCOL_MAGIC,
        schema_version: u16::from(CURRENT_VERSION),
        flags: 0,
        packet_type: 1,
        payload_length: payload.len() as u16,
        sequence_number: 1,
        session_epoch: 12345,
        monotonic_timestamp: 67890,
    };

    let frame = ProtocolFrame {
        header,
        payload: &payload,
    };

    t1.send(frame).await.unwrap();

    let dispatcher_handle = tokio::spawn(async move {
        let _ = dispatcher.run(t2).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    t1.close().await.unwrap();
    dispatcher_handle.abort();
}
