use bw_crypto::DeviceId;
use bw_protocol::error::ProtocolError;
use bw_protocol::message::{MessageType, ProtocolMessage};
use bw_protocol::routing::{MessageEnvelope, NodeId, Route, SessionId};
use bw_protocol::session::SessionManager;

fn make_node_id(val: u8) -> NodeId {
    NodeId(DeviceId::from_digest([val; 32]))
}

fn make_mock_message() -> ProtocolMessage {
    ProtocolMessage {
        message_type: MessageType::Ping,
        message_id: 1,
        flags: 0,
        payload: vec![],
    }
}

#[test]
fn test_session_manager_flows() {
    let manager = SessionManager::new();
    let id1 = SessionId([1u8; 16]);
    let id2 = SessionId([2u8; 16]);

    // Create session
    assert!(manager.create_session(id1).is_ok());

    // Duplicate rejection
    let result = manager.create_session(id1);
    assert_eq!(result.err(), Some(ProtocolError::SessionDuplicate));

    // Validate active session
    assert!(manager.validate_session(&id1).unwrap());
    assert!(!manager.validate_session(&id2).unwrap());

    // Lookup session
    assert_eq!(manager.lookup_session(&id1).unwrap(), id1);
    assert_eq!(
        manager.lookup_session(&id2).err(),
        Some(ProtocolError::SessionNotFound)
    );

    // Close session
    assert!(manager.close_session(&id1).unwrap());
    assert!(!manager.validate_session(&id1).unwrap());
}

#[test]
fn test_envelope_validation_direct_route() {
    let src = make_node_id(1);
    let dst = make_node_id(2);
    let msg = make_mock_message();

    let envelope = MessageEnvelope {
        source: src,
        destination: dst,
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message: msg.clone(),
        routing_flags: 0,
    };
    assert!(envelope.validate().is_ok());

    // Source equals destination direct -> invalid
    let invalid_envelope = MessageEnvelope {
        source: src,
        destination: src,
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message: msg.clone(),
        routing_flags: 0,
    };
    assert_eq!(
        invalid_envelope.validate().err(),
        Some(ProtocolError::InvalidDestination)
    );

    // Direct routing to broadcast destination -> invalid
    let bcast_envelope = MessageEnvelope {
        source: src,
        destination: NodeId::broadcast(),
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message: msg,
        routing_flags: 0,
    };
    assert_eq!(
        bcast_envelope.validate().err(),
        Some(ProtocolError::InvalidDestination)
    );
}

#[test]
fn test_envelope_validation_broadcast_route() {
    let src = make_node_id(1);
    let msg = make_mock_message();

    // Broadcast routing to broadcast destination -> valid
    let envelope = MessageEnvelope {
        source: src,
        destination: NodeId::broadcast(),
        session_id: SessionId([0u8; 16]),
        route: Route::Broadcast,
        message: msg.clone(),
        routing_flags: 0,
    };
    assert!(envelope.validate().is_ok());

    // Broadcast routing to non-broadcast destination -> invalid
    let invalid_envelope = MessageEnvelope {
        source: src,
        destination: make_node_id(2),
        session_id: SessionId([0u8; 16]),
        route: Route::Broadcast,
        message: msg,
        routing_flags: 0,
    };
    assert_eq!(
        invalid_envelope.validate().err(),
        Some(ProtocolError::InvalidDestination)
    );
}

#[test]
fn test_envelope_validation_loopback_route() {
    let src = make_node_id(1);
    let msg = make_mock_message();

    // Loopback with same source/destination -> valid
    let envelope = MessageEnvelope {
        source: src,
        destination: src,
        session_id: SessionId([0u8; 16]),
        route: Route::Loopback,
        message: msg.clone(),
        routing_flags: 0,
    };
    assert!(envelope.validate().is_ok());

    // Loopback with different source/destination -> invalid
    let invalid_envelope = MessageEnvelope {
        source: src,
        destination: make_node_id(2),
        session_id: SessionId([0u8; 16]),
        route: Route::Loopback,
        message: msg,
        routing_flags: 0,
    };
    assert_eq!(
        invalid_envelope.validate().err(),
        Some(ProtocolError::InvalidRoute)
    );
}

#[test]
fn test_envelope_validation_relay_route() {
    let src = make_node_id(1);
    let dst = make_node_id(2);
    let relay = make_node_id(3);
    let msg = make_mock_message();

    // Valid relay
    let envelope = MessageEnvelope {
        source: src,
        destination: dst,
        session_id: SessionId([0u8; 16]),
        route: Route::Relay { via: relay },
        message: msg.clone(),
        routing_flags: 0,
    };
    assert!(envelope.validate().is_ok());

    // Relay via source -> invalid
    let via_src = MessageEnvelope {
        source: src,
        destination: dst,
        session_id: SessionId([0u8; 16]),
        route: Route::Relay { via: src },
        message: msg.clone(),
        routing_flags: 0,
    };
    assert_eq!(via_src.validate().err(), Some(ProtocolError::InvalidRoute));

    // Relay via destination -> invalid
    let via_dst = MessageEnvelope {
        source: src,
        destination: dst,
        session_id: SessionId([0u8; 16]),
        route: Route::Relay { via: dst },
        message: msg.clone(),
        routing_flags: 0,
    };
    assert_eq!(via_dst.validate().err(), Some(ProtocolError::InvalidRoute));
}

#[test]
fn test_envelope_serialization_roundtrip() {
    let envelope = MessageEnvelope {
        source: make_node_id(1),
        destination: make_node_id(2),
        session_id: SessionId([7u8; 16]),
        route: Route::Relay {
            via: make_node_id(3),
        },
        message: make_mock_message(),
        routing_flags: 0xAAAA,
    };

    let encoded = envelope.serialize().unwrap();
    let decoded = MessageEnvelope::deserialize(&encoded).unwrap();
    assert_eq!(decoded, envelope);
}

#[test]
fn test_invalid_inner_message_fails_envelope_validation() {
    let src = make_node_id(1);
    let dst = make_node_id(2);
    // Invalid message: Data type with empty payload but non-zero flags
    let msg = ProtocolMessage {
        message_type: MessageType::Data,
        message_id: 1,
        flags: 0x0001,
        payload: vec![],
    };

    let envelope = MessageEnvelope {
        source: src,
        destination: dst,
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message: msg,
        routing_flags: 0,
    };
    assert_eq!(
        envelope.validate().err(),
        Some(ProtocolError::InvalidPayloadLength)
    );
}
