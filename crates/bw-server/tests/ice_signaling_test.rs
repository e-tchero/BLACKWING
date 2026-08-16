//! End-to-end ICE signaling test (TASK-119): a client-side peer and a
//! server-side peer exchange candidates over a simulated relay channel (an
//! in-process message queue standing in for the relay data plane), then both
//! sides run connectivity checks and establish a direct P2P connection.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use bw_ice::IcePeer;
use bw_protocol::dispatcher::MessageDispatcher;
use bw_protocol::message::ProtocolMessage;
use bw_server::register_ice_handler;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Forwards every outbound candidate message from `peer` into the relay
/// channel for the remote side, until gathering completes.
async fn pump_candidates(peer: &IcePeer, relay_tx: &mpsc::UnboundedSender<ProtocolMessage>) {
    while let Some(message) = peer.next_outbound().await {
        if relay_tx.send(message).is_err() {
            break;
        }
    }
}

#[tokio::test]
async fn ice_candidates_exchange_over_relay_and_p2p_established() {
    // Both sides share the relay token (a placeholder here; in production it
    // comes from the authenticated relay handshake).
    let relay_token = [0x42u8; 32];
    // Host-only gathering (no STUN urls) so the test is deterministic and
    // network-independent.
    let urls = Vec::new();

    // Client = controlling agent; server = controlled agent. The peers are
    // Arc-shared so the dispatcher handler (push_candidate) and the pumping
    // task (next_outbound) can both access them.
    let client_peer = Arc::new(
        IcePeer::new(&relay_token, true, urls.clone())
            .await
            .expect("client peer should start"),
    );
    let server_peer = Arc::new(
        IcePeer::new(&relay_token, false, urls)
            .await
            .expect("server peer should start"),
    );

    // Wire each side's dispatcher to its peer, mirroring the binaries.
    let client_dispatcher = MessageDispatcher::new();
    register_ice_handler(&client_dispatcher, Arc::clone(&client_peer));
    let server_dispatcher = MessageDispatcher::new();
    register_ice_handler(&server_dispatcher, Arc::clone(&server_peer));

    // The relay: each side forwards outbound candidates to the other.
    let (client_to_server_tx, mut server_rx) = mpsc::unbounded_channel::<ProtocolMessage>();
    let (server_to_client_tx, mut client_rx) = mpsc::unbounded_channel::<ProtocolMessage>();

    // Pump client candidates → server, and server candidates → client.
    let pump_client_peer = Arc::clone(&client_peer);
    let pump_client = tokio::spawn(async move {
        pump_candidates(&pump_client_peer, &client_to_server_tx).await;
    });
    let pump_server_peer = Arc::clone(&server_peer);
    let pump_server = tokio::spawn(async move {
        pump_candidates(&pump_server_peer, &server_to_client_tx).await;
    });

    // Deliver the relayed messages into each side's dispatcher (the same
    // entry point a live relay receiver would use).
    let deliver_server = tokio::spawn(async move {
        while let Some(message) = server_rx.recv().await {
            server_dispatcher
                .dispatch(envelope(message))
                .expect("dispatch ok");
        }
    });
    let deliver_client = tokio::spawn(async move {
        while let Some(message) = client_rx.recv().await {
            client_dispatcher
                .dispatch(envelope(message))
                .expect("dispatch ok");
        }
    });

    // Wait for gathering to finish on both sides (candidate streams close),
    // then give the agents a moment to process the exchanged candidates.
    pump_client.await.expect("client pump");
    pump_server.await.expect("server pump");
    deliver_server.await.expect("server deliver");
    deliver_client.await.expect("client deliver");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Both sides run connectivity checks. The server side must be established
    // concurrently with the client side.
    let (client_conn, server_conn) = timeout(Duration::from_secs(30), async {
        tokio::join!(server_peer.establish(), client_peer.establish())
    })
    .await
    .expect("ICE establishment timed out");

    let client_conn = client_conn.expect("client side P2P connection");
    let server_conn = server_conn.expect("server side P2P connection");

    // The direct path carries data.
    client_conn.send(b"p2p").await.expect("client send");
    let mut buf = [0u8; 8];
    let n = timeout(Duration::from_secs(10), server_conn.recv(&mut buf))
        .await
        .expect("server recv timed out")
        .expect("server recv");
    assert_eq!(&buf[..n], b"p2p");
}

/// Builds a valid dispatch envelope around a message.
fn envelope(message: ProtocolMessage) -> bw_protocol::routing::MessageEnvelope {
    use bw_crypto::DeviceId;
    use bw_protocol::routing::{MessageEnvelope, NodeId, Route, SessionId};
    MessageEnvelope {
        source: NodeId(DeviceId::from_digest([0x01; 32])),
        destination: NodeId(DeviceId::from_digest([0x02; 32])),
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message,
        routing_flags: 0,
    }
}
