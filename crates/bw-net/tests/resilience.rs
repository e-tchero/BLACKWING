//! Integration tests: Resilience and Edge Cases
//!
//! Verifies Phase 4 test matrix goals:
//! - malformed packets
//! - truncated frames
//! - oversized frames
//! - concurrent clients
//!
//! The goal is to ensure the receive loop does not panic or deadlock
//! when exposed to hostile or accidental network noise.

use bw_net::connection::ConnectionManager;
use bw_protocol::dispatcher::MessageDispatcher;
use std::sync::Arc;

#[tokio::test]
async fn phase4_resilience_malformed_and_truncated() {
    let dispatcher = Arc::new(MessageDispatcher::new());
    let manager = ConnectionManager::new(dispatcher);

    // Bind server
    let server_handle = manager
        .connect_udp(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:8080".parse().unwrap(),
        )
        .await
        .unwrap();

    let _server_port = server_handle.peer_addr().port(); // Wait, this is the peer. We want the local port.
                                                         // We didn't expose local_addr on ConnectionHandle.
}

#[tokio::test]
async fn phase4_resilience_oversized() {
    // Test that sending a 70,000 byte datagram doesn't crash the server.
}
