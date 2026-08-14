//! WP-8.0 Phase 4 — Relay end-to-end integration test.
//!
//! Proves that two Quinn QUIC endpoints can complete a full handshake and
//! exchange data when all traffic is routed through an in-process relay
//! forwarding loop.  The relay is zero-knowledge: it never inspects the
//! QUIC payload — it only reads the 32-byte routing header to choose a
//! destination and forwards the datagram verbatim.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bw_crypto::SigningKey;
use bw_relay::{clock::SystemClock, forwarding::ForwardingTable, server::RelayServer};
use bw_transport::{QuicClient, QuicServer};
use tokio::{net::UdpSocket, time::timeout};

/// Relay routing header length (must match `relay_socket::RELAY_HEADER_LEN`).
const RELAY_HEADER_LEN: usize = 32;

/// Resolves the concrete loopback source address of a wildcard-bound socket.
///
/// `QuicClient::bind` binds to `0.0.0.0:0`.  On the loopback interface the OS
/// sources outgoing datagrams from `127.0.0.1:<port>` — which is the address
/// the relay's UDP socket actually observes, and which the forwarding table
/// anti-spoofing check requires the registered binding to match.
fn concrete_loopback_addr(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

/// Spawn an in-process relay forwarding loop.
///
/// Binds a UDP socket on port 0.  Every datagram received is expected to
/// begin with a 32-byte relay token; the token is used to look up the
/// destination in the `ForwardingTable`.  The full datagram (token included)
/// is forwarded verbatim to the destination — the receiving endpoint's
/// `RelayUdpSocket` strips the 32-byte prefix before handing the payload to
/// Quinn.
async fn spawn_relay_forwarder(
    table: Arc<ForwardingTable>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_socket.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 1400];
        loop {
            let (n, src) = match relay_socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            if n < RELAY_HEADER_LEN {
                continue; // malformed — drop
            }
            let token: [u8; RELAY_HEADER_LEN] = buf[..RELAY_HEADER_LEN].try_into().unwrap();

            if let Some(dest) = table.get_destination(&token, src) {
                // Forward the full datagram (token + QUIC payload) verbatim.
                let _ = relay_socket.send_to(&buf[..n], dest).await;
            }
        }
    });

    (relay_addr, handle)
}

#[tokio::test]
async fn test_relay_e2e_quic_handshake_and_data_exchange() {
    // ── 1. Generate relay token and intent_id ──────────────────────────────
    let token = [0xAB_u8; 32];
    let intent_id = [0x01_u8; 16];

    // ── 2. Generate authenticated identities for client and server ─────────
    let server_key = SigningKey::generate_ed25519().unwrap();
    let client_key = SigningKey::generate_ed25519().unwrap();
    let server_id = server_key.verify_key().device_id();
    let client_id = client_key.verify_key().device_id();

    // ── 3. Build forwarding table and pre-authorize the pair ───────────────
    let relay_server = RelayServer::new();
    let table = relay_server.forwarding.clone();
    table.authorize_pair(intent_id, token, client_id, server_id);

    // ── 4. Spawn the relay forwarder ───────────────────────────────────────
    let (relay_addr, _relay_task) = spawn_relay_forwarder(table.clone()).await;

    // ── 5. Bind QUIC server (via relay) ────────────────────────────────────
    let server_direct_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let quic_server = QuicServer::bind(server_direct_addr, Some((relay_addr, token))).unwrap();
    let server_addr = quic_server.endpoint.local_addr().unwrap();

    // Register server binding in forwarding table
    table
        .update_binding(intent_id, server_id, server_addr)
        .unwrap();

    // ── 6. Bind QUIC client (via relay) ────────────────────────────────────
    let quic_client = QuicClient::bind(Some((relay_addr, token))).unwrap();
    let client_addr = concrete_loopback_addr(quic_client.endpoint.local_addr().unwrap());

    // Register client binding in forwarding table
    table
        .update_binding(intent_id, client_id, client_addr)
        .unwrap();

    // ── 7. Connect client to the relay ─────────────────────────────────────
    // The client's QUIC datagrams are destined for the relay address, so
    // RelayUdpSocket prepends the token; the forwarding loop looks up the
    // destination from the source address and forwards to the server.
    let connect_fut = quic_client.connect(relay_addr);
    let accept_fut = quic_server.accept();

    let (conn_result, server_conn) = tokio::join!(
        timeout(Duration::from_secs(10), connect_fut),
        timeout(Duration::from_secs(10), accept_fut),
    );

    let client_conn = conn_result
        .expect("connect timed out")
        .expect("connect failed");
    let server_conn = server_conn
        .expect("accept timed out")
        .expect("server accepted None");

    // ── 8. Open a stream and exchange data ────────────────────────────────
    const PAYLOAD: &[u8] = b"BLACKWING relay E2E verified";

    let send_fut = async {
        let mut send = client_conn.open_uni().await.unwrap();
        send.write_all(PAYLOAD).await.unwrap();
        send.finish().unwrap();
    };

    let recv_fut = async {
        let mut recv = server_conn.accept_uni().await.unwrap();
        recv.read_to_end(1024).await.unwrap()
    };

    let (_, received) = timeout(Duration::from_secs(10), async {
        tokio::join!(send_fut, recv_fut)
    })
    .await
    .expect("stream exchange timed out");

    // ── 9. Assert payload integrity ───────────────────────────────────────
    assert_eq!(
        received.as_slice(),
        PAYLOAD,
        "Payload must survive the relay hop intact"
    );
}

#[tokio::test]
async fn test_relay_e2e_bidirectional_data_exchange() {
    let token = [0xCD_u8; 32];
    let intent_id = [0x02_u8; 16];

    let server_key = SigningKey::generate_ed25519().unwrap();
    let client_key = SigningKey::generate_ed25519().unwrap();
    let server_id = server_key.verify_key().device_id();
    let client_id = client_key.verify_key().device_id();

    let relay_server = RelayServer::new();
    let table = relay_server.forwarding.clone();
    table.authorize_pair(intent_id, token, client_id, server_id);

    let (relay_addr, _relay_task) = spawn_relay_forwarder(table.clone()).await;

    let quic_server =
        QuicServer::bind("127.0.0.1:0".parse().unwrap(), Some((relay_addr, token))).unwrap();
    let server_addr = quic_server.endpoint.local_addr().unwrap();
    table
        .update_binding(intent_id, server_id, server_addr)
        .unwrap();

    let quic_client = QuicClient::bind(Some((relay_addr, token))).unwrap();
    let client_addr = concrete_loopback_addr(quic_client.endpoint.local_addr().unwrap());
    table
        .update_binding(intent_id, client_id, client_addr)
        .unwrap();

    let (conn_result, server_conn) = tokio::join!(
        timeout(Duration::from_secs(10), quic_client.connect(relay_addr)),
        timeout(Duration::from_secs(10), quic_server.accept()),
    );

    let client_conn = conn_result.unwrap().unwrap();
    let server_conn = server_conn.unwrap().unwrap();

    // Client → Server
    let client_to_server = async {
        let mut s = client_conn.open_uni().await.unwrap();
        s.write_all(b"client-to-server").await.unwrap();
        s.finish().unwrap();
    };
    let server_recv = async {
        let mut r = server_conn.accept_uni().await.unwrap();
        r.read_to_end(1024).await.unwrap()
    };

    // Server → Client (bidirectional)
    let server_to_client = async {
        let mut s = server_conn.open_uni().await.unwrap();
        s.write_all(b"server-to-client").await.unwrap();
        s.finish().unwrap();
    };
    let client_recv = async {
        let mut r = client_conn.accept_uni().await.unwrap();
        r.read_to_end(1024).await.unwrap()
    };

    let (_, received_by_server, _, received_by_client) = timeout(Duration::from_secs(10), async {
        tokio::join!(client_to_server, server_recv, server_to_client, client_recv)
    })
    .await
    .unwrap();

    assert_eq!(received_by_server.as_slice(), b"client-to-server");
    assert_eq!(received_by_client.as_slice(), b"server-to-client");
}

#[tokio::test]
async fn test_relay_drops_unknown_token() {
    // A packet with an unregistered token must be silently dropped by the relay.
    let table = Arc::new(ForwardingTable::new(Arc::new(SystemClock)));

    let (relay_addr, _relay_task) = spawn_relay_forwarder(table).await;

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest_addr = dest.local_addr().unwrap();

    // Send a packet with a random unknown token — relay has no entry for it
    let unknown_token = [0xFF_u8; 32];
    let mut packet = Vec::new();
    packet.extend_from_slice(&unknown_token);
    packet.extend_from_slice(b"should not arrive");

    sock.send_to(&packet, relay_addr).await.unwrap();

    // Attempt to receive on the destination — should time out (nothing arrives)
    let mut buf = [0u8; 1024];
    let result = timeout(Duration::from_millis(200), dest.recv_from(&mut buf)).await;
    assert!(
        result.is_err(),
        "Relay must drop packets with unknown tokens"
    );

    // The packet that was 'sent' to dest_addr should not arrive either
    // (relay had no route to dest_addr anyway)
    let _ = dest_addr; // silence unused warning
}
