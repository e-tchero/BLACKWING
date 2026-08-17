//! BLACKWING relay — runnable binary.
//!
//! Single UDP socket serving two planes, disambiguated by a magic prefix:
//!
//! * **Control plane** — datagrams beginning with `CONTROL_MAGIC` carry a
//!   CBOR-serialized [`RelayMessage`]; the response is sent back to the
//!   sender with the same magic prefix.
//! * **Data plane** — any other datagram begins with a 32-byte relay token;
//!   the datagram (token included) is forwarded verbatim to the destination
//!   resolved from the [`ForwardingTable`].
//!
//! # Dev mode
//!
//! The client and server binaries use a fixed development token and skip the
//! full control-plane registration flow. `--dev-token <hex>` pre-authorizes a
//! forwarding pair for that token and lazily binds the two distinct source
//! addresses as they first appear — exactly the sequence the in-process relay
//! E2E test performs explicitly. This is a development convenience: real
//! deployments should rely on the signed control-plane flow instead.
#![allow(missing_docs)]

use bw_crypto::DeviceId;
use bw_relay::forwarding::ForwardingTable;
use bw_relay::protocol::RelayMessage;
use bw_relay::server::RelayServer;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Control-plane magic prefix, chosen so it can never collide with a 32-byte
/// relay token (data-plane packets are at least 33 bytes and always begin
/// with the token; control packets begin with this short marker).
const CONTROL_MAGIC: &[u8; 6] = b"BWCTL\x01";
/// Length of a relay routing token.
const RELAY_HEADER_LEN: usize = 32;
/// Max UDP datagram we will handle.
const MAX_DATAGRAM: usize = 1400;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut listen: String = "0.0.0.0:9999".to_string();
    let mut dev_token: Option<[u8; 32]> = None;
    let mut dev_server: Option<std::net::SocketAddr> = None;
    // Default per-session data-plane limit: 50 Mbps. This is well above the
    // 5 Mbps encoder target so IDR keyframe bursts are never dropped; operators
    // can tighten it with --rate-limit for production.
    let mut rate_limit: u64 = 50 * 1024 * 1024 / 8;
    // Default absolute session lifetime: 24 hours. The library default of
    // 2 minutes is a test-friendly value; a real remote-desktop session must
    // last much longer, so the relay binary overrides it by default.
    let mut session_expiry_ms: u64 = 24 * 60 * 60 * 1000;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                listen = args.next().ok_or("--listen requires an address")?;
            }
            "--dev-server" => {
                let addr = args.next().ok_or("--dev-server requires an address")?;
                dev_server = Some(addr.parse()?);
            }
            "--rate-limit" => {
                let val = args.next().ok_or("--rate-limit requires bytes/sec")?;
                rate_limit = val
                    .parse()
                    .map_err(|_| "--rate-limit must be a number (bytes/sec)")?;
            }
            "--session-expiry" => {
                let val = args.next().ok_or("--session-expiry requires ms")?;
                session_expiry_ms = val
                    .parse()
                    .map_err(|_| "--session-expiry must be a number (ms)")?;
            }
            "--dev-token" => {
                let hex = args.next().ok_or("--dev-token requires a hex token")?;
                let bytes = decode_hex(&hex)?;
                if bytes.len() != 32 {
                    return Err("dev token must be exactly 32 bytes (64 hex chars)".into());
                }
                let mut tok = [0u8; 32];
                tok.copy_from_slice(&bytes);
                dev_token = Some(tok);
            }
            "--help" | "-h" => {
                println!(
                    "usage: bw-relay [--listen ADDR] [--rate-limit BYTES/SEC] [--dev-token HEX]\n  \
                     --listen      UDP listen address (default 0.0.0.0:9999)\n  \
                     --rate-limit  per-session data-plane bytes/sec (default 6,250,000 = 50 Mbps)\n  \
                     --dev-token   32-byte hex token to pre-authorize (dev mode)\n  \
                     --dev-server  data-plane address of the server endpoint (dev mode)"
                );
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let relay = RelayServer::with_clock_and_limits(
        std::sync::Arc::new(bw_relay::clock::SystemClock),
        rate_limit,
        session_expiry_ms,
    );
    let table = relay.forwarding.clone();
    eprintln!(
        "rate limit: {rate_limit} bytes/sec per session; session expiry: {session_expiry_ms} ms"
    );

    // Dev mode: pre-authorize a pair for the fixed token and derive two
    // synthetic device IDs from the token (deterministic, dev-only).
    if let Some(token) = dev_token {
        let (initiator_id, target_id) = dev_ids(&token);
        let intent_id = [0xEEu8; 16];
        table.authorize_pair(intent_id, token, initiator_id, target_id);

        // Pre-bind the server's data-plane address so the very first client
        // packet can be forwarded immediately (mirrors the E2E test, which
        // registers both bindings before connecting).
        if let Some(server_addr) = dev_server {
            table
                .update_binding(intent_id, target_id, server_addr)
                .map_err(|e| format!("failed to pre-bind server: {e}"))?;
            eprintln!("dev mode: pre-bound server at {server_addr}");
        }

        eprintln!(
            "dev mode: authorized token {} (initiator={initiator_id}, target={target_id})",
            encode_hex(&token)
        );
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_relay(&listen, relay, table, dev_token, dev_server))?;
    Ok(())
}

async fn run_relay(
    listen: &str,
    server: Arc<RelayServer>,
    table: Arc<ForwardingTable>,
    dev_token: Option<[u8; 32]>,
    dev_server: Option<std::net::SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sock = UdpSocket::bind(listen).await?;
    eprintln!("BLACKWING relay listening on {}", sock.local_addr()?);

    let mut dev_bindings = DevBindings::default();
    if let Some(addr) = dev_server {
        dev_bindings.prebind_target(addr);
    }

    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut packet_count: u64 = 0;
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let packet = &buf[..n];

        if packet.len() >= CONTROL_MAGIC.len() && &packet[..CONTROL_MAGIC.len()] == CONTROL_MAGIC {
            // ── Control plane ─────────────────────────────────────────────
            let body = &packet[CONTROL_MAGIC.len()..];
            match ciborium::de::from_reader::<RelayMessage, _>(body) {
                Ok(msg) => {
                    let resp = server.handle_message_from(msg, Some(src));
                    let mut out = Vec::with_capacity(CONTROL_MAGIC.len() + 512);
                    out.extend_from_slice(CONTROL_MAGIC);
                    match resp {
                        Ok(r) => {
                            let _ = ciborium::ser::into_writer(&r, &mut out);
                            let _ = sock.send_to(&out, src).await;
                        }
                        Err(e) => {
                            let err = RelayMessage::ErrorResponse {
                                reason: e.to_string(),
                            };
                            let _ = ciborium::ser::into_writer(&err, &mut out);
                            let _ = sock.send_to(&out, src).await;
                        }
                    }
                }
                Err(_) => {
                    eprintln!("control frame from {src} failed to decode");
                }
            }
            continue;
        }

        // ── Data plane ────────────────────────────────────────────────────
        if n < RELAY_HEADER_LEN {
            continue; // malformed — drop
        }
        let mut token = [0u8; RELAY_HEADER_LEN];
        token.copy_from_slice(&packet[..RELAY_HEADER_LEN]);

        // Dev mode: lazily bind the two distinct source addresses.
        if let Some(tok) = dev_token
            && token == tok
        {
            dev_bindings.bind(&table, src, tok);
        }

        if let Some(dest) = table.get_destination(&token, src, n) {
            // Forward the full datagram (token + payload) verbatim.
            if let Err(e) = sock.send_to(&buf[..n], dest).await {
                eprintln!("forward error to {dest}: {e}");
            }
            // Brief periodic telemetry so a live session's data flow is
            // observable (and to prove the relay stays active).
            packet_count += 1;
            if packet_count.is_multiple_of(100) {
                eprintln!(
                    "[{}] relay: {} datagrams forwarded ({src} -> {dest})",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    packet_count
                );
            }
        }
    }
}

/// Tracks the two data-plane bindings of a dev-mode forwarding pair.
#[derive(Default)]
struct DevBindings {
    /// The initiator's bound source address, if any.
    initiator: Option<SocketAddr>,
    /// The target's bound source address, if any.
    target: Option<SocketAddr>,
}

impl DevBindings {
    /// Records the target (server) binding up front so the first client
    /// packet can be forwarded immediately.
    fn prebind_target(&mut self, addr: SocketAddr) {
        self.target = Some(addr);
    }

    /// Lazily binds a source address to whichever slot is free. The first
    /// distinct address becomes the initiator, the second the target; any
    /// further distinct address is ignored (the table's `get_destination`
    /// will silently drop its packets).
    fn bind(&mut self, table: &ForwardingTable, src: SocketAddr, token: [u8; 32]) {
        let (initiator_id, target_id) = dev_ids(&token);
        let intent_id = [0xEEu8; 16];

        if self.initiator == Some(src) || self.target == Some(src) {
            return; // already bound
        }
        if self.initiator.is_none() {
            let _ = table.update_binding(intent_id, initiator_id, src);
            self.initiator = Some(src);
        } else if self.target.is_none() {
            let _ = table.update_binding(intent_id, target_id, src);
            self.target = Some(src);
        }
    }
}

/// Deterministic dev-only device IDs derived from the token.
fn dev_ids(token: &[u8; 32]) -> (DeviceId, DeviceId) {
    let mut a = Sha256::new();
    a.update(token);
    a.update(b":initiator");
    let mut b = Sha256::new();
    b.update(token);
    b.update(b":target");
    (
        DeviceId::from_digest(a.finalize().into()),
        DeviceId::from_digest(b.finalize().into()),
    )
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("hex string must have even length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| format!("invalid hex byte at offset {i}"))
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
