use crate::clock::Clock;
use bw_crypto::DeviceId;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

/// Maximum forwarding payload size in bytes. Packets exceeding this are dropped.
/// Set to QUIC minimum MTU minus the 32-byte relay routing header overhead.
pub const MAX_FORWARDING_PAYLOAD: usize = 1168;

/// Maximum raw packet size permitted on the relay data plane (header + payload).
pub const MAX_PACKET_SIZE: usize = 1200;

/// Idle timeout after which an active forwarding context is expired (30 seconds).
const IDLE_TIMEOUT_MS: u64 = 30_000;

/// Absolute session lifetime: 2 minutes from authorization.
pub const SESSION_EXPIRY_MS: u64 = 120_000;

/// Per-session byte cap: 10 GiB.
pub const SESSION_BYTE_CAP: u64 = 10 * 1024 * 1024 * 1024;

/// Exchange timeout: both endpoints must bind within 10 seconds of authorization.
pub const EXCHANGE_TIMEOUT_MS: u64 = 10_000;

/// Rate limit: 5 Mbps per session = 625_000 bytes per second.
pub const RATE_LIMIT_BYTES_PER_SEC: u64 = 625_000;

/// Failed token lookups from one source IP that trigger a temporary block.
const BLOCKLIST_THRESHOLD: u64 = 20;

/// Rolling window (60 seconds) over which failed lookups are counted for the blocklist.
const BLOCKLIST_WINDOW_MS: u64 = 60_000;

/// Lifecycle state of a relay forwarding context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardingState {
    /// Both endpoints are authorized but no EstablishRequest has been received yet.
    Authorized,
    /// At least one endpoint has bound its data-plane address; waiting for the other.
    RelayRequested,
    /// Both endpoints are bound; actively forwarding packets.
    RelayActive,
    /// The context has exceeded its idle timeout; no further forwarding is allowed.
    RelayExpired,
    /// The context was explicitly closed by a disconnect or revocation.
    RelayClosed,
}

/// The authenticated network binding for one endpoint in a forwarding pair.
#[derive(Debug, Clone)]
pub struct EndpointBinding {
    /// The authenticated device identity of this endpoint.
    pub device_id: DeviceId,
    /// The most recently authenticated data-plane SocketAddr for this endpoint.
    pub addr: Option<SocketAddr>,
}

/// Token-bucket rate limiter tracking per-session forwarding bandwidth.
pub struct RateBucket {
    /// Tokens available (bytes). Refilled at `RATE_LIMIT_BYTES_PER_SEC`.
    pub tokens: f64,
    /// Last refill timestamp (ms).
    pub last_refill_ms: u64,
}

/// A live forwarding context binding a relay token to exactly two authenticated endpoints.
///
/// The relay token is the only identifier used on the data plane.
/// Endpoint addresses are validated against their authenticated bindings on every packet.
pub struct ForwardingContext {
    /// The Phase 2 intent identifier that produced this forwarding context.
    pub intent_id: [u8; 16],
    /// The 32-byte relay routing token used to identify this session on the data plane.
    pub token: [u8; 32],
    /// The initiating endpoint's authenticated binding.
    pub initiator: EndpointBinding,
    /// The target endpoint's authenticated binding.
    pub target: EndpointBinding,
    /// The current lifecycle state of this forwarding context.
    pub state: ForwardingState,
    /// Timestamp (ms) of the last forwarded packet, used for idle-timeout tracking.
    pub last_active_ms: u64,
    /// Absolute expiry timestamp (ms since epoch). Set to authorize_pair time + 120_000.
    pub expires_at_ms: u64,
    /// Total bytes forwarded in this session (both directions combined).
    pub bytes_forwarded: u64,
    /// Time (ms) when authorize_pair was called — used for exchange timeout.
    pub authorized_at_ms: u64,
    /// Token-bucket rate limiter for per-session bandwidth control.
    pub rate_bucket: RateBucket,
}

/// The forwarding table: O(1) lookup from token to context, with idle-timeout enforcement.
///
/// # Security model
/// - A context is only created after both parties' identities are signed and verified
///   during the Phase 2 rendezvous handshake.
/// - Forwarding is only permitted when the source address exactly matches the registered
///   binding for the initiator or target.
/// - Spoofed or unassociated source addresses are silently dropped.
/// - NAT rebinding is only accepted via a new signed `RelayEstablishRequest`.
/// - Repeated failed token lookups from a source IP trigger a temporary blocklist.
pub struct ForwardingTable {
    /// Primary store: intent_id -> context.
    contexts: RwLock<HashMap<[u8; 16], ForwardingContext>>,
    /// Fast routing index: relay_token -> intent_id.
    token_index: RwLock<HashMap<[u8; 32], [u8; 16]>>,
    /// Failed lookup counter per source IP: (count, window_start_ms).
    failed_lookups: RwLock<HashMap<IpAddr, (u64, u64)>>,
    /// Per-session rate limit in bytes per second.
    rate_limit_bytes_per_sec: u64,
    /// Absolute per-session lifetime in milliseconds, regardless of activity.
    session_expiry_ms: u64,
    clock: Arc<dyn Clock>,
}

impl ForwardingTable {
    /// Creates a new, empty forwarding table backed by the given clock using
    /// the default per-session rate limit.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self::with_rate_limit(clock, RATE_LIMIT_BYTES_PER_SEC)
    }

    /// Creates a new, empty forwarding table with a custom per-session rate
    /// limit (bytes per second). Operators must size this above the expected
    /// peak stream bitrate: the encoder targets 5 Mbps, but IDR keyframes burst
    /// well above the average, so a limit equal to the average bitrate silently
    /// drops the very keyframes the decoder needs to resync.
    pub fn with_rate_limit(clock: Arc<dyn Clock>, rate_limit_bytes_per_sec: u64) -> Self {
        Self::with_limits(clock, rate_limit_bytes_per_sec, SESSION_EXPIRY_MS)
    }

    /// Creates a new, empty forwarding table with a custom per-session rate
    /// limit and absolute session lifetime (milliseconds).
    pub fn with_limits(
        clock: Arc<dyn Clock>,
        rate_limit_bytes_per_sec: u64,
        session_expiry_ms: u64,
    ) -> Self {
        Self {
            contexts: RwLock::new(HashMap::new()),
            token_index: RwLock::new(HashMap::new()),
            failed_lookups: RwLock::new(HashMap::new()),
            rate_limit_bytes_per_sec,
            session_expiry_ms,
            clock,
        }
    }

    /// Registers a forwarding pair after successful Phase 2 mutual authorization.
    ///
    /// The token is generated by the relay during `AcceptConnect` and is never known
    /// to the relay before that point; it is distributed via `CandidateExchange`.
    pub fn authorize_pair(
        &self,
        intent_id: [u8; 16],
        token: [u8; 32],
        initiator_id: DeviceId,
        target_id: DeviceId,
    ) {
        let now = self.clock.now_ms();
        let ctx = ForwardingContext {
            intent_id,
            token,
            initiator: EndpointBinding {
                device_id: initiator_id,
                addr: None,
            },
            target: EndpointBinding {
                device_id: target_id,
                addr: None,
            },
            state: ForwardingState::Authorized,
            last_active_ms: now,
            expires_at_ms: now + self.session_expiry_ms,
            bytes_forwarded: 0,
            authorized_at_ms: now,
            rate_bucket: RateBucket {
                tokens: self.rate_limit_bytes_per_sec as f64,
                last_refill_ms: now,
            },
        };

        self.contexts
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(intent_id, ctx);
        self.token_index
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token, intent_id);
    }

    /// Authenticates and records the data-plane SocketAddr for one endpoint of the pair.
    ///
    /// This is the only mechanism by which the relay accepts a new or changed source
    /// address. It requires a fresh signed `RelayEstablishRequest`; token possession
    /// alone is insufficient.
    pub fn update_binding(
        &self,
        intent_id: [u8; 16],
        device_id: DeviceId,
        addr: SocketAddr,
    ) -> Result<(), &'static str> {
        let now = self.clock.now_ms();
        let mut contexts = self.contexts.write().unwrap_or_else(|e| e.into_inner());

        let ctx = contexts
            .get_mut(&intent_id)
            .ok_or("Forwarding session not found")?;

        // Reject updates to terminated or expired contexts.
        match ctx.state {
            ForwardingState::RelayExpired | ForwardingState::RelayClosed => {
                return Err("Cannot rebind a closed or expired forwarding session");
            }
            _ => {}
        }

        // Idle-timeout check during binding.
        if now.saturating_sub(ctx.last_active_ms) > IDLE_TIMEOUT_MS {
            ctx.state = ForwardingState::RelayExpired;
            return Err("Forwarding session has expired due to inactivity");
        }

        // Absolute session expiry check during binding.
        if now >= ctx.expires_at_ms {
            ctx.state = ForwardingState::RelayExpired;
            return Err("Forwarding session has reached its absolute expiry");
        }

        // Only the authorized pair members may update bindings.
        if ctx.initiator.device_id == device_id {
            ctx.initiator.addr = Some(addr);
        } else if ctx.target.device_id == device_id {
            ctx.target.addr = Some(addr);
        } else {
            return Err("Device is not part of this forwarding session");
        }

        ctx.last_active_ms = now;

        // Advance state machine.
        ctx.state = if ctx.initiator.addr.is_some() && ctx.target.addr.is_some() {
            ForwardingState::RelayActive
        } else {
            ForwardingState::RelayRequested
        };

        Ok(())
    }

    /// Records a failed token lookup from a source IP for brute-force protection.
    fn record_failed_lookup(&self, ip: IpAddr, now: u64) {
        let mut failed = self
            .failed_lookups
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let entry = failed.entry(ip).or_insert((0, now));
        if now.saturating_sub(entry.1) > BLOCKLIST_WINDOW_MS {
            *entry = (1, now);
        } else {
            entry.0 += 1;
        }
    }

    /// Returns `true` if the source IP is currently blocklisted for repeated failed lookups.
    pub fn is_blocklisted(&self, ip: &IpAddr) -> bool {
        let now = self.clock.now_ms();
        let failed = self
            .failed_lookups
            .read()
            .unwrap_or_else(|e| e.into_inner());
        match failed.get(ip) {
            Some((count, window_start)) => {
                *count >= BLOCKLIST_THRESHOLD
                    && now.saturating_sub(*window_start) <= BLOCKLIST_WINDOW_MS
            }
            None => false,
        }
    }

    /// Looks up the destination address for a forwarded packet.
    ///
    /// Returns `None` and silently drops the packet if:
    /// - The token is unknown.
    /// - The source IP is blocklisted for repeated failed lookups.
    /// - The context is not in `RelayActive` state.
    /// - The source address does not match the registered binding (anti-spoofing).
    /// - The idle timeout, absolute session expiry, or byte cap has been reached.
    /// - The packet would exceed the per-session rate limit.
    ///
    /// No error is returned to avoid leaking information to potential attackers.
    pub fn get_destination(
        &self,
        token: &[u8; 32],
        source_addr: SocketAddr,
        packet_len: usize,
    ) -> Option<SocketAddr> {
        let now = self.clock.now_ms();

        // Brute-force blocklist: block the source IP before any work.
        if self.is_blocklisted(&source_addr.ip()) {
            return None;
        }

        let intent_id = {
            let idx = self.token_index.read().unwrap_or_else(|e| e.into_inner());
            match idx.get(token) {
                Some(id) => *id,
                None => {
                    // Failed lookup: record for brute-force protection, then drop silently.
                    self.record_failed_lookup(source_addr.ip(), now);
                    return None;
                }
            }
        };

        let mut contexts = self.contexts.write().unwrap_or_else(|e| e.into_inner());
        let ctx = contexts.get_mut(&intent_id)?;

        if ctx.state != ForwardingState::RelayActive {
            return None;
        }

        // Absolute session expiry (2 minutes from authorization, regardless of activity).
        if now >= ctx.expires_at_ms {
            ctx.state = ForwardingState::RelayExpired;
            return None;
        }

        // Per-session byte cap: close the session when exceeded.
        if ctx.bytes_forwarded >= SESSION_BYTE_CAP {
            ctx.state = ForwardingState::RelayExpired;
            return None;
        }

        // Idle timeout enforcement.
        if now.saturating_sub(ctx.last_active_ms) > IDLE_TIMEOUT_MS {
            ctx.state = ForwardingState::RelayExpired;
            return None;
        }

        let init_addr = ctx.initiator.addr?;
        let targ_addr = ctx.target.addr?;

        // Source must exactly match one of the two authorized bindings.
        // An unregistered or spoofed source address results in a silent drop.
        let destination = if source_addr == init_addr {
            targ_addr
        } else if source_addr == targ_addr {
            init_addr
        } else {
            return None;
        };

        // Token-bucket rate limiting: refill, then check the packet fits.
        let elapsed_s = now.saturating_sub(ctx.rate_bucket.last_refill_ms) as f64 / 1000.0;
        ctx.rate_bucket.tokens = (ctx.rate_bucket.tokens
            + elapsed_s * self.rate_limit_bytes_per_sec as f64)
            .min(self.rate_limit_bytes_per_sec as f64);
        ctx.rate_bucket.last_refill_ms = now;

        let packet_len_f = packet_len as f64;
        if ctx.rate_bucket.tokens < packet_len_f {
            return None;
        }

        // Charge the packet against the bucket and the session byte counter.
        ctx.rate_bucket.tokens -= packet_len_f;
        ctx.bytes_forwarded += packet_len as u64;
        ctx.last_active_ms = now;

        Some(destination)
    }

    /// Explicitly closes a forwarding context (endpoint disconnect or revocation).
    pub fn close(&self, intent_id: [u8; 16]) {
        if let Ok(mut contexts) = self.contexts.write()
            && let Some(ctx) = contexts.get_mut(&intent_id)
        {
            ctx.state = ForwardingState::RelayClosed;
        }
    }

    /// Sweeps expired and closed contexts and removes their token index entries.
    ///
    /// Should be called periodically by a background task to bound memory usage.
    pub fn sweep(&self) -> usize {
        let now = self.clock.now_ms();
        let mut contexts = self.contexts.write().unwrap_or_else(|e| e.into_inner());
        let mut token_index = self.token_index.write().unwrap_or_else(|e| e.into_inner());

        let mut to_remove: Vec<[u8; 16]> = Vec::new();

        for (id, ctx) in contexts.iter_mut() {
            let idle_timed_out = ctx.state == ForwardingState::RelayActive
                && now.saturating_sub(ctx.last_active_ms) > IDLE_TIMEOUT_MS;

            // Exchange timeout: authorized/requested sessions must bind within 10 seconds.
            let exchange_timed_out = matches!(
                ctx.state,
                ForwardingState::Authorized | ForwardingState::RelayRequested
            ) && now.saturating_sub(ctx.authorized_at_ms)
                > EXCHANGE_TIMEOUT_MS;

            // Absolute expiry applies regardless of state.
            let absolute_expired = now >= ctx.expires_at_ms;

            if idle_timed_out || exchange_timed_out || absolute_expired {
                ctx.state = ForwardingState::RelayExpired;
            }

            let is_terminal = matches!(
                ctx.state,
                ForwardingState::RelayExpired | ForwardingState::RelayClosed
            );
            if is_terminal {
                to_remove.push(*id);
            }
        }

        let count = to_remove.len();
        for id in to_remove {
            if let Some(ctx) = contexts.remove(&id) {
                token_index.remove(&ctx.token);
            }
        }
        count
    }

    /// Returns the current state of a forwarding context for testing/audit.
    pub fn state_of(&self, intent_id: &[u8; 16]) -> Option<ForwardingState> {
        self.contexts
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(intent_id)
            .map(|c| c.state)
    }

    /// Returns the total bytes forwarded by a context (for testing/audit).
    pub fn bytes_forwarded_of(&self, intent_id: &[u8; 16]) -> Option<u64> {
        self.contexts
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(intent_id)
            .map(|c| c.bytes_forwarded)
    }

    /// Overrides the forwarded-byte counter for a context (used by tests to simulate
    /// a session at or beyond its byte cap without forwarding gigabytes of data).
    pub fn set_bytes_forwarded(&self, intent_id: &[u8; 16], bytes: u64) -> bool {
        let mut contexts = self.contexts.write().unwrap_or_else(|e| e.into_inner());
        match contexts.get_mut(intent_id) {
            Some(ctx) => {
                ctx.bytes_forwarded = bytes;
                true
            }
            None => false,
        }
    }
}
