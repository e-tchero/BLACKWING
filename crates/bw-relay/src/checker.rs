use crate::candidate::Candidate;
use std::net::SocketAddr;
use std::time::Duration;

/// Abstracts direct QUIC connection attempts to allow testing without a live network.
///
/// The production implementation wraps `bw-transport`'s `QuicClient`. Tests supply
/// a mock that simulates success or failure deterministically.
pub trait DirectConnector: Send + Sync {
    /// Attempt to establish a connection to `addr` within `timeout`.
    ///
    /// Returns `true` if the path is reachable, `false` otherwise.
    fn try_connect(&self, addr: SocketAddr, timeout: Duration) -> bool;
}

/// Attempts direct QUIC connectivity to a set of candidates in priority order.
///
/// For each candidate (sorted highest priority first), up to `retry_count` connection
/// attempts are made with `retry_delay` between attempts. The first successful
/// address is returned. If all candidates and retries fail, `None` is returned,
/// signalling that the relay fallback path should be used.
///
/// This implements the client-side half of the BLACKWING NAT traversal protocol.
/// It does NOT use ICE or STUN. It borrows the concept of prioritised candidates
/// while operating within BLACKWING's existing QUIC transport architecture.
pub struct ConnectivityChecker<C: DirectConnector> {
    connector: C,
    /// Number of connection attempts per candidate before moving to the next.
    retry_count: u32,
    /// Delay between retries for the same candidate.
    retry_delay: Duration,
}

impl<C: DirectConnector> ConnectivityChecker<C> {
    /// Creates a checker with the production parameters from the WP-8.0 design:
    /// 3 retries, 1 second between attempts (5 second total per candidate set).
    pub fn new(connector: C) -> Self {
        Self {
            connector,
            retry_count: 3,
            retry_delay: Duration::from_secs(1),
        }
    }

    /// Creates a checker with custom retry parameters (useful for tests).
    pub fn with_params(connector: C, retry_count: u32, retry_delay: Duration) -> Self {
        Self {
            connector,
            retry_count,
            retry_delay,
        }
    }

    /// Tries each candidate in descending priority order.
    ///
    /// Returns the first `SocketAddr` that responds within the per-attempt timeout,
    /// or `None` if every candidate fails all retries.
    pub fn find_direct_path(&self, mut candidates: Vec<Candidate>) -> Option<SocketAddr> {
        // Sort by priority descending — Host (30000) before ServerReflexive (20000)
        // before Relay (10000).
        candidates.sort_by_key(|b| std::cmp::Reverse(b.priority));

        for candidate in &candidates {
            for _ in 0..self.retry_count {
                if self.connector.try_connect(candidate.addr, self.retry_delay) {
                    return Some(candidate.addr);
                }
            }
        }
        None
    }
}
