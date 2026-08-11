use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// The type of a network address candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateType {
    /// Bound directly on a local network interface.
    Host,
    /// The public address observed by the relay server when the endpoint registered.
    /// This is the endpoint's external NAT-mapped address.
    ServerReflexive,
    /// The relay server's own address, used as a forwarding fallback.
    Relay,
}

/// A network address candidate for establishing a direct QUIC connection.
///
/// Candidates are gathered by an endpoint at registration time and exchanged
/// via the relay's rendezvous protocol. Both parties then attempt connectivity
/// checks against each other's candidate sets, starting from the highest-priority
/// candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// The candidate classification.
    pub candidate_type: CandidateType,
    /// The network socket address.
    pub addr: SocketAddr,
    /// Priority score. Higher values are preferred. Host > ServerReflexive > Relay.
    pub priority: u32,
}

impl Candidate {
    /// Creates a Host candidate from a locally-bound address.
    pub fn host(addr: SocketAddr) -> Self {
        Self {
            candidate_type: CandidateType::Host,
            addr,
            priority: 30_000,
        }
    }

    /// Creates a ServerReflexive candidate from the relay-observed public address.
    pub fn server_reflexive(addr: SocketAddr) -> Self {
        Self {
            candidate_type: CandidateType::ServerReflexive,
            addr,
            priority: 20_000,
        }
    }

    /// Creates a Relay candidate for fallback forwarding through the relay server.
    pub fn relay_addr(addr: SocketAddr) -> Self {
        Self {
            candidate_type: CandidateType::Relay,
            addr,
            priority: 10_000,
        }
    }
}
