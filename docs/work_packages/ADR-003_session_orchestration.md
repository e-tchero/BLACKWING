# ADR-003: Session Orchestration as a Thin Coordinator

## Status
Accepted

## Context
During the implementation of WP-5.0, we needed a way to bridge the handshake phase (which derives keys) and the session phase (which manages live `EncryptionContext` instances in the `SessionManager`). The bridging function is `create_session_from_handshake`. 

As the protocol evolves, there is a risk that this orchestration function will accumulate unrelated responsibilities, such as enforcing capability requirements, performing authentication checks, or handling transport-specific routing decisions. This would violate the single-responsibility principle and create a tangled dependency graph between the handshake, session, and routing layers.

## Decision
We will enforce that `create_session_from_handshake` acts strictly as a **thin coordinator**. It must not accumulate protocol policy.

Its responsibilities are strictly limited to:
1. Deriving session keys via `bw_protocol::handshake::derive_session_keys`.
2. Constructing the `EncryptionContext` using the derived keys and requested rotation policy.
3. Registering the new session into the `SessionManager`.
4. Propagating any cryptographic or registration errors (e.g., duplicate session ID).

It must **not** perform:
- Capability negotiation or validation.
- Authentication decisions.
- Certificate chain verification.
- Application-layer callbacks.

## Consequences
- **Positive:** The session layer remains cleanly decoupled from the complex policy rules of the handshake. `SessionManager` continues to care only about managing live encryption states.
- **Positive:** Testing the orchestrator is simple and deterministic.
- **Negative:** The caller of `create_session_from_handshake` is responsible for verifying all protocol policies (like capabilities and authentication) *before* calling the orchestrator. If the caller fails to do this, an unauthorized session could theoretically be registered.
