# ADR-004: Session Persistence and Resumption Architecture

## Status
DESIGN ONLY — Not Implemented

## Context
Project BLACKWING is designed for high-performance and resilient networking. Establishing a full cryptographic session via `HandshakeRequest` requires asymmetric cryptographic operations (or expensive key agreement protocols depending on future extensions) and capability negotiation. For clients that frequently reconnect (e.g., mobile networks, intermittent UDP connectivity), paying the full handshake cost every time is inefficient. We need a way to resume previously established sessions securely without a full handshake.

## Decision
We will implement a Session Ticket based resumption mechanism, conceptually similar to TLS 1.3 0-RTT/1-RTT resumption, tailored for our UDP/custom transport.

### 1. Session Ticket Format
The server will issue an encrypted Session Ticket to the client upon successful session establishment.
- The ticket must contain the `master_secret`, `session_id`, negotiated `Capabilities`, and ticket expiration time.
- The ticket must be encrypted using a server-side only key (Ticket Encryption Key - TEK).
- The TEK must be rotated regularly to limit the compromise window.

### 2. Storage Interface
- **Client:** Must securely store the Session Ticket and the associated `master_secret` in hardware-backed storage (if available) or an encrypted local vault.
- **Server:** Server is stateless regarding resumption tickets. It relies entirely on decrypting the client-presented ticket using its active TEK.

### 3. Security Considerations
- **Ticket Theft:** If a ticket is stolen from the client, an attacker could attempt to hijack the session. To mitigate this, ticket presentation must be bound to the client's `DeviceId` and accompanied by a proof-of-possession of the original `master_secret` (e.g., a MAC over the resumption request).
- **Replay Attacks:** Resumption requests must include a fresh client nonce, and the server must mix this nonce with the ticket's `master_secret` to derive fresh session keys for the resumed session, ensuring that replaying the resumption packet does not result in the same key stream.
- **Forward Secrecy:** Resumption inherently trades some forward secrecy for performance. If the server's TEK is compromised, all tickets encrypted with that TEK can be decrypted, exposing the `master_secret`. The server TEK rotation policy must be aggressive (e.g., daily or hourly) and old TEKs must be securely zeroized.

## Consequences
- **Positive:** Significant reduction in latency and CPU usage for reconnecting clients.
- **Positive:** Server remains mostly stateless for session resumption, improving scalability.
- **Negative:** Adds complexity to the client state management and server key rotation infrastructure.
- **Negative:** Introduces new threat vectors (ticket theft, TEK compromise) that must be carefully managed.
