# ADR-005: Pluggable Key Rotation Architecture

## Status
DESIGN ONLY — Not Implemented

## Context
Long-lived sessions in Project BLACKWING will eventually encrypt large amounts of data. Relying on a single SymmetricKey for the lifetime of a long session risks cryptographic exhaustion (e.g., nonce reuse if the monotonic counter wraps, or exposing too much ciphertext under a single key, weakening AEAD security bounds). 

We need a mechanism to securely and seamlessly rotate the underlying session keys without tearing down the connection or requiring a full handshake.

## Decision
We will implement an epoch-based, pluggable key rotation architecture.

### 1. Epoch-Based Rotation
- `EncryptionContext` already tracks a `session_epoch` (starting at 0).
- Key rotation advances the epoch `N -> N+1`.
- The new keys for epoch `N+1` will be derived deterministically from the keys of epoch `N` (e.g., using HKDF-Extract and Expand with a "key_rotation" label).

### 2. `KeyRotationPolicy` Enum Extension
The existing `KeyRotationPolicy` enum will be expanded to support pluggable triggers:
- `Manual`: Rotation is explicitly triggered by the application.
- `TimeBased(Duration)`: Rotation occurs automatically after a specified time interval.
- `VolumeBased(u64)`: Rotation occurs automatically after a specified number of bytes or frames have been encrypted.

### 3. Mid-Session Rotation Protocol
- **Trigger:** Either side can trigger a rotation based on the negotiated policy.
- **Signaling:** A special control frame (e.g., `KeyUpdate`) must be sent.
- **Synchronization:** The protocol must handle in-flight packets encrypted with the old key. The `EncryptionContext` must retain the epoch `N` key for a short grace period or sequence window while transitioning to epoch `N+1` for new outbound traffic.

### 4. Atomic Key Swap Semantics
- The rotation must be atomic with respect to the `MessageDispatcher` and `SessionManager`. 
- Due to the `with_session_context()` design, the context is safely locked during the actual `derive_next_keys()` and swap operation, preventing race conditions with concurrent frame encryption/decryption on other threads.

## Consequences
- **Positive:** Guarantees cryptographic bounds are never exceeded, ensuring long-term confidentiality and integrity.
- **Positive:** Pluggable policies allow different applications to choose the appropriate performance/security tradeoff.
- **Negative:** Adds state complexity to `EncryptionContext` (need to store previous keys temporarily).
- **Negative:** Requires a robust signaling protocol to ensure both client and server advance epochs synchronously despite UDP unreliability.
