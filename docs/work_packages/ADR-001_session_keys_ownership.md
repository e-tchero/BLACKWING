# ADR-001: Ownership Model between SessionKeys and EncryptionContext

## Status
Candidate / Deferred to Future Architectural Review

## Context
In `bw-protocol`, `SessionKeys` represents the cryptographic state of a session (send key, receive key, and epoch) derived during handshake negotiation. `EncryptionContext` is the operational engine that encrypts/decrypts frames and manages mutable runtime state (counters, replay protection).

During the implementation of WP-4.10, implementing `ZeroizeOnDrop` for `SessionKeys` made it a `Drop` type. Under Rust compiler rule `E0509`, fields cannot be moved out of a type that implements `Drop`. 

To initialize the internal encryptor and decryptor inside `EncryptionContext::new(keys: SessionKeys, ...)` without compile errors, we had to clone the keys:
```rust
encryptor: FrameEncryptor::new(keys.send_key.clone(), keys.epoch),
decryptor: FrameDecryptor::new(keys.recv_key.clone(), keys.epoch),
```
This introduces short-lived, transient copies of the key material in memory during constructor execution. Although zeroization hygiene guarantees all copies are zeroized upon dropping, this duplication is a candidate for structural optimization.

## Proposed Alternatives

### Alternative A: Retain Cloned Ownership (Current Status)
* **Pros:** Simple implementation; keeps `FrameEncryptor` and `FrameDecryptor` decoupled and individually testable.
* **Cons:** Temporary duplicate key material exists during context creation (though zeroized immediately afterward).

### Alternative B: Direct Parameter Passing (Destructured Constructor)
Change the constructor of `EncryptionContext` to take the keys by value directly:
```rust
pub fn new(send_key: SymmetricKey, recv_key: SymmetricKey, epoch: u32, policy: KeyRotationPolicy) -> Self
```
* **Pros:** Bypasses `SessionKeys` packaging in the operational path, avoiding `E0509` and removing the need to clone.
* **Cons:** Splits the logical `SessionKeys` domain concept at the constructor interface boundary.

### Alternative C: Safe Replacement/Swapping (Option::take / std::mem::take)
Define a dummy/default state for `SymmetricKey` (e.g. wrapping key bytes in an `Option`), allowing us to swap the keys out of the `SessionKeys` container:
```rust
let send_key = std::mem::take(&mut keys.send_key);
```
* **Pros:** Avoids cloning without changing the constructor parameters.
* **Cons:** Introduces complexity (wrapping key arrays in `Option` or allocating dummy state structures) in critical hot paths.

## Decision
Ownership refactoring is deferred to a future architectural review. The current cloning model is retained for WP-4.10 because it satisfies Rust's borrow checker, guarantees zeroization of all transient memory copies, and prevents unnecessary API changes to the constructor interfaces.
