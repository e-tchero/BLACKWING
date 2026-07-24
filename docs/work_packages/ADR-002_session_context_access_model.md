# ADR-002: Session Context Access Model

## Status
Accepted and Implemented

## Context
During the implementation of WP-4.10, `SessionManager` was refactored to associate a `SessionId` with its corresponding `EncryptionContext`. Initially, `SessionManager::get_encryption_context` returned an owned clone of the context. 

However, `EncryptionContext` is mutable per-session runtime state containing:
- Monotonic frame counters (`counter`)
- Sliding window replay state (`ReplayProtection`)
- Cryptographic key epochs (`epoch`)

Returning cloned copies produced independent, forked instances of this runtime state. Mutations applied to the returned clone (such as updating replay masks or incrementing counters) were never written back to the authoritative instance held in the `SessionManager` map. This created critical security and correctness vulnerabilities:
1. **AEAD Nonce Reuse:** Callers encrypting frames on separate cloned contexts reuse the same counter/nonce sequences.
2. **Replay Bypass:** The sliding replay window inside the stored context remains un-updated, allowing identical frames to pass replay verification.
3. **Lost Epoch Rotations:** Epoch updates performed on the clone are lost, keeping the stored copy on stale keys.

## Decision
We rejected the clone-based access model (`get_encryption_context`) and replaced it with a closure-based guarded access API:
```rust
pub fn with_session_context<F, R>(&self, id: &SessionId, f: F) -> Result<R, ProtocolError>
where
    F: FnOnce(&mut EncryptionContext) -> R
```

All operations modifying or reading the session's active cryptographic state must execute within the closure. The context is accessed exclusively via an `&mut` reference passed into the closure.

## Consequences & Guarantees

### 1. Ownership & Thread Safety
The outer `Mutex` protecting the map is locked for the duration of the closure. The borrow checker ensures the `&mut` reference cannot outlive the closure or be stored by the caller, guaranteeing that only one thread can mutate the context at any time.

### 2. State Integrity
Because mutations occur directly on the authoritative instance stored inside the `SessionManager`, counter advancement, epoch updates, and replay validation state are preserved atomically and monotonically. State fork/divergence is eliminated.

### 3. Re-entrancy & Deadlocks
The internal mutex is non-reentrant. Callers must **not** invoke other `SessionManager` methods (like `close_session` or nested `with_session_context`) from inside the closure scope as it will result in a thread deadlock. This constraint is documented in the API.

## Future Migration Path
If mutex contention on the global map becomes a bottleneck under high concurrent load, the map values can be migrated to thread-safe sharded mutexes (e.g., `HashMap<SessionId, Arc<Mutex<EncryptionContext>>>`) or lock-free partition structures. Because the outer closure-based signature `with_session_context` is decoupled from the map structure, this refactoring can be done entirely inside `SessionManager` without breaking downstream public APIs.
