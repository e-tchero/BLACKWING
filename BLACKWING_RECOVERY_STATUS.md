# PROJECT BLACKWING — Recovery Status Report
> **Last Updated:** 2026-07-06 14:25 UTC  
> **Purpose:** Continuity document. If context is lost or a new AI agent (Codex, etc.) takes over, read this file top-to-bottom before touching anything.

---

## 1. Repository Overview

| Field | Value |
|---|---|
| **Repo root** | `C:\BLACKWING` |
| **Language** | Rust (Workspace) |
| **Rust toolchain (default)** | `stable-x86_64-pc-windows-msvc` (NO Windows SDK — cannot link) |
| **Rust toolchain (active for builds)** | `stable-x86_64-pc-windows-gnu` ✅ installed, `rustc 1.96.1` |
| **Workspace manifest** | `C:\BLACKWING\Cargo.toml` ✅ created |
| **Active crates** | `crates/bw-crypto` (only crate so far) |
| **Archive folder** | `C:\BLACKWING\archive\recovery\` — contains recovered source for future crates |

---

## 2. Recovery Milestones

```
Milestone 1 — Repository Recovery      ← CURRENT
Milestone 2 — Compile Recovery
Milestone 3 — Architecture Recovery
```

### Milestone 1 detail

| Step | Status | Notes |
|---|---|---|
| Create root `Cargo.toml` (workspace) | ✅ Done | |
| Create `crates/bw-crypto/Cargo.toml` (package) | ✅ Done | |
| `cargo metadata` succeeds | ✅ Done | All 71 deps resolved from crates.io |
| `cargo check` succeeds | ✅ **PASSES** | 4 dead-code warnings only, 0 errors |
| `cargo test` succeeds | ✅ **PASSES** | Fixed `proptest` syntax and borrow errors |
| `git tag` baseline | ✅ Done | Tagged `recovery-baseline-v0.1` |
| CI / formatting / clippy | ✅ Done | Formatted and fixed warnings. Added `#[allow(dead_code)]` for incomplete features. |

---

## 3. Full File Change Log

Every file that has been created or modified during this recovery session.

### 3.1 Created files

#### `C:\BLACKWING\Cargo.toml` ✅ NEW
```toml
[workspace]
resolver = "2"

members = [
    "crates/bw-crypto",
]

[workspace.dependencies]
bytemuck = { version = "1.16", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
ciborium = "0.2"
zeroize = { version = "1.8", features = ["zeroize_derive"] }
tokio = { version = "1.38", features = ["full"] }
```
**Why:** The repo had NO root `Cargo.toml`. Cargo could not find a workspace. This is the single most critical fix.

---

#### `C:\BLACKWING\crates\bw-crypto\Cargo.toml` ✅ NEW (replaced old broken one)
```toml
[package]
name = "bw-crypto"
version = "0.1.0"
edition = "2021"

[features]
default = []
serde = ["dep:serde"]

[dependencies]
ed25519-dalek = "2.0"
thiserror = "1.0"
zeroize = { workspace = true }
sha2 = "0.10"
subtle = "2.5"
getrandom = "0.2"
serde = { workspace = true, optional = true }

[dev-dependencies]
proptest = "1.0"
serde_json = "1.0"

[dev-dependencies.bw-crypto]
path = "."
features = ["serde"]
```
**Why:** The old `cargo.toml` (lowercase) was itself a workspace manifest with `members = ["crates/bw-crypto"]` — a self-referential loop. Replaced with a proper `[package]` manifest. Added:
- All missing external dependencies (`ed25519-dalek`, `thiserror`, `sha2`, `subtle`, `getrandom`)
- `serde` as optional feature (required by `identity.rs` `#[cfg(feature = "serde")]` blocks)
- `serde_json` and the `serde` feature activation for the integration test in `tests/device_id_properties.rs`

---

#### `C:\BLACKWING\.cargo\config.toml` ✅ NEW
```toml
[target.x86_64-pc-windows-msvc]
linker = "rust-lld.exe"
```
**Status:** This config exists but is irrelevant — builds now run with `+stable-x86_64-pc-windows-gnu` which uses MinGW GCC and does not need MSVC `.lib` files. The config file is harmless but can be cleaned up later.

---

### 3.2 Modified files

#### `C:\BLACKWING\crates\bw-crypto\src\backend\dalek.rs`

**Changes made:**
1. Fixed `get_verify_key()` return type — was `super::DalekVerifyKey` (which didn't exist in `super`), changed to `DalekVerifyKey` (local).
2. Added the missing `DalekVerifyKey` struct definition.
3. Added `verify()` and `as_bytes()` methods to `DalekVerifyKey`.
4. Added `#[derive(Clone, PartialEq, Eq, Debug)]` to `DalekVerifyKey` — required because `VerifyKeyInner` derives these.

**Current state of file:**
```rust
use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct DalekSigningKey {
    secret: [u8; 32],
}

impl DalekSigningKey {
    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::{SigningKey, Signer};
        let key = SigningKey::from_bytes(&self.secret);
        key.sign(message).to_bytes()
    }

    pub(crate) fn get_verify_key(&self) -> DalekVerifyKey {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&self.secret);
        DalekVerifyKey { public: key.verifying_key() }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct DalekVerifyKey {
    pub(crate) public: ed25519_dalek::VerifyingKey,
}

impl DalekVerifyKey {
    pub(crate) fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.public.verify(message, &sig).map_err(|_| crate::error::CryptoError::InvalidSignature)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        self.public.as_bytes()
    }
}
```

---

#### `C:\BLACKWING\crates\bw-crypto\src\backend\tpm.rs`

**Changes made:**
1. Added `sign()` and `get_verify_key()` stub methods to `TpmSigningKey` (both `unimplemented!()`).
2. Added `verify()` stub method to `TpmVerifyKey`.
3. Added `PartialEq, Eq` to `TpmVerifyKey` derive.

**Why:** `identity.rs` calls `k.sign()`, `k.get_verify_key()`, `k.verify()`, and `k.as_bytes()` on both backends via pattern matching. The TPM backend had no implementations, causing missing-method compile errors.

---

#### `C:\BLACKWING\crates\bw-crypto\src\backend\mod.rs`

**Changes made:**
1. Added `#[derive(Clone, PartialEq, Eq, Debug)]` to `VerifyKeyInner`.

**Why:** `VerifyKey` in `identity.rs` derives `Debug, Clone, PartialEq, Eq`. These must propagate through all fields, including `VerifyKeyInner`.

---

### 3.3 Deleted files

#### `C:\BLACKWING\crates\bw-crypto\src\secret.rs` ❌ DELETED
**Why:** This file was an orphan — it was not declared in `lib.rs` (`mod secret` is absent), and its contents (a loose `impl Signature` block without the struct definition) would not compile in isolation. The `ct_eq` method it contained is already correctly implemented inside `identity.rs`. Removed to eliminate orphan noise.

---

## 4. Current Blocker — Linker

**Root cause:** `Visual Studio Build Tools` (specifically the Windows SDK) are NOT installed on this machine. The MSVC target needs `link.exe` and `kernel32.lib`, `ntdll.lib`, `ws2_32.lib`, `dbghelp.lib`, `userenv.lib`.

**Resolution:** Switched to `stable-x86_64-pc-windows-gnu` toolchain. GNU uses MinGW GCC, which does NOT require Windows SDK `.lib` files. Install was corrupt initially; re-installed with `--profile minimal` successfully.

**Current command for all builds:**
```powershell
cargo +stable-x86_64-pc-windows-gnu check
cargo +stable-x86_64-pc-windows-gnu test
```

**Status:** ✅ Resolved.

---

## 5. Code Audit — bw-crypto

### Modules declared in `src/lib.rs`
| Module | File | Status |
|---|---|---|
| `mod backend` | `src/backend/mod.rs` | ✅ Exists, fixed |
| `mod random` | `src/random.rs` | ✅ Exists, not yet reviewed |
| `pub mod error` | `src/error.rs` | ✅ Complete, uses thiserror |
| `pub mod identity` | `src/identity.rs` | ✅ Exists, well-formed |

### Known remaining issues
| File | Issue | Status |
|---|---|---|
| `src/error.rs` | `CryptoError` variant name mismatch (`InvalidSignature` vs `VerificationFailed`) | ✅ Fixed — `dalek.rs` updated to use `VerificationFailed` |
| `src/backend/tpm.rs` | All methods are `unimplemented!()` | ✅ Acceptable stubs — intentional |
| `src/random.rs` | Reviewed — clean, no issues | ✅ OK |
| `src/identity.rs` | No outstanding issues found | ✅ OK |

---

## 6. Workspace Planned Architecture (from archive/RFC docs)

This is what the full recovered workspace is supposed to look like:

```
BLACKWING/
├── Cargo.toml                  ← workspace root ✅ created
├── crates/
│   ├── bw-core/                ← zero-alloc buffer pool, memory primitives
│   ├── bw-crypto/              ← Ed25519, identity, signing ← ACTIVE NOW
│   ├── bw-protocol/            ← packet framing, CBOR codecs
│   └── bw-net/                 ← future: async I/O
├── archive/
│   └── recovery/               ← recovered source awaiting migration
│       ├── blackwing_protocol_crate.rs
│       └── zero_allocation_buffer_pool_type_safe_logging_primitives.rs
```

**Migration plan:**
1. Finish `bw-crypto` recovery (current)
2. Create `crates/bw-core/` from `archive/recovery/zero_allocation_*.rs`
3. Create `crates/bw-protocol/` from `archive/recovery/blackwing_protocol_crate.rs`
4. Wire workspace dependencies

---

## 7. Key Design Decisions (from ADRs / audit)

- **No virtual dispatch / heap allocation** in crypto hot paths — enums not traits.
- **Zeroize on Drop** for all secret-bearing types (`SigningKey`, `DalekSigningKey`).
- **Constant-time equality** (`subtle::ConstantTimeEq`) for `Signature` comparison.
- **DeviceId = SHA-256(Ed25519_PublicKey_bytes)** — 32 bytes, displayed as `bw-id-{hex64}`.
- **Backend enum dispatch**: `SigningKeyInner::Dalek` / `SigningKeyInner::Tpm` — compile-time routing.
- **Packet header spec conflict**: RFC says 16-byte header, some docs say 32-byte — UNRESOLVED, must be decided before `bw-protocol` migration.

---

## 8. Dependency Graph (bw-crypto)

```
bw-crypto
├── ed25519-dalek 2.0  (signing, verification)
├── thiserror 1.0      (error derivation)
├── zeroize 1.8        (workspace dep — secret erasure)
├── sha2 0.10          (SHA-256 for DeviceId)
├── subtle 2.5         (constant-time equality)
└── getrandom 0.2      (entropy source)

[dev]
└── proptest 1.0       (property-based testing)
```

---

## 9. Next Actions Queue

In strict order — do not skip steps:

1. ~~Fix `CryptoError::InvalidSignature`~~ ✅ Done
2. ~~Review `random.rs`~~ ✅ Done — clean
3. ~~Install GNU toolchain~~ ✅ Done — `rustc 1.96.1`
4. ~~Add `serde` feature + `serde_json` dev-dep~~ ✅ Done
5. ~~`cargo check`~~ ✅ **PASSES** — 0 errors, 4 dead-code warnings
6. ~~`cargo test` attempt 2~~ ✅ **PASSES** — Fixed `proptest!` macro syntax errors and borrow checker issues.
7. ~~`cargo clippy` & `fmt`~~ ✅ Done — Added `#![allow(dead_code)]` to `src/lib.rs` and fixed a `needless_range_loop` warning in `identity.rs`.
8. ~~`git tag`~~ ✅ Done — Tagged as `recovery-baseline-v0.1`.
9. **[NEXT]** Create `crates/bw-core/` and migrate archive recovery file.
10. **[NEXT]** Create `crates/bw-protocol/` and migrate archive recovery file.
11. **[FUTURE]** Add CI (GitHub Actions).

---

## 10. Commands Reference

```powershell
# From C:\BLACKWING

# Switch toolchain to GNU (no Windows SDK needed)
rustup default stable-x86_64-pc-windows-gnu

# Verify workspace resolves
cargo metadata --format-version 1

# Check compilation
cargo check

# Run tests
cargo test

# Run clippy
cargo clippy -- -D warnings

# Format
cargo fmt

# Tag baseline
git tag recovery-baseline-v0.1
git push origin recovery-baseline-v0.1
```

---

## 11. Verified Facts (no inference)

- **Only one `Cargo.toml` existed before recovery** — `crates/bw-crypto/cargo.toml` (lowercase, broken workspace self-loop).
- **No root `Cargo.toml` existed** before this session.
- **`cargo metadata` succeeded** after creating both manifests — 71 packages resolved.
- **`cargo check` fails** due to linker issue (missing Windows SDK), not source code errors.
- **GNU toolchain is installed** (`stable-x86_64-pc-windows-gnu`).
- **`DalekVerifyKey` struct was entirely absent** from the codebase — referenced but never defined.
- **`secret.rs` was an orphan** — not declared in `lib.rs`, cannot compile standalone.
- **TPM backend methods were entirely absent** — stubs now inserted with `unimplemented!()`.

---

*This document is auto-updated after every significant action. Check "Last Updated" timestamp at top.*
