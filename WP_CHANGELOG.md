# Work Package & Architecture Changelog

**Last Updated:** 2026-07-08
**Phase:** Transitioning from Recovery to Implementation

This document tracks every structural, architectural, and work package change made to PROJECT BLACKWING. It is written so that any engineer or AI agent can understand exactly what happened, in what order, and why.

---

## Milestone 0: Repository Triage (Completed)

### What was found
The repository had no functioning Cargo workspace. The only `Cargo.toml` that existed was `crates/bw-crypto/cargo.toml` (lowercase), and it was incorrectly written as a workspace manifest pointing to itself — a self-referential loop that made it impossible for Cargo to resolve dependencies or compile anything.

Additional problems found:
- No root `Cargo.toml` workspace manifest.
- The MSVC toolchain was the default but the machine has no Visual Studio Build Tools or Windows SDK — so the linker would fail.
- `DalekVerifyKey` struct was referenced in the codebase but never defined anywhere.
- `secret.rs` was an orphan file — not declared in `lib.rs` and would not compile standalone.
- TPM backend methods were entirely absent — `TpmSigningKey` had no `sign()`, `get_verify_key()`, or `verify()` implementations.
- `proptest!` macro blocks had incorrect `Result<(), TestCaseError>` return types.
- Property-based tests had borrow checker errors (`prop_assert_eq!(s1, s2)` consumed `s1` before it was borrowed again).

### What was fixed

| Fix | Detail |
|---|---|
| Created root `Cargo.toml` | Workspace manifest with `resolver = "2"` and `members = ["crates/bw-crypto"]` |
| Replaced `bw-crypto/cargo.toml` | Proper `[package]` manifest. Added all missing dependencies (`ed25519-dalek`, `thiserror`, `sha2`, `subtle`, `getrandom`). Added `serde` as optional feature. Added `proptest` and `serde_json` as dev-dependencies. |
| Switched toolchain to GNU | `stable-x86_64-pc-windows-gnu`. Installed MinGW via `scoop install mingw` to supply `dlltool.exe` and `as.exe`. |
| Added `DalekVerifyKey` struct | Defined in `src/backend/dalek.rs` with `verify()` and `as_bytes()` methods. |
| Added TPM stubs | `TpmSigningKey::sign()`, `TpmSigningKey::get_verify_key()`, `TpmVerifyKey::verify()` — all `unimplemented!()`. |
| Added derives to `VerifyKeyInner` | `#[derive(Clone, PartialEq, Eq, Debug)]` required because `VerifyKey` in `identity.rs` derives these. |
| Deleted `secret.rs` | Orphan file. Its content was already implemented in `identity.rs`. |
| Fixed `proptest!` macro bodies | Removed `Result<(), TestCaseError>` return types — the macro injects `Ok(())` automatically. |
| Fixed borrow checker errors | Changed `prop_assert_eq!(s1, s2)` to `prop_assert_eq!(&s1, &s2)` to avoid moving Strings. |
| Fixed clippy warning | Changed `for i in 0..DEVICE_ID_BYTES` to `for (i, byte) in bytes.iter_mut().enumerate()` in `identity.rs`. |
| Added `#![allow(dead_code)]` to `lib.rs` | Suppresses warnings for incomplete backend features (TPM, OsRandom) at this stage. |
| Created `.gitignore` | Excludes `/target`, `*.rs.bk`. |

**Result:** `cargo check` ✅, `cargo test` ✅ (13/13), `cargo fmt` ✅, `cargo clippy` ✅.
**Tagged:** `recovery-baseline-v0.1`

---

## Milestone 1: Architecture Audit (Completed)

A full read-only engineering audit was performed. No files were modified.

### Audit Findings
- Single active crate: `bw-crypto`
- 3 recovered source files in `archive/` awaiting migration
- 18+ `.docx` specification documents organized into `docs/`
- No CI pipeline
- No GitHub Actions workflows
- No root README
- No ADRs beyond ADR-001 (Device Identifier)
- `PacketHeader` size conflict between documents (16 bytes vs 32 bytes — 32-byte layout confirmed in recovered source, wins)

**Report saved:** `BLACKWING_ENGINEERING_BASELINE.md`

---

## Milestone 1.5: Repository Hard Freeze (Completed)

### Changes Made

| Action | Detail |
|---|---|
| Renamed `archive/recovery/` | → `archive/recovered_sources/` (permanent historical artifacts, not active work) |
| Created `docs/REPOSITORY_MAP.md` | Physical layout of the workspace. First document every contributor reads. |
| Created `docs/WORKSPACE_VISION.md` | Dependency direction rules, public API freeze policy, full 12-crate future vision. |
| Created ADR-002 | `docs/adr/ADR-002_Workspace_Structure.md` — Draft |
| Created ADR-003 | `docs/adr/ADR-003_Crate_Boundaries.md` — Draft |
| Created ADR-004 | `docs/adr/ADR-004_Memory_Allocation_Policy.md` — Draft |
| Created ADR-005 | `docs/adr/ADR-005_Cryptographic_Backend_Strategy.md` — Draft |
| Created ADR-006 | `docs/adr/ADR-006_Error_Handling_Policy.md` — Draft |
| Created ADR-007 | `docs/adr/ADR-007_Async_Runtime_Policy.md` — Draft |
| Created ADR-008 | `docs/adr/ADR-008_Logging_Strategy.md` — Draft |
| Working tree verified clean | `git status` confirmed. |
| Tagged | `git tag architecture-baseline-v0.2` |

**Rationale:** Any crate migration done without this governance in place risks introducing API sprawl and architectural drift.

---

## Work Package 3.1: `bw-core` Crate Bootstrap (Completed)

**Objective:** Create a production-ready empty crate scaffold. No code migration. No recovered source included. Success = cleanly compiling, documented, empty crate.

### Files Created

| File | Detail |
|---|---|
| `crates/bw-core/Cargo.toml` | `[package]` manifest. Only dependency: `thiserror = "1"`. Intentionally minimal. |
| `crates/bw-core/src/lib.rs` | `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`. Declares `pub mod error`, `logging`, `memory`, `pool`. |
| `crates/bw-core/src/error.rs` | Empty module. Module-level docstring: `//! Error types and handling utilities for bw-core.` |
| `crates/bw-core/src/logging.rs` | Empty module. Module-level docstring: `//! Type-safe, lock-free logging primitives.` |
| `crates/bw-core/src/memory.rs` | Empty module. Module-level docstring: `//! Memory allocation utilities and zero-allocation buffers.` |
| `crates/bw-core/src/pool.rs` | Empty module. Module-level docstring: `//! Lock-free pool implementations.` |
| `crates/bw-core/README.md` | Answers Purpose / Responsibilities / Non-responsibilities / Public API. |
| `crates/bw-core/tests/` | Empty directory. Reserved for integration tests. |
| `crates/bw-core/benches/` | Empty directory. Reserved for benchmarks. |

### Workspace Updated
- Added `"crates/bw-core"` to `members` array in root `Cargo.toml`.

### Quality Gates
| Gate | Result |
|---|---|
| `cargo check` | ✅ 0 errors |
| `cargo test` | ✅ 100% pass (13 bw-crypto tests, 0 regressions) |
| `cargo fmt --check` | ✅ Clean |
| `cargo clippy -- -D warnings` | ✅ 0 warnings |

**Tagged:** `wp-3.1-complete`

---

## Additional Infrastructure Files Created

| File | Purpose |
|---|---|
| `BLACKWING_ENGINEERING_BASELINE.md` | Full engineering audit report |
| `HANDOFF.md` | Complete AI/engineer handoff document — canonical context file |
| `WP_CHANGELOG.md` | This file |

---

## Architectural Principles Established (Locked)

These decisions are locked. Do not reverse without creating a new ADR.

| Principle | Detail |
|---|---|
| Dependency direction | `bw-core` → `bw-crypto` → `bw-protocol` → `bw-net`. Never upward. |
| Default visibility | `pub(crate)`. Only `pub` after ADR review. |
| No unsafe in `bw-core` | `#![forbid(unsafe_code)]` is enforced at compiler level. |
| No panics in library code | `clippy::unwrap_used` and `clippy::expect_used` are denied. |
| No virtualisation in hot paths | Enum dispatch, not trait objects. |
| Zeroize on Drop | All secret-bearing types must implement `ZeroizeOnDrop`. |
| DeviceId format | `bw-id-` prefix + 64 lowercase hex chars (32 bytes SHA-256 of Ed25519 public key). |
| Quality gates mandatory | All four must pass before any WP is tagged complete. |
| Git tagging convention | `wp-X.Y-complete`, `bw-CRATE-vX.Y`, `milestone-N-complete`. |

---

## Upcoming Work Packages

| Work Package | Objective | Status |
|---|---|---|
| WP-3.2 | Migrate `BwError` enum into `bw-core/src/error.rs` | 🔲 Not Started |
| WP-3.3 | Migrate `Severity`, `LogEvent`, `HealthReport` into `bw-core/src/logging.rs` | 🔲 Not Started |
| WP-3.4 | Migrate `LockFreeMemoryPool` + `PoolGuard` into `bw-core/src/memory.rs` | 🔲 Not Started |
| WP-3.5 | Migrate `StaticSlotPool` into `bw-core/src/pool.rs` (unsafe review required) | 🔲 Not Started |
| WP-3.6 | Integration tests for `StaticSlotPool` | 🔲 Not Started |
| WP-3.7 | All integration tests from recovered sources into `bw-core/tests/` | 🔲 Not Started |
| WP-3.8 | Benchmarks in `bw-core/benches/` | 🔲 Not Started |
| WP-3.9 | Documentation & public API review → tag `bw-core-v0.1` | 🔲 Not Started |
| WP-4.1 | `bw-protocol` crate bootstrap (empty scaffold) | 🔲 Not Started |
| WP-4.2 | Migrate `PacketHeader`, `ProtocolError` | 🔲 Not Started |
| WP-4.3 | Migrate `FeatureManifest`, `DisplayProfile`, `CapabilityMessage` | 🔲 Not Started |
| WP-4.4 | Protocol tests | 🔲 Not Started |
| WP-4.5 | Protocol docs & API review → tag `bw-protocol-v0.1` | 🔲 Not Started |
