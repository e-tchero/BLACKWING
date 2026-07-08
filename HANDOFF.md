# PROJECT BLACKWING — Master Handoff Document

> **CRITICAL:** If you are a new AI agent reading this, read this document top-to-bottom BEFORE touching any file or running any command. This document is the single source of truth for the current state of this project.
>
> **Last Updated:** 2026-07-06 16:35 UTC
> **Repository Root:** `C:\BLACKWING`
> **Current Phase:** Implementation (Milestone 2 begins next)

---

## 0. How to Read This Document

1. Read sections 1-4 to understand what this project is and where it stands.
2. Read section 5 to understand the toolchain constraints — this is the most critical environmental fact.
3. Read sections 6-7 to understand what work was done and what decisions were made.
4. Read section 8 to understand what files exist.
5. Read sections 9-10 to understand what to do next and in what order.
6. Never skip the quality gate checks described in section 10.

---

## 1. Project Summary

**PROJECT BLACKWING** is a remote desktop and device-management platform being built in Rust. It is a monorepo structured as a Cargo workspace. The repository is on a Windows machine and has been fully recovered from a broken state into a clean, structured, buildable baseline. The engineering phase is now beginning.

The project is similar in scope to something like RustDesk but with a focus on enterprise cryptographic identity, zero-allocation memory primitives, and a clean multi-crate workspace architecture.

---

## 2. Architectural Philosophy (agreed with the user)

The following principles were explicitly discussed and adopted. **Do not contradict them.**

- **No virtual dispatch in hot paths.** Use enum dispatch instead of trait objects.
- **No unsafe code in `bw-core`.** `lib.rs` enforces `#![forbid(unsafe_code)]`.
- **No allocation in pool hot paths.** Memory pools pre-allocate and use atomic CAS.
- **Zeroize on Drop** for all types that hold secrets.
- **No circular dependencies** between crates. Flow is strictly top-down.
- **Default visibility is `pub(crate)`.** Only expose `pub` after an explicit ADR review.
- **No panics in library code.** Forbid `unwrap_used` and `expect_used` in production paths.
- **Every public API decision is traceable to an ADR.**
- **No migration of recovered code without a dedicated Work Package.**

---

## 3. Dependency Direction (strictly enforced)

```text
bw-core          ← bottom of the stack, no dependencies on other bw-* crates
   ↓
bw-crypto        ← may depend on bw-core only
   ↓
bw-protocol      ← may depend on bw-crypto and bw-core
   ↓
bw-net           ← may depend on bw-protocol and below
   ↓
bw-capture / bw-relay  ← may depend on bw-net and below
   ↓
bw-video / bw-audio
   ↓
bw-agent
   ↓
bw-console / bw-cli / bw-update
```

**Forbidden:** Any upward or sideways dependency (e.g., `bw-core` depending on `bw-protocol`).

---

## 4. Toolchain — CRITICAL ENVIRONMENTAL FACT

> Do NOT attempt to build with the MSVC toolchain. It will fail.

| Fact | Detail |
|---|---|
| **Active Rust toolchain** | `stable-x86_64-pc-windows-gnu` |
| **Rustc version** | `1.96.1` |
| **Why GNU?** | The machine has no Visual Studio Build Tools / Windows SDK installed. MSVC toolchain needs `link.exe`, `kernel32.lib`, etc. GNU uses MinGW GCC and does not need them. |
| **MinGW location** | Installed via `scoop install mingw` (non-admin) |
| **MinGW path** | `C:\Users\ETCHE\scoop\apps\mingw\current\bin` |
| **Required PATH prefix** | Must prefix this to PATH before running cargo. See commands section. |

**All cargo commands must be run as:**
```powershell
$env:PATH = "C:\Users\ETCHE\scoop\apps\mingw\current\bin;" + $env:PATH
cargo +stable-x86_64-pc-windows-gnu <command>
```

Or simply:
```powershell
cargo <command>   # if the default toolchain is already set to GNU
```

---

## 5. Repository Tag History (Git)

| Tag | Meaning |
|---|---|
| `recovery-baseline-v0.1` | First buildable state. `cargo test` passes. |
| `architecture-baseline-v0.2` | ADRs, REPOSITORY_MAP, WORKSPACE_VISION added. Architecture governance established. |
| `wp-3.1-complete` | `bw-core` crate bootstrap complete. Empty scaffold with all quality gates passing. |

---

## 6. Current Build Status

| Command | Status |
|---|---|
| `cargo check` | ✅ 0 errors |
| `cargo test` | ✅ 13/13 tests pass (all in `bw-crypto`) |
| `cargo fmt --check` | ✅ Clean |
| `cargo clippy -- -D warnings` | ✅ 0 warnings |

---

## 7. Workspace Members

```toml
# C:\BLACKWING\Cargo.toml
[workspace]
resolver = "2"
members = [
    "crates/bw-crypto",
    "crates/bw-core",
]
```

---

## 8. Complete File Inventory (non-generated, non-.git)

### Active Rust Source
```
crates/bw-crypto/
    Cargo.toml                   ← Package manifest. serde is an optional feature.
    src/lib.rs                   ← Crate root. Re-exports DeviceId, Signature, SigningKey, VerifyKey.
    src/error.rs                 ← CryptoError enum via thiserror.
    src/identity.rs              ← DeviceId (SHA-256 of ed25519 pubkey), Signature, SigningKey, VerifyKey.
    src/random.rs                ← SecureRandom trait + OsRandom struct. Currently unused stubs.
    src/backend/mod.rs           ← SigningKeyInner + VerifyKeyInner enum dispatch.
    src/backend/dalek.rs         ← Software (ed25519-dalek) implementation.
    src/backend/tpm.rs           ← TPM stub. All methods are unimplemented!(). Acceptable.
    tests/device_id_properties.rs ← 13 property-based tests using proptest.

crates/bw-core/
    Cargo.toml                   ← Only dependency: thiserror = "1"
    src/lib.rs                   ← #![forbid(unsafe_code)] #![deny(missing_docs)]
    src/error.rs                 ← Empty. Module-level docstring only.
    src/logging.rs               ← Empty. Module-level docstring only.
    src/memory.rs                ← Empty. Module-level docstring only.
    src/pool.rs                  ← Empty. Module-level docstring only.
    README.md                    ← Purpose / Responsibilities / Non-responsibilities / Public API.
    tests/                       ← Empty directory. Reserved for integration tests.
    benches/                     ← Empty directory. Reserved for benchmarks.
```

### Archive / Recovered Sources (DO NOT MODIFY THESE FILES — they are historical artifacts awaiting migration)
```
archive/recovered_sources/
    zero_allocation_buffer_pool_type_safe_logging_primitives.rs
        → Intended target: bw-core (error.rs, logging.rs, memory.rs, pool.rs)
        → Contains: BwError enum, LogEvent, Severity, HealthReport, LockFreeMemoryPool, PoolGuard
        → Dependencies needed: thiserror, serde, zeroize, serde_json
        → Has inline unit tests (4 tests, all passing when compiled).

    static_slot_pool_refinement.rs
        → Intended target: bw-core/src/pool.rs (refinement of the above pool)
        → Contains: StaticSlotPool<SLOT_SIZE, POOL_SIZE> (const-generic), TaggedIndex (ABA protection)
        → Has unsafe blocks. Requires careful review before migration.
        → References `crate::BwError` — assumes it is co-located in the same crate.
        → Has no tests of its own.

    blackwing_protocol_crate.rs
        → Intended target: bw-protocol crate (future, not yet created)
        → Contains: PacketHeader (32-byte, zero-copy via bytemuck), FeatureManifest,
                    DisplayProfile, CapabilityMessage, ProtocolError
        → Dependencies needed: bytemuck, serde, thiserror, zeroize, ciborium
        → Has inline unit tests (4 tests).
        → PacketHeader is 32-byte layout with 8-byte alignment (verified by test).
        → Uses CBOR serialization via ciborium for CapabilityMessage.
```

### Archive / Previous Versions
```
archive/previous_versions/
    internal_constant_time_trait.rs  ← Obsolete. Constant-time comparison is already in identity.rs.
```

### Archive / Exports
```
archive/exports/
    _MConverter.eu_ADR-001_ Device Identifier Specification.md  ← Exported markdown of ADR-001.
```

### Documentation
```
docs/
    REPOSITORY_MAP.md            ← Physical layout of the workspace. Read first.
    WORKSPACE_VISION.md          ← Dependency rules, API freeze policy, future crate list.
    adr/
        ADR-001_ Device Identifier Specification.docx      ← IMPLEMENTED. DeviceId = bw-id-{hex64}
        ADR-001_ Revised Device Identifier Specification.docx
        ADR-002_Workspace_Structure.md                     ← DRAFT. Not yet finalized.
        ADR-003_Crate_Boundaries.md                        ← DRAFT.
        ADR-004_Memory_Allocation_Policy.md                ← DRAFT.
        ADR-005_Cryptographic_Backend_Strategy.md          ← DRAFT.
        ADR-006_Error_Handling_Policy.md                   ← DRAFT.
        ADR-007_Async_Runtime_Policy.md                    ← DRAFT.
        ADR-008_Logging_Strategy.md                        ← DRAFT.
    architecture/
        Blackwing Architecture Baseline Specifications.docx
        bw-crypto Crate Architecture.docx
        Project Blackwing Architecture Handbook & Protocol Specification.docx
        Project Blackwing Operational Architecture.docx
        Project Blackwing Phase 2 Final Architecture.docx
    dashboard/
        project_blackwing_discovery_dashboard.html
    handbook/
        Implementation Architecture & SRE Handbook.docx
        Repository Standards & SRE Manual.docx
    planning/
        Detailed Engineering Specification.docx
        Phase 3 Bootstrap Manifest.docx
        Product Requirements Document (PRD) v1.0.docx
        Project Blackwing Phase 1_ Professional Product Discovery.docx
    protocol/
        Blackwing RFC Protocol Spec.docx
        Device ID Protocol Specification.docx
        Transport Scheduler & Session Lifecycle Specification.docx
    work_packages/
        WP-2.3 Display Capture Pipeline.docx
        WP-2.4 Video Encoding.docx
        WP-2.5 Input & Clipboard.docx
        WP-2.6 Cryptography & Authentication.docx
        WP-2.7 Relay & Control Plane Architecture.docx
```

### Root Files
```
BLACKWING/
    .gitignore                   ← Excludes /target, *.rs.bk, Cargo.lock
    Cargo.toml                   ← Workspace root.
    Cargo.lock                   ← Committed (reproducible builds).
    BLACKWING_RECOVERY_STATUS.md ← Legacy status report. Superseded by this document.
    BLACKWING_ENGINEERING_BASELINE.md ← Engineering audit report.
    WP_CHANGELOG.md              ← Brief work package completion notes.
```

---

## 9. Key Design Decisions (Already Made)

These are locked in. Do not reverse them without a new ADR.

| Decision | Rationale |
|---|---|
| DeviceId = `bw-id-` prefix + 64 hex chars (32 bytes SHA-256) | ADR-001 |
| Ed25519 (dalek) for signing | Audited, well-maintained, constant-time |
| Zeroize on Drop for all secret types | Memory hygiene, prevents secret leakage after dealloc |
| Constant-time equality (`subtle::ConstantTimeEq`) for Signature | Prevents timing attacks |
| Enum dispatch for cryptographic backends | Avoids vtable overhead in hot paths |
| `thiserror` for all error enums | Consistent, ergonomic, zero-cost |
| No unwrap/expect in library code | `clippy::unwrap_used` is enforced as a deny-lint |
| `#![forbid(unsafe_code)]` in bw-core | Safety boundary enforced at compiler level |
| `pub(crate)` by default | API sprawl prevention |
| CBOR (ciborium) for protocol serialization | Compact binary, fits inside MTU |
| PacketHeader is 32-byte, 8-byte aligned | Matches RFC spec, verified by test |

---

## 10. Work Package Roadmap

### Completed

| Tag | Work Package | Outcome |
|---|---|---|
| `recovery-baseline-v0.1` | Milestone 1: Repository Recovery | `cargo test` passing, toolchain fixed |
| `architecture-baseline-v0.2` | Milestone 1.5: Hard Freeze | ADRs, maps, vision committed |
| `wp-3.1-complete` | WP-3.1: bw-core Bootstrap | Empty crate skeleton, all quality gates green |

### To Do (in strict order)

**WP-3.2 — bw-core Error Types**
- Migrate `BwError` enum from `archive/recovered_sources/zero_allocation_buffer_pool_type_safe_logging_primitives.rs` into `crates/bw-core/src/error.rs`.
- Add `serde` as an optional feature (BwError derives Serialize/Deserialize).
- Add `serde` and `thiserror` to `bw-core/Cargo.toml` (thiserror is already there).
- Migrate the `test_error_formatting` test into `crates/bw-core/tests/`.
- Quality gates must pass before proceeding.

**WP-3.3 — bw-core Logging Primitives**
- Migrate `Severity`, `LogEvent`, `HealthReport` from the same recovered source file.
- Place into `crates/bw-core/src/logging.rs`.
- `LogEvent::emit_json()` requires `serde_json` as a dev-dependency.
- Migrate the `test_structured_logging_output` and `test_system_health_evaluation` tests.

**WP-3.4 — bw-core Memory Abstractions**
- Migrate `LockFreeMemoryPool` and `PoolGuard` into `crates/bw-core/src/memory.rs`.
- This pool uses `Vec<u8>` and `Arc<[AtomicBool]>` — it does allocate during initialization, only zero-allocation in the hot path.
- Add `zeroize` to `bw-core/Cargo.toml`.

**WP-3.5 — bw-core Lock-Free Pool (Advanced)**
- Migrate `StaticSlotPool` from `archive/recovered_sources/static_slot_pool_refinement.rs` into `crates/bw-core/src/pool.rs`.
- **WARNING:** This file contains `unsafe` blocks (`UnsafeCell`). The `#![forbid(unsafe_code)]` in `lib.rs` MUST be removed or the pool must be re-implemented safely before migration.
- Requires ABA-protection design review (TaggedIndex using 64-bit tagged indices).
- This is the most complex step. Do not rush it.

**WP-3.6 — bw-core Static Slot Refinement**
- Write integration tests for `StaticSlotPool` covering full checkout/release/exhaustion cycles.

**WP-3.7 — bw-core Integration Tests**
- All test coverage from recovered sources merged into `crates/bw-core/tests/`.

**WP-3.8 — bw-core Benchmarks**
- Create `crates/bw-core/benches/pool_throughput.rs`.
- Benchmark pool checkout/release under contention.

**WP-3.9 — bw-core Documentation & API Review**
- Audit every `pub` item. Demote to `pub(crate)` anything not needed externally.
- Complete all doc comments.
- Tag `bw-core-v0.1`.

---

**WP-4.1 — bw-protocol Bootstrap** (after bw-core is stable)
- Same pattern: empty scaffold first, quality gates, then migrate.

**WP-4.2 — bw-protocol Packet Header**
- Migrate `PacketHeader`, `ProtocolError` from `archive/recovered_sources/blackwing_protocol_crate.rs`.
- Requires `bytemuck` dependency (Pod, Zeroable).
- Note: `unsafe impl Zeroable` and `unsafe impl Pod` are present — bw-protocol should NOT have `#![forbid(unsafe_code)]`.

**WP-4.3 — bw-protocol Capabilities**
- Migrate `FeatureManifest`, `DisplayProfile`, `CapabilityMessage`.
- Requires `ciborium` for CBOR serialization.

**WP-4.4 through WP-4.5** — tests and documentation.

---

## 11. Quality Gate Checklist (Run After Every WP)

Run this sequence after EVERY work package completes. Do not skip any step.

```powershell
$env:PATH = "C:\Users\ETCHE\scoop\apps\mingw\current\bin;" + $env:PATH

cargo check
# Expected: 0 errors

cargo test
# Expected: all tests pass, 0 failures

cargo fmt --check
# Expected: no diffs (run `cargo fmt` to fix if diffs appear)

cargo clippy -- -D warnings
# Expected: 0 warnings

git add -A
git commit -m "feat(bw-core): WP-3.X description"
git tag wp-3.X-complete
```

---

## 12. Open Questions (Not Yet Resolved)

| Question | Context | Priority |
|---|---|---|
| Should `StaticSlotPool` use unsafe? | `#![forbid(unsafe_code)]` in bw-core conflicts with UnsafeCell usage in the recovered pool. Either relax the lint or rewrite the pool. | High |
| Async runtime: Tokio or custom? | ADR-007 is drafted but not finalized. The workspace `Cargo.toml` already lists tokio as a workspace dep. | Medium |
| PacketHeader size: 16 or 32 bytes? | RFC conflicts with some docs. Recovered source uses 32-byte. Needs explicit ADR before protocol migration. | High |
| CI pipeline | No GitHub Actions workflow exists yet. Needed before any external contributors. | Medium |

---

## 13. Commands Quick Reference

```powershell
# Navigate to repo
cd C:\BLACKWING

# All cargo commands require this PATH if not already set
$env:PATH = "C:\Users\ETCHE\scoop\apps\mingw\current\bin;" + $env:PATH

# Core build commands
cargo check
cargo build
cargo test
cargo fmt
cargo clippy -- -D warnings

# View dependency tree
cargo tree

# View workspace metadata
cargo metadata --format-version 1

# Git tags
git tag                    # list all tags
git log --oneline          # brief history
git status                 # verify clean working tree
```

---

*This document is the canonical handoff document. Update it after every work package completion.*
