# PROJECT BLACKWING — Engineering Baseline

**Date:** 2026-07-06  
**Status:** READ-ONLY Engineering Audit  
**Phase:** Milestone 1 Completed (Recovery Baseline Frozen)

## 1. Executive Summary

A complete read-only engineering audit of `C:\BLACKWING` was performed. The repository has successfully exited a corrupted state and stabilized at `recovery-baseline-v0.1`. The Rust workspace compiles, passes all unit and property-based integration tests, and is warning-free under Cargo clippy (with `#[allow(dead_code)]` enabled for unimplemented traits). The immediate priority shifts from repository triage to workspace reconstruction and migrating the recovered protocol and core logic currently sitting in the `archive/` folder.

## 2. Repository Inventory

### Active Source Code
- `C:\BLACKWING\Cargo.toml` (Active Workspace Manifest)
- `C:\BLACKWING\crates\bw-crypto\` (Active Workspace Member)
  - `Cargo.toml` (Package manifest)
  - `src\lib.rs` (Crate root)
  - `src\error.rs` (Error types)
  - `src\identity.rs` (Core identity models)
  - `src\random.rs` (Entropy traits)
  - `src\backend\mod.rs`, `dalek.rs`, `tpm.rs` (Cryptographic backends)
  - `tests\device_id_properties.rs` (Integration test suite)

### Archive & Recovery (Awaiting Migration)
- `C:\BLACKWING\archive\recovery\blackwing_protocol_crate.rs` (Obsolete location, future `bw-protocol`)
- `C:\BLACKWING\archive\recovery\static_slot_pool_refinement.rs` (Obsolete location, future `bw-core`)
- `C:\BLACKWING\archive\recovery\zero_allocation_buffer_pool_type_safe_logging_primitives.rs` (Obsolete location, future `bw-core`)
- `C:\BLACKWING\archive\exports\_MConverter.eu_ADR-001_ Device Identifier Specification.md` (Archive)
- `C:\BLACKWING\archive\previous_versions\internal_constant_time_trait.rs` (Obsolete)

### Documentation (`docs/`)
- `adr\ADR-001_ Device Identifier Specification.docx`
- `adr\ADR-001_ Revised Device Identifier Specification.docx`
- `architecture\Blackwing Architecture Baseline Specifications.docx`
- `architecture\bw-crypto Crate Architecture.docx`
- `architecture\Project Blackwing Architecture Handbook & Protocol Specification.docx`
- `architecture\Project Blackwing Operational Architecture.docx`
- `architecture\Project Blackwing Phase 2 Final Architecture.docx`
- `dashboard\project_blackwing_discovery_dashboard.html`
- `handbook\Implementation Architecture & SRE Handbook.docx`
- `handbook\Repository Standards & SRE Manual.docx`
- `planning\Detailed Engineering Specification.docx`
- `planning\Phase 3 Bootstrap Manifest.docx`
- `planning\Product Requirements Document (PRD) v1.0.docx`
- `planning\Project Blackwing Phase 1_ Professional Product Discovery.docx`
- `protocol\Blackwing RFC Protocol Spec.docx`
- `protocol\Device ID Protocol Specification.docx`
- `protocol\Transport Scheduler & Session Lifecycle Specification.docx`
- `work_packages\WP-2.3 Display Capture Pipeline.docx`
- `work_packages\WP-2.4 Video Encoding.docx`
- `work_packages\WP-2.5 Input & Clipboard.docx`
- `work_packages\WP-2.6 Cryptography & Authentication.docx`
- `work_packages\WP-2.7 Relay & Control Plane Architecture.docx`

### Configuration & Infrastructure
- `.gitignore` (Active)
- `Cargo.lock` (Generated)
- `BLACKWING_RECOVERY_STATUS.md` (Active Status Report)

---

## 3. Workspace Status

- **Workspace Members:** `bw-crypto`
- **Compile Status (`cargo check`):** ✅ Passing (GNU toolchain required)
- **Test Status (`cargo test`):** ✅ 13/13 passing
- **Format Status (`cargo fmt`):** ✅ Compliant
- **Clippy Status (`cargo clippy`):** ✅ Passing (Warnings resolved or allowed)
- **Features Used:** `serde` (optional)

*Note: Building native Windows libraries (e.g. `windows-sys`) requires MinGW binutils (`dlltool.exe`, `as.exe`) due to the absence of the MSVC SDK.*

---

## 4. Crate Status: `bw-crypto`

- **Maturity:** Prototype / Recovery
- **Public API:** `DeviceId`, `Signature`, `SigningKey`, `VerifyKey`, `CryptoError`, `Result`
- **Internal API:** `backend::SigningKeyInner`, `backend::VerifyKeyInner`, `backend::dalek::*`, `backend::tpm::*`
- **Dependency Relationships:** Wraps `ed25519-dalek`, `sha2`, uses `zeroize` for memory hygiene, exposes `serde` optionally.
- **Module Graph:**
  ```
  bw-crypto
  ├── error (CryptoError enum)
  ├── identity (DeviceId, Signature, Key structs)
  ├── random (SecureRandom, OsRandom)
  └── backend
      ├── dalek (Software fallback)
      └── tpm (Hardware security module stub)
  ```

---

## 5. Dependency Graph

```text
bw-crypto v0.1.0
├── ed25519-dalek v2.2.0
│   ├── curve25519-dalek v4.1.3
│   ├── ed25519 v2.2.3
│   ├── sha2 v0.10.9
│   ├── subtle v2.6.1
│   └── zeroize v1.9.0
├── getrandom v0.2.17
├── serde v1.0.228 (optional)
├── sha2 v0.10.9
├── subtle v2.6.1
├── thiserror v1.0.69
└── zeroize v1.9.0
[dev-dependencies]
├── proptest v1.11.0
└── serde_json v1.0.150
```

---

## 6. Documentation Audit

Due to the `.docx` binary format, documentation content could not be deeply parsed for explicit contradictions. However, structural cross-validation indicates:

| Specification | Implemented? | Missing? | Conflicts? | Priority |
|---|---|---|---|---|
| ADR-001 (Device ID) | ✅ Yes | No | None detected | High |
| bw-crypto Architecture | ✅ Yes | HSM/TPM | None detected | High |
| Protocol Specification | ❌ No | Yes (`bw-protocol`) | N/A | High |
| Operational Architecture | ❌ No | Yes (`bw-core`) | N/A | Medium |

---

## 7. Security Audit

- **Memory Safety:** No `unsafe` blocks detected in `bw-crypto`. Safe abstractions used throughout.
- **Zeroization:** `zeroize` crate is used and explicitly applied to cryptographic types, ensuring memory hygiene.
- **Panic Paths:** All error cases are handled through `Result` and `thiserror`. Explicit `.unwrap()` and `.expect()` calls are forbidden (`#![deny(clippy::unwrap_used, clippy::expect_used)]` in tests).
- **Cryptography:** Relying on audited crates (`ed25519-dalek`, `sha2`). Hardware abstraction (TPM) is correctly isolated in a backend module but currently unimplemented.
- **Findings:**
  - **Informational:** TPM backend is stubbed. A secure enclave solution remains incomplete.
  - **Informational:** `OsRandom` and `SecureRandom` traits are defined but currently unused.

---

## 8. Migration Readiness

| Milestone | Status | Blocked By | Estimated Effort |
|---|---|---|---|
| **M2: Compile Recovery** | ✅ Ready | - | Complete |
| **M3: Architecture Recovery** | 🟡 Partially Ready | Workspace restructuring | Low |
| **M4: Core Crate Migration** | 🟡 Partially Ready | Extracting from archive | Medium |
| **M5: Protocol Crate Migration** | 🟡 Partially Ready | Extracting from archive | High |

---

## 9. Technical Debt & Repository Hygiene

- **Orphan / Misplaced Files:** Recovery files are incorrectly sitting in `archive/recovery/`.
- **Missing CI:** No GitHub Actions workflows exist to enforce the baseline.
- **Missing Licenses / README:** Repository lacks root documentation and open-source licensing models.
- **Dead Code:** Cryptographic abstractions (like TPM) are structurally sound but functionally dead. Allowed temporarily.

---

## 10. Engineering Roadmap

### Immediate
1. **Priority:** High
2. **Reason:** Establish standard open-source conventions and CI enforcement.
3. **Dependencies:** None
4. **Action:** Create Root `README.md`, `.github/workflows/ci.yml`.

### Next Sprint
1. **Priority:** High
2. **Reason:** Complete Workspace reconstruction.
3. **Dependencies:** Immediate milestone.
4. **Action:** Create `crates/bw-core` and `crates/bw-protocol` and migrate `archive/recovery` code.

### Medium Term
1. **Priority:** Medium
2. **Reason:** Fulfill hardware security specifications.
3. **Dependencies:** Next Sprint milestone.
4. **Action:** Implement Windows CNG or TPM 2.0 bindings for `bw-crypto::backend::tpm`.

---

## 11. Immediate Next Actions

1. Scaffold the remaining workspace packages (`bw-core` and `bw-protocol`).
2. Move files from `archive/recovery/` into their respective new crates.
3. Verify the workspace again.
