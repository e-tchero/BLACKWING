# Code Migration Policy

**Location:** `docs/engineering/CODE_MIGRATION_POLICY.md`  
**Status:** Active  
**Applies to:** All migrations from `archive/recovered_sources/` into workspace crates  
**Enforced from:** Milestone 1.5 onward

---

## Purpose

The files in `archive/recovered_sources/` are **reference implementations**, not production code. They document the intended design of BLACKWING subsystems and serve as a starting point for engineering decisions. They are never to be copied verbatim into a crate and committed.

This policy defines the required process for migrating any recovered source into the active workspace.

---

## The Core Rule

> **Treat archive files as specifications written in Rust, not as source files.**

Every migrated module must be:
- Reviewed
- Renamed where the original name is unclear
- Decomposed into logical sub-modules where a single file is too large
- Documented before merging
- Compiling immediately when added

---

## Migration Rules

### 1. Never copy verbatim

Recovered code was written under different conditions, without the current architecture constraints. It may contain:

- Temporary workarounds
- Naming inconsistencies
- Missing documentation
- Dead abstractions
- Historical hacks that no longer apply

Review every line. If a function or type is copied exactly, there must be a comment explaining why it requires no change.

### 2. Rename APIs when necessary

If a recovered name is ambiguous, misleading, or inconsistent with the rest of the codebase, rename it during migration. Do not preserve bad names for historical fidelity.

Examples:
- `LockFreeMemoryPool` → consider `MemoryPool` if the lock-free property is an implementation detail, not a public contract
- `BwError` → evaluate whether it belongs in `bw-core::error` as a flat enum or should be split into domain-specific error types

### 3. Eliminate dead abstractions

If a recovered file contains a trait, struct, or enum that is never used and has no planned consumer, do not migrate it. Leave it in the archive. Add a comment in the archive file explaining why it was not migrated.

### 4. Remove historical hacks

If a recovered file contains code that was clearly a workaround (e.g., a stub with `unimplemented!()`, a placeholder `todo!()`, or a comment like "fix later"), that code is not migrated. Either implement it properly or leave it out of the current work package scope.

### 5. Add documentation during migration, not after

Every migrated item must have its documentation written as part of the migration work package. Documentation is not a separate step. A type or function without a `///` doc comment does not pass the quality gate.

### 6. Every migrated file must compile immediately

No partial migrations. If a module cannot be made to compile in the current work package, it does not get merged. Scope the work package narrowly enough that everything within it compiles and passes the quality gates.

### 7. Decompose large recovered files into modules

The recovered files are single-file bundles of multiple logical subsystems. When migrating, break them into the appropriate module structure:

**Example:**
```
zero_allocation_buffer_pool_type_safe_logging_primitives.rs
  → bw-core/src/error.rs       (BwError enum)
  → bw-core/src/logging.rs     (Severity, LogEvent, HealthReport)
  → bw-core/src/memory.rs      (LockFreeMemoryPool, PoolGuard)
  → bw-core/src/pool.rs        (StaticSlotPool, ZeroizePolicy)
```

Do not create a single large module mirroring the original file structure.

### 8. Unsafe code requires explicit review

If recovered code contains `unsafe` blocks:
- It must be documented with a `// SAFETY:` comment explaining the invariant being upheld.
- It must be reviewed before merging.
- If the crate has `#![forbid(unsafe_code)]`, the unsafe block cannot be migrated as-is. Either rewrite it safely or create a separate crate without the forbid and document the decision in an ADR.

---

## Definition of Done for a Migration Work Package

A migration WP is complete only when ALL of the following are true:

| Criterion | Required |
|---|---|
| `cargo build` passes | ✅ |
| `cargo test` passes (100%) | ✅ |
| `cargo fmt --check` clean | ✅ |
| `cargo clippy -- -D warnings` clean | ✅ |
| `cargo doc --no-deps` produces no warnings | ✅ |
| Every public item has a `///` doc comment | ✅ |
| Every `unsafe` block has a `// SAFETY:` comment | ✅ |
| `WP_CHANGELOG.md` updated | ✅ |
| Relevant ADR updated if architecture changed | ✅ |
| Git commit made with WP reference in message | ✅ |
| Git tag applied | ✅ |

---

## What Stays in the Archive

The following must remain in `archive/recovered_sources/` and are never migrated:

- Historical hacks without a current use case
- Placeholder implementations with no specification backing them
- Dead code with no planned consumer
- Anything that conflicts with an ADR without a new ADR approving the change

---

## Summary

| ❌ Never do this | ✅ Always do this |
|---|---|
| Copy a recovered file directly into `src/` | Review it, decompose it, migrate one subsystem per WP |
| Migrate without documentation | Write docs during migration |
| Commit code that does not compile | Scope WPs so everything compiles on completion |
| Preserve bad names for historical reasons | Rename to match current architecture |
| Skip the quality gate because "it's just a migration" | Run all four checks before tagging |
| Leave `unsafe` without a `SAFETY:` comment | Document every unsafe invariant |
