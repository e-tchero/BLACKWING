# bw-core

## Purpose
Fundamental types, memory pooling, locks, and basic traits for Project Blackwing.

## Responsibilities
- Lock-free object pooling
- Zero-allocation buffers
- Type-safe, lock-free logging primitives
- Core error definitions

## Non-responsibilities
- Cryptography (see bw-crypto)
- Protocol parsing (see bw-protocol)
- Async runtime execution

## Public API
All APIs are pub(crate) by default until explicitly exposed via ADR.

