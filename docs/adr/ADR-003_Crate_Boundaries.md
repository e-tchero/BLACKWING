# ADR-003: Crate Boundaries

## Status
Proposed

## Context
Need to prevent API sprawl.

## Decision
Freeze public APIs for bw-core, bw-crypto, and bw-protocol. Default visibility is pub(crate).

