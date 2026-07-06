# ADR-005: Cryptographic Backend Strategy

## Status
Proposed

## Context
Need a strategy for hardware/software cryptographic implementations.

## Decision
Use backend-agnostic enum dispatch for software (Dalek) and hardware (TPM/CNG) fallbacks.

