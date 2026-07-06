# ADR-004: Memory Allocation Policy

## Status
Proposed

## Context
Need to establish rules around heap allocation.

## Decision
Zero-allocation buffers and object pools should be prioritized in hot paths.

