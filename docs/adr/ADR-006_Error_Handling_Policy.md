# ADR-006: Error Handling Policy

## Status
Proposed

## Context
Need a unified way to handle errors without panics.

## Decision
Use 	hiserror for library error definitions. Avoid unwrap() and expect() in production code.

