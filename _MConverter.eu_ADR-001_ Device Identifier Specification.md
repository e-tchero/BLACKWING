# ADR 001: Device Identifier Specification

## Status

Proposed/Frozen

## Context

The DeviceId is the primary identifier for a participant in the system. It is used in wire protocols, audit logs, and policy enforcement. To ensure long-term stability and interoperability, the derivation and serialization must be immutable.

## Specification

- **Derivation:** DeviceId = SHA-256(Raw_Ed25519_Public_Key_Bytes)

- **Input:** Exactly 32 bytes of Ed25519 public key.

- **Storage:** Fixed-size array \[u8; 32\].

- **Display Format:** bw-id- + lowercase hex encoding of the 32-byte hash (64 hex characters).

- **Total Length:** 70 ASCII characters.

## Invariants

1.  DeviceId construction is only permitted via derivation from a VerifyKey.

2.  Direct construction from raw bytes is forbidden outside of the crate boundary.

3.  Serialization/Deserialization must adhere strictly to the format defined above.
