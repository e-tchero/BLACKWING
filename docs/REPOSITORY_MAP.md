# PROJECT BLACKWING — Repository Map

This is the first document every contributor reads. It outlines the physical structure of the workspace.

```text
BLACKWING/
├── archive/
│   └── recovered_sources/        # Historical source artifacts
│
├── crates/                       # Active Rust Workspace
│   ├── bw-core/                  # Core primitives
│   │   ├── memory/               # Zero-allocation buffers, object pools
│   │   ├── pool/                 # Thread pooling, connection pooling
│   │   └── logging/              # Type-safe, lock-free logging
│   │
│   ├── bw-crypto/                # Cryptography & Identity (Baseline complete)
│   │   ├── identity/             # Device IDs, cryptographic identities
│   │   ├── crypto/               # Signatures, key generation
│   │   └── backend/              # TPM / Dalek implementations
│   │
│   └── bw-protocol/              # Wire protocol parsing
│       ├── packet/               # Packet structures, framing
│       ├── transport/            # Session lifecycle
│       └── codec/                # Binary encoding/decoding
│
└── docs/                         # Specifications & ADRs
    ├── adr/                      # Architecture Decision Records
    ├── architecture/             # High-level architecture docs
    ├── dashboard/                # Analytics & Discovery
    ├── handbook/                 # Operations & SRE manuals
    ├── planning/                 # Engineering specifications, PRDs
    ├── protocol/                 # RFCs, Protocol Specs
    └── work_packages/            # Specific feature implementations
```
