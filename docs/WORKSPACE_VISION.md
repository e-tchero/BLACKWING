# PROJECT BLACKWING — Workspace Vision & Rules

## 1. Workspace Vision

This outlines the intended final shape of the Project Blackwing workspace. Planning and scoping become significantly easier when the target crate graph is defined upfront, even if many of these crates remain empty today.

```text
BLACKWING
└── crates/
    ├── bw-core      (Fundamental types, memory pooling, locks, basic traits)
    ├── bw-crypto    (Identity, cryptographic verification, signing, keys)
    ├── bw-protocol  (Wire formats, packet framing, codecs)
    ├── bw-net       (Transport layers, connection management, sockets)
    ├── bw-capture   (Screen capture, OS windowing interfaces)
    ├── bw-video     (Video encoding pipeline, compression)
    ├── bw-audio     (Audio capture, encoding, mixing)
    ├── bw-relay     (Relay server & control plane routing logic)
    ├── bw-agent     (Endpoint daemon / service payload)
    ├── bw-console   (Admin/User TUI or GUI interface)
    ├── bw-cli       (Command-line tools for operators)
    └── bw-update    (Over-the-air update mechanisms, staging, verification)
```

## 2. Dependency Rules

To prevent spaghetti architecture and circular dependencies, the dependency flow must strictly be top-down. 

**Permitted Flow Example:**
```text
bw-core
   ↓
bw-crypto
   ↓
bw-protocol
   ↓
bw-net
```

**Forbidden:**
- `bw-core` CANNOT depend on `bw-protocol`.
- `bw-crypto` CANNOT depend on `bw-net`.
- Circular dependencies are absolutely forbidden by policy. 
- Higher-level crates (like `bw-agent` or `bw-relay`) depend on lower-level crates, but never the reverse.

## 3. Public API Freeze Policy

To prevent API sprawl, the boundaries of the following foundational crates are frozen.

### Frozen Public APIs:
- **`bw-core`**
- **`bw-crypto`**
- **`bw-protocol`**

### Rule:
Anything that does not explicitly need to be consumed externally by a downstream workspace member **must** remain `pub(crate)`. If a feature is only needed within the boundaries of `bw-protocol`, it should not leak into the global namespace via `pub`.
