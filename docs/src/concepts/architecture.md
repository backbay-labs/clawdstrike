# Architecture

Hushclaw is designed as a modular, composable security enforcement layer.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Your Agent                               │
│  (Claude Code, OpenClaw, Custom Agent)                          │
└────────────────────────────────┬────────────────────────────────┘
                                 │ Events
┌────────────────────────────────▼────────────────────────────────┐
│                         Hushclaw                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    Policy Engine                         │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    │    │
│  │  │ Load    │→ │ Parse   │→ │ Compile │→ │ Cache   │    │    │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                 │                                │
│  ┌─────────────────────────────▼───────────────────────────┐    │
│  │                    Guard Registry                        │    │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │    │
│  │  │ Forbidden │ │ Egress    │ │ Secret    │ │ Patch   │ │    │
│  │  │ Path      │ │ Allowlist │ │ Leak      │ │ Integrity│ │    │
│  │  └───────────┘ └───────────┘ └───────────┘ └─────────┘ │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                 │                                │
│  ┌─────────────────────────────▼───────────────────────────┐    │
│  │                    Decision Engine                       │    │
│  │  Event → Guards → Aggregate → Decision (Allow/Warn/Deny) │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                 │                                │
│  ┌─────────────────────────────▼───────────────────────────┐    │
│  │                    Audit Ledger                          │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐                  │    │
│  │  │ Events  │→ │ Merkle  │→ │ Sign    │→ Receipts       │    │
│  │  └─────────┘  └─────────┘  └─────────┘                  │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### Policy Engine

Loads, parses, and compiles YAML policies into efficient evaluation structures.

```rust
let policy = Policy::from_yaml_file("policy.yaml")?;
let engine = HushEngineBuilder::new()
    .with_policy(policy)
    .build()?;
```

Key features:
- **Inheritance** - Extend built-in policies with `extends:`
- **Hot reload** - Update policies without restart
- **Validation** - Catch errors before deployment

### Guard Registry

Guards are modular security checks. Each guard handles specific event types:

| Guard | Events | Purpose |
|-------|--------|---------|
| ForbiddenPathGuard | FileRead, FileWrite | Block sensitive paths |
| EgressAllowlistGuard | NetworkEgress | Domain allowlist |
| SecretLeakGuard | PatchApply | Detect secrets in output |
| PatchIntegrityGuard | PatchApply | Block dangerous code |
| McpToolGuard | ToolCall | Tool allow/deny lists |

### Decision Engine

Aggregates guard results into a final decision:

```
Allow + Allow + Allow = Allow
Allow + Warn + Allow = Warn
Allow + Deny + Allow = Deny (short-circuit)
```

### Audit Ledger

Records all events and decisions for accountability:

- **Events** - What was attempted
- **Decisions** - What was decided
- **Merkle Tree** - Tamper-evident log
- **Signatures** - Cryptographic proof

## Event Flow

```
1. Agent requests action (file read, network call, etc.)
         ↓
2. Action converted to Event
         ↓
3. Event sent to Guard Registry
         ↓
4. Each applicable Guard evaluates
         ↓
5. Results aggregated into Decision
         ↓
6. Event + Decision logged to Ledger
         ↓
7. Decision returned to Agent
         ↓
8. Allow → proceed, Deny → block, Warn → proceed + log
```

## Crate Structure

```
hush-core       # Crypto primitives (Ed25519, SHA-256, Merkle)
    ↓
hush-proxy      # Network interception utilities
    ↓
hushclaw        # Runtime enforcement (guards, policy, IRM)
    ↓
hush-cli        # Command-line interface
    ↓
hushd           # Long-running daemon (optional)
```

## Integration Points

### Direct Library

```rust
use hushclaw::{HushEngine, Event};

let engine = HushEngine::new(policy)?;
let decision = engine.evaluate(&event).await;
```

### CLI Wrapper

```bash
hush run --policy policy.yaml -- your-command
```

### OpenClaw Plugin

```typescript
// Automatically intercepts tool calls
await openclaw.registerPlugin("@hushclaw/openclaw");
```

### Daemon Mode

```bash
hushd --config /etc/hush/config.yaml
```

## Performance

| Operation | Target Latency |
|-----------|----------------|
| Cached evaluation | < 1ms |
| Uncached evaluation | < 5ms |
| Async (with I/O) | < 20ms |
| Policy load | < 100ms |
| Hot reload | < 50ms |

## Next Steps

- [Guards](./guards.md) - Deep dive into guard types
- [Policies](./policies.md) - Policy system details
- [Decisions](./decisions.md) - Decision types and modes
