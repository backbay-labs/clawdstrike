# API Reference

Hushclaw is available in multiple languages.

## Available SDKs

| Language | Package | Registry |
|----------|---------|----------|
| [Rust](./rust.md) | `hushclaw`, `hush-core` | crates.io |
| [TypeScript](./typescript.md) | `@hushclaw/sdk` | npm |
| [CLI](./cli.md) | `hush-cli` | crates.io |
| Python (coming) | `hush` | PyPI |

## Quick Comparison

### Rust

```rust
use hushclaw::{HushEngine, Event, Decision};

let engine = HushEngine::new(policy)?;
let decision = engine.evaluate(&event).await;
```

### TypeScript

```typescript
import { HushEngine } from '@hushclaw/sdk';

const engine = new HushEngine(policy);
const decision = await engine.evaluate(event);
```

### CLI

```bash
hush run --policy policy.yaml -- your-command
```

## Core Types

All SDKs share these core types:

### Event

```typescript
interface Event {
  event_id: string;
  event_type: EventType;
  timestamp: string;
  session_id?: string;
  data: EventData;
}
```

### Decision

```typescript
type Decision =
  | { type: 'allow' }
  | { type: 'warn'; message: string }
  | { type: 'deny'; reason: string; severity: Severity };
```

### Policy

```typescript
interface Policy {
  version: string;
  extends?: string;
  egress?: EgressPolicy;
  filesystem?: FilesystemPolicy;
  execution?: ExecutionPolicy;
  tools?: ToolPolicy;
  limits?: ResourceLimits;
  on_violation?: ViolationAction;
}
```

## Feature Matrix

| Feature | Rust | TypeScript | CLI |
|---------|------|------------|-----|
| Policy evaluation | Yes | Yes | Yes |
| Guard execution | Yes | Yes | Yes |
| Crypto (signing) | Yes | Yes | Yes |
| Merkle trees | Yes | Yes | Yes |
| Hot reload | Yes | No | Yes |
| Daemon mode | Yes | No | Yes |
| WASM | Yes | Yes | N/A |

## Next Steps

- [Rust API](./rust.md) - Native Rust library
- [TypeScript API](./typescript.md) - Node.js and browser
- [CLI Reference](./cli.md) - Command-line interface
