# Installation

Clawdstrike ships as a Rust workspace with a CLI (`clawdstrike`) and libraries (`clawdstrike`, `hush-core`, `hush-proxy`).

## Rust CLI (`clawdstrike`)

### From source (recommended)

```bash
# From a workspace checkout
cargo install --path crates/hush-cli
```

### From crates.io (if published)

If your environment has `hush-cli` available in a Cargo registry:

```bash
cargo install hush-cli
```

### Verify installation

```bash
clawdstrike --version
```

## Daemon (`clawdstriked`) (optional)

`clawdstriked` is an HTTP daemon that can evaluate checks server-side. It is still evolving, so treat it as optional/WIP.

```bash
cargo install --path crates/hushd
```

You can start it via the CLI:

```bash
clawdstrike daemon start
```

## TypeScript SDK

```bash
npm install @clawdstrike/sdk
```

```typescript
import { Clawdstrike } from "@clawdstrike/sdk";

const cs = Clawdstrike.withDefaults("strict");
const decision = await cs.checkFile("~/.ssh/id_rsa", "read");
```

## Python SDK

```bash
pip install clawdstrike
```

```python
from clawdstrike import Policy, PolicyEngine, GuardAction, GuardContext

policy = Policy.from_yaml_file("policy.yaml")
engine = PolicyEngine(policy)
```

## Requirements

- Rust `1.93+` (workspace `rust-version`)

## Next Steps

- [Quick Start](./quick-start.md) - Get running in 5 minutes
- [Your First Policy](./first-policy.md) - Write a custom policy
