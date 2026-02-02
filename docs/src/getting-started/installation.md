# Installation

Clawdstrike currently ships as a Rust workspace with a CLI (`hush`) and libraries (`clawdstrike`, `hush-core`, `hush-proxy`).

## Rust CLI (`hush`)

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
hush --version
```

## Daemon (`hushd`) (optional)

`hushd` is an HTTP daemon that can evaluate checks server-side. It is still evolving, so treat it as optional/WIP.

```bash
cargo install --path crates/hushd
```

You can start it via the CLI:

```bash
hush daemon start
```

## TypeScript / Python (experimental)

This repo contains experimental SDKs under `packages/` (TypeScript, Python, OpenClaw plugin). Their APIs and schemas are not yet guaranteed to match the Rust policy schema.

## Requirements

- Rust `1.75+` (workspace `rust-version`)

## Next Steps

- [Quick Start](./quick-start.md) - Get running in 5 minutes
- [Your First Policy](./first-policy.md) - Write a custom policy
