# Installation

Choose your preferred installation method.

## Rust CLI (hush-cli)

The CLI is the primary way to use hushclaw.

### From crates.io (Recommended)

```bash
cargo install hush-cli
```

### From Source

```bash
git clone https://github.com/hushclaw/hushclaw
cd hushclaw
cargo install --path crates/hush-cli
```

### Verify Installation

```bash
hush --version
# hush-cli 0.1.0
```

## TypeScript SDK

For Node.js and browser environments:

```bash
npm install @hushclaw/sdk
# or
yarn add @hushclaw/sdk
# or
pnpm add @hushclaw/sdk
```

## OpenClaw Plugin

If you're using OpenClaw:

```bash
npm install @hushclaw/openclaw
openclaw plugins enable @hushclaw/openclaw
```

## Python SDK (Coming Soon)

```bash
pip install hush
```

## Docker

Run the daemon in a container:

```bash
docker run -d \
  --name hushd \
  -v ~/.hush:/root/.hush \
  -p 9090:9090 \
  ghcr.io/hushclaw/hushd:latest
```

## System Requirements

| Component | Requirement |
|-----------|-------------|
| Rust CLI | Rust 1.75+ |
| TypeScript SDK | Node.js 18+ |
| Python SDK | Python 3.10+ |
| Docker | Docker 20.10+ |

## Next Steps

- [Quick Start](./quick-start.md) - Get running in 5 minutes
- [Your First Policy](./first-policy.md) - Write a custom policy
