# Secure Coding Assistant (Example)

This example demonstrates a **secure coding assistant preflight** flow:

- Convert simulated tool calls into canonical `PolicyEvent` objects
- Evaluate them via the Rust `hush` CLI (`hush policy eval …`)
- Print allow/deny decisions suitable for IDE hooks, pre-commit hooks, or tool dispatchers

It is intentionally framework-agnostic (no OpenClaw required).

## Prerequisites

- Node.js 18+
- Rust toolchain (to build `hush`)

## Run

```bash
cd examples/secure-coding-assistant
node simulate.js
```

What it does:
- Attempts a forbidden file read (`~/.ssh/id_rsa`) → denied
- Attempts allowed/blocked network egress → policy-dependent (see `policy.yaml`)
- Attempts a dangerous patch payload → denied

