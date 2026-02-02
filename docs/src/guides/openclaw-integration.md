# OpenClaw Integration (experimental)

This repository contains an OpenClaw plugin under `packages/hushclaw-openclaw`.

## Enforcement boundaries (read this)

The current OpenClaw plugin enforces policy at the **tool boundary**:

- **Preflight** via the `policy_check` tool (agents should call it before risky operations).
- **Post-action** via the `tool_result_persist` hook (can block/redact what is persisted + record violations).

This is **not** an OS sandbox and does not intercept syscalls. If an agent/runtime bypasses the OpenClaw tool layer, hushclaw cannot stop it.

CI runs an **in-process simulated runtime** E2E (`npm run e2e` in `packages/hushclaw-openclaw`) to verify wiring/behavior without starting OpenClaw itself.

## Important: policy schema is different from Rust

The OpenClaw plugin uses its **own policy schema** (currently `version: "hushclaw-v1.0"`). It is **not** the same as the Rust `hushclaw::Policy` schema (`version: "1.0.0"`).

If you paste a Rust policy into OpenClaw, it should fail closed (and it does): unknown fields are rejected.

See [Schema Governance](../concepts/schema-governance.md) for the repo-wide versioning/compat rules.

## Recommended flow

- Use a built-in ruleset as a starting point: `hushclaw:ai-agent-minimal` or `hushclaw:ai-agent`.
- Validate policies before running agents:

```bash
hushclaw policy lint .hush/policy.yaml
```

- Use `policy_check` for **preflight** decisions (before the agent attempts an action).
- Use the OpenClaw hook(s) for **post-action** defense-in-depth (e.g., block/strip tool outputs that contain secrets).

## Where to look

- OpenClaw plugin docs: `packages/hushclaw-openclaw/docs/`
- OpenClaw plugin code: `packages/hushclaw-openclaw/src/`
- Example (minimal wiring): `examples/hello-secure-agent/`
- Example (agentic EDR triage loop): `examples/bb-edr/`
