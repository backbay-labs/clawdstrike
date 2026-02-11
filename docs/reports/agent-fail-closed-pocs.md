# Agent Fail-Closed POCs

Deterministic POCs that emulate Codex- and Claude Code-style tool execution and prove fail-closed behavior.

## Included POCs

- `packages/adapters/clawdstrike-codex/examples/fail-closed-poc/run.mjs`
- `packages/adapters/clawdstrike-claude-code/examples/fail-closed-poc/run.mjs`
- `packages/adapters/clawdstrike-hush-cli-engine/examples/fail-closed-poc/run.mjs`
- `packages/adapters/clawdstrike-hushd-engine/examples/fail-closed-poc/run.mjs`

## Run all at once

```bash
node tools/scripts/agent-fail-closed-smoke.mjs
```

Outputs:

- `docs/reports/agent-fail-closed-smoke.json`
- `docs/reports/agent-fail-closed-smoke.md`

## What this proves

- Codex adapter: blocked command throws `ClawdstrikeBlockedError` and dispatcher side effect never executes.
- Claude Code adapter: blocked command throws `ClawdstrikeBlockedError` and dispatcher side effect never executes.
- Engine local: local transport/spawn error fails closed (`deny` + `engine_error`).
- Engine remote: daemon transport error fails closed (`deny` + `engine_error`).
