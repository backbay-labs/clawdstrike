# Codex Fail-Closed POC

Deterministic proof that blocked tool invocations fail closed and do not execute dispatcher side effects.

## Run

```bash
npm --prefix packages/adapters/clawdstrike-codex run build
npm --prefix packages/adapters/clawdstrike-codex run poc:fail-closed
```

## What it proves

- blocked command throws `ClawdstrikeBlockedError`
- blocked command does not run dispatcher side effects
- allowed action still executes dispatcher
- blocked audit event is recorded
