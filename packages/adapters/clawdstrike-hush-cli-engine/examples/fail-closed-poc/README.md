# Engine-Local Fail-Closed POC

Deterministic proof that local engine transport errors fail closed.

## Run

```bash
npm --prefix packages/adapters/clawdstrike-hush-cli-engine run build
npm --prefix packages/adapters/clawdstrike-hush-cli-engine run poc:fail-closed
```

## What it proves

- missing/invalid `hush` binary causes a deny decision
- reason is `engine_error`
