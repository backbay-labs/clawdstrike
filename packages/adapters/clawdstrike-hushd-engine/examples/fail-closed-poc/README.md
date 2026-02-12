# Engine-Remote Fail-Closed POC

Deterministic proof that daemon transport failures fail closed.

## Run

```bash
npm --prefix packages/adapters/clawdstrike-hushd-engine run build
npm --prefix packages/adapters/clawdstrike-hushd-engine run poc:fail-closed
```

## What it proves

- unreachable daemon returns deny decision
- reason is `engine_error`
