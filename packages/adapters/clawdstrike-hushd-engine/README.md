# @clawdstrike/engine-remote

Policy engine adapter that calls a running `hushd` daemon for evaluation.

This is useful when you want TypeScript tool-boundary enforcement but prefer the Rust policy engine
for ruleset parsing and evaluation, without spawning the `hush` CLI per request.

## Usage

```ts
import { createHushdEngine } from "@clawdstrike/engine-remote";

const engine = createHushdEngine({
  baseUrl: "http://127.0.0.1:9876",
  // token: process.env.HUSHD_CHECK_KEY,
  timeoutMs: 10_000,
});

const decision = await engine.evaluate(event);
if (decision.status === "deny") throw new Error(decision.message ?? "Blocked by policy");
```

## Fail-Closed POC

```bash
npm --prefix packages/adapters/clawdstrike-hushd-engine run build
npm --prefix packages/adapters/clawdstrike-hushd-engine run poc:fail-closed
```

This deterministic POC proves daemon transport failures return fail-closed decisions (`deny` + `engine_error`).
