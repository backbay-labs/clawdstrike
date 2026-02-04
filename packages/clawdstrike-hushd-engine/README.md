# @clawdstrike/hushd-engine

Policy engine adapter that calls a running `hushd` daemon for evaluation.

This is useful when you want TypeScript tool-boundary enforcement but prefer the Rust policy engine
for ruleset parsing and evaluation, without spawning the `hush` CLI per request.

## Usage

```ts
import { createHushdEngine } from "@clawdstrike/hushd-engine";

const engine = createHushdEngine({
  baseUrl: "http://127.0.0.1:9876",
  // token: process.env.HUSHD_CHECK_KEY,
  timeoutMs: 10_000,
});

const decision = await engine.evaluate(event);
if (!decision.allowed) throw new Error(decision.message);
```

