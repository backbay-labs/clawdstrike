# @clawdstrike/engine-remote

Policy engine adapter that calls a running `hushd` daemon for evaluation.

This is useful when you want TypeScript tool-boundary enforcement but prefer the Rust policy engine
for ruleset parsing and evaluation, without spawning the `hush` CLI per request.

See [Enforcement Tiers & Integration Contract](https://github.com/backbay-labs/clawdstrike/blob/main/docs/src/concepts/enforcement-tiers.md) for what is enforceable at the tool boundary (and what requires a sandbox/broker).

## Usage

```ts
import { createStrikeCell } from "@clawdstrike/engine-remote";

const engine = createStrikeCell({
  baseUrl: "http://127.0.0.1:9876",
  // token: process.env.HUSHD_CHECK_KEY,
  timeoutMs: 10_000,
});

const decision = await engine.evaluate(event);
if (decision.status === "deny") throw new Error(decision.message ?? "Blocked by policy");
```
