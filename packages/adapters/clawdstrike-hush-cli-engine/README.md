# @clawdstrike/engine-local

Policy engine adapter that shells out to the `hush` CLI for evaluation.

This is useful when you want TypeScript tool-boundary enforcement but prefer the Rust policy engine for ruleset parsing and evaluation.

See [Enforcement Tiers & Integration Contract](https://github.com/backbay-labs/clawdstrike/blob/main/docs/src/concepts/enforcement-tiers.md) for what is enforceable at the tool boundary (and what requires a sandbox/broker).

## Prerequisites

- `hush` installed and available on your PATH (or provide a custom `hushPath`).

## Usage

```ts
import { createStrikeCell } from "@clawdstrike/engine-local";
import type { PolicyEvent } from "@clawdstrike/adapter-core";

const engine = createStrikeCell({
  policyRef: "default",
  // hushPath: "/path/to/hush",
});

const event: PolicyEvent = {
  eventId: "evt-1",
  eventType: "tool_call",
  timestamp: new Date().toISOString(),
  data: { type: "tool", toolName: "bash", parameters: { cmd: "echo hello" } },
};

const decision = await engine.evaluate(event);
if (decision.status === "deny") throw new Error(decision.message ?? "Blocked by policy");
```
