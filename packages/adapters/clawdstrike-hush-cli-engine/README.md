# @clawdstrike/hush-cli-engine

Policy engine adapter that shells out to the `hush` CLI for evaluation.

This is useful when you want TypeScript tool-boundary enforcement but prefer the Rust policy engine for ruleset parsing and evaluation.

## Prerequisites

- `hush` installed and available on your PATH (or provide a custom `hushPath`).

## Usage

```ts
import { createHushCliEngine } from "@clawdstrike/hush-cli-engine";
import type { PolicyEvent } from "@clawdstrike/adapter-core";

const engine = createHushCliEngine({
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
