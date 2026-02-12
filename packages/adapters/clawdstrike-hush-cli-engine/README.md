# @clawdstrike/engine-local

Policy engine adapter that shells out to the `hush` CLI for evaluation.

This is useful when you want TypeScript tool-boundary enforcement but prefer the Rust policy engine for ruleset parsing and evaluation.

## Prerequisites

- `hush` installed and available on your PATH (or provide a custom `hushPath`).

## Usage

```ts
import { createHushCliEngine } from "@clawdstrike/engine-local";
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

## Fail-Closed POC

```bash
npm --prefix packages/adapters/clawdstrike-hush-cli-engine run build
npm --prefix packages/adapters/clawdstrike-hush-cli-engine run poc:fail-closed
```

This deterministic POC proves local transport/spawn errors return fail-closed decisions (`deny` + `engine_error`).
