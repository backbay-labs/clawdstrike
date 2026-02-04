# @clawdstrike/hush-cli-engine

Policy engine adapter that shells out to the `hush` CLI for evaluation.

This is useful when you want TypeScript tool-boundary enforcement but prefer the Rust policy engine for ruleset parsing and evaluation.

## Prerequisites

- `hush` installed and available on your PATH (or provide a custom `hushPath`).

## Usage

```ts
import { createHushCliEngine } from "@clawdstrike/hush-cli-engine";

const engine = createHushCliEngine({
  policyRef: "default",
  // hushPath: "/path/to/hush",
});

const result = await engine.check({
  actionType: "command_exec",
  target: "bash",
  args: { cmd: "echo hello" },
});

if (!result.allowed) throw new Error(result.message);
```
