# `@clawdstrike/openai`

In-process tool-boundary hooks for the OpenAI Agents SDK.

This package is intentionally **runtime-agnostic**: you wire it into the layer that actually executes tools (file/network/command/etc).

See [Enforcement Tiers & Integration Contract](https://github.com/backbay-labs/clawdstrike/blob/main/docs/src/concepts/enforcement-tiers.md) for what this does and does not prevent (and what requires a sandbox/broker).

## Install

```bash
npm install @clawdstrike/openai @clawdstrike/adapter-core @clawdstrike/engine-local
```

## Usage

```ts
import { createStrikeCell } from '@clawdstrike/engine-local';
import { OpenAIToolBoundary, wrapOpenAIToolDispatcher } from '@clawdstrike/openai';

const engine = createStrikeCell({ policyRef: 'default' });
const boundary = new OpenAIToolBoundary({ engine });

// Drop-in wrapper around your real dispatcher:
const dispatchTool = wrapOpenAIToolDispatcher(boundary, async (toolName, input, runId) => {
  // ...execute the tool...
  return { toolName, input, runId };
});

await dispatchTool('bash', { cmd: 'echo hello' }, 'run-123');
```
