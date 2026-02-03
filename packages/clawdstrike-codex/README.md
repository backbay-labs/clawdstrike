# `@clawdstrike/codex`

In-process tool-boundary hooks for Codex-style coding assistants.

This package is intentionally **runtime-agnostic**: you wire it into the layer that actually executes tools (file/network/command/etc).

## Install

```bash
npm install @clawdstrike/codex @clawdstrike/adapter-core
```

## Usage

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import { CodexToolBoundary, wrapCodexToolDispatcher } from '@clawdstrike/codex';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new CodexToolBoundary({ engine });

// Drop-in wrapper around your real dispatcher:
const dispatchTool = wrapCodexToolDispatcher(boundary, async (toolName, input, runId) => {
  // ...execute the tool...
  return { toolName, input, runId };
});

await dispatchTool('bash', { cmd: 'echo hello' }, 'run-123');
```
