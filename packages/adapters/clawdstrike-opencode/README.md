# `@clawdstrike/opencode`

In-process tool-boundary hooks for OpenCode-style coding assistants.

See [Enforcement Tiers & Integration Contract](https://github.com/backbay-labs/clawdstrike/blob/main/docs/src/concepts/enforcement-tiers.md) for what this does and does not prevent (and what requires a sandbox/broker).

## Install

```bash
npm install @clawdstrike/opencode @clawdstrike/adapter-core @clawdstrike/engine-local
```

## Usage

```ts
import { createStrikeCell } from '@clawdstrike/engine-local';
import { OpenCodeToolBoundary, wrapOpenCodeToolDispatcher } from '@clawdstrike/opencode';

const engine = createStrikeCell({ policyRef: 'default' });
const boundary = new OpenCodeToolBoundary({ engine });

const dispatchTool = wrapOpenCodeToolDispatcher(boundary, async (toolName, input, runId) => {
  // ...execute the tool...
  return { toolName, input, runId };
});

await dispatchTool('write_file', { path: './out.txt', content: 'hi' }, 'run-1');
```
