# `@clawdstrike/claude`

In-process tool-boundary hooks for Claude Code and the Claude Agent SDK.

Use this at the layer that executes tools on behalf of the model.

See [Enforcement Tiers & Integration Contract](https://github.com/backbay-labs/clawdstrike/blob/main/docs/src/concepts/enforcement-tiers.md) for what this does and does not prevent (and what requires a sandbox/broker).

## Install

```bash
npm install @clawdstrike/claude @clawdstrike/adapter-core @clawdstrike/engine-local
```

## Usage

```ts
import { createStrikeCell } from '@clawdstrike/engine-local';
import { ClaudeToolBoundary, wrapClaudeToolDispatcher } from '@clawdstrike/claude';

const engine = createStrikeCell({ policyRef: 'default' });
const boundary = new ClaudeToolBoundary({ engine });

const dispatchTool = wrapClaudeToolDispatcher(boundary, async (toolName, input, runId) => {
  // ...execute the tool...
  return { toolName, input, runId };
});

await dispatchTool('read_file', { path: './README.md' }, 'run-1');
```
