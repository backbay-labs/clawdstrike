# `@clawdstrike/claude-code`

In-process tool-boundary hooks for Claude Code-style assistants.

Use this at the layer that executes tools on behalf of the model.

See [Enforcement Tiers & Integration Contract](https://github.com/backbay-labs/clawdstrike/blob/main/docs/src/concepts/enforcement-tiers.md) for what this does and does not prevent (and what requires a sandbox/broker).

## Install

```bash
npm install @clawdstrike/claude-code @clawdstrike/adapter-core @clawdstrike/engine-local
```

## Usage

```ts
import { createHushCliEngine } from '@clawdstrike/engine-local';
import { ClaudeCodeToolBoundary, wrapClaudeCodeToolDispatcher } from '@clawdstrike/claude-code';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new ClaudeCodeToolBoundary({ engine });

const dispatchTool = wrapClaudeCodeToolDispatcher(boundary, async (toolName, input, runId) => {
  // ...execute the tool...
  return { toolName, input, runId };
});

await dispatchTool('read_file', { path: './README.md' }, 'run-1');
```
