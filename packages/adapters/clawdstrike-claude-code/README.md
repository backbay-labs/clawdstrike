# `@clawdstrike/claude-code`

In-process tool-boundary hooks for Claude Code-style assistants.

Use this at the layer that executes tools on behalf of the model.

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

## Fail-Closed POC

```bash
npm --prefix packages/adapters/clawdstrike-claude-code run build
npm --prefix packages/adapters/clawdstrike-claude-code run poc:fail-closed
```

This deterministic POC proves blocked tool calls throw `ClawdstrikeBlockedError` and do not execute dispatcher side effects.
