# @clawdstrike/claude-code

Tool-boundary wrapper utilities for Claude Code-style tool dispatchers.

## Install

```bash
npm install @clawdstrike/claude-code @clawdstrike/engine-local
```

## Quick start

```ts
import { createHushCliEngine } from '@clawdstrike/engine-local';
import { ClaudeCodeToolBoundary, wrapClaudeCodeToolDispatcher } from '@clawdstrike/claude-code';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new ClaudeCodeToolBoundary({ engine });

const dispatchTool = wrapClaudeCodeToolDispatcher(boundary, async (toolName, input, runId) => {
  return { toolName, input, runId };
});

await dispatchTool('read_file', { path: './README.md' }, 'run-1');
```

## Exports

- `ClaudeCodeToolBoundary`
- `wrapClaudeCodeToolDispatcher`
- `ClaudeCodeAdapter`
- `ClawdstrikeBlockedError`
