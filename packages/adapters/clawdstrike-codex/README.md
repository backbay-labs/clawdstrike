# @clawdstrike/codex

Tool-boundary wrapper utilities for Codex-style tool dispatchers.

## Install

```bash
npm install @clawdstrike/codex @clawdstrike/engine-local
```

## Quick start

```ts
import { createHushCliEngine } from '@clawdstrike/engine-local';
import { CodexToolBoundary, wrapCodexToolDispatcher } from '@clawdstrike/codex';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new CodexToolBoundary({ engine });

const dispatchTool = wrapCodexToolDispatcher(boundary, async (toolName, input, runId) => {
  return { toolName, input, runId };
});

await dispatchTool('bash', { cmd: 'echo hello' }, 'run-123');
```

## Exports

- `CodexToolBoundary`
- `wrapCodexToolDispatcher`
- `CodexAdapter`
- `ClawdstrikeBlockedError`
