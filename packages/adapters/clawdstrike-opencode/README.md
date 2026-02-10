# @clawdstrike/opencode

Tool-boundary wrapper utilities for OpenCode-style tool dispatchers.

## Install

```bash
npm install @clawdstrike/opencode @clawdstrike/engine-local
```

## Quick start

```ts
import { createHushCliEngine } from '@clawdstrike/engine-local';
import { OpenCodeToolBoundary, wrapOpenCodeToolDispatcher } from '@clawdstrike/opencode';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new OpenCodeToolBoundary({ engine });

const dispatchTool = wrapOpenCodeToolDispatcher(boundary, async (toolName, input, runId) => {
  return { toolName, input, runId };
});

await dispatchTool('write_file', { path: './out.txt', content: 'hi' }, 'run-1');
```

## Exports

- `OpenCodeToolBoundary`
- `wrapOpenCodeToolDispatcher`
- `OpenCodeAdapter`
- `ClawdstrikeBlockedError`
