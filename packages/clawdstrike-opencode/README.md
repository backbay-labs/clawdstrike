# `@clawdstrike/opencode`

In-process tool-boundary hooks for OpenCode-style coding assistants.

## Install

```bash
npm install @clawdstrike/opencode @clawdstrike/adapter-core
```

## Usage

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import { OpenCodeToolBoundary, wrapOpenCodeToolDispatcher } from '@clawdstrike/opencode';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new OpenCodeToolBoundary({ engine });

const dispatchTool = wrapOpenCodeToolDispatcher(boundary, async (toolName, input, runId) => {
  // ...execute the tool...
  return { toolName, input, runId };
});

await dispatchTool('write_file', { path: './out.txt', content: 'hi' }, 'run-1');
```
