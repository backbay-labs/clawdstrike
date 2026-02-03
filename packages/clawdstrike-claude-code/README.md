# `@clawdstrike/claude-code`

In-process tool-boundary hooks for Claude Code-style assistants.

Use this at the layer that executes tools on behalf of the model.

## Install

```bash
npm install @clawdstrike/claude-code @clawdstrike/adapter-core
```

## Usage

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import { ClaudeCodeToolBoundary, wrapClaudeCodeToolDispatcher } from '@clawdstrike/claude-code';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new ClaudeCodeToolBoundary({ engine });

const dispatchTool = wrapClaudeCodeToolDispatcher(boundary, async (toolName, input, runId) => {
  // ...execute the tool...
  return { toolName, input, runId };
});

await dispatchTool('read_file', { path: './README.md' }, 'run-1');
```
