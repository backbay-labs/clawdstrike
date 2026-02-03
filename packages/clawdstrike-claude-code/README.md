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
import { ClaudeCodeToolBoundary } from '@clawdstrike/claude-code';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new ClaudeCodeToolBoundary({ engine });

await boundary.handleToolStart('read_file', { path: './README.md' }, 'run-1');
const output = '...';
await boundary.handleToolEnd(output, 'run-1');
```

