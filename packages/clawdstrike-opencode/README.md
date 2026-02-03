# `@clawdstrike/opencode`

In-process tool-boundary hooks for OpenCode-style coding assistants.

## Install

```bash
npm install @clawdstrike/opencode @clawdstrike/adapter-core
```

## Usage

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import { OpenCodeToolBoundary } from '@clawdstrike/opencode';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new OpenCodeToolBoundary({ engine });

await boundary.handleToolStart('write_file', { path: './out.txt', content: 'hi' }, 'run-1');
await boundary.handleToolEnd('ok', 'run-1');
```

