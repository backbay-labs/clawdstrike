# `@clawdstrike/codex`

In-process tool-boundary hooks for Codex-style coding assistants.

This package is intentionally **runtime-agnostic**: you wire it into the layer that actually executes tools (file/network/command/etc).

## Install

```bash
npm install @clawdstrike/codex @clawdstrike/adapter-core
```

## Usage

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import { CodexToolBoundary } from '@clawdstrike/codex';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new CodexToolBoundary({ engine });

// Call these from your tool dispatcher:
await boundary.handleToolStart('bash', { cmd: 'echo hello' }, 'run-123');
const output = 'ok';
await boundary.handleToolEnd(output, 'run-123');
```

