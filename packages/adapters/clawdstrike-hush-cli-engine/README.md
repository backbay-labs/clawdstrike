# @clawdstrike/engine-local

Local policy-engine adapter that evaluates policy by invoking the Clawdstrike CLI process.

## Install

```bash
npm install @clawdstrike/engine-local @clawdstrike/adapter-core
```

## Prerequisites

- Clawdstrike CLI available on `PATH` (default command is `hush`; you can override via `hushPath`).

## Quick start

```ts
import { createHushCliEngine } from '@clawdstrike/engine-local';
import type { PolicyEvent } from '@clawdstrike/adapter-core';

const engine = createHushCliEngine({
  policyRef: 'default',
  // hushPath: 'clawdstrike',
  timeoutMs: 10_000,
});

const event: PolicyEvent = {
  eventId: 'evt-1',
  eventType: 'tool_call',
  timestamp: new Date().toISOString(),
  data: { type: 'tool', toolName: 'bash', parameters: { cmd: 'echo hello' } },
};

const decision = await engine.evaluate(event);
if (decision.status === 'deny') throw new Error(decision.message ?? 'blocked');
```

## Behavior

- Fail-closed: engine errors return `deny` with `reason: "engine_error"`
- Supports local policy refs and optional `--resolve`
