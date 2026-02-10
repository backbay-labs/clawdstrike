# @clawdstrike/engine-remote

Remote policy-engine adapter that evaluates policy via the Clawdstrike daemon HTTP API.

## Install

```bash
npm install @clawdstrike/engine-remote @clawdstrike/adapter-core
```

## Quick start

```ts
import { createHushdEngine } from '@clawdstrike/engine-remote';

const engine = createHushdEngine({
  baseUrl: 'http://127.0.0.1:9876',
  // token: process.env.CLAWDSTRIKE_CHECK_KEY,
  timeoutMs: 10_000,
});

const decision = await engine.evaluate(event);
if (decision.status === 'deny') throw new Error(decision.message ?? 'blocked');
```

## Behavior

- POSTs evaluation events to `/api/v1/eval`
- Optional bearer token auth
- Fail-closed on timeout, network, and parse errors
