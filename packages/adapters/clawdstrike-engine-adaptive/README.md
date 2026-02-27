# @clawdstrike/engine-adaptive

Adaptive policy engine with automatic mode switching between local and remote engines.

## Overview

The adaptive engine wraps a local `PolicyEngineLike` and an optional remote `PolicyEngineLike`, automatically switching between three modes:

- **standalone** — local engine only (no remote configured or not yet connected)
- **connected** — remote engine is the primary evaluator
- **degraded** — remote is unreachable; local engine handles evaluation while receipts are queued for later sync

## Installation

```bash
npm install @clawdstrike/engine-adaptive @clawdstrike/adapter-core
```

## Usage

```typescript
import { createAdaptiveEngine } from '@clawdstrike/engine-adaptive';
import { createStrikeCell } from '@clawdstrike/engine-remote';
import { createLocalEngine } from './my-local-engine.js';

const engine = createAdaptiveEngine({
  local: createLocalEngine(),
  remote: createStrikeCell({ baseUrl: 'https://hushd.example.com' }),
  probe: {
    remoteHealthUrl: 'https://hushd.example.com/health',
    intervalMs: 30_000,
    timeoutMs: 5_000,
  },
  receiptQueue: {
    maxSize: 1000,
    persistPath: '/tmp/adaptive-queue.jsonl',
  },
  onModeChange: (event) => {
    console.log(`Mode changed: ${event.from} → ${event.to} (${event.reason})`);
  },
});

// Use like any PolicyEngineLike.
const decision = await engine.evaluate(policyEvent);

// Decisions include provenance metadata in `decision.details.provenance`.

// Clean up when done.
engine.dispose();
```

## Mode Transitions

```
standalone ──→ connected    (remote becomes healthy)
connected  ──→ degraded     (connectivity error during evaluation or probe)
degraded   ──→ connected    (probe succeeds, queue is drained)
degraded   ──→ standalone   (give up on remote)
```

## Fail-Closed Guarantee

Every error path calls `failClosed()` from `@clawdstrike/adapter-core`, returning a deny decision with reason code `ADC_GUARD_ERROR`. No evaluation error can result in an implicit allow.

## License

Apache-2.0
