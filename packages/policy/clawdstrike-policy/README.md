# @clawdstrike/policy

Canonical JavaScript/TypeScript policy loader and evaluation engine for Clawdstrike.

## Install

```bash
npm install @clawdstrike/policy
```

## Quick start

```ts
import { createPolicyEngineFromPolicy, loadPolicyFromFile } from '@clawdstrike/policy';

const policy = loadPolicyFromFile('./policy.yaml', { resolve: true });
const engine = createPolicyEngineFromPolicy(policy);

const decision = await engine.evaluate({
  eventId: 'evt_1',
  eventType: 'network_egress',
  timestamp: new Date().toISOString(),
  data: { type: 'network', host: 'api.github.com', port: 443 },
});

if (decision.status === 'deny') throw new Error(decision.message ?? 'blocked');
```

## Capabilities

- YAML policy load/validate (`loadPolicyFromFile`, `loadPolicyFromString`, `validatePolicy`)
- Engine creation (`createPolicyEngine`, `createPolicyEngineFromPolicy`)
- Custom guard registry (`CustomGuardRegistry`)
- Plugin inspection/loading utilities

## Notes

- The Rust implementation (`crates/libs/clawdstrike`) remains the authoritative reference for schema semantics.
- For maximum production parity with Rust enforcement, pair adapter packages with `@clawdstrike/engine-remote`.
