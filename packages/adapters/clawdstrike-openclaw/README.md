# @clawdstrike/openclaw

OpenClaw plugin package for Clawdstrike policy checks, guards, and security hooks.

## Install

```bash
npm install @clawdstrike/openclaw
```

## What this package includes

- Policy loading + validation
- Policy evaluation engine for OpenClaw-shaped events
- Tool-policy check helper (`policyCheckTool`)
- Agent bootstrap and audit hook handlers
- CLI registration helpers

## Quick start

```ts
import { PolicyEngine, loadPolicy, policyCheckTool } from '@clawdstrike/openclaw';

const policy = loadPolicy('./policy.yaml');
const engine = new PolicyEngine(policy);

const result = await policyCheckTool({
  action: 'file_read',
  target: '~/.ssh/id_rsa',
  context: { cwd: process.cwd() },
}, { engine });

console.log(result.allowed, result.message);
```

## Docs

- See `packages/adapters/clawdstrike-openclaw/docs/getting-started.md` for full setup and policy authoring.
