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
import { checkPolicy, PolicyEngine, policyCheckTool } from '@clawdstrike/openclaw';

const config = { policy: './policy.yaml' };

// Direct policy check
const result = await checkPolicy(config, 'file_read', '~/.ssh/id_rsa');
console.log(result.allowed, result.message);

// Build an OpenClaw tool definition
const engine = new PolicyEngine(config);
const tool = policyCheckTool(engine);
const toolResult = await tool.execute({
  action: 'file_read',
  resource: '~/.ssh/id_rsa',
});
console.log(toolResult.allowed, toolResult.message);
```

## Docs

- See `packages/adapters/clawdstrike-openclaw/docs/getting-started.md` for full setup and policy authoring.
