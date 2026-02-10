# @clawdstrike/vercel-ai

Vercel AI SDK integration helpers for Clawdstrike policy enforcement.

## Install

```bash
npm install @clawdstrike/vercel-ai @clawdstrike/engine-local ai
```

## Quick start

```ts
import { createHushCliEngine } from '@clawdstrike/engine-local';
import { createClawdstrikeMiddleware } from '@clawdstrike/vercel-ai';

const engine = createHushCliEngine({ policyRef: 'default' });
const security = createClawdstrikeMiddleware({
  engine,
  config: { blockOnViolation: true, injectPolicyCheckTool: true },
});

const tools = security.wrapTools({
  bash: { async execute(input: { cmd: string }) { return input.cmd; } },
});
```

## Features

- Tool wrapping (`secureTools` / middleware wrappers)
- Optional model middleware wrapper
- Prompt-security features (jailbreak detection, output sanitization, watermarking)
- Stream-aware enforcement hooks

## Errors

- `ClawdstrikeBlockedError`
- `ClawdstrikePromptSecurityError`
