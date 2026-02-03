# `@clawdstrike/vercel-ai`

Minimal, runtime-optional wrappers for Vercel AI SDK-style tools.

## Install

```bash
npm install @clawdstrike/vercel-ai @clawdstrike/adapter-core
```

## Usage (tool wrapping)

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import { createVercelAiInterceptor, secureTools } from '@clawdstrike/vercel-ai';

const engine = createHushCliEngine({ policyRef: 'default' });
const interceptor = createVercelAiInterceptor(engine, { blockOnViolation: true });

const tools = secureTools(
  {
    bash: {
      async execute(input: { cmd: string }) {
        return `ran: ${input.cmd}`;
      },
    },
  },
  interceptor,
);

await tools.bash.execute({ cmd: 'echo hello' });
```

## Middleware-style API

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
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

## Model wrapper (AI SDK)

```ts
import { openai } from '@ai-sdk/openai';

const model = security.wrapLanguageModel(openai('gpt-4o-mini'));
```

## Errors

Blocked tool calls throw `ClawdstrikeBlockedError` (includes `decision` and `toolName`).
