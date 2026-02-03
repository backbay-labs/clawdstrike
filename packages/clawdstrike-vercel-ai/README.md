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

## Prompt Security (P1)

Enable prompt-security features (instruction hierarchy, jailbreak detection, output sanitization, optional watermarking)
for model calls:

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import { createClawdstrikeMiddleware } from '@clawdstrike/vercel-ai';
import { openai } from '@ai-sdk/openai';

const engine = createHushCliEngine({ policyRef: 'default' });
const security = createClawdstrikeMiddleware({
  engine,
  config: {
    blockOnViolation: true,
    // Tool-call streaming evaluation/annotation (best-effort; depends on AI SDK stream part shapes):
    streamingEvaluation: true,
    promptSecurity: {
      enabled: true,
      mode: 'block', // 'warn' | 'audit'
      applicationId: 'my-app',
      jailbreakDetection: { enabled: true },
      instructionHierarchy: { enabled: true },
      outputSanitization: { enabled: true },
      // Optional: embed a signed watermark marker in a system message:
      watermarking: { enabled: true },
    },
  },
});

const model = security.wrapLanguageModel(openai('gpt-4o-mini'));
```

Notes:
- Prompt-security blocks throw `ClawdstrikePromptSecurityError` (no raw prompt contents included).
- Prompt-security findings are recorded in `security.getAuditLog()` as `prompt_security_*` audit events.

## Errors

Blocked tool calls throw `ClawdstrikeBlockedError` (includes `decision` and `toolName`).
