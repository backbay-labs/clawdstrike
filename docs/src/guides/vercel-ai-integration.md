# Vercel AI SDK Integration

`@clawdstrike/vercel-ai` provides runtime-optional wrappers for the Vercel AI SDK:

- Tool wrapping (block/modify/redact) via a `PolicyEngineLike`
- Model wrapper (`wrapLanguageModel`) with optional prompt-security checks
- React hook (`useSecureChat`) for guarding streaming tool calls in `ai/react`

This package does **not** ship a policy engine. You provide one:

- `@clawdstrike/hush-cli-engine` (shells out to the `hush` CLI), or
- your own implementation of `PolicyEngineLike`.

## Installation

```bash
npm install @clawdstrike/vercel-ai @clawdstrike/hush-cli-engine ai
```

If you use a provider package:

```bash
npm install @ai-sdk/openai
```

## 1) Create an engine (policy evaluation)

The simplest engine is `@clawdstrike/hush-cli-engine`, which calls `hush policy eval` under the hood.

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';

const engine = createHushCliEngine({
  policyRef: 'default', // or 'strict', or a policy file path
  // hushPath: '/path/to/hush',
  // resolve: true, // resolve extends for file inputs
});
```

## 2) Create middleware and wrap tools/models

```ts
import { createClawdstrikeMiddleware } from '@clawdstrike/vercel-ai';

const security = createClawdstrikeMiddleware({
  engine,
  config: {
    blockOnViolation: true,
    // Best-effort: depends on the AI SDK stream part shapes.
    streamingEvaluation: true,
  },
});
```

### Wrap tools

`wrapTools` works with any “tool-like” object that has an async `execute()` function (including tools created via `ai`'s `tool()` helper).

```ts
import { tool } from 'ai';
import { z } from 'zod';

const tools = security.wrapTools({
  bash: tool({
    description: 'Run a command',
    parameters: z.object({ cmd: z.string() }),
    execute: async ({ cmd }) => `ran: ${cmd}`,
  }),
});
```

### Wrap a model

```ts
import { openai } from '@ai-sdk/openai';

const model = security.wrapLanguageModel(openai('gpt-4o-mini'));
```

Now pass `model` and `tools` to `generateText` / `streamText` as usual.

## Prompt Security (P1)

Prompt-security runs on model calls (not tool execution). Enable it via `config.promptSecurity`:

```ts
const security = createClawdstrikeMiddleware({
  engine,
  config: {
    blockOnViolation: true,
    streamingEvaluation: true,
    promptSecurity: {
      enabled: true,
      mode: 'block', // 'warn' | 'audit'
      applicationId: 'my-app',
      jailbreakDetection: { enabled: true },
      instructionHierarchy: { enabled: true },
      outputSanitization: { enabled: true },
      // Optional: embed a signed watermark marker in a system message:
      watermarking: { enabled: false },
    },
  },
});
```

Notes:

- Prompt-security blocks throw `ClawdstrikePromptSecurityError` (no raw prompt text in error details).
- Prompt-security findings are recorded in `security.getAuditLog()` as `prompt_security_*` audit events.

## React: `useSecureChat`

Guard tool calls for `ai/react` streaming chats.

Note: `@clawdstrike/hush-cli-engine` shells out to the `hush` binary, so it is **server-only**. In the browser, use an engine that calls a server endpoint (or a `clawdstriked` instance).

```tsx
'use client';

import { useSecureChat } from '@clawdstrike/vercel-ai/react';
import type { PolicyEngineLike, PolicyEvent, Decision } from '@clawdstrike/adapter-core';

const engine: PolicyEngineLike = {
  async evaluate(event: PolicyEvent): Promise<Decision> {
    const resp = await fetch('/api/policy/eval', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(event),
    });
    if (!resp.ok) {
      throw new Error(`policy eval failed: ${resp.status}`);
    }
    return (await resp.json()) as Decision;
  },
};

export function Chat() {
  const { messages, input, handleInputChange, handleSubmit, securityStatus } = useSecureChat({
    api: '/api/chat',
    engine,
    securityConfig: { blockOnViolation: true },
  });

  return (
    <div>
      {securityStatus.blocked ? <p>Blocked by policy</p> : null}
      <form onSubmit={handleSubmit}>
        <input value={input} onChange={handleInputChange} />
        <button type="submit">Send</button>
      </form>
      <pre>{JSON.stringify(messages, null, 2)}</pre>
    </div>
  );
}
```

Example server endpoint for `/api/policy/eval` (Next.js route handler):

```ts
import type { PolicyEvent } from '@clawdstrike/adapter-core';
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';

const engine = createHushCliEngine({ policyRef: 'default' });

export async function POST(req: Request) {
  const event = (await req.json()) as PolicyEvent;
  const decision = await engine.evaluate(event);
  return Response.json(decision);
}
```

## Errors

- `ClawdstrikeBlockedError` — thrown when a tool is blocked (includes `toolName` + `decision`)
- `ClawdstrikePromptSecurityError` — thrown when prompt-security blocks a model call
