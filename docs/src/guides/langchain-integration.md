# LangChain Integration

`@clawdstrike/langchain` is a small, runtime-agnostic wrapper layer for LangChain-style tools.

- Wrap tools that implement `invoke()` or `_call()`
- Optional callback handler hooks you can wire into LangChain's callback system
- Optional LangGraph helpers for inserting a security checkpoint node

This package does **not** ship a policy engine. You provide one:

- `@clawdstrike/hush-cli-engine` (shells out to the `hush` CLI), or
- your own implementation of `PolicyEngineLike`.

## Installation

```bash
npm install @clawdstrike/langchain @clawdstrike/hush-cli-engine @clawdstrike/adapter-core
```

## Wrap tools (tool boundary)

Wrap a single tool:

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import { BaseToolInterceptor } from '@clawdstrike/adapter-core';
import { wrapTool } from '@clawdstrike/langchain';

const engine = createHushCliEngine({ policyRef: 'default' });
const interceptor = new BaseToolInterceptor(engine, { blockOnViolation: true });

const tool = {
  name: 'bash',
  async invoke(input: { cmd: string }) {
    return `ran: ${input.cmd}`;
  },
};

const secureTool = wrapTool(tool, interceptor);
await secureTool.invoke({ cmd: 'echo hello' });
```

Wrap an array of tools:

```ts
import { wrapTools } from '@clawdstrike/langchain';

const secureTools = wrapTools([toolA, toolB], interceptor);
```

## Config convenience

If you want the wrapper to create its own interceptor:

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import { wrapToolWithConfig } from '@clawdstrike/langchain';

const engine = createHushCliEngine({ policyRef: 'default' });
const tool = { name: 'bash', async _call() { return 'ok'; } };

const wrapped = wrapToolWithConfig(tool, engine, { blockOnViolation: false });
const stricter = wrapped.withConfig({ blockOnViolation: true });
```

## Callback handler (in-process hooks)

`ClawdstrikeCallbackHandler` exposes explicit hook methods you can call from your runtime’s callback surface.

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import { ClawdstrikeCallbackHandler } from '@clawdstrike/langchain';

const engine = createHushCliEngine({ policyRef: 'default' });
const handler = new ClawdstrikeCallbackHandler({ engine });

// Pseudocode: wire these into your callback implementation.
await handler.handleToolStart({ name: 'bash' }, JSON.stringify({ cmd: 'ls' }), 'run-123');
await handler.handleToolEnd('ok', 'run-123');
```

Audit events are available via `handler.getAuditEvents()`.

## LangGraph helpers

If you use LangGraph, `@clawdstrike/langchain` also exports helpers like:

- `createSecurityCheckpoint`
- `addSecurityRouting`
- `wrapToolNode`

See the package README for the latest helper surface.

## Errors

Blocked tool calls throw `ClawdstrikeViolationError` (includes `decision` and `toolName`).
