# @clawdstrike/adapter-core

Framework-agnostic adapter interfaces for Clawdstrike tool-boundary enforcement.

## Installation

```bash
npm install @clawdstrike/adapter-core
```

## Usage

```ts
import { BaseToolInterceptor, createSecurityContext } from "@clawdstrike/adapter-core";

// Create an engine for policy evaluation (implementation-specific).
// For example, use @clawdstrike/hush-cli-engine to shell out to `hush`.
const engine = /* ... */;

const interceptor = new BaseToolInterceptor(engine, { blockOnViolation: true });
const ctx = createSecurityContext({ sessionId: "session-123" });

const preflight = await interceptor.beforeExecute("bash", { cmd: "echo hello" }, ctx);
if (!preflight.proceed) throw new Error("Blocked by policy");
```

## Generic tool runner wrapper

`@clawdstrike/adapter-core` can also wrap any `(toolName, input, runId) => Promise<output>`
dispatcher directly:

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import { GenericToolBoundary, wrapGenericToolDispatcher } from '@clawdstrike/adapter-core';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new GenericToolBoundary({ engine });

const dispatchTool = wrapGenericToolDispatcher(
  boundary,
  async (toolName, input, runId) => {
    return { toolName, input, runId };
  },
);

await dispatchTool('write_file', { path: './out.txt', content: 'hi' }, 'run-1');
console.log(boundary.getAuditEvents().length);
```
