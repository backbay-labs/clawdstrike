# Generic Adapter Integration

Use this when your framework does not have a first-party `@backbay/*` integration yet.

The generic wrapper secures any dispatcher shaped like:

`(toolName, input, runId) => Promise<output>`

## Enforcement boundaries (read this)

This approach enforces at the **tool boundary**. It is not an OS sandbox; for the full integration contract (and what requires a sandbox/broker), see [Enforcement Tiers & Integration Contract](../concepts/enforcement-tiers.md).

## Install

```bash
npm install @backbay/adapter-core @backbay/hush-cli-engine
```

## Sample app (framework-agnostic)

```ts
import { createHushCliEngine } from '@backbay/hush-cli-engine';
import { GenericToolBoundary, wrapGenericToolDispatcher } from '@backbay/adapter-core';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new GenericToolBoundary({ engine });

const dispatchTool = wrapGenericToolDispatcher(boundary, async (toolName, input, runId) => {
  return { ok: true, toolName, input, runId };
});

const result = await dispatchTool('read_file', { path: './README.md' }, 'run-123');
console.log(result);
console.log(boundary.getAuditEvents().length);
```

## Server-side handler pattern

```ts
import type { Request, Response } from 'express';
import { createHushCliEngine } from '@backbay/hush-cli-engine';
import { GenericToolBoundary, wrapGenericToolDispatcher } from '@backbay/adapter-core';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new GenericToolBoundary({ engine });

const executeTool = wrapGenericToolDispatcher(
  boundary,
  async (toolName, input, runId) => runTool(toolName, input, runId),
);

export async function toolHandler(req: Request, res: Response): Promise<void> {
  const runId = String(req.headers['x-run-id'] ?? req.body.runId ?? crypto.randomUUID());
  const toolName = String(req.body.toolName);
  const input = req.body.input ?? {};

  try {
    const output = await executeTool(toolName, input, runId);
    res.status(200).json({ ok: true, output });
  } catch (error) {
    res.status(403).json({
      ok: false,
      error: error instanceof Error ? error.message : 'tool execution failed',
    });
  }
}
```

## Notes

- If you need custom session semantics, pass `createContext` and `keyFromRunId` to `GenericToolBoundary`.
- `getAuditEvents()` returns all captured audit events across active/seen runs.
- Blocked calls raise `GenericToolCallBlockedError`.
