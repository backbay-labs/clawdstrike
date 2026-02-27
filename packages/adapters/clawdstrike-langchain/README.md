# `@clawdstrike/langchain`

Baseline wrappers for LangChain-style tools. No hard runtime dependency on LangChain.

See [Enforcement Tiers & Integration Contract](https://github.com/backbay-labs/clawdstrike/blob/main/docs/src/concepts/enforcement-tiers.md) for what is enforceable at the tool boundary (and what requires a sandbox/broker).

## Install

```bash
npm install @clawdstrike/langchain @clawdstrike/engine-local
```

## Usage

```ts
import { createStrikeCell } from '@clawdstrike/engine-local';
import { BaseToolInterceptor } from '@clawdstrike/adapter-core';
import { wrapTool } from '@clawdstrike/langchain';

const engine = createStrikeCell({ policyRef: 'default' });
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

## Config overrides

```ts
import { createStrikeCell } from '@clawdstrike/engine-local';
import { wrapToolWithConfig } from '@clawdstrike/langchain';

const engine = createStrikeCell({ policyRef: 'default' });
const tool = { name: 'bash', async _call() { return 'ok'; } };

const secureTool = wrapToolWithConfig(tool, engine, { blockOnViolation: false });
const stricter = secureTool.withConfig({ blockOnViolation: true });
```

## Callback handler (in-process hooks)

```ts
import { createStrikeCell } from '@clawdstrike/engine-local';
import { ClawdstrikeCallbackHandler } from '@clawdstrike/langchain';

const engine = createStrikeCell({ policyRef: 'default' });
const handler = new ClawdstrikeCallbackHandler({ engine });
```

## LangGraph integration

### Security checkpoint

```ts
import { createSecurityCheckpoint } from '@clawdstrike/langchain';

const checkpoint = createSecurityCheckpoint({ engine });

// Use in a LangGraph node to check pending tool calls
const decision = await checkpoint.check(graphState);
if (decision.status === 'deny') {
  // block the tool execution
}
```

### Conditional routing

```ts
import { addSecurityRouting, createSecurityCheckpoint } from '@clawdstrike/langchain';

const checkpoint = createSecurityCheckpoint({ engine });

addSecurityRouting(graph, 'plan_node', checkpoint, {
  allow: 'execute_tools',
  block: 'blocked_handler',
  warn: 'warn_handler',
});
```

### Wrap a tool node

```ts
import { wrapToolNode, createSecurityCheckpoint } from '@clawdstrike/langchain';

const checkpoint = createSecurityCheckpoint({ engine });
wrapToolNode(graph, 'tool_node', checkpoint, { sanitize: true });
```

### LangGraph API reference

- `createSecurityCheckpoint(options)` -- Creates a `SecurityCheckpointNode` that evaluates pending tool calls against policy
- `addSecurityRouting(graph, fromNode, checkpoint, mapping)` -- Adds conditional edges that route based on security decisions (`allow`, `block`, `warn`)
- `wrapToolNode(graph, nodeName, checkpoint, options?)` -- Wraps an existing graph node with preflight security checks and optional output sanitization
- `sanitizeState(value, engine)` -- Recursively redacts secrets from graph state

## Errors

Blocked tool calls throw `ClawdstrikeViolationError` (includes `decision` and `toolName`).
