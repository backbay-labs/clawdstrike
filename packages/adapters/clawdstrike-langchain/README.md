# @clawdstrike/langchain

LangChain/LangGraph-facing wrappers for Clawdstrike tool-boundary enforcement.

## Install

```bash
npm install @clawdstrike/langchain @clawdstrike/engine-local
```

## Quick start

```ts
import { createHushCliEngine } from '@clawdstrike/engine-local';
import { wrapTool } from '@clawdstrike/langchain';
import { BaseToolInterceptor } from '@clawdstrike/adapter-core';

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

## Exports

- Tool wrappers: `wrapTool`, `wrapTools`, `secureTool`, `secureTools`
- Callback integration: `ClawdstrikeCallbackHandler`
- LangGraph helpers: `createSecurityCheckpoint`, `addSecurityRouting`, `wrapToolNode`
- Error type: `ClawdstrikeViolationError`
