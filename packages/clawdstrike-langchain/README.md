# `@clawdstrike/langchain`

Baseline wrappers for LangChain-style tools. No hard runtime dependency on LangChain.

## Install

```bash
npm install @clawdstrike/langchain @clawdstrike/adapter-core
```

## Usage

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

## Config overrides

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import { wrapToolWithConfig } from '@clawdstrike/langchain';

const engine = createHushCliEngine({ policyRef: 'default' });
const tool = { name: 'bash', async _call() { return 'ok'; } };

const secureTool = wrapToolWithConfig(tool, engine, { blockOnViolation: false });
const stricter = secureTool.withConfig({ blockOnViolation: true });
```

## Callback handler (in-process hooks)

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import { ClawdstrikeCallbackHandler } from '@clawdstrike/langchain';

const engine = createHushCliEngine({ policyRef: 'default' });
const handler = new ClawdstrikeCallbackHandler({ engine });
```

## Errors

Blocked tool calls throw `ClawdstrikeViolationError` (includes `decision` and `toolName`).
