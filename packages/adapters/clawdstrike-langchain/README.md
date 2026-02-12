# `@clawdstrike/langchain`

Baseline wrappers for LangChain-style tools. No hard runtime dependency on LangChain.

See [Enforcement Tiers & Integration Contract](https://github.com/backbay-labs/clawdstrike/blob/main/docs/src/concepts/enforcement-tiers.md) for what is enforceable at the tool boundary (and what requires a sandbox/broker).

## Install

```bash
npm install @clawdstrike/langchain @clawdstrike/adapter-core @clawdstrike/engine-local
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

## Errors

Blocked tool calls throw `ClawdstrikeViolationError` (includes `decision` and `toolName`).
