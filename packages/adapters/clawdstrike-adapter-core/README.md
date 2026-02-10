# @clawdstrike/adapter-core

Framework-agnostic primitives for enforcing Clawdstrike policy decisions at the tool boundary.

## Install

```bash
npm install @clawdstrike/adapter-core
```

## What this package provides

- Shared decision and event types (`PolicyEvent`, `Decision`, `PolicyEngineLike`)
- Security context + audit logging helpers
- Tool interceptors (`BaseToolInterceptor`, `GenericToolBoundary`)
- Output sanitization interface + default implementation

## Quick start

```ts
import {
  BaseToolInterceptor,
  createSecurityContext,
  type PolicyEngineLike,
} from '@clawdstrike/adapter-core';

const engine: PolicyEngineLike = {
  async evaluate(event) {
    return { status: 'allow' };
  },
};

const interceptor = new BaseToolInterceptor(engine, { blockOnViolation: true });
const ctx = createSecurityContext({ sessionId: 'run-123' });

const result = await interceptor.beforeExecute('bash', { cmd: 'echo hello' }, ctx);
if (!result.proceed) throw new Error(result.decision?.message ?? 'blocked');
```

## Dispatcher wrapper

```ts
import { GenericToolBoundary, wrapGenericToolDispatcher } from '@clawdstrike/adapter-core';

const boundary = new GenericToolBoundary({ engine });

const dispatch = wrapGenericToolDispatcher(
  boundary,
  async (toolName, input, runId) => ({ toolName, input, runId }),
);

await dispatch('write_file', { path: './out.txt', content: 'ok' }, 'run-1');
```

## Notes

- `@clawdstrike/adapter-core` is runtime-neutral. It does not force any framework or model SDK.
- Pair it with an engine adapter such as `@clawdstrike/engine-local` or `@clawdstrike/engine-remote`.
