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

