# `@clawdstrike/vercel-ai`

Minimal, runtime-optional wrappers for Vercel AI SDK-style tools.

## Install

```bash
npm install @clawdstrike/vercel-ai @clawdstrike/adapter-core
```

## Usage

```ts
import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import { createVercelAiInterceptor, secureTools } from '@clawdstrike/vercel-ai';

const engine = createHushCliEngine({ policyRef: 'default' });
const interceptor = createVercelAiInterceptor(engine, { blockOnViolation: true });

const tools = secureTools(
  {
    bash: {
      async execute(input: { cmd: string }) {
        return `ran: ${input.cmd}`;
      },
    },
  },
  interceptor,
);

await tools.bash.execute({ cmd: 'echo hello' });
```

