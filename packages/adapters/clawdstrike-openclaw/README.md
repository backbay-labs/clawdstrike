# @clawdstrike/openclaw

Clawdstrike security plugin for OpenClaw. Provides tool-layer guardrails (preflight policy checks + post-action output blocking/redaction) for AI agents running in OpenClaw.

See [Enforcement Tiers & Integration Contract](https://github.com/backbay-labs/clawdstrike/blob/main/docs/src/concepts/enforcement-tiers.md) for what is enforceable at the tool boundary (and what requires a sandbox/broker).

## Installation

```bash
npm install @clawdstrike/openclaw
```

## Getting Started

See the [OpenClaw adapter getting-started guide](https://github.com/backbay-labs/clawdstrike/blob/main/packages/adapters/clawdstrike-openclaw/docs/getting-started.md) for full setup instructions.

## Usage

### FrameworkAdapter API

```ts
import { OpenClawAdapter, PolicyEngine } from '@clawdstrike/openclaw';

const engine = new PolicyEngine({ policy: 'strict' });
const adapter = new OpenClawAdapter(engine);

const ctx = adapter.createContext({ userId: 'user-1' });
const result = await adapter.interceptToolCall(ctx, {
  name: 'bash',
  parameters: { cmd: 'echo hello' },
});

if (!result.proceed) {
  console.error('Blocked:', result.decision.message);
}
```

### Policy checking

```ts
import { checkPolicy } from '@clawdstrike/openclaw';
import type { ClawdstrikeConfig } from '@clawdstrike/openclaw';

const config: ClawdstrikeConfig = { policy: 'default' };
const decision = await checkPolicy(config, 'file_read', '~/.ssh/id_rsa');
console.log(decision.status); // "deny"
```

### OpenClaw plugin hooks

The package exports hook handlers for direct OpenClaw integration:

- `agentBootstrapHandler` -- Injects security prompt at session start
- `toolPreflightHandler` -- Preflight policy check before tool execution
- `cuaBridgeHandler` -- Computer-use agent bridge with CUA-specific checks

### CLI

```bash
# Installed via the bin entry
clawdstrike policy lint ./policy.yaml
clawdstrike audit query --denied
clawdstrike audit export ./audit-dump.jsonl
clawdstrike why <event-id>
```

## Development Testing

When running this package from the monorepo workspace, build local package dependencies first:

```bash
bun --cwd packages/adapters/clawdstrike-openclaw run test:workspace
bun --cwd packages/adapters/clawdstrike-openclaw run typecheck:workspace
```

These commands build `@clawdstrike/policy` and `@clawdstrike/adapter-core` before running tests/typecheck.

## API Overview

| Export | Description |
|--------|-------------|
| `PolicyEngine` | Core policy evaluation engine |
| `OpenClawAdapter` | Standard `FrameworkAdapter` implementation |
| `loadPolicy` / `validatePolicy` | Policy loading and validation |
| `checkPolicy` / `policyCheckTool` | Policy check utilities |
| `AuditStore` / `OpenClawAuditLogger` | Audit event storage and logging |
| `ReceiptSigner` | Decision receipt signing |
| `generateSecurityPrompt` | Security system prompt generation |
| `openclawTranslator` | OpenClaw config translation |
| `registerCli` / `createCli` | CLI registration helpers |

## License

Apache-2.0
