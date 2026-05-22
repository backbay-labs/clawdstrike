# @clawdstrike/openclaw

Clawdstrike security plugin for OpenClaw. Provides tool-layer guardrails (preflight policy checks + synchronous post-action output rewriting/redaction) for AI agents running in OpenClaw.

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
- `toolGuardHandler` -- Post-result policy check, output redaction, and result telemetry
- `cuaBridgeHandler` -- Computer-use agent bridge with CUA-specific checks
- `inboundMessageHandler` -- Pre-context inbound message guard (`inbound_message` / `user_input`)

When the local ClawdStrike agent token is available, `toolPreflightHandler`
also publishes best-effort canonical `PolicyEvent` telemetry to the local agent
EDR API for the preflight file, command, patch, network, and tool events it
already evaluates. Package-manager lifecycle commands, including Composer,
Maven, Gradle, uv, Poetry, Pipenv, .NET/NuGet, SwiftPM, and Mix command forms,
and sensitive cloud-CLI commands, including
Firebase Functions Secrets, Railway variables, Sentry/Snyk auth tokens, Bitwarden
item reads, AWS/GCP/Azure credential and kubeconfig operations, and Terraform-family state,
output, and login commands, are also
emitted as normalized developer-activity facts with credential-bearing command
tokens redacted. Telemetry failure does not
affect preflight enforcement.

When the local ClawdStrike agent token is available, `toolGuardHandler` also
publishes best-effort post-execution EDR telemetry for `tool_result_persist`
events. It sends scrubbed `PolicyEvent` evidence with result/content bodies
omitted and hashed, and emits normalized developer-activity facts for
result-discovered local downloads, browser extension installs, credential-like
paths, and secret-like tool outputs with tokenized source URLs scrubbed before
submission. Telemetry failure does not affect post-result blocking or
redaction.

When inbound message handling is enabled and the local ClawdStrike agent token
is available, `inboundMessageHandler` also publishes best-effort custom
`PolicyEvent` evidence for prompt/message decisions. It records message hashes,
sizes, sender/session metadata, and allow/warn/deny/sanitize decisions without
uploading raw prompt text. Telemetry failure does not affect inbound blocking or
sanitization.

When the local ClawdStrike agent token is available, `cuaBridgeHandler` also
publishes best-effort developer-activity telemetry to the agent EDR API.
Recognized CUA input/session actions are recorded as `browser_automation`
facts, and file-download actions with local paths are recorded as
`browser_download` facts. Tool parameters and tokenized source URLs are scrubbed
before submission. Telemetry failure does not affect CUA policy enforcement.

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
| `inboundMessageHandler` | Inbound message hook handler |
| `registerCli` / `createCli` | CLI registration helpers |

## License

Apache-2.0
