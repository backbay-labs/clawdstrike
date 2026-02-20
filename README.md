<p align="center">
  <img src=".github/assets/clawdstrike-hero.png" alt="Clawdstrike" width="900" />
</p>

<p align="center">
  <a href="https://github.com/backbay-labs/clawdstrike/actions"><img src="https://img.shields.io/github/actions/workflow/status/backbay-labs/clawdstrike/ci.yml?branch=main&style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <a href="https://crates.io/crates/clawdstrike"><img src="https://img.shields.io/crates/v/clawdstrike?style=flat-square&logo=rust" alt="crates.io"></a>
  <a href="https://docs.rs/clawdstrike"><img src="https://img.shields.io/docsrs/clawdstrike?style=flat-square&logo=docs.rs" alt="docs.rs"></a>
  <a href="https://artifacthub.io/packages/search?repo=clawdstrike"><img src="https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/clawdstrike" alt="Artifact Hub"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/MSRV-1.93-orange?style=flat-square&logo=rust" alt="MSRV: 1.93">
</p>

<p align="center">
  <em>
    The claw strikes back.<br/>
    At the boundary between intent and action,<br/>
    it watches what leaves, what changes, what leaks.<br/>
    Not "visibility." Not “telemetry.” Not "vibes." Logs are stories—proof is a signature.<br/>
    If the tale diverges, the receipt won't sign.
  </em>
</p>

<p align="center">
  <img src=".github/assets/divider.png" alt="" width="520" />
</p>

<p align="center">
  <img src=".github/assets/sigils/claw-light.svg#gh-light-mode-only" height="42" alt="" />
  <img src=".github/assets/sigils/claw-dark.svg#gh-dark-mode-only"   height="42" alt="" />
</p>

<h1 align="center">Clawdstrike</h1>

<p align="center">
  <em>Fail closed. Sign the truth.</em>
</p>

<p align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/sigils/boundary-dark.svg"><img src=".github/assets/sigils/boundary-light.svg" width="16" height="16" alt=""  style="vertical-align:-3px;" ></picture>&nbsp;Tool-boundary enforcement
   <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/sigils/seal-dark.svg"><img src=".github/assets/sigils/seal-light.svg" width="16" height="16" alt=""  style="vertical-align:-3px;" ></picture>&nbsp;Signed receipts
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/sigils/plugin-dark.svg"><img src=".github/assets/sigils/plugin-light.svg" width="16" height="16" alt=""  style="vertical-align:-3px;" ></picture>&nbsp;Multi-framework
</p>

<p align="center">
  <a href="docs/src/getting-started/quick-start.md">Docs</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="docs/src/getting-started/quick-start-typescript.md">TypeScript</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="docs/src/getting-started/quick-start-python.md">Python</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="packages/adapters/clawdstrike-openclaw/docs/getting-started.md">OpenClaw</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="examples">Examples</a>
</p>

---

## Overview

> **Alpha software** — APIs and import paths may change between releases. See GitHub Releases and the package registries (crates.io / npm / PyPI) for published versions.

Clawdstrike is a fail-closed policy + attestation runtime for AI agents and computer-use systems, designed for developers building EDR solutions and security infrastructure for autonomous agent swarms. It sits at the boundary between intent and execution: normalize actions, enforce policy, and sign what happened.

<img src=".github/assets/sigils/boundary-light.svg#gh-light-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;margin-right:6px;" /> <img src=".github/assets/sigils/boundary-dark.svg#gh-dark-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;margin-right:6px;" />**Guards** — Block sensitive paths, control network egress, detect secrets, validate patches, restrict tools, catch jailbreaks

<img src=".github/assets/sigils/policy-light.svg#gh-light-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;margin-right:6px;" /> <img src=".github/assets/sigils/policy-dark.svg#gh-dark-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;margin-right:6px;" />**Receipts** — Ed25519-signed attestations proving what was decided, under which policy, with what evidence

<img src=".github/assets/sigils/seal-light.svg#gh-light-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;margin-right:6px;" /> <img src=".github/assets/sigils/seal-dark.svg#gh-dark-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;margin-right:6px;" />**Multi-language** — Rust, TypeScript, Python, WebAssembly

<img src=".github/assets/sigils/ruleset-light.svg#gh-light-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;margin-right:6px;" /> <img src=".github/assets/sigils/ruleset-dark.svg#gh-dark-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;margin-right:6px;" />**Multi-framework** — OpenClaw, Vercel AI, LangChain, Claude, OpenAI, and more

## Computer Use Gateway

Clawdstrike now includes dedicated CUA gateway coverage for real runtime paths (not just static policy checks):

- Canonical CUA action translation across providers/runtimes.
- Side-channel policy controls for remote desktop surfaces (`clipboard`, `audio`, `drive_mapping`, `printing`, `session_share`, file transfer bounds).
- Deterministic decision metadata (`reason_code`, guard, severity) for machine-checkable analytics.
- Fixture-driven validator suites plus runtime bridge tests for regression safety.

## Architecture At A Glance

```mermaid
flowchart LR
    A[Provider Runtime<br/>OpenAI / Claude / OpenClaw] --> B[Clawdstrike Adapter]
    B --> C[Canonical Action Event]
    C --> D[Policy Engine + Guard Evaluation]
    D -->|allow| E[Gateway / Tool / Remote Action]
    D -->|deny| F[Fail-Closed Block]
    D --> G[Signed Receipt + reason_code]
```

## Quick Start

### Computer use gateway smoke (agent-owned OpenClaw path)

```bash
scripts/openclaw-agent-smoke.sh \
  --start-local-gateway \
  --gateway-url ws://127.0.0.1:18789 \
  --gateway-token dev-token
```

Runbook and flow details:
- `docs/src/guides/agent-openclaw-operations.md`
- `apps/desktop/docs/openclaw-gateway-testing.md`

### CLI (Rust)

```bash
cargo install --path crates/services/hush-cli

clawdstrike policy list
clawdstrike check --action-type file --ruleset strict ~/.ssh/id_rsa
```

### TypeScript (unified SDK)

```typescript
import { Clawdstrike } from "@clawdstrike/sdk";

// Simple: use built-in strict rules (fail-closed)
const cs = Clawdstrike.withDefaults("strict");

// Check an action
const decision = await cs.checkFile("~/.ssh/id_rsa", "read");
if (decision.status === "deny") {
  throw new Error(`Blocked: ${decision.message}`);
}

// Or use sessions for stateful tracking
const session = cs.session({ agentId: "my-agent" });
const result = await session.check("file_access", { path: "~/.ssh/id_rsa" });
console.log(session.getSummary()); // { checkCount, denyCount, ... }
```

### TypeScript (tool boundary with interceptor)

For framework integrations, use the interceptor pattern:

```typescript
import { Clawdstrike } from "@clawdstrike/sdk";

const cs = Clawdstrike.withDefaults("strict");
const interceptor = cs.createInterceptor();
const session = cs.session({ sessionId: "session-123" });

const preflight = await interceptor.beforeExecute("bash", { cmd: "echo hello" }, session);
if (!preflight.proceed) throw new Error("Blocked by policy");
```

### OpenClaw plugin

- Quick start: `packages/adapters/clawdstrike-openclaw/docs/getting-started.md`
- Integration guide: `docs/src/guides/openclaw-integration.md`

## Highlights

| Feature | Description |
| --- | --- |
| **Computer Use Gateway Controls** | Canonical CUA policy evaluation for click/type/scroll/key-chord and remote side-channel actions |
| **Provider Translation Layer** | Runtime translators for OpenAI/Claude/OpenClaw flows into a unified policy surface |
| **7 Built-in Guards** | Path, egress, secrets, patches, tools, prompt injection, jailbreak |
| **4-Layer Jailbreak Detection** | Heuristic + statistical + ML + optional LLM-as-judge with session aggregation |
| **Deterministic Decisions** | Stable `reason_code` + severity metadata for enforcement analytics and regression checks |
| **Fail-Closed Design** | Invalid policies reject at load time; evaluation errors deny access |
| **Signed Receipts** | Tamper-evident audit trail with Ed25519 signatures |
| **Output Sanitization** | Redact secrets/PII/internal data from model output with streaming support |
| **Prompt Watermarking** | Embed signed provenance markers for attribution and forensics |

## Performance

Guard checks add **<0.05ms** overhead per tool call. For context, typical LLM API calls take 500-2000ms.

| Operation | Latency | % of LLM call |
|-----------|---------|---------------|
| Single guard check | <0.001ms | <0.0001% |
| Full policy evaluation | ~0.04ms | ~0.004% |
| Jailbreak detection (heuristic+statistical) | ~0.03ms | ~0.003% |

No external API calls required for core detection. [Full benchmarks →](docs/src/reference/benchmarks.md)

## Documentation

- [Quick Start (Rust)](docs/src/getting-started/quick-start.md)
- [Quick Start (TypeScript)](docs/src/getting-started/quick-start-typescript.md)
- [Quick Start (Python)](docs/src/getting-started/quick-start-python.md)
- [OpenClaw Integration Guide](docs/src/guides/openclaw-integration.md)
- [Agent OpenClaw Operations Runbook](docs/src/guides/agent-openclaw-operations.md)
- [OpenClaw Gateway Testing Guide](apps/desktop/docs/openclaw-gateway-testing.md)
- [CUA Production Readiness Test Plan](production-readiness-test-plan.md)
- [CUA Roadmap Index](docs/roadmaps/cua/INDEX.md)
- [Design Philosophy](docs/src/concepts/design-philosophy.md)
- [Enforcement Tiers & Integration Contract](docs/src/concepts/enforcement-tiers.md)
- [Guards Reference](docs/src/reference/guards/README.md)
- [Policy Schema](docs/src/reference/policy-schema.md)
- [Repository Map](docs/REPO_MAP.md)
- [Documentation Map](docs/DOCS_MAP.md)

## Security

We take security seriously. If you discover a vulnerability:

- **For sensitive issues**: Email [connor@backbay.io](mailto:connor@backbay.io) with details. We aim to respond within 48 hours.
- **For non-sensitive issues**: Open a [GitHub issue](https://github.com/backbay-labs/clawdstrike/issues) with the `security` label.

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
cargo build && cargo test && cargo clippy
```

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
