<p align="center">
  <img src=".github/assets/clawdstrike-hero.png" alt="Clawdstrike" width="900" />
</p>

<p align="center">
  <a href="https://github.com/backbay-labs/clawdstrike/actions"><img src="https://img.shields.io/github/actions/workflow/status/backbay-labs/clawdstrike/ci.yml?branch=main&style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <a href="https://crates.io/crates/clawdstrike"><img src="https://img.shields.io/crates/v/clawdstrike?style=flat-square&logo=rust" alt="crates.io"></a>
  <a href="https://www.npmjs.com/package/@clawdstrike/sdk"><img src="https://img.shields.io/npm/v/@clawdstrike/sdk?style=flat-square&logo=npm&label=npm" alt="npm"></a>
  <a href="https://pypi.org/project/clawdstrike/"><img src="https://img.shields.io/pypi/v/clawdstrike?style=flat-square&logo=python&logoColor=white&label=PyPI" alt="PyPI"></a>
  <a href="https://docs.rs/clawdstrike"><img src="https://img.shields.io/docsrs/clawdstrike?style=flat-square&logo=docs.rs" alt="docs.rs"></a>
  <a href="https://github.com/backbay-labs/homebrew-tap/blob/main/Formula/clawdstrike.rb"><img src="https://img.shields.io/badge/homebrew-clawdstrike-FBB040?style=flat-square&logo=homebrew" alt="Homebrew"></a>
  <a href="https://crates.io/crates/clawdstrike"><img src="https://img.shields.io/crates/d/clawdstrike?style=flat-square&logo=rust&label=downloads" alt="crates.io downloads"></a>
  <a href="https://artifacthub.io/packages/search?repo=clawdstrike"><img src="https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/clawdstrike" alt="Artifact Hub"></a>
  <a href="https://discord.gg/clawdstrike"><img src="https://img.shields.io/badge/discord-join-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/MSRV-1.93-orange?style=flat-square&logo=rust" alt="MSRV: 1.93">
</p>

<p align="center">
  <em>
    The claw strikes back.<br/>
    At the boundary between intent and action,<br/>
    it watches what leaves, what changes, what leaks.<br/>
    Not "visibility." Not "telemetry." Not "vibes." Logs are stories; proof is a signature.<br/>
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
  <strong>EDR for the age of the swarm.</strong><br/>
  <em>Fail closed. Sign the truth.</em>
</p>

<p align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/sigils/boundary-dark.svg"><img src=".github/assets/sigils/boundary-light.svg" width="16" height="16" alt=""  style="vertical-align:-3px;" ></picture>&nbsp;Kernel to chain
   <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/sigils/seal-dark.svg"><img src=".github/assets/sigils/seal-light.svg" width="16" height="16" alt=""  style="vertical-align:-3px;" ></picture>&nbsp;Tool-boundary enforcement
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/sigils/plugin-dark.svg"><img src=".github/assets/sigils/plugin-light.svg" width="16" height="16" alt=""  style="vertical-align:-3px;" ></picture>&nbsp;Swarm-native security
</p>

<p align="center">
  <a href="#enforcement-stack">Enforcement Stack</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="https://backbay.io/attack-range">Attack Range</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="#off-grid-enforcement-plane-a-r">Off-Grid</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="#guard-stack">Guards</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="#enterprise-architecture">Enterprise</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="#quick-start">Quick Start</a>
</p>

---

> **Alpha software.** APIs and import paths may change between releases.

## Quick Start

### CLI

```bash
brew tap backbay-labs/tap
brew install clawdstrike

# Block access to sensitive paths
clawdstrike check --action-type file --ruleset strict ~/.ssh/id_rsa
# → BLOCKED [Critical]: Access to forbidden path: ~/.ssh/id_rsa

# Control network egress
clawdstrike check --action-type egress --ruleset strict api.openai.com:443
# → BLOCKED [Error]: Egress to api.openai.com blocked by policy

# Restrict MCP tool invocations
clawdstrike check --action-type mcp --ruleset strict shell_exec
# → BLOCKED [Error]: Tool 'shell_exec' is blocked by policy

# Show available rulesets
clawdstrike policy list

# Diff two policies
clawdstrike policy diff strict default
```

### TypeScript

```bash
npm install @clawdstrike/sdk
```

```typescript
import { Clawdstrike } from "@clawdstrike/sdk";

const cs = Clawdstrike.withDefaults("strict");
const decision = await cs.checkNetwork("api.openai.com:443");
console.log(decision.status); // "denied" - strict blocks all egress by default
```

### Python

```bash
pip install clawdstrike
```

```python
from clawdstrike import Clawdstrike

cs = Clawdstrike.with_defaults("strict")
decision = cs.check_file("/home/user/.ssh/id_rsa")
print(decision.denied)   # True
print(decision.message)  # "Access to forbidden path: ..."
```

### OpenClaw Plugin

Clawdstrike ships as a first-class [OpenClaw](https://openclaw.com) plugin that enforces policy at the tool boundary — every tool call your agent makes is checked against your policy before execution.

```bash
openclaw plugins install @clawdstrike/openclaw
openclaw plugins enable clawdstrike-security
```

[Configure the plugin](docs/src/guides/openclaw-integration.md#configuration) in your project's `openclaw.json`.

### Additional SDKs & Bindings

Framework adapters: [OpenAI](packages/adapters/clawdstrike-openai/README.md) · [Claude](packages/adapters/clawdstrike-claude/README.md) · [Vercel AI](docs/src/guides/vercel-ai-integration.md) · [LangChain](docs/src/guides/langchain-integration.md)

[C, Go, C#](docs/src/concepts/multi-language.md) via FFI · [WebAssembly](crates/libs/hush-wasm/README.md)

---

## The Problem

Google's 2026 Cybersecurity Forecast calls it the **"Shadow Agent" crisis**: employees and teams spinning up AI agents without corporate oversight, creating invisible pipelines that exfiltrate sensitive data, violate compliance, and leak IP. No one sanctioned them. No one is watching them. And your security stack wasn't built for this.

Your org provisioned 50 agents. Shadow IT spun up 50 more outside your asset inventory. One is exfiltrating `.env` secrets to an unclassified endpoint. Another is patching auth middleware with no peer review, no receipt, no rollback. A third just ran `chmod 777` against a production filesystem. Your SIEM shows green across the board because none of these actions generate the signals it was built to detect.

**Logs tell you what happened. Clawdstrike stops it before it happens.**

**Every decision is signed. Every receipt is non-repudiable. If it didn't get a signature, it didn't get permission.**

## What Clawdstrike Is

Clawdstrike is a **fail-closed policy engine and cryptographic attestation runtime** for autonomous AI agents. It sits at the tool boundary, the exact point where an agent's intent becomes a real-world action, and enforces security policy with signed proof. From a single SDK install to a fleet of thousands of managed agents, the same engine, the same receipts, the same guarantees.

Every action. Every agent. Every time. No exceptions.

```mermaid
flowchart LR
    A[Agent Swarm<br/>OpenAI / Claude / OpenClaw / LangChain] --> B[Clawdstrike Adapter]
    B --> C[Canonical Action Event]
    C --> D[Policy Engine<br/>+ Guard Stack]
    D -->|allow| E[Tool Execution]
    D -->|deny| F[Fail-Closed Block]
    D --> G[Ed25519 Signed Receipt]
    G -.->|enterprise| H[Spine Audit Trail]
    H -.-> I[Cloud API + Dashboard]
```

---

## Why This Matters

<table>
<tr>
<td width="50%">

### Without Clawdstrike

- Agent reads `~/.ssh/id_rsa`. You find out from the incident report
- Secret leaks into model output. Compliance discovers it 3 months later
- Jailbreak prompt bypasses safety. No one notices until the damage is public
- Multi-agent delegation escalates privileges. Who authorized what?
- "We have logging." Logs are stories anyone can rewrite

</td>
<td width="50%">

### With Clawdstrike

- `ForbiddenPathGuard` blocks the read, signs a receipt
- `OutputSanitizer` redacts the secret before it ever leaves the pipeline
- 4-layer jailbreak detection catches it across the session, even across multi-turn grooming attempts
- Delegation tokens with cryptographic capability ceilings. Privilege escalation is mathematically impossible
- Ed25519 signed receipts. Tamper-evident proof, not narratives

</td>
</tr>
</table>

---

## Core Capabilities

<p align="center">
  <a href="#guard-stack"><kbd>Guard Stack</kbd></a>&nbsp;&nbsp;
  <a href="#jailbreak-detection"><kbd>Jailbreak Detection</kbd></a>&nbsp;&nbsp;
  <a href="#cryptographic-receipts"><kbd>Receipts</kbd></a>&nbsp;&nbsp;
  <a href="#multi-agent-security-primitives"><kbd>Multi-Agent</kbd></a>&nbsp;&nbsp;
  <a href="#irm--output-sanitization--watermarking--threat-intel"><kbd>IRM · Sanitization · Watermarking · Threat Intel</kbd></a>&nbsp;&nbsp;
  <a href="#spider-sense"><kbd>Spider-Sense</kbd></a>&nbsp;&nbsp;
  <a href="#off-grid-enforcement-plane-a-r"><kbd>Off-Grid Enforcement</kbd></a>&nbsp;&nbsp;
  <a href="#deployment-modes"><kbd>Deployment Modes</kbd></a>&nbsp;&nbsp;
  <a href="#enterprise-architecture"><kbd>Enterprise</kbd></a>
</p>

### Guard Stack

Composable, policy-driven security checks at the tool boundary. Each guard handles a specific threat surface and returns a verdict with evidence. Fail-fast or aggregate, your call.

| Guard                    | What It Catches                                                                  |
| ------------------------ | -------------------------------------------------------------------------------- |
| **ForbiddenPathGuard**   | Blocks access to `.ssh`, `.env`, `.aws`, credential stores, registry hives       |
| **EgressAllowlistGuard** | Controls outbound network by domain. Deny-by-default or allowlist                |
| **SecretLeakGuard**      | Detects AWS keys, GitHub tokens, private keys, API secrets in file writes        |
| **PatchIntegrityGuard**  | Validates patch safety. Catches `rm -rf /`, `chmod 777`, `disable security`      |
| **McpToolGuard**         | Restricts which MCP tools agents can invoke, with confirmation gates             |
| **PromptInjectionGuard** | Detects injection attacks in untrusted input                                     |
| **JailbreakGuard**       | 4-layer detection engine with session aggregation (see below)                    |
| **ComputerUseGuard**     | Controls CUA actions: remote sessions, clipboard, input injection, file transfer |
| **ShellCommandGuard**    | Blocks dangerous shell commands before execution                                 |
| **SpiderSenseGuard**&nbsp;<sup>β</sup> | Hierarchical threat screening adapted from [Yu et al. 2026](https://arxiv.org/abs/2602.05386): fast vector similarity resolves known patterns, optional LLM escalation for ambiguous cases |

---

<h3 align="center">Jailbreak Detection</h3>

<a id="jailbreak-detection"></a>
<table>
<tr>
<td width="50%">
<img src="docs/static/jailbreak-intro.png" alt="4-Layer Jailbreak Detection" width="100%" />
</td>
<td width="50%" valign="top">

**~15ms total latency.** All four layers run in sequence without external API calls (unless you opt into the LLM judge). The ML layer is a configurable linear model with sigmoid activation — weights live in your YAML policy, not a black box.

**9 attack taxonomies.** Role-play, authority confusion, encoding attacks, hypothetical framing, adversarial suffixes, system impersonation, instruction extraction, multi-turn grooming, and payload splitting.

**Session aggregation** tracks cumulative risk across an entire conversation with a time-decaying rolling score (15-minute half-life). An attacker who spreads a jailbreak across 20 innocuous messages still triggers detection — their score rises until it crosses the threshold.

**Privacy-safe.** Raw input never appears in detection results. Only match spans and SHA-256 fingerprints are stored. Unicode NFKC normalization and zero-width character stripping happen before any pattern matching.

**[Try this out for yourself in our Attack Range!](https://backbay.io/attack-range)**

</td>
</tr>
</table>

---

### Cryptographic Receipts

Every policy decision produces an **Ed25519-signed receipt**: a tamper-evident attestation proving what was decided, under which policy, with what evidence. Portable across Rust, TypeScript, and Python via RFC 8785 canonical JSON.

```rust
// A receipt proves: "Under policy X, action Y was evaluated with verdict Z"
// Signed with Ed25519. Forge one and we'll be impressed
let receipt = engine.create_signed_receipt(content_hash).await?;
```

This isn't logging. This is **cryptographic proof** that holds up under audit.

---

### Multi-Agent Security Primitives

When agents spawn agents, who controls whom? Clawdstrike's multi-agent layer provides:

- **Agent Identity Registry.** Ed25519 public key identity with role-based trust levels (Untrusted through System)
- **Signed Delegation Tokens.** Cryptographically signed capability grants with time bounds, audience validation, and revocation
- **Capability Attenuation.** Agents delegate subsets of their capabilities, never escalate. Privilege escalation is structurally impossible
- **Delegation Chains.** Full provenance tracking through multi-hop delegation with chain validation
- **Replay Protection & Revocation.** Nonce-based replay prevention with configurable TTL, instant revocation via SQLite or in-memory stores
- **W3C Traceparent Correlation.** Cross-agent audit trails following the W3C trace context standard

---

<a id="irm--output-sanitization--watermarking--threat-intel"></a>
<table>
<tr>
<td width="50%" valign="top">
<h4 align="center">Inline Reference Monitors</h4>

Runtime interceptors between sandboxed modules and host calls. Every intercepted call produces an `IrmEvent` with a decision for complete behavioral audit.

```
Sandboxed Module
            │
IRM Router ─┬─ Filesystem Monitor
            ├─ Network Monitor
            └─ Execution Monitor
```

</td>
<td width="50%" valign="top">
<h4 align="center">Output Sanitization</h4>

Catches secrets that make it into model output on the way out. Scans for API keys, tokens, PII, internal URLs, and custom patterns. Redaction strategies: full replacement, partial masking, type labels, stable SHA-256 hashing. Batch and streaming modes.

The `Sanitize` decision verdict allows operations to proceed with modified content — guards can redact or rewrite dangerous payloads instead of outright blocking.

</td>
</tr>
<tr>
<td width="50%" valign="top">
<h4 align="center">Prompt Watermarking</h4>

Ed25519-signed provenance markers embedded in prompts for attribution and forensic tracing. Carries app ID, session ID, sequence number, and timestamp (RFC 8785). Survives model inference round-trips.

</td>
<td width="50%" valign="top">
<a id="spider-sense"></a>
<h4 align="center">Threat Intel · Spider-Sense · WASM</h4>

**Threat feeds:** VirusTotal, Snyk, Google Safe Browsing — with circuit breakers, rate limiting, and caching. External failures never block the pipeline.

**Spider-Sense** <sup>β</sup> adapts the hierarchical screening pattern from [Yu et al. (2026)](https://arxiv.org/abs/2602.05386) as a tool-boundary guard. Fast-path cosine similarity against an attack pattern database resolves known threats; ambiguous inputs optionally escalate to an external LLM for deeper analysis. Test coverage uses the paper's S2Bench taxonomy (4 lifecycle stages × 9 attack types). Note: the original paper proposes agent-intrinsic risk sensing — our adaptation applies the screening hierarchy as middleware, not as an intrinsic agent capability. Feature-gated: `--features clawdstrike-spider-sense`.

**WASM runtime:** Custom guards in sandboxed WebAssembly with declared capability sets and resource limits.

</td>
</tr>
</table>

---

<a id="off-grid-enforcement-plane-a-r"></a>

### Off-Grid Enforcement (Plane A-R)

Your revocation doesn't matter if it can't reach the node. Cut the fiber, jam the satellite uplink, airgap the facility. If your security plane requires the internet, you don't have a security plane. You have a suggestion.

For agents running local models in environments where the internet is a liability, not an assumption.

Clawdstrike's [Spine protocol](docs/specs/12-reticulum-adapter.md) carries the same Ed25519-signed envelopes over [Reticulum](https://reticulum.network/) mesh networks: LoRa radios, packet radio, serial lines, WiFi, TCP/UDP. Anything that can move 5 bits per second through a 500-byte aperture. The transport changes. The cryptographic proof doesn't.

| Environment | What Propagates | How |
|---|---|---|
| **SCIF / air-gapped facility** | Policy deltas, revocations, checkpoints | USB sneakernet with offline Merkle proof verification |
| **Disaster response / degraded infra** | Emergency revocations, incident facts | Ad-hoc LoRa mesh, store-and-forward via LXMF |
| **Hostile network / denied spectrum** | Signed revocations at priority 1 | Multi-hop Reticulum over any available carrier |
| **Remote IoT / edge** | Policy enforcement + attestation receipts | LoRa at 1,200 bps, 6+ km line-of-sight |

**Bandwidth-aware priority scheduling.** Seven tiers. Revocations always transmit first. Under 2 seconds on LoRa. Heartbeats drop when the link can't spare the bytes. A compromised signing key gets revoked across the mesh before the attacker finishes their coffee.

**[$98 reference gateway.](integrations/transports/reticulum/pi-gateway/)** Raspberry Pi 4 + RNode LoRa USB radio. Bridges the off-grid mesh to your NATS backbone. Disclosure policy controls what crosses the boundary. Hash-chained audit log records every envelope forwarded or dropped. 5 watts.

---

## Framework Adapters

Drop Clawdstrike into your existing agent stack. Every adapter normalizes framework-specific tool calls into canonical action events and routes them through the guard stack.

| Framework              | Package                  | Install                                                        |
| ---------------------- | ------------------------ | -------------------------------------------------------------- |
| **OpenAI Agents SDK**  | `@clawdstrike/openai`    | `npm install @clawdstrike/openai @clawdstrike/engine-local`    |
| **Claude / Agent SDK** | `@clawdstrike/claude`    | `npm install @clawdstrike/claude @clawdstrike/engine-local`    |
| **Vercel AI SDK**      | `@clawdstrike/vercel-ai` | `npm install @clawdstrike/vercel-ai @clawdstrike/engine-local` |
| **LangChain**          | `@clawdstrike/langchain` | `npm install @clawdstrike/langchain @clawdstrike/engine-local` |
| **OpenClaw**           | `@clawdstrike/openclaw`  | `openclaw plugins install @clawdstrike/openclaw`               |

```typescript
// 3 lines to secure any OpenAI agent
import { createStrikeCell } from "@clawdstrike/engine-local";
import {
  OpenAIToolBoundary,
  wrapOpenAIToolDispatcher,
} from "@clawdstrike/openai";

const secure = wrapOpenAIToolDispatcher(
  new OpenAIToolBoundary({ engine: createStrikeCell({ policyRef: "strict" }) }),
  yourToolDispatcher,
);
```

Additional language bindings (C, Go, C#) available via FFI. See [Multi-Language Support](docs/src/concepts/multi-language.md).

---

## Deployment Modes

Clawdstrike scales from a single developer's laptop to a fleet of thousands of managed agents. The same policy engine and receipt format work at every tier.

| Mode | How You Run It | Who It's For |
| ---- | -------------- | ------------ |
| **SDK** | `npm install @clawdstrike/sdk` or `pip install clawdstrike` | Individual devs, CI/CD pipelines |
| **Desktop Agent** | Tauri app with system tray, hushd daemon, local dashboard | Teams, workstation security |
| **Enterprise Fleet** | Cloud API + NATS + enrollment + cloud dashboard | Security teams managing org-wide agent fleets |

### Adaptive Engine

The `@clawdstrike/engine-adaptive` package bridges standalone and enterprise deployments. It wraps a local and remote engine behind the same `PolicyEngineLike` interface and automatically transitions between three modes:

```mermaid
stateDiagram-v2
    [*] --> standalone
    standalone --> connected : remote healthy
    connected --> degraded : remote fails
    degraded --> connected : remote recovers
```

- **Standalone** — local policy engine only. Zero network dependency.
- **Connected** — remote (enterprise) engine for centrally managed policy. Falls back to local on connectivity failure.
- **Degraded** — local engine with offline receipt queue. Queued receipts are drained and replayed when the remote recovers.

Every error path produces a **fail-closed deny**. The agent is never unprotected, regardless of network conditions.

---

## Enterprise Architecture

For organizations managing agent fleets across teams and environments, Clawdstrike provides a full enterprise control plane.

```mermaid
flowchart TB
    subgraph agents ["Agent Fleet"]
        A1[Desktop Agent 1]
        A2[Desktop Agent 2]
        AN[Desktop Agent N]
    end

    subgraph nats ["NATS JetStream"]
        KV[(Policy KV)]
        JS[(Telemetry Stream)]
        CMD[Command Subjects]
    end

    subgraph cloud ["Cloud Control Plane"]
        API[Cloud API]
        DB[(PostgreSQL)]
        DASH[Cloud Dashboard]
    end

    A1 & A2 & AN <-->|policy sync<br/>telemetry<br/>posture commands| nats
    nats <--> API
    API <--> DB
    DASH <--> API
```

### Enrollment

Agents bootstrap into enterprise management with a single enrollment token. No pre-shared keys, no manual certificate provisioning.

```bash
# From the cloud dashboard, generate an enrollment token for your tenant.
# On the agent machine:
curl -X POST http://localhost:9878/api/v1/enroll \
  -H "Content-Type: application/json" \
  -d '{"cloud_api_url": "https://api.clawdstrike.io", "enrollment_token": "cs_enroll_..."}'
```

The enrollment handshake:
1. Agent generates an Ed25519 keypair
2. Sends the public key + enrollment token to the cloud API
3. Cloud API validates the token, provisions NATS credentials, and returns connection details
4. Agent stores credentials and activates enterprise features on next restart
5. Enrollment token is invalidated after first use

### Spine — Tamper-Evident Audit Trail

Every policy evaluation produces a **Spine envelope**: an Ed25519-signed, hash-chained attestation record published to NATS JetStream.

```json
{
  "seq": 42,
  "prev_envelope_hash": "sha256:abc123...",
  "fact": { "type": "policy.eval", "decision": { "allowed": false }, ... },
  "signature": "ed25519:...",
  "envelope_hash": "sha256:def456..."
}
```

Hash chaining means tampering with any single record breaks the chain for every subsequent record. The cloud API's audit consumer verifies each envelope on ingestion, providing a cryptographically verifiable audit log across your entire fleet.

### Real-Time Fleet Management

All enterprise features run over NATS JetStream with scoped credentials per agent:

| Capability | Direction | Mechanism |
| ---------- | --------- | --------- |
| **Policy Sync** | Cloud → Agent | KV watch — policy updates propagate to agents in real time |
| **Telemetry** | Agent → Cloud | JetStream publish — heartbeats, eval receipts, agent metadata |
| **Posture Commands** | Cloud → Agent | NATS request/reply — `set_posture`, `request_policy_reload` |
| **Kill Switch** | Cloud → Agent | Immediate posture lock to deny-all + daemon restart |
| **Approval Escalation** | Agent → Cloud → Agent | High-risk actions escalated for human review via cloud dashboard |

### Kill Switch

When a compromised agent is detected, a single command from the cloud dashboard:
1. Sets the agent's posture to `locked` (deny-all for every policy evaluation)
2. Restarts the enforcement daemon with the locked posture
3. Reports status back to the operator

The agent is locked down before the next tool invocation fires, regardless of what code is running.

### Cloud Dashboard

Web UI for security teams to manage their agent fleet:
- Real-time agent status, heartbeats, and enrollment state
- Pending approval queue for high-risk actions escalated by agents
- Policy management and distribution
- Compliance reporting and audit log viewer
- Alert management and stale agent detection

See [Enterprise Enrollment Guide](docs/src/guides/enterprise-enrollment.md) and [Adaptive Deployment Guide](docs/src/guides/adaptive-deployment.md) for detailed setup instructions.

### Compliance Templates

Every guard decision maps to a regulatory control. Templates ship with pre-built evidence collectors, guard-to-control mappings, and exportable evidence bundles for auditors.

| Framework | What Clawdstrike Proves | Key Controls |
|---|---|---|
| **HIPAA** | PHI never left the allowed path. Signed receipts for every access decision. Breach forensics from session reconstruction, not guesswork | 164.312(a)(1) Access Control · 164.312(b) Audit · 164.312(e)(1) Transmission Security |
| **PCI-DSS v4.0** | Cardholder data stayed in scope. Egress locked to the CDE. Secrets masked before they hit the model | 1.4.1 Network Segmentation · 3.5.1 PAN Masking · 7.2.1 Access Control · 10.2.1 Audit Trail |
| **SOC2 Type II** | Continuous control evidence across a 6-12 month observation window. Guard verdicts feed directly into CC6/CC7/CC8 criteria with zero manual evidence collection | CC6.1 Logical Access · CC6.6 Network Boundaries · CC7.2 Security Anomalies · CC8.1 Change Management |

**Certification tiers:** Certified (OSS baseline) → Silver (egress lockdown, secret redaction, 90-day retention) → Gold (compliance templates, external auditor attestation, 1-year retention) → Platinum (multi-framework, 7-year archive, real-time SIEM, 99.9% SLA).

See [Certification Program](docs/plans/certification/overview.md) · [HIPAA Template](docs/plans/certification/hipaa-template.md) · [PCI-DSS Template](docs/plans/certification/pci-dss-template.md) · [SOC2 Template](docs/plans/certification/soc2-template.md)

---

## Policy System

Declarative YAML policies with inheritance, composable guards, and built-in rulesets.

```yaml
# policy.yaml - inherit strict defaults, override what you need
version: "1.1.0"
extends: strict

guards:
  egress_allowlist:
    allow:
      - "api.openai.com"
      - "api.anthropic.com"
      - "api.github.com"
    default_action: block

  jailbreak:
    enabled: true
    detector:
      block_threshold: 40 # aggressive - catch even suspicious prompts
      session_aggregation: true # track risk across the conversation

settings:
  fail_fast: true
```

**Built-in rulesets:** `permissive` | `default` | `strict` | `ai-agent` | `ai-agent-posture` | `cicd` | `remote-desktop` | `remote-desktop-permissive` | `remote-desktop-strict`

Policies support inheritance via `extends`: local files, remote URLs, and git refs.

---

## Computer Use Gateway

Full CUA policy enforcement for agents operating remote desktop surfaces:

- **Canonical action translation** across OpenAI, Claude, and OpenClaw CUA providers
- **Side-channel controls** for clipboard, audio, drive mapping, printing, session sharing, file transfer bounds
- **Deterministic decision metadata** with stable `reason_code` + severity for machine-checkable analytics
- **Three enforcement modes:** Observe (log only), Guardrail (warn on unknown), Fail-Closed (deny on unknown)

---

## Enforcement Stack

Six layers. Kernel to chain. Every layer signs its work.

| Layer | What | How |
|---|---|---|
| **L0 — Identity** | Workload identity binding | [SPIRE/SPIFFE](docs/specs/06-spire-identity-binding.md) X.509 SVIDs, automated rotation, bound to Spine Ed25519 issuers |
| **L1 — Kernel** | Syscall-level runtime visibility | [Tetragon](crates/bridges/tetragon-bridge/) eBPF kprobes + LSM hooks — process ancestry, file integrity (IMA), capability enforcement |
| **L2 — Network** | Identity-based L7 segmentation | [Cilium/Hubble](crates/bridges/hubble-bridge/) CNI with WireGuard encryption, FQDN egress control, flow-level audit |
| **L3 — Agent** | Tool-boundary policy enforcement | Guard stack + cryptographic receipts + delegation tokens with capability ceilings |
| **L4 — Attestation** | Tamper-evident proof chain | [AegisNet](docs/specs/13-eas-onchain-anchoring.md) Merkle tree (RFC 6962), witness co-signatures, on-chain anchoring via EAS on Base L2 |
| **L5 — Transport** | Multi-plane envelope distribution | NATS JetStream (datacenter) · libp2p gossipsub (P2P) · [Reticulum mesh](integrations/transports/reticulum/) (off-grid) · WireGuard overlay (enclaves) |

Every layer produces signed facts that feed into the same append-only Spine protocol. An attestation for a file write carries the process ancestry from Tetragon, the SPIFFE ID from SPIRE, the network policy from Cilium, the guard verdict from Clawdstrike, and a Merkle inclusion proof from AegisNet — in one envelope, verified with one signature check.

---

## Design Principles

**Fail closed.** Invalid policies reject at load time. Evaluation errors deny access. Missing config defaults to restrictive. Security degradation requires explicit, auditable action.

**Proof, not logs.** Ed25519 receipts are cryptographic attestations, not log lines someone can edit. Canonical JSON (RFC 8785) ensures signatures verify identically in Rust, TypeScript, and Python.

**Same envelope, any pipe.** A signed Spine envelope is byte-identical whether it travels over NATS at 100K msg/sec, libp2p gossipsub over residential internet, or a LoRa radio at 1,200 bps. The transport is invisible to the truth layer.

**Attenuation only.** Agents delegate subsets of their capabilities, never escalate. Delegation tokens carry cryptographic capability ceilings. Privilege escalation isn't prevented by policy; it's prevented by math.

**Own your stack.** Apache-2.0. Self-hostable. No vendor dependency for security-critical infrastructure. The same engine runs on a developer laptop, an enterprise fleet, and a Raspberry Pi on a radio mesh.

---

## Documentation

| Category             | Links                                                                                                                                                                                                                                                                                                                 |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Getting Started**  | [Rust](docs/src/getting-started/quick-start.md) &middot; [TypeScript](docs/src/getting-started/quick-start-typescript.md) &middot; [Python](docs/src/getting-started/quick-start-python.md)                                                                                                                           |
| **Concepts**         | [Design Philosophy](docs/src/concepts/design-philosophy.md) &middot; [Enforcement Tiers](docs/src/concepts/enforcement-tiers.md) &middot; [Multi-Language](docs/src/concepts/multi-language.md)                                                                                                                       |
| **Framework Guides** | [OpenAI](packages/adapters/clawdstrike-openai/README.md) &middot; [Claude](packages/adapters/clawdstrike-claude/README.md) &middot; [Vercel AI](docs/src/guides/vercel-ai-integration.md) &middot; [LangChain](docs/src/guides/langchain-integration.md) &middot; [OpenClaw](docs/src/guides/openclaw-integration.md) |
| **Reference**        | [Guards](docs/src/reference/guards/README.md) &middot; [Policy Schema](docs/src/reference/policy-schema.md) &middot; [Repo Map](docs/REPO_MAP.md)                                                                                                                                                                     |
| **Enterprise**       | [Enrollment Guide](docs/src/guides/enterprise-enrollment.md) &middot; [Adaptive Deployment](docs/src/guides/adaptive-deployment.md) &middot; [Adaptive Architecture](docs/src/concepts/adaptive-architecture.md)                                                                                                       |
| **Operations**       | [OpenClaw Runbook](docs/src/guides/agent-openclaw-operations.md) &middot; [CUA Gateway Testing](apps/desktop/docs/openclaw-gateway-testing.md) &middot; [CUA Roadmap](docs/roadmaps/cua/INDEX.md)                                                                                                                     |

## Security

If you discover a vulnerability:

- **Sensitive issues**: Email [connor@backbay.io](mailto:connor@backbay.io). We respond within 48 hours.
- **Non-sensitive issues**: Open a [GitHub issue](https://github.com/backbay-labs/clawdstrike/issues) with the `security` label.

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
cargo fmt --all && cargo clippy --workspace -- -D warnings && cargo test --workspace
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
