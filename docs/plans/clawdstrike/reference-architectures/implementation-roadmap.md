# Implementation Roadmap (Reference Architectures)

This document translates the reference architecture specs in `docs/plans/clawdstrike/reference-architectures/` into an implementation roadmap for this repository (Clawdstrike + Hush).

Source specs (imported as requirements):
- `overview.md`
- `secure-coding-assistant.md`
- `autonomous-sandbox.md`
- `multi-agent-orchestration.md`
- `enterprise-deployment.md`
- `cloud-native.md`
- `build-your-own-edr.md`

## Repo status (implemented artifacts)

Reference implementations and deployment kits added in-tree:

- Secure coding assistant demo: `examples/secure-coding-assistant/`
- Autonomous sandbox (IRM wrapper) demo: `examples/autonomous-sandbox/`
- Multi-agent primitives demo: `examples/multi-agent-orchestration/`
- Enterprise signed policy bundle rollout: `examples/enterprise-deployment/`
- EDR-style detect/triage loop using `hushd`: `examples/edr-pipeline/`
- Kubernetes/Kustomize deployment for `hushd`: `deploy/kubernetes/hushd/`

## Sync rules (to avoid worktree drift)

- Treat `docs/plans/implementation-pad.md` as the canonical execution scratchpad; this document maps *architectures → deliverables/workstreams*.
- Prefer additive changes in new `examples/<arch>/` and `deploy/<arch>/` folders to minimize merge conflicts with other worktrees.
- Follow accepted ADRs in `docs/plans/decisions/` (CLI naming, policy schema convergence, canonical `PolicyEvent`).
- Any new telemetry/audit format should be validated against `fixtures/policy-events/v1/` and kept compatible across Rust + TypeScript.

## Current repo building blocks (quick inventory)

| Capability | Status | Where |
|---|---:|---|
| Guard-centric policy schema (`version: "1.1.0"`) + merge/extends | ✅ | `crates/clawdstrike/src/policy.rs`, `rulesets/*.yaml` |
| Tool-boundary policy evaluation (`HushEngine`) | ✅ | `crates/clawdstrike/src/engine.rs` |
| Built-in guards (path/egress/secrets/patch/mcp/prompt/jailbreak) | ✅ | `crates/clawdstrike/src/guards/`, `crates/clawdstrike/src/jailbreak.rs` |
| Signed receipts + cryptographic primitives | ✅ | `crates/hush-core/src/receipt.rs`, `crates/hush-core/src/signing.rs` |
| IRM router + sandbox wrapper (policy for host-calls) | ✅ (policy-only) | `crates/clawdstrike/src/irm/` |
| Central HTTP daemon for checks/audit (`hushd`) | 🟡 (WIP) | `crates/hushd/` |
| TS adapters + framework integrations | ✅ | `packages/clawdstrike-*/` |
| Agentic EDR-style example loop (simulated) | ✅ | `examples/bb-edr/` |
| Deployment packaging (systemd/launchd + docker image) | 🟡 | `deploy/`, `Dockerfile.hushd`, `examples/docker-compose/` |

> NOTE: Several reference architectures describe “sandboxing”. Clawdstrike’s core principle is *tool-boundary enforcement* (not an OS sandbox). The roadmap treats OS-level isolation (containers, K8s, cgroups) as *deployment scaffolding* around Clawdstrike, not a new core guarantee.

## Cross-cutting deliverables (shared dependencies)

These show up in 3+ architectures and should be treated as platform workstreams:

1. **Audit/telemetry sink interface**
   - Targets: JSONL/stdout, webhook, OTLP, Splunk HEC, Elastic, Kafka/NATS.
   - Repo landing zone: `crates/hushd/` (server-side sinks) + `packages/clawdstrike-adapter-core/` (client-side logger interface).
2. **Canonical event model parity**
   - Keep Rust + TS decisions identical on the same `PolicyEvent` corpus.
   - Expand fixtures in `fixtures/policy-events/v1/` and add cross-SDK parity tests.
3. **Policy distribution + versioning**
   - Git-backed policy repo + compilation (inheritance + overlays) + signed policy bundles.
   - Likely implemented as: `hushd` endpoints + a “policy distributor” service/tooling.
4. **Identity, capabilities, and approvals**
   - Needed for multi-agent + enterprise rollout (RBAC), and for “dangerous tool” gating.
5. **Deployment kits**
   - Docker-compose and Kubernetes manifests/Helm charts for `hushd` + optional proxy sidecars.

## Milestone map (aligns with `docs/plans/implementation-pad.md`)

Use these milestones as the “spine”; each reference architecture becomes an “integration slice” on top.

### M0 — Reference architecture kits (docs + examples)

- Create/refresh `examples/<arch>/` skeletons for each architecture with:
  - policy template(s) (`rulesets/`-compatible)
  - minimal runnable demo (Rust/TS/Python) that emits audit events
  - README with “what this is / what this isn’t” boundaries

### M1 — Foundation required by most architectures

- Audit sink interface + at least: JSONL, webhook, OTLP (logs), Splunk HEC.
- First-class “policy bundle” artifact (compiled + signed) with versioning semantics.
- `hushd` stabilization for “central evaluation + central audit” mode (API stability + auth story).

### M2 — Multi-agent + capability model baseline

- Agent identity attestation + delegation tokens + audit correlation (per `docs/plans/multi-agent/*`).
- Capability model enforced consistently:
  - at tool dispatcher hooks (TS adapters)
  - at `hushd` request boundaries
  - in IRM host-call evaluation (Rust)

### M3 — Enterprise + cloud-native + EDR expansions

- Enterprise policy governance: overlays (SOC2/HIPAA/GDPR), regional scoping, exceptions workflow.
- SIEM/SOAR exports (Elastic + Kafka) + compliance reporting outputs.
- Kubernetes packaging: charts/manifests; optional operator/webhook if justified.
- EDR pipeline: streaming collector + rule engine + enrichment + dashboards (reference implementation).

## Architecture roadmaps (deliverables + dependencies)

### 1) Secure Coding Assistant

**Goal:** ship a “secure-by-default” integration path for local coding assistants (Claude Code/Codex/OpenClaw/etc).

**Already in repo:** tool-boundary guards + output sanitization + multiple Node adapters.

**Gaps to close (roadmap):**
- Publish a *canonical* “coding assistant” policy template and keep it in lockstep with Rust `rulesets/ai-agent.yaml`.
- Add “developer workflow” kits:
  - pre-commit secret scanning (policy-driven)
  - CI job templates (policy lint/test + audit upload)
  - optional local `hushd` mode for centralized checks on the workstation
- IDE/editor integration should be treated as optional: ship a reference extension only if it materially improves adoption.

**Deliverables:**
- `examples/secure-coding-assistant/` (policy + hooks + CI templates + demo).
- Doc cross-links into `docs/src/getting-started/*` once stabilized.

**Depends on:** M1 (audit sinks) for “team rollout” and central audit collection.

### 2) Autonomous Sandbox (deployment scaffolding + IRM)

**Goal:** provide a reference pattern for running autonomous agents in isolated compute (container/WASM), with Clawdstrike providing *policy + audit* at the tool boundary and IRM host-call boundary.

**Already in repo:** IRM router + `Sandbox` wrapper (`crates/clawdstrike/src/irm/sandbox.rs`).

**Gaps to close (roadmap):**
- Define a first-class “capability template” model for sandboxes (read/write/net/exec/secret/tool) and enforce it via policy.
- Provide an orchestrator reference:
  - creates workspaces
  - provisions policy + run IDs
  - collects audit events
  - applies TTL/GC
- Provide container/K8s scaffolding, but keep it outside the “core guarantees” (document clearly).

**Deliverables:**
- `examples/autonomous-sandbox/` (local runner).
- `deploy/autonomous-sandbox/kubernetes/` (optional).

**Depends on:** M1 (audit sinks), M2 (capabilities).

### 3) Multi-Agent Orchestration

**Goal:** secure agent-to-agent coordination (prevent confused deputy, replay, privilege escalation) with end-to-end audit correlation.

**Canonical spec in this repo:** `docs/plans/multi-agent/*` (treat as source of truth; this reference architecture is a deployment view).

**Gaps to close (roadmap):**
- Implement identity attestation + delegation tokens + coordination protocol enforcement.
- Add message-signing and deterministic serialization rules.
- Provide a reference “orchestrator” service (can start as a library) that:
  - issues identities/tokens
  - validates task handoffs
  - emits correlated audit trails

**Deliverables:**
- `crates/` or `packages/` module(s) for identity/tokens (exact split decided by M2 design).
- `examples/multi-agent-orchestration/` showing 2–4 agent roles with different trust levels.

**Depends on:** M2 (identity/capabilities).

### 4) Build Your Own EDR (agent-boundary EDR)

**Goal:** a reference implementation that turns Clawdstrike audit into an EDR-like pipeline (detect/triage/respond) suitable for SIEM ingestion.

**Already in repo:** `examples/bb-edr/` demonstrates simulated detect/triage/respond.

**Gaps to close (roadmap):**
- Standardize an “agent telemetry” event envelope (agent_id, session_id, run_id, policy_version, decision, evidence).
- Provide exporters to Kafka/NATS + Elastic-friendly JSON.
- Provide a simple “stream processor” reference:
  - sessionization + correlation
  - rule evaluation (YARA-style or JSON rules) + enrichment hooks
  - response hooks (webhook, issue creation, policy update suggestion)

**Deliverables:**
- `examples/edr-pipeline/` (docker-compose with broker + processor + sink).
- Rule format + starter rules (align with `docs/plans/threat-intel/*`).

**Depends on:** M1 (audit sinks), M3 (SIEM exports).

### 5) Enterprise Deployment

**Goal:** centralized governance + distributed enforcement with compliance overlays and SIEM/SOAR integration.

**Already in repo:** policy merge/extends; `hushd` has auth scaffolding and a place to centralize evaluation.

**Gaps to close (roadmap):**
- Git-backed policy distribution (compile overlays, sign bundles, push to regions).
- Exception workflow (expiring approvals) and audit of exceptions.
- SIEM sinks (Splunk/Elastic/Kafka) + compliance reporting exports (SOC2/HIPAA/GDPR mappings).

**Deliverables:**
- `deploy/enterprise/` (reference topology + runbooks + threat model).
- `hushd` endpoints for policy bundle distribution + audit export.

**Depends on:** M1 (policy bundle + sinks), M3 (enterprise expansions).

### 6) Cloud-Native Deployment

**Goal:** make `hushd` and related components easy to run in Kubernetes/serverless environments with cloud-native observability.

**Already in repo:** container build (`Dockerfile.hushd`) + proxy utilities (`crates/hush-proxy/`).

**Gaps to close (roadmap):**
- Helm chart + manifests for `hushd` (TLS, auth, config, persistence).
- Sidecar patterns:
  - `hushd` as local policy evaluator + audit forwarder
  - optional egress proxy sidecar using `hush-proxy`
- Observability:
  - Prometheus metrics
  - OTLP trace/log export
- Operator/webhook is optional: only build if it significantly improves adoption vs Helm + Kustomize.

**Deliverables:**
- `deploy/kubernetes/hushd/` (Helm or Kustomize).
- `examples/cloud-native/` (kind/minikube walkthrough).

**Depends on:** M1 (audit sinks), M3 (K8s packaging).

## Open decisions / risks (call out early)

1. **Where evaluation runs (TS in-process vs `hushd`)**
   - Reference architectures assume both patterns; the roadmap should keep them interoperable via the canonical event model.
2. **“Sandbox” semantics**
   - Keep OS isolation as deployment scaffolding; do not blur Clawdstrike’s threat model claims.
3. **Event volume + storage**
   - EDR + enterprise deployments require retention, aggregation, and backpressure strategy (do not default to “log everything forever”).
