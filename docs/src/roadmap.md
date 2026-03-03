# Implementation Roadmap

**Last updated:** 2026-02-27
**Status:** Living document

---

## Current State

Clawdstrike is a fail-closed policy engine and cryptographic attestation runtime for autonomous AI agents. It sits at the tool boundary — the point where an agent's intent becomes a real-world action — and enforces security policy with signed proof. Here is what ships today.

### Core Engine (Rust)

| Component | Crate | Status |
|-----------|-------|--------|
| Cryptographic primitives (Ed25519, SHA-256, Keccak-256, Merkle trees, RFC 8785 canonical JSON) | `hush-core` | Stable |
| Policy engine, guard pipeline, receipt signing | `clawdstrike` | Stable (v0.1.3) |
| Signed envelopes, checkpoints, NATS transport, Merkle proofs | `spine` | Stable |
| CLI binary (`clawdstrike`, `hush` commands) | `hush-cli` | Stable |
| Spine protocol CLI tools | `spine-cli` | Stable |
| HTTP enforcement daemon (RBAC, multi-tenant auth, rate limiting, SIEM, TLS) | `hushd` | Beta |
| Control API service (auth, models, routes, services) | `control-api` | Alpha |
| EAS on-chain anchoring (Base L2) | `eas-anchor` | Experimental |
| Tetragon eBPF bridge | `tetragon-bridge` | Experimental |
| Cilium Hubble bridge | `hubble-bridge` | Experimental |
| WebAssembly bindings | `hush-wasm` | Stable |
| C ABI FFI (C, Go, C#) | `hush-ffi` | Stable |
| Compliance templates (HIPAA, PCI-DSS, SOC2) | `hush-certification` | Stable |
| Multi-agent orchestration (delegation, attenuation, revocation) | `hush-multi-agent` | Stable |
| Network proxy utilities | `hush-proxy` | Stable |
| Native Python extension | `hush-native` | Stable |

### Guard Stack (12 Built-in Guards)

| Guard | Threat Surface |
|-------|---------------|
| ForbiddenPathGuard | Blocks `.ssh`, `.env`, `.aws`, credential stores |
| PathAllowlistGuard | Allowlist-based filesystem access control |
| EgressAllowlistGuard | Domain-level outbound network control |
| SecretLeakGuard | Detects API keys, tokens, private keys in file writes |
| PatchIntegrityGuard | Catches `rm -rf /`, `chmod 777`, security disablement |
| ShellCommandGuard | Blocks dangerous shell commands pre-execution |
| McpToolGuard | Restricts MCP tool invocations with confirmation gates |
| PromptInjectionGuard | Detects injection attacks in untrusted input |
| JailbreakGuard | 4-layer detection (heuristic + statistical + ML + optional LLM judge) |
| ComputerUseGuard | Controls CUA actions for remote desktop sessions |
| RemoteDesktopSideChannelGuard | Clipboard, audio, drive mapping, file transfer controls |
| InputInjectionCapabilityGuard | Restricts input injection in CUA environments |

**SpiderSenseGuard** (beta): Hierarchical threat screening adapted from Yu et al. 2026 — fast vector similarity for known patterns, optional LLM escalation for ambiguous cases. Feature-gated: `--features clawdstrike-spider-sense`.

### Policy System

- **Schema:** v1.2.0 (backward-compatible with v1.1.0)
- **Inheritance:** `extends` with local files, remote URLs, git refs
- **Built-in rulesets (9):** `permissive`, `default`, `strict`, `ai-agent`, `ai-agent-posture`, `cicd`, `remote-desktop`, `remote-desktop-permissive`, `remote-desktop-strict`
- **Dynamic postures:** Named security states with capability budgets, event-driven transitions, time-based escalation
- **Observe-Synth-Tighten:** Record agent activity, synthesize least-privilege policy candidates

### SDK & Integrations

| Platform | Package | Status |
|----------|---------|--------|
| TypeScript SDK | `@clawdstrike/sdk` (200+ exports) | Stable |
| Python SDK | `clawdstrike` (v0.2.0 with native backend) | Stable |
| Canonical policy engine (TS) | `@clawdstrike/policy` | Stable |
| Adapter core interface | `@clawdstrike/adapter-core` | Stable |
| OpenAI Agents SDK adapter | `@clawdstrike/openai` | Stable |
| Claude / Agent SDK adapter | `@clawdstrike/claude` | Stable |
| Vercel AI SDK adapter | `@clawdstrike/vercel-ai` | Stable |
| LangChain adapter | `@clawdstrike/langchain` | Stable |
| OpenClaw plugin | `@clawdstrike/openclaw` | Stable |
| OpenCode adapter | `@clawdstrike/opencode` | Stable |
| CLI engine bridge | `@clawdstrike/hush-cli-engine` | Stable |
| hushd engine bridge | `@clawdstrike/hushd-engine` | Stable |
| Adaptive engine | `@clawdstrike/engine-adaptive` | Stable |
| WebAssembly | `hush-wasm` | Stable |
| FFI (C, Go, C#) | `hush-ffi` | Stable |

### Enterprise & Deployment

- **Desktop Agent:** Tauri app with system tray, local hushd daemon, local dashboard
- **Control Plane:** Control API + NATS JetStream + enrollment + control console
- **Enrollment:** Single-token bootstrap, Ed25519 keypair generation, NATS credential provisioning
- **Spine Audit Trail:** Hash-chained, Ed25519-signed envelopes over NATS JetStream
- **Fleet Management:** Real-time policy sync, telemetry, posture commands, kill switch, approval escalation
- **SIEM Integrations:** Datadog, Elastic, Splunk, Sumo Logic, PagerDuty/Opsgenie, Slack/Teams, STIX/TAXII
- **Compliance:** HIPAA, PCI-DSS v4.0, SOC2 Type II templates with evidence bundles

### Enforcement Stack (6 Layers)

| Layer | What | How |
|-------|------|-----|
| L0 - Identity | Workload identity binding | SPIRE/SPIFFE X.509 SVIDs |
| L1 - Kernel | Syscall-level runtime visibility | Tetragon eBPF kprobes + LSM hooks |
| L2 - Network | Identity-based L7 segmentation | Cilium/Hubble CNI + WireGuard |
| L3 - Agent | Tool-boundary policy enforcement | Guard stack + receipts + delegation tokens |
| L4 - Attestation | Tamper-evident proof chain | AegisNet Merkle tree, EAS on-chain anchoring |
| L5 - Transport | Multi-plane envelope distribution | NATS, libp2p gossipsub, Reticulum mesh, WireGuard |

### Off-Grid Enforcement

- **Reticulum mesh transport:** Same Ed25519 envelopes over LoRa, packet radio, serial, WiFi
- **$98 reference gateway:** Raspberry Pi 4 + RNode LoRa USB radio
- **Bandwidth-aware priority scheduling:** 7 tiers, revocations first, <2s on LoRa
- **Air-gapped operation:** USB sneakernet with offline Merkle proof verification

---

## Vision

Clawdstrike evolves from a standalone policy engine into an **ecosystem platform** — a place where the security community builds, shares, and composes guards, policies, and compliance packs for AI agent security. The trajectory:

```text
Standalone Engine ──> Package Manager ──> Registry ──> Ecosystem Platform
     (today)         (local packages)    (shared)      (community + enterprise)
```

**Core thesis:** The guard stack should be as extensible as a package registry. Security teams should install a HIPAA compliance pack the same way they install an npm package. Community researchers should publish novel detection guards and have them deployed across thousands of agent fleets within hours, not months.

**Non-negotiable invariants as the platform scales:**
1. **Fail closed.** Every new abstraction layer defaults to deny.
2. **Proof, not logs.** Community guards produce the same Ed25519 receipts as built-in guards.
3. **Same envelope, any pipe.** Package metadata and guard decisions travel over the same Spine protocol.
4. **Attenuation only.** Third-party guards receive capability subsets, never escalate.
5. **Own your stack.** Apache-2.0. Self-hostable. No vendor lock-in.

---

## Package Manager Roadmap

The package manager is the highest-priority initiative. It transforms Clawdstrike from a closed set of 12 built-in guards into an open ecosystem where anyone can publish guards, policies, and compliance packs.

### Phase 0: Local Packages (4-6 weeks)

**Goal:** Users can package guards and policies into `.cpkg` archives and install them locally. The engine loads them at startup.

```text
Developer writes guard
        |
        v
  clawdstrike-pkg.toml    <-- manifest
        |
        v
  clawdstrike pkg pack     <-- produces .cpkg archive
        |
        v
  ~/.clawdstrike/packages/ <-- local package store
        |
        v
  Engine discovers & loads  <-- CustomGuardRegistry + PolicyResolver
```

**Deliverables:**

| Deliverable | Description |
|-------------|-------------|
| `clawdstrike-pkg.toml` manifest spec | Package metadata: name, version, authors, guard entry points, policy files, dependencies, capability requirements |
| `.cpkg` archive format | Deterministic tar+zstd archive with embedded SHA-256 content hashes |
| `clawdstrike pkg pack` | CLI command to produce `.cpkg` from a project directory |
| `clawdstrike pkg install <path>` | Install a `.cpkg` into the local package store |
| `clawdstrike pkg list` | List installed packages with versions and capabilities |
| `CustomGuardRegistry` loader | Discovers and loads guard implementations from installed packages |
| `PolicyResolver` extension | Resolves `extends: pkg:<name>/<policy>` references to installed package policies |

**Manifest example:**

```toml
[package]
name = "hipaa-guards"
version = "0.1.0"
description = "HIPAA compliance guards for healthcare AI agents"
authors = ["Security Team <security@example.com>"]
license = "Apache-2.0"

[guards]
phi-access = { entry = "src/phi_access.wasm", capabilities = ["fs:read"] }
phi-egress = { entry = "src/phi_egress.wasm", capabilities = ["net:check"] }

[policies]
hipaa-strict = "policies/hipaa-strict.yaml"
hipaa-default = "policies/hipaa-default.yaml"

[dependencies]
clawdstrike-guard-sdk = "0.1"
```

**Exit criteria:** A user can build a custom guard package, install it locally, and reference its policies via `extends: pkg:hipaa-guards/hipaa-strict` in their policy YAML.

---

### Phase 1: WASM Guard Runtime (4-6 weeks)

**Goal:** Third-party guards execute in sandboxed WebAssembly with declared capabilities and resource limits. No native code execution from community packages.

```text
.cpkg contains .wasm guard
        |
        v
  WasmGuardFactory validates capabilities
        |
        v
  wasmtime sandbox with:
    - memory limit (configurable, default 16 MB)
    - fuel metering (CPU budget)
    - capability-gated host imports
        |
        v
  WasmGuard implements Guard trait
        |
        v
  Same verdict/receipt pipeline as built-in guards
```

**Deliverables:**

| Deliverable | Description |
|-------------|-------------|
| Guest ABI specification | Stable ABI contract between host and WASM guest: `check(action) -> verdict` |
| `clawdstrike-guard-sdk` crate | Rust SDK for writing guards that compile to WASM. Provides `#[clawdstrike_guard]` proc macro |
| `WasmGuard` / `WasmGuardFactory` | Host-side runtime that loads `.wasm` modules, enforces capabilities, and translates verdicts |
| Capability model | Declared capabilities (`fs:read`, `net:check`, `env:read`) validated at install time, enforced at runtime |
| Resource limits | Per-guard memory ceiling, fuel metering, wall-clock timeout |
| Guard SDK templates | `cargo generate` templates for common guard patterns (path-based, regex-based, ML-based) |
| Guard testing harness | `clawdstrike pkg test` runs guard against fixture actions, validates verdicts and receipt generation |

**Capability model:**

```text
+------------------+-------------------------------------------+
| Capability       | Host Import Granted                       |
+------------------+-------------------------------------------+
| fs:read          | read_file(path) -> bytes                  |
| fs:metadata      | file_metadata(path) -> stat               |
| net:check        | check_dns(domain) -> resolved             |
| env:read         | read_env(key) -> value                    |
| crypto:verify    | verify_signature(key, data, sig) -> bool  |
| (none declared)  | Only action context + verdict response    |
+------------------+-------------------------------------------+
```

**Exit criteria:** A community developer can write a guard in Rust, compile to WASM, package it, and have it execute in the sandboxed runtime with the same receipt guarantees as a built-in guard.

---

### Phase 2: Registry MVP (6-8 weeks)

**Goal:** A public package registry where authors publish guards and policies, and users install them with dependency resolution.

```text
Author                          Registry                        User
  |                                |                              |
  |  clawdstrike pkg publish       |                              |
  |------------------------------->|                              |
  |  .cpkg + signature + metadata  |                              |
  |                                |  sparse index update         |
  |                                |                              |
  |                                |   clawdstrike pkg install    |
  |                                |<-----------------------------|
  |                                |  resolve deps (pubgrub)      |
  |                                |  download .cpkg from registry blob storage |
  |                                |  verify signatures           |
  |                                |----------------------------->|
  |                                |  write lockfile              |
```

**Deliverables:**

| Deliverable | Description |
|-------------|-------------|
| Sparse index | HTTP sparse index endpoint (`GET /api/v1/index/{name}`) with ETag revalidation |
| Storage backend | **Current (2026-02-28):** filesystem blob store + SQLite metadata. **Planned:** OCI-backed artifact storage for hosted deployments |
| Axum API service | `POST /api/v1/packages`, `GET /api/v1/packages/{name}`, `GET /api/v1/packages/{name}/{version}`, `GET /api/v1/search` |
| `clawdstrike pkg publish` | Upload `.cpkg` with Ed25519 signature to the registry |
| `clawdstrike pkg install <name>` | Resolve dependencies, download, verify, install |
| `clawdstrike pkg search <query>` | Full-text search across package names, descriptions, tags |
| pubgrub dependency resolution | SAT-based version resolution with clear error messages on conflicts |
| `clawdstrike-pkg.lock` | Deterministic lockfile pinning exact versions and content hashes |
| Namespace reservation | Package names are globally unique; org-scoped names (`@org/package`) for verified organizations |

**Exit criteria:** An author can publish a guard package to the registry, and a user on a different machine can install it by name, with all dependencies resolved and signatures verified.

---

### Phase 3: Trust & Transparency (4-6 weeks)

**Goal:** Cryptographic trust chain from author to deployment. Every package is signed, counter-signed by the registry, and recorded in a transparency log.

```text
Author signs package
        |
        v
  Registry counter-signs (Spine envelope)
        |
        v
  Merkle transparency log (append-only)
        |
        v
  Client verifies: author sig + registry sig + inclusion proof
```

**Deliverables:**

| Deliverable | Description |
|-------------|-------------|
| Ed25519 author signing | Authors sign packages with their Ed25519 keypair. Key management via `clawdstrike pkg keygen` |
| Spine counter-signatures | Registry wraps each publish event in a Spine envelope, adding its own signature |
| Merkle transparency log | RFC 6962-style append-only log. Every publish is a leaf. Clients verify inclusion proofs |
| Trust levels | `unverified` (no signature) -> `signed` (publisher Ed25519) -> `verified` (publisher + registry counter-sig + pinned registry public key trust anchor) -> `certified` (all above + cryptographically verified checkpoint signature + transparency inclusion proof) |
| OIDC trusted publishing | GitHub Actions, GitLab CI, and other OIDC providers can publish without long-lived keys |
| Key rotation ceremony | Documented procedure for rotating registry signing keys with overlapping validity windows |
| Audit monitor | Independent service that watches the transparency log and alerts on anomalies |

**Trust level enforcement:**

```text
+------------+---------------------------------------------+
| Level      | Requirements                                |
+------------+---------------------------------------------+
| unverified | No valid signature. Install requires --allow-unverified flag |
| signed     | Valid publisher Ed25519 signature            |
| verified   | Publisher sig + registry counter-signature + pinned registry public key |
| certified  | All above + checkpoint-signature verification + inclusion-proof verification |
+------------+---------------------------------------------+
```

**Exit criteria:** A user installing a package sees the trust level, can verify the author signature, and can independently check the transparency log for the package's inclusion proof.

---

### Phase 4: Ecosystem (Ongoing)

**Goal:** A thriving ecosystem of community-contributed guards, policy packs, and compliance templates.

| Initiative | Description | Target |
|-----------|-------------|--------|
| Multi-language guard SDKs | Guard SDKs for TypeScript, Python, Go (all compile to WASM) | Q3 2026 |
| `cargo generate` / `create-clawdstrike-guard` | Scaffolding templates for common guard patterns | Q3 2026 |
| Web UI for registry | Browse, search, and inspect packages with documentation rendering | Q3 2026 |
| Organization accounts | Scoped namespaces, team permissions, org-wide trust policies | Q4 2026 |
| Self-hosted registry | Helm chart for deploying a private registry behind your firewall | Q4 2026 |
| Registry mirroring | Pull-through cache for air-gapped environments | Q4 2026 |
| Policy composition marketplace | Curated collections of guards + policies for common use cases (HIPAA, PCI, SOC2, NIST) | Q4 2026 |
| Guard analytics | Download counts, security audit status, compatibility matrix | 2027 |

---

## SDK & Integrations Roadmap

### TypeScript SDK

| Milestone | Description | Target |
|-----------|-------------|--------|
| Engine-local WASM backend | Run the Rust policy engine in-process via WASM for zero-latency TS evaluation | Q2 2026 |
| Streaming guard support | Guards that evaluate streaming tool output incrementally (for LLM streaming responses) | Q2 2026 |
| React hooks library | `useClawdstrike()` for dashboard components and approval UIs | Q3 2026 |
| Deno / Bun compatibility | Verified support and CI testing for non-Node runtimes | Q3 2026 |
| OpenTelemetry exporter | Receipt spans as OTLP traces for existing observability stacks | Q3 2026 |

### Python SDK

| Milestone | Description | Target |
|-----------|-------------|--------|
| v0.3.0: Async-native API | `async def check_*` methods throughout, native `asyncio` integration | Q2 2026 |
| CrewAI adapter | First-class integration with CrewAI multi-agent framework | Q2 2026 |
| AutoGen adapter | Microsoft AutoGen framework adapter | Q2 2026 |
| LlamaIndex adapter | Guard pipeline integration for LlamaIndex tool use | Q3 2026 |
| Jupyter/notebook integration | Inline guard checks with rich HTML verdict rendering in notebooks | Q3 2026 |

### Framework Adapters

| Adapter | Status | Next Milestone |
|---------|--------|----------------|
| OpenAI Agents SDK | Stable | Streaming support, function calling interception |
| Claude / Agent SDK | Stable | Computer use gateway integration |
| Vercel AI SDK | Stable | Edge runtime support |
| LangChain | Stable | LangGraph multi-agent support |
| OpenClaw | Stable | Plugin marketplace listing |
| OpenCode | Stable | IDE sidebar integration |
| **CrewAI** | Planned | Adapter + delegation token bridge |
| **AutoGen** | Planned | Adapter + conversation-level posture tracking |
| **LlamaIndex** | Planned | Tool-level guard injection |
| **Semantic Kernel** | Planned | .NET adapter via FFI |

### WASM & FFI

| Milestone | Description | Target |
|-----------|-------------|--------|
| WASM size optimization | Tree-shaking + wasm-opt to reduce bundle size below 500KB | Q2 2026 |
| Go SDK (native) | Generated from FFI with idiomatic Go wrappers and `context.Context` support | Q3 2026 |
| C# SDK (native) | NuGet package with `IAsyncDisposable` lifecycle and Semantic Kernel integration | Q3 2026 |
| Swift bindings | UniFFI-generated bindings for iOS/macOS agent runtimes | Q4 2026 |

---

## Enterprise Roadmap

### Self-Hosted Registry

| Milestone | Description | Target |
|-----------|-------------|--------|
| Helm chart for private registry | Single-command deployment: `helm install clawdstrike-registry` | Q4 2026 |
| Air-gapped operation | Offline package installation from USB/filesystem with full signature verification | Q4 2026 |
| Pull-through proxy | Cache public registry packages behind enterprise firewall with policy-based filtering | Q4 2026 |
| Content scanning | Automated security scan of WASM guard bytecode before admission to private registry | Q4 2026 |

### Organization Management

| Milestone | Description | Target |
|-----------|-------------|--------|
| Org accounts & namespaces | `@org/package` scoping, team-level publish permissions, org-wide trust policies | Q4 2026 |
| SSO / SAML integration | Enterprise identity provider integration for registry authentication | Q4 2026 |
| RBAC for policy management | Role-based access control: policy author, policy reviewer, fleet admin, auditor | Q4 2026 |
| Policy approval workflows | Git-ops style: PR -> review -> merge -> auto-deploy to fleet | 2027 |

### Compliance & Certification

| Milestone | Description | Target |
|-----------|-------------|--------|
| HIPAA compliance pack (registry) | Pre-built guard + policy + evidence bundle package installable via `clawdstrike pkg install @clawdstrike/hipaa` | Q3 2026 |
| PCI-DSS compliance pack | Same for PCI-DSS v4.0 controls | Q3 2026 |
| SOC2 continuous evidence | Automated evidence collection feeding SOC2 Type II audit periods | Q3 2026 |
| EU AI Act mapping | Guard-to-requirement mapping for EU AI Act Article 9 (risk management) and Article 15 (accuracy/robustness) | Q4 2026 |
| NIST AI RMF alignment | Map guard verdicts to NIST AI 100-1 risk management functions | Q4 2026 |
| FedRAMP readiness | Cloud control plane documentation and authorization package | 2027 |

### Fleet Operations

| Milestone | Description | Target |
|-----------|-------------|--------|
| Multi-tenant control API | Isolated tenant environments with per-tenant NATS credentials and data residency controls | Q2 2026 |
| Canary deployments | Roll policy changes to 5% of fleet, monitor for regressions, auto-promote or rollback | Q3 2026 |
| Incident response automation | Auto-quarantine agents exceeding violation thresholds, generate incident timeline from Spine log | Q3 2026 |
| Agent inventory & SBOM | Track installed guard packages, WASM module versions, and policy hashes per agent | Q4 2026 |
| Cost attribution | Per-agent, per-guard evaluation cost tracking for chargeback models | 2027 |

---

## Community & Ecosystem Goals

### Milestones

```text
  Q2 2026          Q3 2026          Q4 2026          2027
     |                |                |               |
     v                v                v               v
  pkg format       10 community     50 community    200+ guards
  finalized        guards           guards          ecosystem
  guard SDK        3 compliance     self-hosted     marketplace
  released         packs            registry        GA
                   registry MVP     org accounts
                   transparency     mirroring
                   log live
```

| Milestone | Description | Target |
|-----------|-------------|--------|
| Guard SDK v1.0 | Stable ABI for WASM guards, published `clawdstrike-guard-sdk` crate | Q2 2026 |
| 10 community guards | First community-authored guards published to registry (target domains: PII detection, code review, license compliance, API rate limiting) | Q3 2026 |
| 3 compliance packs | HIPAA, PCI-DSS, SOC2 packs available as installable packages | Q3 2026 |
| First security audit | Independent third-party audit of core engine, WASM sandbox, and receipt verification | Q3 2026 |
| 50 community guards | Broad coverage across file, network, MCP, shell, and domain-specific threat surfaces | Q4 2026 |
| Guard certification program | Community guards can apply for "verified" trust level with code review and testing requirements | Q4 2026 |
| 200+ guards ecosystem | Mature ecosystem with guards for healthcare, finance, legal, DevOps, and research verticals | 2027 |
| Policy pack marketplace | Curated, rated, and reviewed collections of guards + policies for specific compliance frameworks | 2027 |

### Community Programs

| Program | Description |
|---------|-------------|
| **Guard Bounty Program** | Rewards for guards that detect novel attack patterns from S2Bench and real-world incidents |
| **Clawdstrike Champions** | Recognition program for top community contributors with early access to features |
| **Security Research Grants** | Fund academic research into AI agent security, with findings published as guards |
| **Attack Range** | Public sandbox environment where researchers test guards against real attack taxonomies |
| **Quarterly Security Report** | Aggregated (anonymized) statistics on blocked attacks, guard effectiveness, and emerging threat patterns |

---

## Research & Experimental

These capabilities are under active development. APIs are unstable and may change significantly.

### hushd HTTP Daemon

**Status:** Experimental
**Crate:** `crates/services/hushd`

Centralized enforcement server for environments where embedding the engine in every process is impractical. Agents send check requests over HTTP; hushd evaluates the policy and returns signed verdicts.

| Milestone | Description | Target |
|-----------|-------------|--------|
| Multi-policy routing | Route requests to different policies based on agent identity, team, or project scope | Q2 2026 |
| Policy hot-reload | Watch filesystem or NATS KV for policy changes, reload without restart | Q2 2026 |
| High-availability mode | Active-active clustering with shared state via NATS JetStream | Q3 2026 |
| gRPC API | Alternative to HTTP for high-throughput internal service meshes | Q3 2026 |

### EAS On-Chain Anchoring

**Status:** Experimental
**Crate:** `crates/services/eas-anchor`
**Spec:** [docs/specs/13-eas-onchain-anchoring.md](../specs/13-eas-onchain-anchoring.md)

Anchor Spine Merkle roots to Ethereum Attestation Service on Base L2, creating an immutable public timeline of attestation checkpoints.

| Milestone | Description | Target |
|-----------|-------------|--------|
| Batch anchoring | Aggregate N checkpoint roots into a single on-chain transaction to amortize gas costs | Q3 2026 |
| Verification client | `clawdstrike verify --on-chain <receipt-hash>` checks inclusion against the on-chain Merkle root | Q3 2026 |
| Cross-chain support | Anchor to additional L2s (Arbitrum, Optimism) for redundancy | Q4 2026 |

### Tetragon & Hubble Bridges

**Status:** Experimental
**Crates:** `tetragon-bridge`, `hubble-bridge`

Bridges that ingest kernel-level (Tetragon eBPF) and network-level (Cilium Hubble) events into the Spine protocol, enabling L1/L2 enforcement correlation with L3 agent-level decisions.

| Milestone | Description | Target |
|-----------|-------------|--------|
| Event correlation engine | Correlate Tetragon process events with Clawdstrike guard decisions by PID and timestamp | Q3 2026 |
| Hubble flow-to-egress mapping | Map Cilium flow observations to EgressAllowlistGuard decisions for L2+L3 enforcement proof | Q3 2026 |
| Combined attestation | Single Spine envelope carrying process ancestry + network policy + guard verdict + Merkle proof | Q4 2026 |

### Spider-Sense Integration

**Status:** Beta (feature-gated)
**Paper:** [Yu et al. 2026 — Spider-Sense](https://arxiv.org/abs/2602.05386)

Hierarchical threat screening adapted as a tool-boundary guard. Fast-path cosine similarity for known patterns; optional LLM escalation for ambiguous inputs.

| Milestone | Description | Target |
|-----------|-------------|--------|
| Plan-stage defense | Extend screening to the plan stage (currently the "dominant blind spot" per the paper) | Q2 2026 |
| Custom pattern databases | Users supply domain-specific attack pattern databases per deployment | Q2 2026 |
| S2Bench integration tests | Full test coverage against the paper's taxonomy (4 lifecycle stages x 9 attack types) | Q2 2026 |
| Graduate from feature gate | Move from `--features clawdstrike-spider-sense` to default-on with opt-out | Q3 2026 |

### Adaptive Security Decision Runtime (SDR)

**Status:** Shipped
**Spec:** [docs/specs/15-adaptive-sdr-architecture.md](../specs/15-adaptive-sdr-architecture.md)

Automatic mode transition between standalone, connected, and degraded enforcement modes. Agents are never unprotected regardless of network conditions.

| Milestone | Description | Target |
|-----------|-------------|--------|
| Offline receipt queue compaction | Compact queued receipts during extended offline periods to bound storage | Q2 2026 |
| Predictive mode switching | Use network quality metrics to proactively switch modes before failure | Q3 2026 |
| Multi-remote failover | Support multiple remote engine endpoints with automatic failover | Q3 2026 |

---

## Timeline Overview

```text
2026
=====

Q2 (Apr-Jun)                     Q3 (Jul-Sep)                    Q4 (Oct-Dec)
---------------------------------|---------------------------------|---------------------------------
PACKAGE MANAGER                  |                                 |
 Phase 0: Local packages ========|                                 |
 Phase 1: WASM guard runtime ====|====                             |
                                 | Phase 2: Registry MVP ==========|
                                 | Phase 3: Trust & transparency ==|====
                                 |                                 | Phase 4: Ecosystem (ongoing)-->
                                 |                                 |
SDK & INTEGRATIONS               |                                 |
 TS: WASM backend, streaming ====|                                 |
 Python v0.3.0 async-native =====|                                 |
                                 | CrewAI + AutoGen adapters ======|
                                 | React hooks, Deno/Bun ===========|
                                 |                                 | Go + C# native SDKs ==========>
                                 |                                 | Swift bindings ================>
                                 |                                 |
ENTERPRISE                       |                                 |
 Multi-tenant control API =========|                                 |
 hushd hot-reload + routing =====|                                 |
                                 | Canary deployments =============|
                                 | Incident response automation ===|
                                 | HIPAA + PCI + SOC2 packs =======|
                                 |                                 | Self-hosted registry ==========>
                                 |                                 | Org accounts + SSO ============>
                                 |                                 | EU AI Act mapping =============>
                                 |                                 |
RESEARCH                         |                                 |
 Spider-Sense plan stage ========|                                 |
 SDR queue compaction ============|                                 |
                                 | EAS batch anchoring =============|
                                 | Tetragon correlation =============|
                                 | hushd HA + gRPC ==================|
                                 |                                 | Cross-chain anchoring =========>
                                 |                                 | Combined L0-L5 attestation ====>

2027
=====
 - 200+ community guards ecosystem
 - Policy pack marketplace GA
 - FedRAMP readiness
 - Policy approval workflows (git-ops)
 - Cost attribution / chargeback
 - Guard analytics dashboard
```

### Priority Stack Rank

When resources are constrained, work is prioritized top-to-bottom:

| Priority | Initiative | Rationale |
|----------|-----------|-----------|
| P0 | Package Manager Phase 0-1 (local + WASM) | Unblocks the entire ecosystem play |
| P0 | hushd multi-policy routing + hot-reload | Required for enterprise control API |
| P1 | Package Manager Phase 2 (registry MVP) | Enables community contribution |
| P1 | Python v0.3.0 async + CrewAI/AutoGen adapters | Captures the fastest-growing agent framework markets |
| P1 | HIPAA/PCI/SOC2 compliance packs | Direct enterprise revenue driver |
| P2 | Package Manager Phase 3 (trust) | Builds confidence for production adoption of community guards |
| P2 | Self-hosted registry + air-gapped mode | Enterprise deal requirement |
| P2 | Spider-Sense graduation | Novel detection capability differentiator |
| P3 | EAS on-chain anchoring | Unique value prop but narrow buyer segment |
| P3 | Tetragon/Hubble correlation | Deep-stack differentiator, long implementation horizon |
| P3 | Multi-language guard SDKs (TS, Python, Go WASM) | Ecosystem growth, but Rust-first is sufficient initially |

---

## How to Contribute

The roadmap is open. If you want to work on any of these initiatives:

1. Check the [GitHub issues](https://github.com/backbay-labs/clawdstrike/issues) for existing tracking issues tagged with `roadmap`
2. Comment on the relevant issue to signal interest
3. For new guard contributions, start with the [Custom Guards guide](guides/custom-guards.md)
4. For policy pack contributions, see the [Certification Program overview](../plans/certification/overview.md)
5. Join the [Discord](https://discord.gg/clawdstrike) `#contributors` channel

**Every contribution that touches the guard pipeline must include:**
- Tests (unit + integration against fixture actions)
- Receipt generation (guards must produce verifiable receipts)
- Policy schema documentation (if adding new guard config fields)
- Clippy clean: `cargo clippy --workspace -- -D warnings`
