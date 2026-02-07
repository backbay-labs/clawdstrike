# ClawdStrike Open Source Consolidation Strategy: Defining the SDR Category

> Strategy document for consolidating AegisNet, Reticulum transport, Tetragon/Cilium
> bridges, and the policy marketplace into a single open source platform under the
> ClawdStrike project. "Swarm Detection & Response" (SDR) is a new security category
> purpose-built for AI agent swarms.
>
> **Status:** Strategy Draft | **Date:** 2026-02-07
> **Audience:** Founding team, engineering leadership, investors, open source community

---

## Table of Contents

1. [The Category: Swarm Detection & Response](#1-the-category-swarm-detection--response)
2. [Unified Project Structure](#2-unified-project-structure)
3. [Migration Plan](#3-migration-plan)
4. [Open Source Strategy](#4-open-source-strategy)
5. [Business Model (Open Core)](#5-business-model-open-core)
6. [Competitive Positioning](#6-competitive-positioning)
7. [Community Growth Strategy](#7-community-growth-strategy)
8. [Brand & Naming](#8-brand--naming)
9. [Timeline: Phased Execution](#9-timeline-phased-execution)

---

## 1. The Category: Swarm Detection & Response

### 1.1 Why a New Category

In 2013, CrowdStrike defined **Endpoint Detection and Response (EDR)** by putting an agent on every endpoint that could detect and respond to threats in real time. The "endpoints" of 2013 were laptops and servers. The "endpoints" of 2026 are **AI agents**.

The AI agent market is growing at 40-46% CAGR, projected to reach $52-139 billion by 2030-2034. Gartner estimates 40% of enterprise applications will embed task-specific agents by the end of 2026. Yet the security story for these agents is catastrophically behind deployment velocity:

- **63% of organizations** have no limits on what AI agents are authorized to do
- **60% of organizations** cannot terminate AI agents quickly
- **Zero mainstream products** provide runtime enforcement at the AI agent tool boundary
- **Zero products** provide cryptographic proof of what an AI agent did at runtime
- In November 2025, Anthropic detected the first documented AI-orchestrated espionage campaign: **autonomous agents working as a coordinated swarm** targeting 30 organizations simultaneously

Traditional EDR cannot address this threat. EDR watches endpoints for malware signatures and behavioral anomalies. AI agents are not malware -- they are authorized code with authorized access that can be manipulated via prompt injection, jailbreaking, tool abuse, and lateral data exfiltration. The attack surface is the **tool boundary**, not the binary. The threat unit is the **swarm**, not the individual process.

**Swarm Detection & Response (SDR)** is the security category that addresses this gap. SDR provides:

1. **Runtime enforcement at the agent tool boundary** -- every file access, network request, MCP tool invocation, and code patch is policy-gated
2. **Kernel-level execution proofs** -- not just what was deployed, but what actually executed, verified by eBPF at the Linux kernel level
3. **Cryptographic attestation** -- every guard decision produces an Ed25519-signed receipt recorded in an append-only Merkle tree transparency log
4. **Cross-layer proof chains** -- a single verification request returns evidence spanning kernel syscalls, network flows, workload identity, and agent-level guard decisions
5. **Swarm-aware detection** -- correlation of agent process trees to MITRE ATT&CK kill chains, with awareness of multi-agent coordination patterns
6. **Decentralized policy marketplace** -- community-curated security policies with multi-curator attestation, not single-vendor controlled detection logic
7. **Offline-capable mesh enforcement** -- via the Reticulum transport profile, security facts propagate even over LoRa, packet radio, and intermittent connectivity

### 1.2 The CrowdStrike Analogy

| Dimension | CrowdStrike (EDR, 2013) | ClawdStrike (SDR, 2026) |
|-----------|-------------------------|-------------------------|
| **Protected entity** | Endpoints (laptops, servers) | AI agents (Claude, GPT, Codex, custom) |
| **Agent placement** | Kernel sensor on every endpoint | Guards at every agent tool boundary |
| **Detection method** | Behavioral analysis + IOC matching | 7 built-in guards + kernel eBPF + ML/LLM judge |
| **Enforcement** | Process kill, network quarantine | Tool boundary deny, kernel Sigkill, network policy drop |
| **Evidence** | Mutable event logs | Append-only Merkle tree with witness co-signatures |
| **Policy source** | CrowdStrike threat intel (proprietary) | Community marketplace (multi-curator, signed, IPFS) |
| **Deployment** | Agent per endpoint + cloud console | SDK per agent runtime + hushd daemon + desktop console |
| **Trust model** | Trust CrowdStrike completely | Configurable trust roots, offline verification, no vendor lock |

### 1.3 Market Validation

The market is signaling readiness for this category:

- **Cloud Security Alliance** published the "Agentic Trust Framework" (Feb 2026) outlining zero-trust governance for AI agents -- which ClawdStrike's architecture directly implements
- **AccuKnox** published "Top 5 ADR Security Solutions" (2026), recognizing Agent Detection & Response as an emerging space
- **Operant AI** launched "Agent Protector" (Feb 2026) to secure autonomous agents at scale -- validating market demand
- **Harvard Business Review / Palo Alto Networks** published "6 Cybersecurity Predictions for the AI Economy" predicting a new category of AI governance tools providing runtime enforcement
- **Gravitee** published "State of AI Agent Security 2026" reporting that adoption has outpaced control across enterprises
- The **EU AI Act** (full implementation 2027) will require exactly the kind of runtime transparency and auditability that ClawdStrike provides

The governance gap is widening. Deployment velocity is accelerating. No incumbent has the architecture to address AI agent swarm security. The category is open.

---

## 2. Unified Project Structure

### 2.1 Target Monorepo

The consolidation merges four currently separate codebases and projects into one cohesive repository:

```
clawdstrike/
├── README.md                    # Project overview + quickstart
├── LICENSE                      # Apache 2.0
├── SECURITY.md                  # Security policy
├── CONTRIBUTING.md              # Contribution guide
├── CODE_OF_CONDUCT.md           # Contributor covenant
├── Cargo.toml                   # Rust workspace root
├── package.json                 # JS/TS workspace root
│
├── core/                        # hush-core: cryptographic primitives
│   ├── Cargo.toml               #   Ed25519, SHA-256, Merkle trees, canonical JSON (RFC 8785)
│   └── src/
│
├── guards/                      # clawdstrike crate: policy engine + guards
│   ├── Cargo.toml               #   7 built-in guards + async guard trait
│   └── src/
│       ├── engine.rs            #   HushEngine facade
│       ├── policy.rs            #   YAML policy system (schema v1.1.0)
│       ├── receipt.rs           #   Ed25519-signed receipts
│       └── guards/
│           ├── forbidden_path.rs
│           ├── egress_allowlist.rs
│           ├── secret_leak.rs
│           ├── patch_integrity.rs
│           ├── mcp_tool.rs
│           ├── prompt_injection.rs
│           └── jailbreak.rs     #   4-layer: heuristic + statistical + ML + LLM-judge
│
├── daemon/                      # hushd: HTTP enforcement daemon
│   ├── Cargo.toml               #   Axum server, SSE broadcast, NATS subscriber
│   └── src/
│
├── cli/                         # hush-cli: command-line interface
│   ├── Cargo.toml
│   └── src/
│
├── desktop/                     # Tauri 2 + React 19 SDR console
│   ├── src-tauri/               #   Rust backend
│   ├── src/                     #   React frontend
│   │   ├── features/
│   │   │   ├── threat-radar/    #   3D threat visualization (R3F)
│   │   │   ├── attack-graph/    #   MITRE ATT&CK chain correlation
│   │   │   ├── network-map/     #   Live Hubble flow topology (R3F)
│   │   │   ├── events/          #   Real-time event stream
│   │   │   └── marketplace/     #   Policy marketplace UI
│   │   └── shell/               #   Plugin system + app shell
│   └── package.json
│
├── spine/                       # Aegis Spine protocol (moved from aegis)
│   ├── Cargo.toml               #   Envelope/fact schemas, checkpointing, proofs
│   ├── src/
│   │   ├── envelope.rs          #   SignedEnvelope (aegis.spine.envelope.v1)
│   │   ├── checkpoint.rs        #   RFC 6962 Merkle tree checkpoints
│   │   ├── witness.rs           #   Witness co-signing
│   │   ├── proofs.rs            #   Inclusion/consistency proof verification
│   │   └── sync.rs              #   Head announcements, sync request/response
│   ├── nats/                    #   Plane B: NATS JetStream adapter
│   │   ├── Cargo.toml
│   │   └── src/
│   ├── libp2p/                  #   Plane A-L: libp2p gossipsub adapter
│   │   ├── Cargo.toml
│   │   └── src/
│   └── reticulum/               #   Plane A-R: Reticulum transport adapter
│       ├── pyproject.toml       #     Python (Reticulum is Python-native)
│       └── src/
│
├── bridges/                     #   Kernel-level event bridges
│   ├── tetragon/                #   Tetragon gRPC -> Spine SignedEnvelope -> NATS
│   │   ├── Cargo.toml           #     ~500-800 lines Rust (tonic + async-nats + ed25519-dalek)
│   │   └── src/
│   └── hubble/                  #   Hubble flow export -> Spine attestation -> NATS
│       ├── Cargo.toml
│       └── src/
│
├── marketplace/                 #   Decentralized policy distribution
│   ├── Cargo.toml               #   Feed signing, bundle signing, P2P discovery
│   └── src/
│       ├── feed.rs              #   MarketplaceFeed, multi-curator verification
│       ├── bundle.rs            #   PolicyBundle signing/verification
│       ├── discovery.rs         #   libp2p gossipsub + mDNS + DHT discovery
│       ├── provenance.rs        #   AegisNet attestation, EAS anchoring
│       └── trust.rs             #   TrustBundle, curator registry
│
├── certification/               #   Compliance templates
│   ├── Cargo.toml               #   SOC2, HIPAA, EU AI Act, FedRAMP
│   └── templates/
│
├── sdk/                         #   Client libraries
│   ├── rust/                    #   Rust SDK (re-export of guards crate)
│   ├── typescript/              #   @clawdstrike/sdk (TypeScript)
│   │   ├── package.json
│   │   └── src/
│   ├── python/                  #   clawdstrike (Python)
│   │   ├── pyproject.toml
│   │   └── src/
│   └── wasm/                    #   hush-wasm (WebAssembly bindings)
│       ├── Cargo.toml
│       └── src/
│
├── adapters/                    #   Framework-specific adapters
│   ├── claude-code/             #   @clawdstrike/claude-code
│   ├── vercel-ai/               #   @clawdstrike/vercel-ai
│   ├── langchain/               #   @clawdstrike/langchain
│   ├── codex/                   #   @clawdstrike/codex
│   └── opencode/                #   @clawdstrike/opencode
│
├── rulesets/                    #   Community policy templates
│   ├── permissive.yaml
│   ├── default.yaml
│   ├── strict.yaml
│   ├── ai-agent.yaml
│   ├── cicd.yaml
│   └── community/               #   Community-contributed rulesets
│
├── deploy/                      #   Kubernetes deployment manifests
│   ├── helm/                    #   Helm chart for hushd + spine + bridges
│   ├── argocd/                  #   ArgoCD Application resources
│   └── tetragon-policies/       #   TracingPolicy CRDs
│
├── docs/                        #   mdBook documentation
│   ├── book.toml
│   ├── src/
│   │   ├── SUMMARY.md
│   │   ├── quickstart.md
│   │   ├── architecture/
│   │   ├── guards/
│   │   ├── spine/
│   │   ├── marketplace/
│   │   └── deployment/
│   └── research/                #   Research docs (this directory)
│
└── examples/                    #   Runnable examples
    ├── basic-verification/
    ├── autonomous-sandbox/
    └── multi-agent-orchestration/
```

### 2.2 Crate/Package Map

| Crate/Package | Current Location | Target Location | Language |
|---------------|-----------------|-----------------|----------|
| `hush-core` | `clawdstrike/crates/hush-core` | `core/` | Rust |
| `clawdstrike` | `clawdstrike/crates/clawdstrike` | `guards/` | Rust |
| `hushd` | `clawdstrike/crates/hushd` | `daemon/` | Rust |
| `hush-cli` | `clawdstrike/crates/hush-cli` | `cli/` | Rust |
| `hush-proxy` | `clawdstrike/crates/hush-proxy` | `daemon/proxy/` | Rust |
| `hush-wasm` | `clawdstrike/crates/hush-wasm` | `sdk/wasm/` | Rust |
| `hush-certification` | `clawdstrike/crates/hush-certification` | `certification/` | Rust |
| `hush-multi-agent` | `clawdstrike/crates/hush-multi-agent` | `guards/multi-agent/` | Rust |
| `hush-ts` | `clawdstrike/packages/hush-ts` | `sdk/typescript/` | TypeScript |
| `hush-py` | `clawdstrike/packages/hush-py` | `sdk/python/` | Python |
| Desktop app | `clawdstrike/apps/desktop` | `desktop/` | TS + Rust |
| AegisNet checkpointer | `aegis/services/aegisnet/checkpointer` | `spine/nats/checkpointer/` | Rust |
| AegisNet witness | `aegis/services/aegisnet/witness` | `spine/nats/witness/` | Rust |
| AegisNet proofs-api | `aegis/services/aegisnet/proofs-api` | `spine/nats/proofs-api/` | Rust |
| AegisNet observability | `aegis/services/aegisnet/observability` | `desktop/` (dashboards) + `spine/metrics/` | Mixed |
| Reticulum adapter | `platform/docs/specs/` (spec only) | `spine/reticulum/` | Python |
| tetragon-nats-bridge | New | `bridges/tetragon/` | Rust |
| hubble-flow-bridge | New | `bridges/hubble/` | Rust |

---

## 3. Migration Plan

### 3.1 What Moves From Where

**From `standalone/aegis/` (AegisNet services):**

| AegisNet Component | Target | Notes |
|-------------------|--------|-------|
| `services/aegisnet/checkpointer/` | `spine/nats/checkpointer/` | Core Merkle tree builder, checkpoint emitter |
| `services/aegisnet/witness/` | `spine/nats/witness/` | Independent co-signer |
| `services/aegisnet/proofs-api/` | `spine/nats/proofs-api/` | HTTP endpoints for inclusion proofs |
| `services/aegisnet/observability/` | Split: metrics to `spine/metrics/`, dashboards to `desktop/` | Prometheus alerts stay in `deploy/` |
| `services/aegisnet/model-registry/` | Stays in Aegis | Not security-specific |
| `services/aegisnet/smoketest*` | `spine/nats/tests/` | Integration tests |
| `crates/aegisnet/` | `spine/src/` | Core Spine protocol types |
| `crates/cyntra-trust/` | `core/trust/` | Attestation/trust primitives |

**From `platform/docs/specs/` (Reticulum + Spine specs):**

| Spec | Target | Notes |
|------|--------|-------|
| `cyntra-aegis-spine-reticulum.md` | `docs/src/spine/reticulum.md` | Transport profile spec |
| `cyntra-aegis-spine.md` | `docs/src/spine/protocol.md` | Core Spine protocol spec |
| `cyntra-aegis-net-design-axioms.md` | `docs/src/architecture/design-axioms.md` | Design invariants |
| `cyntra-aegis-trust-infrastructure.md` | `docs/src/architecture/trust-infrastructure.md` | Trust model |

**From `standalone/clawdstrike/` (current repo -- restructure in place):**

| Current | Target | Notes |
|---------|--------|-------|
| `crates/hush-core` | `core/` | Rename crate directory |
| `crates/clawdstrike` | `guards/` | Rename crate directory |
| `crates/hushd` | `daemon/` | Rename crate directory |
| `crates/hush-cli` | `cli/` | Rename crate directory |
| `crates/hush-wasm` | `sdk/wasm/` | Move to SDK directory |
| `packages/hush-ts` | `sdk/typescript/` | Move to SDK directory |
| `packages/hush-py` | `sdk/python/` | Move to SDK directory |
| `apps/desktop` | `desktop/` | Move to top level |

**What stays in `platform/infra/` (Kubernetes infrastructure):**

- ArgoCD Application manifests (`cilium.yaml`, `tetragon.yaml`, `aegisnet-*.yaml`, `spire.yaml`)
- Terraform modules for EKS, VPC, IAM
- Karpenter NodePool/EC2NodeClass definitions
- Docker Compose for local development services
- These are deployment-specific and do not belong in the OSS repo

### 3.2 Migration Sequence

```
Phase 1: Restructure ClawdStrike repo (rename crates/ → top-level dirs)
    │     This is a local refactor with no external dependencies.
    │     All existing functionality preserved.
    │
Phase 2: Copy AegisNet service code into spine/
    │     The AegisNet K8s deployments continue pointing at the aegis repo
    │     until Phase 4. The spine/ code is a parallel copy for development.
    │
Phase 3: Implement bridges/ (tetragon-nats-bridge, hubble-flow-bridge)
    │     New code. No migration needed.
    │
Phase 4: Deploy spine/ services alongside existing AegisNet
    │     Blue-green deploy: new Helm chart in deploy/, ArgoCD switches over.
    │     Verify checkpointing, witnessing, proofs all work from ClawdStrike repo.
    │
Phase 5: Deprecate standalone aegis/services/aegisnet/
    │     Redirect ARCHITECTURE.md to clawdstrike docs.
    │     The aegis repo retains agents-api, bff, and web surface only.
    │
Phase 6: Public release
         GitHub public repo, documentation site, npm/crates.io packages.
```

### 3.3 Dependency Considerations

The consolidated repo's Rust workspace dependencies (from the current `Cargo.toml`) are already well-suited for open source:

- **Crypto**: `ed25519-dalek`, `sha2`, `sha3` (pure Rust, no vendored C)
- **Serialization**: `serde`, `serde_json`, `serde_yaml`
- **Async**: `tokio`, `async-trait`
- **HTTP**: `axum`, `tower`, `reqwest` (with `rustls`, not OpenSSL)
- **Database**: `rusqlite` (bundled SQLite)
- **Config**: `toml`, `dirs`

One concern: `openssl = { version = "0.10", features = ["vendored"] }` should be audited. If only used for TLS in specific adapters, it can be feature-gated or replaced with `rustls` throughout. For an open source release, minimizing vendored C dependencies reduces build friction.

---

## 4. Open Source Strategy

### 4.1 License Choice

**Recommendation: Apache 2.0**

The current `Cargo.toml` specifies `license = "MIT"`. For the consolidated public release, we recommend switching to **Apache 2.0** for these reasons:

| Factor | MIT | Apache 2.0 |
|--------|-----|------------|
| **Patent protection** | Silent on patents | Explicit patent grant + termination clause |
| **Enterprise adoption** | Good | Excellent (patent clarity removes legal friction) |
| **CNCF alignment** | Accepted | Preferred (Cilium, Tetragon, Falco all use Apache 2.0) |
| **Contributor clarity** | Ambiguous patent rights | Clear patent grant from contributors |
| **Competitive moat** | None | Patent termination clause discourages patent trolling |
| **Market data** | #1 by pageviews (2025) | #2 and growing, dominant in infrastructure/security |

Apache 2.0 is the standard for CNCF cloud-native security projects. Using it signals professionalism and aligns ClawdStrike with the ecosystem it integrates with (Cilium, Tetragon, SPIRE, NATS). The explicit patent grant removes a common enterprise adoption blocker.

The TypeScript/Python SDKs and adapters can remain MIT for maximum flexibility if desired, since they are thin wrappers. The core Rust crates, Spine protocol, bridges, and marketplace should be Apache 2.0.

### 4.2 Repository Structure

**Monorepo with Cargo workspace + npm workspaces:**

- All Rust crates in a single `Cargo.toml` workspace (as today)
- All TypeScript packages in npm workspaces
- Python packages managed via `pyproject.toml` with uv/pip
- Single CI pipeline (GitHub Actions) testing all languages
- Releases coordinated: Rust crates published to crates.io, TS packages to npm, Python to PyPI

**Why monorepo:**
- Atomic cross-crate refactors (Spine protocol changes affect guards, bridges, marketplace simultaneously)
- Single CI pipeline ensures compatibility
- Easier contributor onboarding (one repo to clone, one README)
- Matches successful precedent: Cilium monorepo, Sigstore monorepo

### 4.3 Community Governance Model

**Phase 1 (0-12 months): BDFL with Maintainer Council**

- Founding team retains final decision authority (BDFL = Benevolent Dictator For Life)
- Maintainer Council of 3-5 core contributors with commit access
- All design decisions documented in RFCs (markdown in `docs/rfcs/`)
- Weekly community call (recorded, notes published)
- Decision process: RFC -> community comment period (2 weeks) -> BDFL approval

**Phase 2 (12-24 months): Steering Committee**

As the contributor base grows beyond the founding team:
- Transition to 5-member elected Steering Committee
- BDFL retains veto on security-critical decisions only
- Sub-teams form around components: Guards, Spine, Desktop, Bridges, Marketplace
- Each sub-team has a lead with merge authority for their area
- Steering Committee resolves cross-cutting decisions

**Phase 3 (24+ months): CNCF Sandbox Application**

- Apply to CNCF Sandbox (requirements: 2+ maintainers from different orgs, Apache 2.0 license, CLA or DCO)
- Adopt CNCF governance template
- Dual-company maintainership (recruit maintainers from adopting companies)
- Path to CNCF Incubation requires: production adoption by 3+ organizations, security audit

This governance evolution mirrors successful projects like containerd (BDFL -> neutral governance on CNCF joining).

### 4.4 Contribution Guidelines

**Extension points (easiest contributions):**

1. **Rulesets** (`rulesets/community/`) -- YAML security policies. Lowest barrier to entry. Validated by schema, tested by CI. This is the on-ramp for security practitioners who are not Rust developers.

2. **Guard plugins** -- Implement the `Guard` trait (sync) or `AsyncGuard` trait (async) in Rust. Well-defined interface. Examples provided. New guards are the primary feature contribution path.

3. **Transport adapters** (`spine/`) -- New Spine transport planes. The Reticulum adapter is the template. MQTT, ZeroMQ, or custom transports can be added without modifying the core protocol.

4. **Framework adapters** (`adapters/`) -- TypeScript/Python adapters for new agent frameworks (AutoGen, CrewAI, LangGraph). Thin wrappers that integrate the SDK with framework-specific hooks.

5. **Compliance templates** (`certification/`) -- SOC2, HIPAA, PCI-DSS, EU AI Act, FedRAMP templates mapping ClawdStrike capabilities to regulatory requirements.

6. **Bridge plugins** (`bridges/`) -- New kernel-level event sources (beyond Tetragon and Hubble). Falco, Sysdig, or custom eBPF programs can be bridged to the Spine.

**Contribution process:**
- All contributions via GitHub Pull Request
- DCO sign-off required (Developer Certificate of Origin, `Signed-off-by:` trailer)
- CI must pass: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --workspace`
- Security-sensitive changes require review from 2 maintainers
- Guard and ruleset contributions require test coverage

### 4.5 Documentation Strategy

**mdBook (already set up in ClawdStrike) + GitHub Pages:**

```
docs/src/
├── SUMMARY.md           # Table of contents
├── quickstart.md        # 5-minute getting started
├── installation.md      # All platforms + package managers
├── architecture/
│   ├── overview.md      # The five-layer stack
│   ├── design-axioms.md # From Aegis axioms
│   ├── trust-model.md   # Cryptographic trust chain
│   └── data-flow.md     # Event flow diagrams
├── guards/
│   ├── overview.md      # Guard system concepts
│   ├── built-in/        # One page per guard
│   ├── custom/          # Writing custom guards
│   └── async-guards.md  # AsyncGuard trait
├── spine/
│   ├── protocol.md      # Envelope/fact schemas
│   ├── nats.md          # NATS JetStream plane
│   ├── libp2p.md        # Public mesh plane
│   ├── reticulum.md     # Off-grid transport
│   └── proofs.md        # RFC 6962 verification
├── marketplace/
│   ├── overview.md      # Trust model
│   ├── publishing.md    # Author/curator workflow
│   ├── verification.md  # Client verification
│   └── curators.md      # Multi-curator configuration
├── deployment/
│   ├── standalone.md    # SDK-only (no daemon)
│   ├── daemon.md        # hushd deployment
│   ├── kubernetes.md    # K8s with Tetragon/Cilium
│   └── desktop.md       # Tauri desktop app
├── compliance/
│   ├── eu-ai-act.md
│   ├── soc2.md
│   ├── hipaa.md
│   └── fedramp.md
├── contributing/
│   ├── getting-started.md
│   ├── rulesets.md
│   ├── guards.md
│   ├── rfcs.md
│   └── code-of-conduct.md
└── research/            # Research docs (internal)
```

### 4.6 Release Cadence and Versioning

**Semantic Versioning (SemVer)** for all packages:

| Milestone | Version | Commitment |
|-----------|---------|------------|
| Initial public release | 0.1.0 | API unstable, expect breaking changes |
| Guard trait stabilized | 0.5.0 | Guard and AsyncGuard traits frozen |
| Spine protocol stabilized | 0.8.0 | Envelope/fact schemas frozen |
| Production-ready | 1.0.0 | Full API stability guarantee |

**Release cadence:**
- **Minor releases**: Monthly (new guards, adapters, rulesets, bug fixes)
- **Patch releases**: As needed for security fixes (within 48 hours for critical)
- **Major releases**: Yearly at most (1.0 -> 2.0 only for fundamental changes)

**Multi-language release coordination:**
- Rust crates: `cargo publish` to crates.io
- TypeScript: `npm publish` to npmjs.com as `@clawdstrike/*`
- Python: `uv publish` / `twine upload` to PyPI as `clawdstrike`
- WASM: Published alongside TypeScript as `@clawdstrike/wasm`
- Helm chart: Published to OCI registry (GitHub Container Registry)
- Desktop: GitHub Releases with platform-specific binaries (macOS, Linux, Windows)

---

## 5. Business Model (Open Core)

### 5.1 Open Source (Community Edition)

Everything needed to secure AI agents in production is free and open source:

| Component | What's Included |
|-----------|----------------|
| **Core engine** | HushEngine, Guard/AsyncGuard traits, policy evaluation, receipt signing |
| **7 built-in guards** | ForbiddenPath, EgressAllowlist, SecretLeak, PatchIntegrity, McpTool, PromptInjection, Jailbreak |
| **hushd daemon** | HTTP enforcement, SSE event broadcast, NATS subscriber, audit logging |
| **CLI** | `clawdstrike check`, policy validation, receipt verification |
| **Spine protocol** | SignedEnvelope, checkpointing, witness, proofs API, all transport adapters |
| **Bridges** | tetragon-nats-bridge, hubble-flow-bridge |
| **Desktop app** | Full SDR console (ThreatRadar, AttackGraph, NetworkMap, EventStream, Marketplace) |
| **SDK** | Rust, TypeScript, Python, WebAssembly |
| **Framework adapters** | Claude Code, Vercel AI, LangChain, Codex, OpenCode |
| **Marketplace** | Feed signing, bundle verification, P2P discovery, IPFS distribution |
| **Rulesets** | All built-in rulesets + community templates |
| **Compliance templates** | SOC2, HIPAA, EU AI Act, FedRAMP baseline templates |
| **Helm chart** | K8s deployment of full stack |
| **Documentation** | Complete mdBook docs, API reference, tutorials |

### 5.2 Commercial (ClawdStrike Cloud)

Revenue comes from managed services and enterprise features that organizations do not want to operate themselves:

**Tier 1: ClawdStrike Cloud (SaaS) -- Team Plan**

| Feature | Description |
|---------|-------------|
| **Managed Spine** | Hosted NATS JetStream cluster, checkpointer, witness, proofs API |
| **Dashboard** | Web-based SDR console (no Tauri desktop needed) |
| **Agent fleet management** | Centralized policy deployment across agent populations |
| **Hosted marketplace** | Curated marketplace with ClawdStrike-verified policies |
| **Alerting** | PagerDuty/Slack/webhook integrations for guard violations |
| **30-day retention** | Event and proof retention with query API |
| **Up to 50 agents** | Per-agent/month pricing |

**Pricing target**: $15-25/agent/month (comparable to infrastructure security tooling)

**Tier 2: ClawdStrike Cloud -- Enterprise Plan**

Everything in Team, plus:

| Feature | Description |
|---------|-------------|
| **RBAC** | Role-based access control for multi-team organizations |
| **SSO/SAML** | Enterprise identity provider integration |
| **Audit export** | Compliance-ready audit log export (JSON, CSV, SIEM format) |
| **Custom retention** | Configurable retention up to 2 years |
| **SLA** | 99.95% uptime guarantee with 24/7 support |
| **Dedicated infrastructure** | Isolated NATS cluster, dedicated witness |
| **Compliance bundles** | Pre-configured SOC2 Type II, HIPAA, FedRAMP evidence collection |
| **Priority support** | Slack channel, <4hr response for P1 incidents |
| **Unlimited agents** | Volume-based pricing |

**Pricing target**: Custom, starting at $5,000/month

**Tier 3: Verified Publisher Program**

| Feature | Description |
|---------|-------------|
| **Verification badge** | "ClawdStrike Verified" badge on marketplace policies |
| **Automated review** | CI/CD pipeline that validates policies against quality/security criteria |
| **Revenue share** | Authors earn 70% of commercial policy bundle sales |
| **Featured placement** | Priority listing in marketplace search results |
| **Publisher dashboard** | Install analytics, vulnerability reporting, version management |

**Pricing target**: Free to apply; 30% revenue share on commercial bundles

### 5.3 Revenue Model Analysis

**Comparable companies (security open core):**

| Company | Model | OSS License | ARR (2025) | How They Make Money |
|---------|-------|-------------|------------|---------------------|
| **Wiz** | Cloud-native security SaaS | Proprietary | ~$700M+ (targeting $1B) | Agentless cloud scanning, CNAPP |
| **Snyk** | Developer security SaaS | Freemium + OSS scanners | ~$343M | SCA, SAST, container scanning |
| **Elastic** | Open core + cloud | SSPL / Apache 2.0 | ~$1.3B | Elastic Cloud managed service |
| **HashiCorp** | Open core + cloud | BSL / MPL 2.0 | ~$614M | HCP managed Terraform/Vault/Consul |
| **Sysdig** | Open core + cloud | Apache 2.0 (Falco) | ~$250M+ | Sysdig Secure SaaS |
| **CrowdStrike** | SaaS + agent | Proprietary | ~$3.7B | Falcon platform subscription |

**Key insight**: The most successful model for infrastructure security is **fully open source core + managed SaaS**. Elastic proved that SSPL/proprietary conversion destroys community trust. Sysdig proved that keeping Falco fully open while selling managed services works. HashiCorp's BSL switch was controversial. The market rewards genuine openness.

ClawdStrike's advantage: the **Spine protocol** creates natural SaaS monetization. Running NATS JetStream clusters, checkpoint operators, witnesses, and proofs APIs at scale is operationally complex. Organizations that adopt ClawdStrike self-hosted for development will naturally upgrade to ClawdStrike Cloud for production -- the same pattern that drove Elastic Cloud, HCP, and Sysdig Secure adoption.

### 5.4 Revenue Projections (Conservative)

| Timeline | Milestone | Estimated ARR |
|----------|-----------|--------------|
| Month 0-6 | Open source launch, early adopters | $0 |
| Month 6-12 | Team plan beta, 50 organizations | $100K-$300K |
| Month 12-18 | Enterprise plan GA, 200 organizations | $1M-$3M |
| Month 18-24 | Enterprise traction, marketplace revenue | $5M-$10M |
| Year 3 | Growth phase, compliance demand (EU AI Act) | $20M-$40M |
| Year 5 | Category leader | $100M+ |

These projections assume the AI agent security market develops along the trajectory suggested by the 40-46% CAGR of the broader AI agent market, and that ClawdStrike captures a meaningful share of the security spend (~2-5% of the $52B agent economy's infrastructure/security budget).

---

## 6. Competitive Positioning

### 6.1 Competitive Landscape Matrix

| Capability | ClawdStrike (SDR) | CrowdStrike Falcon | Wiz | Sysdig / Falco | Aqua Security | OPA / Gatekeeper | Operant AI |
|---|---|---|---|---|---|---|---|
| **Agent-specific guards** (MCP, prompt injection, jailbreak) | 7 built-in + custom | No | No | No | No | No | Partial |
| **Kernel runtime enforcement** (eBPF) | Via Tetragon bridge | Falcon sensor (proprietary) | No (agentless) | Falco (detect only) | Runtime policies | No | No |
| **Kernel-level execution proofs** | Spine Merkle proofs | No | No | No | No | No | No |
| **Cross-layer attestation chain** | SPIRE -> Cilium -> Tetragon -> Spine | No | No | No | No | No | No |
| **Cryptographic receipt per decision** | Ed25519 signed receipts | No | No | No | No | No | No |
| **Transparency log + witness** | RFC 6962 Merkle tree + witness co-sign | No | No | No | No | No | No |
| **Offline mesh enforcement** | Reticulum transport (LoRa, serial, packet radio) | No | No | No | No | No | No |
| **Policy marketplace** | Community-curated, multi-curator, signed | CrowdStrike Store (vendor) | No | No | No | Bundles (unsigned) | No |
| **Decentralized trust** | Multi-curator, IPFS, EAS anchoring | No | No | No | No | No | No |
| **Offline verification** | Portable proof bundles | No | No | No | No | No | No |
| **Open source** | Full stack (Apache 2.0) | Proprietary | Proprietary | Falco (Apache 2.0) | Trivy (Apache 2.0) | Apache 2.0 | Proprietary |
| **License** | Apache 2.0 | N/A | N/A | Apache 2.0 | Apache 2.0 | Apache 2.0 | N/A |

### 6.2 Detailed Competitive Analysis

**vs CrowdStrike Falcon**

CrowdStrike dominates EDR with ~$3.7B ARR and the Falcon sensor on millions of endpoints. But Falcon is designed for endpoints, not AI agents. It has no concept of:
- Agent tool boundaries (MCP, function calling, prompt injection)
- Policy-gated actions with cryptographic receipts
- Community-curated security policies
- Offline-capable mesh enforcement

CrowdStrike could theoretically build agent-specific features, but their architecture is fundamentally endpoint-centric. The Falcon sensor watches processes and files; ClawdStrike watches agent actions and tool invocations. These are different security primitives requiring different architectures.

**Strategic positioning**: "CrowdStrike secures your laptops. ClawdStrike secures your AI agents."

**vs Wiz**

Wiz is the fastest-growing security company ($700M+ ARR, targeting $1B by 2026), focused on cloud security posture management (CSPM). Wiz is agentless -- it scans cloud configurations and finds misconfigurations. It has no runtime enforcement capability. No agent-level visibility. No proof infrastructure.

**Strategic positioning**: "Wiz tells you your cloud is misconfigured. ClawdStrike proves your agents operated within policy."

**vs Sysdig / Falco**

Sysdig is the closest architectural competitor. Falco (open source, Apache 2.0, CNCF graduated) provides runtime security detection using eBPF. Sysdig Secure adds commercial features on top. However:
- Falco is detection-only (alerts, not enforcement)
- No agent-specific guards
- No cryptographic proof chain
- No marketplace for community policies
- No offline mesh capability

ClawdStrike integrates with Tetragon (which provides enforcement, not just detection) and adds the attestation layer that Falco lacks.

**Strategic positioning**: "Falco detects container threats. ClawdStrike enforces AI agent policy with cryptographic proof."

**vs OPA / Gatekeeper**

OPA is the standard for Kubernetes admission control. Gatekeeper enforces OPA policies on cluster resources. But OPA is policy-only:
- No runtime detection
- No agent-level guards
- No proof infrastructure
- No eBPF integration
- Kubernetes-specific (not agent-runtime-aware)

ClawdStrike could potentially generate OPA/Rego policies from its YAML rulesets for complementary k8s enforcement.

**Strategic positioning**: "OPA gates what enters your cluster. ClawdStrike gates what your agents do inside it."

**vs Operant AI (Agent Protector)**

Operant AI launched Agent Protector in February 2026, the most direct competitor. However, Operant is:
- Proprietary (no open source core)
- No kernel-level enforcement (application layer only)
- No cryptographic proof chain
- No offline capability
- No community marketplace

**Strategic positioning**: "Operant AI is a proprietary agent firewall. ClawdStrike is an open source, kernel-enforced, cryptographically provable SDR platform."

**vs Nothing (Greenfield)**

The most honest comparison: 63% of organizations deploying AI agents have no security controls at all. ClawdStrike's primary competitor is **inertia and the absence of tooling**. The quickest path to adoption is making the open source SDK trivially easy to integrate:

```bash
# One line to add ClawdStrike to any AI agent
pip install clawdstrike
```

```python
from clawdstrike import HushEngine

engine = HushEngine.from_policy("strict")
result = engine.check(action_type="file_access", target="/etc/passwd")
if result.denied:
    raise SecurityError(result.reason)
```

### 6.3 Defensibility

ClawdStrike's competitive moat has multiple layers:

1. **Protocol moat**: The Spine protocol (SignedEnvelope + Merkle proofs + witness co-signatures) is a novel combination. Competitors cannot replicate the cross-layer attestation chain without building equivalent infrastructure.

2. **Ecosystem moat**: The policy marketplace creates network effects. More rulesets attract more users. More users attract more ruleset authors. This flywheel is hard to replicate once established.

3. **Community moat**: Open source projects with active communities are very difficult to displace. Once organizations invest in writing ClawdStrike guards and rulesets, switching costs are high.

4. **Integration moat**: Deep integration with CNCF ecosystem (Tetragon, Cilium, SPIRE, NATS) creates an infrastructure surface area that proprietary competitors cannot match.

5. **Compliance moat**: Once compliance teams standardize on ClawdStrike's audit trail format for EU AI Act / SOC2 / HIPAA reporting, changing systems requires re-certifying.

---

## 7. Community Growth Strategy

### 7.1 Launch Playbook

**Pre-launch (Month -2 to 0):**

- Polish README with compelling "what is this" narrative + animated demo
- 5-minute quickstart that works on macOS, Linux, and Windows (WSL)
- `clawdstrike init` command that generates a starter policy for any project
- GitHub repository with all CI green, documentation deployed, examples working
- Announce on Hacker News, Reddit r/netsec, r/machinelearning, CNCF Slack

**Launch week:**

- Blog post: "Introducing ClawdStrike: Open Source Swarm Detection & Response for AI Agents"
- Live demo: Secure a Claude agent with ClawdStrike in 5 minutes (YouTube)
- Twitter/X thread: The CrowdStrike -> ClawdStrike narrative
- Discord community launch with `#rulesets`, `#guards`, `#spine`, `#help` channels

**Month 1-3:**

- Weekly blog series: "Securing AI Agent Swarms" (thought leadership content)
- KubeCon / CNCF presentation proposal
- CTF challenge: "Break through ClawdStrike's guards" (security education + community engagement)
- First community ruleset contributions merged

### 7.2 Contribution On-Ramps (Ordered by Difficulty)

| Level | Contribution Type | Skill Required | Example |
|-------|-------------------|---------------|---------|
| 1 | **Rulesets** | YAML, security knowledge | `rulesets/community/prevent-ssh-key-exfil.yaml` |
| 2 | **Documentation** | English, technical writing | Improve quickstart, add deployment guide |
| 3 | **Framework adapters** | TypeScript/Python | `@clawdstrike/autogen`, `@clawdstrike/crewai` |
| 4 | **Compliance templates** | Regulatory knowledge | EU AI Act Article 12 mapping template |
| 5 | **Custom guards** | Rust | New guard implementing `Guard` or `AsyncGuard` trait |
| 6 | **Transport adapters** | Rust/Python + networking | MQTT Spine transport, ZeroMQ transport |
| 7 | **Bridge plugins** | Rust + eBPF knowledge | Falco -> Spine bridge, custom eBPF program bridge |
| 8 | **Core protocol** | Rust + cryptography | Spine protocol extensions, Merkle tree optimizations |

### 7.3 Community Channels

| Channel | Purpose | Audience |
|---------|---------|----------|
| **GitHub Discussions** | Feature requests, architecture discussions, Q&A | All |
| **Discord** | Real-time chat, community support, contributor coordination | All |
| **Weekly community call** (30min, recorded) | Demos, roadmap updates, contributor spotlights | Contributors |
| **Monthly security office hours** | Deep dives into guard design, threat modeling | Security engineers |
| **Blog** (clawdstrike.io/blog) | Thought leadership, tutorials, release notes | Broader audience |
| **Twitter/X** (@clawdstrike) | Announcements, links, community highlights | Broader audience |

### 7.4 Adoption Flywheel

```
Open source SDK is easy to install
         │
         ▼
Developers add ClawdStrike to their agents (5 min)
         │
         ▼
Agents produce cryptographic receipts (audit trail)
         │
         ▼
Compliance teams discover receipts satisfy EU AI Act / SOC2
         │
         ▼
Organization mandates ClawdStrike across all agent workloads
         │
         ▼
Organization needs fleet management → ClawdStrike Cloud ($$)
         │
         ▼
Organization contributes guards/rulesets back to community
         │
         ▼
More rulesets → more value → more developers adopt
```

### 7.5 CTF / Education Strategy

**ClawdStrike CTF: "Swarm Wars"**

A series of CTF challenges designed to teach AI agent security concepts:

1. **Level 1**: Bypass a permissive policy to exfiltrate a secret (teaches: why rulesets matter)
2. **Level 2**: Prompt-inject an agent to call unauthorized MCP tools (teaches: McpToolGuard)
3. **Level 3**: Jailbreak an agent past the 4-layer detection (teaches: JailbreakGuard)
4. **Level 4**: Tamper with a guard receipt (teaches: cryptographic verification)
5. **Level 5**: Coordinate a multi-agent swarm attack (teaches: why SDR is needed)

Each challenge runs in a sandboxed environment with ClawdStrike deployed. Solutions are educational write-ups published after the event. This builds community, generates content, and positions ClawdStrike as the thought leader in AI agent security.

---

## 8. Brand & Naming

### 8.1 Project Name: ClawdStrike

- **Memorable**: Playful, immediately evokes CrowdStrike (the gold standard in endpoint security)
- **Aspirational**: Signals ambition to define a category, not just build a tool
- **Searchable**: Unique enough to own search results
- **Personality**: The "Clawd" pun (Claude + claws) adds character without being unprofessional

### 8.2 Category Name: SDR (Swarm Detection & Response)

- **Clear parallel**: EDR -> SDR. Security buyers instantly understand the positioning
- **Descriptive**: "Swarm" captures the multi-agent threat model. "Detection & Response" captures the dual capability
- **Expandable**: SDR can encompass runtime enforcement, attestation, marketplace, and compliance -- just as EDR expanded from "detect endpoint threats" to a full platform

### 8.3 Component Names

| Name | Component | Meaning |
|------|-----------|---------|
| **ClawdStrike** | The project | The platform, the brand, the category creator |
| **SDR** | The category | Swarm Detection & Response |
| **hush-core** | Crypto primitives | "Hush" = quiet, confidential security |
| **hushd** | Enforcement daemon | "Hush daemon" = silent enforcement |
| **HushEngine** | Policy engine facade | The orchestrator of quiet enforcement |
| **Guards** | Policy enforcement primitives | Guards at the tool boundary |
| **Spine** | Protocol layer | The backbone connecting all layers |
| **Receipts** | Signed attestations | Proof of guard decisions |
| **Marketplace** | Policy distribution | Community-curated security policies |

### 8.4 Taglines

- **Primary**: "Swarm Detection & Response for AI Agents"
- **Technical**: "Kernel-enforced, cryptographically provable security for autonomous AI"
- **Business**: "Prove what your AI agents did. Every action. Every proof."
- **Community**: "The open source standard for AI agent security"

---

## 9. Timeline: Phased Execution

### Phase 0: Foundation (Weeks 1-4)

**Goal**: Restructure the ClawdStrike repo for the target monorepo layout.

| Task | Owner | Duration | Dependencies |
|------|-------|----------|--------------|
| Restructure crates/ → top-level directories | Core team | 1 week | None |
| Move packages/ → sdk/ | Core team | 3 days | Restructure |
| Move apps/desktop → desktop/ | Core team | 3 days | Restructure |
| Update all import paths, Cargo.toml workspace | Core team | 1 week | All moves |
| CI green on restructured layout | Core team | 3 days | Path updates |
| Switch license to Apache 2.0 | Legal review | 1 week | None |
| Create CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md | Core team | 3 days | None |

**Milestone**: All existing tests pass on the new repo structure. License updated.

### Phase 1: Spine Integration (Weeks 3-8)

**Goal**: Copy AegisNet services into the repo and make Spine a first-class citizen.

| Task | Owner | Duration | Dependencies |
|------|-------|----------|--------------|
| Copy AegisNet checkpointer/witness/proofs-api into spine/nats/ | Core team | 1 week | Phase 0 |
| Adapt Spine services to build within ClawdStrike workspace | Core team | 1 week | Copy |
| Copy Aegis Spine protocol types into spine/src/ | Core team | 1 week | Phase 0 |
| Implement Reticulum adapter scaffold (spine/reticulum/) | Reticulum lead | 2 weeks | Spine types |
| Write mdBook docs for Spine protocol | Docs lead | 2 weeks | Spine types |
| Helm chart for deploying Spine services (deploy/helm/) | Infra lead | 1 week | Spine build |

**Milestone**: `cargo build --workspace` includes Spine services. Spine E2E test passes.

### Phase 2: Bridges (Weeks 6-12)

**Goal**: Build the Tetragon and Hubble bridges.

| Task | Owner | Duration | Dependencies |
|------|-------|----------|--------------|
| Implement tetragon-nats-bridge (bridges/tetragon/) | Bridge team | 3 weeks | Spine integration |
| Implement hubble-flow-bridge (bridges/hubble/) | Bridge team | 2 weeks | Spine integration |
| TracingPolicy templates (deploy/tetragon-policies/) | Security team | 1 week | None |
| Integration test: Tetragon event -> Spine -> Merkle proof | QA | 1 week | Both bridges |

**Milestone**: Tetragon events flow through Spine and produce verifiable Merkle inclusion proofs.

### Phase 3: Documentation & Polish (Weeks 10-14)

**Goal**: Documentation, examples, and contributor experience ready for public launch.

| Task | Owner | Duration | Dependencies |
|------|-------|----------|--------------|
| Complete mdBook documentation site | Docs team | 3 weeks | All features |
| 5-minute quickstart guide | Developer advocate | 1 week | Docs |
| 3 runnable examples (basic, sandbox, multi-agent) | Examples team | 2 weeks | Docs |
| README with animated demo (asciinema/GIF) | Developer advocate | 1 week | Examples |
| CTF challenge design (3 levels minimum) | Security team | 2 weeks | Docs |
| Community infrastructure: Discord, GitHub Discussions | Community lead | 1 week | None |
| Security audit (external, focused on crypto + Spine) | External firm | 4 weeks | Phase 2 |

**Milestone**: A new contributor can clone, build, run examples, and submit a ruleset PR in under 30 minutes.

### Phase 4: Public Launch (Week 14-16)

**Goal**: Open source release.

| Task | Owner | Duration | Dependencies |
|------|-------|----------|--------------|
| GitHub public repo (transfer from private) | Core team | 1 day | Phase 3 |
| crates.io publish (hush-core, clawdstrike, hushd, hush-cli) | Release engineer | 1 day | Public repo |
| npm publish (@clawdstrike/sdk, adapters) | Release engineer | 1 day | Public repo |
| PyPI publish (clawdstrike) | Release engineer | 1 day | Public repo |
| Blog post: "Introducing ClawdStrike" | Comms | 1 day | All packages |
| Hacker News, Reddit, CNCF Slack announcements | Comms | 1 day | Blog post |
| Community call #1 | Community lead | 1 week after launch | Launch |

**Milestone**: Public GitHub repo with >100 stars in first week. First external PR merged.

### Phase 5: Commercial (Weeks 16-30)

**Goal**: Launch ClawdStrike Cloud beta.

| Task | Owner | Duration | Dependencies |
|------|-------|----------|--------------|
| ClawdStrike Cloud infrastructure (hosted Spine) | Infra team | 6 weeks | Phase 4 |
| Web dashboard (SPA, read-only console) | Frontend team | 4 weeks | Cloud infra |
| Team plan billing (Stripe integration) | Billing team | 3 weeks | Cloud infra |
| Enterprise plan features (RBAC, SSO, audit export) | Platform team | 6 weeks | Team plan |
| Verified Publisher Program infrastructure | Marketplace team | 4 weeks | Phase 4 |
| First compliance certification (SOC2 Type II) | Compliance | Ongoing | Cloud infra |

**Milestone**: 50 paying organizations on ClawdStrike Cloud Team plan.

### Phase 6: Category Establishment (Months 6-18)

**Goal**: Establish SDR as a recognized security category.

| Task | Duration | Dependencies |
|------|----------|--------------|
| CNCF Sandbox application | 2 months | >3 production adopters, >2 company maintainers |
| Analyst briefings (Gartner, Forrester) | Ongoing | Commercial traction |
| KubeCon / Black Hat / RSA presentations | Event-driven | Technical content |
| EU AI Act compliance toolkit launch | 3 months | Compliance templates |
| "State of SDR" annual report | Yearly | Community data |
| Multi-company maintainership | Ongoing | Community growth |

**Milestone**: Gartner mentions SDR as an emerging category. CNCF Sandbox accepted.

---

## References

### Internal Sources

- [Architecture Vision](./architecture-vision.md) -- Five-layer security stack, data flow, competitive positioning
- [Tetragon Integration](./tetragon-integration.md) -- eBPF runtime security, TracingPolicies, AegisNet pipeline
- [Cilium Network Security](./cilium-network-security.md) -- CNI migration, SPIRE mTLS, Hubble observability
- [Marketplace Trust Evolution](./marketplace-trust-evolution.md) -- Multi-curator, AegisNet notary, EAS, IPFS, community curation
- [Reticulum Transport Profile](../../../../platform/docs/specs/cyntra-aegis-spine-reticulum.md) -- Off-grid Spine transport
- [Aegis Net Design Axioms](../../../../platform/docs/specs/cyntra-aegis-net-design-axioms.md) -- Security invariants
- [AegisNet Architecture](../../../aegis/apps/aegis/services/aegisnet/ARCHITECTURE.md) -- Verifiable log system

### Market Research

- [AI Agents Market Size, Share & Trends (2026-2034)](https://www.fortunebusinessinsights.com/ai-agents-market-111574) -- $9.14B (2026) to $139.19B (2034), 40.5% CAGR
- [AI Agents Market (DemandSage)](https://www.demandsage.com/ai-agents-market-size/) -- $7.8B (2025) to $52.6B (2030), 46.3% CAGR
- [Agentic AI Market (Precedence)](https://www.precedenceresearch.com/agentic-ai-market) -- USD $199.05 billion by 2034
- [Official 2026 Cybersecurity Market Report](https://cybersecurityventures.com/official-2026-cybersecurity-market-report-predictions-and-statistics/) -- $520B annual cybersecurity spending by 2026
- [What's Shaping the AI Agent Security Market in 2026 (CyberArk)](https://www.cyberark.com/resources/blog/whats-shaping-the-ai-agent-security-market-in-2026) -- 63% governance gap
- [AI Swarm Attacks: What Security Teams Need to Know (Kiteworks)](https://www.kiteworks.com/cybersecurity-risk-management/ai-swarm-attacks-2026-guide/) -- First documented AI swarm attack (Nov 2025)
- [State of AI Agent Security 2026 (Gravitee)](https://www.gravitee.io/blog/state-of-ai-agent-security-2026-report-when-adoption-outpaces-control) -- Adoption outpacing control
- [Enterprise AI Security Predictions 2026 (Lasso Security)](https://www.lasso.security/blog/enterprise-ai-security-predictions-2026) -- Runtime enforcement as new category
- [Operant AI Agent Protector Launch](https://siliconangle.com/2026/02/05/operant-ai-debuts-agent-protector-secure-autonomous-ai-agents-scale/) -- Competitive validation
- [Agentic Trust Framework (CSA)](https://cloudsecurityalliance.org/blog/2026/02/02/the-agentic-trust-framework-zero-trust-governance-for-ai-agents) -- Zero trust for AI agents
- [6 Cybersecurity Predictions for AI Economy (HBR/Palo Alto)](https://hbr.org/sponsored/2025/12/6-cybersecurity-predictions-for-the-ai-economy-in-2026) -- AI security market trends

### Competitive Intelligence

- [Wiz Growth Playbook (Software Analyst)](https://softwareanalyst.substack.com/p/the-wiz-playbook-how-they-dominated) -- Fastest to $500M ARR
- [Snyk Business Breakdown (Contrary Research)](https://research.contrary.com/company/snyk) -- $343M ARR, open source security model
- [CrowdStrike EDR Overview](https://www.crowdstrike.com/en-us/cybersecurity-101/endpoint-security/endpoint-detection-and-response-edr/) -- Category definition
- [Tetragon eBPF Runtime Security](https://tetragon.io/) -- CNCF project, Apache 2.0
- [Cilium Documentation](https://docs.cilium.io/) -- CNCF graduated, Apache 2.0
- [Falco Cloud Native Runtime Security](https://github.com/falcosecurity/falco) -- CNCF graduated, Apache 2.0
- [Best OSS Security for Kubernetes 2026 (ARMO)](https://www.armosec.io/blog/best-open-source-kubernetes-security-tools/) -- Landscape overview

### Open Source & Governance

- [MIT and Apache 2.0 Lead Open Source Licensing 2025 (Linuxiac)](https://linuxiac.com/mit-and-apache-2-0-lead-open-source-licensing-in-2025/) -- License popularity data
- [Apache License 2.0 Guide (FOSSA)](https://fossa.com/blog/open-source-licenses-101-apache-license-2-0/) -- Patent grant details
- [CNCF Governance Principles](https://www.cncf.io/blog/2019/08/30/cncf-technical-principles-and-open-governance-success/) -- Open governance model
- [Understanding Open Source Governance (Red Hat)](https://www.redhat.com/en/blog/understanding-open-source-governance-models) -- BDFL vs committee models
- [CNCF Governance Elections Template](https://contribute.cncf.io/resources/templates/governance-elections/) -- Steering committee template

### Regulatory

- [EU AI Act Implementation Timeline](https://artificialintelligenceact.eu/implementation-timeline/) -- Key compliance dates
- [EU AI Act Article 16: Provider Obligations](https://artificialintelligenceact.eu/article/16/) -- Post-market monitoring
- [EU AI Act Article 50: Transparency Obligations](https://artificialintelligenceact.eu/article/50/) -- Disclosure requirements
- [EU AI Act Compliance Checker](https://artificialintelligenceact.eu/assessment/eu-ai-act-compliance-checker/) -- Self-assessment tool
