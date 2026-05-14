# Sentinel Swarm — Architecture & Planning Index

> Brainstorming, planning, and architecture design for evolving the Clawdstrike Workbench
> into a sentinel-swarm model with Speakeasy-backed trust coordination.

**Status:** Design complete, phase 1 execution in progress
**Date:** 2026-03-12
**Branch:** `feat/sentinel-swarm`

---

## Table of Contents

1. [Product Ontology](#1-product-ontology)
2. [Current Codebase State](#2-current-codebase-state)
3. [Proposed Object Model](#3-proposed-object-model)
4. [Architecture Mapping: What Exists → What's Needed](#4-architecture-mapping)
5. [Speakeasy Integration Design](#5-speakeasy-integration-design)
6. [Information Architecture (Navigation)](#6-information-architecture)
7. [Data Flow: Sentinel → Signal → Finding → Intel → Swarm](#7-data-flow)
8. [Phased Implementation Plan](#8-phased-implementation-plan)
9. [Key File Reference](#9-key-file-reference)
10. [Open Questions](#10-open-questions)
11. [Next-Wave Plans](#11-next-wave-plans)

---

## 1. Product Ontology

The core product model uses six nouns, each with a distinct job:

| Object        | What it is                                                              | Volume / Certainty       |
|---------------|-------------------------------------------------------------------------|--------------------------|
| **Sentinel**  | A persistent, user-owned autonomous defender with memory, goals, policies | The main autonomous worker |
| **Signal**    | A raw clue, anomaly, event, weak indicator, or candidate detection      | High volume, low certainty |
| **Finding**   | A grouped, enriched, scored conclusion built from one or more signals   | Lower volume, higher value |
| **Intel**     | A portable, shareable knowledge artifact derived from findings          | Distilled, publishable   |
| **Swarm**     | A coordination layer where sentinels and operators share intel          | Network effects          |
| **Speakeasy** | A private signed room for sensitive collaboration and intel exchange    | Trust-gated coordination |

**Key distinction:** Signal = "something interesting happened." Finding = "this is worth a human or another agent caring about."

### Sentinel Modes

All modes are still "Sentinels" — keeps the product simple:

- **Watcher** — continuous monitoring/detection
- **Hunter** — exploratory or recurring threat hunts
- **Curator** — groups signals, writes summaries, promotes patterns
- **Liaison** — participates in swarms/speakeasies and exchanges intel

### Swarm Layers

| Layer              | Scope                          | When it matters           |
|--------------------|--------------------------------|---------------------------|
| **Personal swarm** | Your own sentinels coordinating | Solo user, day 1          |
| **Trusted swarm**  | Team, org, or invited peers    | Shared detection lift     |
| **Federated swarm**| Cross-org, opt-in exchange     | Network effects at scale  |

---

## 2. Current Codebase State

### Workbench App (`apps/workbench/`)

**Stack:** React 19 + Vite 6 + TypeScript 5 + TailwindCSS 4 + Tauri 2 (desktop)
**Scale:** 237 TSX files, ~47K lines of component code

**Current navigation (15 routes):**
```
/home          Dashboard with guard health ring
/editor        Policy visual/YAML editor (multi-tab)
/simulator     Threat Lab — scenario builder + red-team (promptfoo)
/hunt          Activity stream + anomaly detection + investigations + patterns
/compare       Side-by-side policy diffs
/compliance    Regulatory framework coverage (HIPAA/SOC2/PCI-DSS)
/receipts      Receipt inspector + import/export
/delegation    Multi-agent capability graph (force-directed SVG)
/approvals     Approval queue + origin-aware scoping
/hierarchy     Scoped policies + assignment matrix
/fleet         Agent dashboard (status, heartbeat, versions, drift)
/audit         Event log (multi-source)
/guards        Guard reference catalog (13 guards)
/library       Policy templates + pre-built scenarios
/settings      General preferences
```

**State management:** React Context + useReducer (`MultiPolicyState`), feature-scoped hooks
**Persistence:** localStorage (policies, settings, receipts), Stronghold vault (Tauri credentials)
**Real-time:** HTTP polling only (30s health, 60s agents, 30s hunt stream). No WebSocket/SSE yet.

### Existing Swarm-Adjacent Features

| Feature | Location | Relevance |
|---------|----------|-----------|
| **Hunt Lab** | `/hunt` — `hunt-layout.tsx`, `hunt-engine.ts`, `hunt-types.ts` | Has AgentEvent, anomaly scoring, baselines, pattern mining, investigations — natural Signal/Finding precursor |
| **Delegation Graph** | `/delegation` — `delegation-page.tsx`, `delegation-types.ts` | Force-directed graph of Principals → Sessions → Grants → Approvals → Events — models trust flow |
| **Approval Queue** | `/approvals` — `approval-queue.tsx`, `approval-types.ts` | Origin-aware (Slack/Teams/GitHub/Jira), TTL-scoped, risk-leveled — natural Speakeasy integration point |
| **Hierarchy** | `/hierarchy` — `hierarchy-page.tsx` | Scoped policies per org/team/agent, sync to fleet — precursor to swarm policy distribution |
| **Fleet Dashboard** | `/fleet` — `fleet-dashboard.tsx`, `fleet-client.ts` | Agent enrollment, heartbeat, drift detection — precursor to sentinel registration |
| **Pattern Mining** | Within hunt — `hunt-engine.ts` | N-gram discovery, pattern promotion — precursor to Intel artifacts |

### Existing Hunt Types (map directly to Signal/Finding)

```typescript
// Current: AgentEvent → maps to Signal
AgentEvent {
  id, timestamp, agentId, sessionId, actionType, target,
  verdict: "allow" | "deny" | "warn",
  guardResults: GuardSimResult[],
  flags: EventFlag[],        // anomaly, escalated, tag, pattern-match
  anomalyScore: 0–1
}

// Current: Investigation → maps to Finding
Investigation {
  title, status, severity,
  eventIds[], agentIds[], sessionIds[], timeRange,
  annotations[],             // analyst notes with provenance
  verdict?, actions?         // policy-updated, pattern-added, agent-revoked, escalated
}

// Current: HuntPattern → maps to Intel candidate
HuntPattern {
  sequence: PatternStep[],
  matchCount, exampleSessionIds,
  status: "draft" | "confirmed" | "promoted" | "dismissed"
}
```

### Rust Core Types

**Policy engine** (`crates/libs/clawdstrike/src/`):
- `Policy`, `GuardConfigs`, `HushEngine` — orchestrates 13 built-in guards
- `Receipt`, `SignedReceipt` — Ed25519-signed attestations with RFC 8785 canonical JSON
- `GuardAction`, `GuardResult`, `GuardContext`, `Severity`
- Guard pipeline: BuiltIn → Custom → Extra → Async (fail-closed)

**Multi-agent** (`crates/libs/hush-multi-agent/src/`):
- `DelegationClaims` — JWT-like with capability ceiling, attenuation-only chains
- `SignedDelegationToken` — Ed25519-signed delegation
- `AgentCapability`, `AgentId`

**Spine protocol** (`crates/libs/spine/src/`):
- `Envelope` — signed fact messages on attestation log
- `Checkpoint` — log snapshot with Merkle root
- NATS transport + trust model for issuer verification

**Hunt correlation** (`crates/libs/hunt-correlate/src/`):
- `Alert`, `DetectionRuleCompilation`, `EvidenceItem`, `TimelineEvent`, `IocMatch`
- Supports native correlation, Sigma, YARA, threshold-based, policy-backed rules
- `HuntReport` — Merkle-anchored evidence with inclusion proofs

**Spider-Sense** (`crates/libs/clawdstrike/src/spider_sense.rs`):
- Two-tier: fast-path (embedding cosine similarity) + deep-path (optional LLM)
- `PatternDb`, `PatternEntry`, `PatternMatch`, `ScreeningResult`
- Embedded `s2bench-v1` pattern database (36 entries)

**Origin-aware** (`crates/libs/clawdstrike/src/origin.rs`):
- `OriginContext` — provider, space, actor, visibility, tags, sensitivity
- `OriginProvider` — Slack, Teams, GitHub, Jira, Email, Discord, Webhook

### TS SDK (`packages/`)

- `@clawdstrike/sdk` (hush-ts) — `Clawdstrike` class, 13 guards, receipts, SIEM exporters
- `@clawdstrike/hunt` — `hunt()`, `CorrelationEngine`, `correlate()`, `Playbook`, `stream()`, MITRE ATT&CK mapping
- `@clawdstrike/policy` — canonical TS policy engine, custom guard registry
- `@clawdstrike/adapter-core` — `FrameworkAdapter`, `ToolInterceptor`, `SecurityContext`, `Decision` types
- `@clawdstrike/origin-core` — `OriginContext`, `TrustAdapter`, approval workflows
- Framework adapters: Claude, OpenAI, LangChain, Vercel AI, OpenCode
- Engine bridges: local (CLI subprocess), remote (hushd HTTP), adaptive (hybrid fallback)

### Backbay SDK — Speakeasy (`@backbay/speakeasy`)

**Location:** `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/speakeasy/`

**Identity system:**
- `BayChatIdentity` — Ed25519 keypair, 16-char hex fingerprint, BIP39 24-word seed phrase
- `generateIdentity()`, `recoverIdentity(seedPhrase)` — deterministic derivation
- 8 sigil types (diamond, eye, wave, crown, spiral, key, star, moon) — derived from fingerprint
- Color derivation: HSL from fingerprint bytes

**Message signing:**
- `createSignedMessage()` — Ed25519 over SHA-256 hash of canonical content
- `verifyMessage()` — recompute hash, verify signature, check sender
- Message types: `ChatMessage`, `SentinelRequest`, `SentinelResponse`, `PresenceMessage`, `TypingMessage`, `BountyCreated/Claimed`
- Nonce per message (replay prevention), 5-min timestamp tolerance

**Transport (libp2p 2.0 + Gossipsub):**
- WebSocket, WebRTC, Circuit Relay transports
- Ed25519 Noise encryption for peer connections
- Topic structure: `/baychat/v1/speakeasy/{id}/messages|presence|typing`
- Global topics: `/baychat/v1/discovery`, `/baychat/v1/sentinels`
- `MessageEnvelope` — version, type, payload, TTL (default 10 hops), created timestamp
- Peer discovery, connect/disconnect events, subscription management

**React hooks:**
- `useIdentity()` — create, recover, persist to IndexedDB
- `useTransport()` — connect, joinSpeakeasy, publish, peer tracking
- `useMessages()` — dedup by ID, auto-verify signatures, sorted storage (max 1000)

**Related packages:**
- `@backbay/witness` — RunReceipt verification via WASM, Merkle proofs, multi-chain (Rekor, EAS, Solana)
- `@backbay/notary` — IPFS + EAS attestation publishing, Lit Protocol, ENS, cross-chain proofs
- `@backbay/contract` — shared platform types (UserProfile, marketplace, mission, agent contracts)

---

## 3. Proposed Object Model

### New Types to Introduce

```typescript
// ─── Sentinel ───────────────────────────────────────
interface Sentinel {
  id: string                          // Unique sentinel ID
  name: string                        // User-facing name
  mode: "watcher" | "hunter" | "curator" | "liaison"
  owner: string                       // User/org who created it
  identity: SentinelIdentity          // Ed25519 keypair (Speakeasy-compatible)
  policy: PolicyRef                   // Policy governing this sentinel
  goals: SentinelGoal[]               // What it's looking for
  memory: SentinelMemory              // Accumulated knowledge
  schedule: string | null             // Cron expression for recurring hunts
  status: "active" | "paused" | "retired"
  swarms: SwarmMembership[]           // Which swarms it participates in
  stats: SentinelStats                // Lifetime metrics
  createdAt: number
}

interface SentinelGoal {
  type: "detect" | "hunt" | "monitor" | "enrich"
  description: string
  sources: DataSource[]               // What to watch
  patterns?: PatternRef[]             // What to look for
  escalation: EscalationPolicy        // When to promote to Finding
}

interface SentinelMemory {
  knownPatterns: MemoryPattern[]      // Accumulated pattern knowledge (see DATA-MODEL.md)
  baselineProfiles: AgentBaseline[]   // Learned normal behavior
  falsePositiveHashes: string[]      // SHA-256 hashes of known FPs for suppression
  lastUpdated: number
}

// ─── Signal ─────────────────────────────────────────
// Evolution of current AgentEvent
interface Signal {
  id: string
  type: "anomaly" | "detection" | "indicator" | "policy_violation" | "behavioral"
  source: SignalSource                // Which sentinel, guard, or external feed
  timestamp: number
  severity: "info" | "low" | "medium" | "high" | "critical"
  confidence: number                  // 0.0–1.0
  data: SignalData                    // Typed payload per signal type
  context: SignalContext              // Agent, session, origin info
  relatedSignals: string[]           // Correlation links (default [])
  ttl: number | null                 // Auto-expire weak signals (null = persist)
  findingId: string | null           // Set when rolled into a Finding
}

interface SignalSource {
  sentinelId: string | null
  guardId: string | null
  externalFeed: string | null
  provenance: SignalProvenance        // How this was generated
}
// SignalProvenance = "guard_evaluation" | "anomaly_detection" | "pattern_match"
//   | "correlation_rule" | "spider_sense" | "external_feed" | "swarm_intel" | "manual"

// ─── Finding ────────────────────────────────────────
// Evolution of current Investigation
interface Finding {
  id: string
  title: string
  status: "emerging" | "confirmed" | "promoted" | "dismissed" | "false_positive"
  severity: "low" | "medium" | "high" | "critical"
  confidence: number
  signalIds: string[]                 // Contributing signals
  signalCount: number
  timeline: TimelineEntry[]           // Chronological narrative
  enrichments: Enrichment[]           // Added context (MITRE, IOC, etc.)
  annotations: Annotation[]           // Human/sentinel commentary
  verdict: FindingVerdict | null
  actions: FindingAction[]
  promotedToIntel: string | null      // Intel artifact ID if promoted
  receipt: SignedReceipt | null       // Provenance attestation
  createdAt: number
  createdBy: string                   // Sentinel or human who created
  updatedBy: string                   // Sentinel or human who last updated
}

// ─── Intel ──────────────────────────────────────────
// Portable knowledge derived from Findings
interface Intel {
  id: string
  type: "detection_rule" | "pattern" | "ioc" | "campaign" | "advisory" | "policy_patch"
  title: string
  description: string
  content: IntelContent               // The actual shareable artifact
  derivedFrom: string[]               // Finding IDs
  confidence: number
  tags: string[]
  mitre: MitreMapping[]
  shareability: "private" | "swarm" | "public"
  signature: string                   // Ed25519 hex (128 chars)
  signerPublicKey: string             // Ed25519 public key hex (64 chars)
  receipt: SignedReceipt              // Provenance chain
  createdAt: number
  author: string                      // Sentinel or human fingerprint
}

interface IntelContent {
  // Summaries by default, not raw evidence
  pattern?: PatternEntry              // Behavioral pattern
  rule?: DetectionRule                // Detection logic
  indicators?: IOC[]                  // Hashes, domains, IPs
  policyPatch?: PolicyDelta           // Recommended policy change
  narrative?: string                  // Human-readable summary
}

// ─── Swarm ──────────────────────────────────────────
interface Swarm {
  id: string
  name: string
  type: "personal" | "trusted" | "federated"
  members: SwarmMember[]
  sharedIntel: IntelRef[]             // Published intel artifacts
  sharedDetections: DetectionRef[]    // Active detection rules
  trustGraph: TrustEdge[]             // Who trusts whom, how much
  policies: SwarmPolicy               // Governance rules
  speakeasies: SpeakeasyRef[]         // Attached private rooms
  stats: SwarmStats
  createdAt: number
}

interface SwarmMember {
  type: "sentinel" | "operator"
  identity: string                    // Public key fingerprint
  role: "admin" | "contributor" | "observer"
  reputation: ReputationScore         // Earned over time
  joinedAt: number
}

interface SwarmPolicy {
  minReputation?: number              // To publish intel
  requireSignatures: boolean          // All shared artifacts must be signed
  autoShareDetections: boolean        // Push confirmed detections to members
  compartmentalized: boolean          // Need-to-know by default
}

// ─── Speakeasy (extends @backbay/speakeasy) ─────────
interface ClawdstrikeSpeakeasy {
  id: string
  swarmId: string                     // Parent swarm
  purpose: "finding" | "campaign" | "incident" | "coordination" | "mentoring"
  attachedTo?: string                 // Finding ID, campaign ID, etc.
  members: SpeakeasyMember[]
  classification: "routine" | "sensitive" | "restricted"
  // Inherits from @backbay/speakeasy:
  // - Signed membership (Ed25519)
  // - Fingerprint-based trust
  // - Signed messages with verification
  // - Gossipsub transport
  // - Sigil visual identity
}
```

---

## 4. Architecture Mapping

### What Exists → What's Needed

| Current Concept | Current Location | Sentinel-Swarm Evolution | Gap |
|----------------|------------------|--------------------------|-----|
| `AgentEvent` | `hunt-types.ts` | → `Signal` | Add source attribution, confidence, TTL, correlation links |
| `Investigation` | `hunt-types.ts` | → `Finding` | Add signal rollup, enrichment pipeline, promotion workflow |
| `HuntPattern` | `hunt-types.ts` | → `Intel` candidate | Add signature, shareability, receipt, MITRE mapping |
| Fleet agents | `fleet-dashboard.tsx` | → `Sentinel` registration | Add goals, memory, schedule, mode, swarm membership |
| `AgentBaseline` | `hunt-types.ts` | → `SentinelMemory.baselineProfiles` | Already good; add per-sentinel scoping |
| Delegation graph | `delegation-types.ts` | → Swarm trust graph substrate | Extend with reputation, intel-sharing edges |
| Approval queue | `approval-types.ts` | → Speakeasy-integrated approvals | Wire approvals through signed rooms |
| `hunt-engine.ts` | anomaly scoring | → Signal scoring pipeline | Extract as standalone Signal evaluator |
| Pattern mining | `hunt-engine.ts` | → Intel promotion pipeline | Add signature, receipt, publish-to-swarm flow |
| Origin context | `origin.rs`, `origin-core` | → Signal/Finding provenance | Already rich; thread through new types |
| `@backbay/speakeasy` | backbay-sdk | → `ClawdstrikeSpeakeasy` | Extend with purpose, classification, finding attachment |
| Spine envelopes | `spine/src/envelope.rs` | → Swarm intel transport | Use for signed intel distribution |
| Spider-Sense | `spider_sense.rs` | → Sentinel detection module | Already first-class; feed patterns from swarm intel |
| `hunt-correlate` | Rust crate | → Sentinel correlation engine | Already has Alert, rules, reports — wire to Signal/Finding |
| Delegation tokens | `hush-multi-agent` | → Sentinel-to-sentinel delegation | Already has capability ceilings, attenuation chains |
| Receipts | `hush-core/receipt.rs` | → Intel provenance chain | Already signs decisions; extend to sign Intel artifacts |
| NATS subjects | Spine transport | → Swarm pub/sub backbone | Add `swarm.*`, `intel.*`, `sentinel.*` subject families |

### New Components Needed

| Component | Layer | Purpose |
|-----------|-------|---------|
| `SentinelManager` | Workbench lib | CRUD, lifecycle, scheduling for sentinels |
| `SignalPipeline` | Workbench lib | Ingest, score, correlate, deduplicate signals |
| `FindingEngine` | Workbench lib | Cluster signals into findings, manage lifecycle |
| `IntelForge` | Workbench lib | Promote findings to intel, sign, package |
| `SwarmCoordinator` | Workbench lib | Manage swarm membership, publish/subscribe intel |
| `SpeakeasyBridge` | Workbench lib | Integrate `@backbay/speakeasy` with clawdstrike types |
| `ReputationTracker` | Workbench lib | Score members based on intel quality over time |
| `sentinel-store.tsx` | State | React context for sentinel CRUD + active sentinel tracking |
| `swarm-store.tsx` | State | React context for swarm membership + shared intel |
| `SentinelPage` | Component | Create, configure, monitor sentinels |
| `FindingsPage` | Component | View, triage, promote findings |
| `IntelPage` | Component | Browse, share, import intel artifacts |
| `SwarmPage` | Component | Manage swarms, trust graph, shared detections |
| `SpeakeasyPanel` | Component | Inline private rooms attached to findings/campaigns |

---

## 5. Speakeasy Integration Design

### Speakeasy as Trust & Coordination Layer (not "chat")

Frame Speakeasy as **private signed rooms for operational coordination**, not messaging:

| Use Case | Room Type | Attached To |
|----------|-----------|-------------|
| Threat-intel exchange | `coordination` | Swarm |
| Incident response cell | `incident` | Finding (critical) |
| Finding discussion | `finding` | Specific Finding |
| Campaign tracking | `campaign` | Campaign/case |
| Sentinel steering | `mentoring` | Sentinel (human guides agent) |

### Integration Points with Speakeasy Primitives

| Speakeasy Primitive | Clawdstrike Use |
|---------------------|-----------------|
| `BayChatIdentity` (Ed25519) | Sentinel identity — same keypair signs receipts and messages |
| `Sigil` (8 types) | Visual identity for sentinels in UI (deterministic from fingerprint) |
| `signMessage()` / `verifyMessage()` | All intel artifacts and findings carry verifiable provenance |
| Gossipsub topics | Swarm pub/sub: `/baychat/v1/swarm/{id}/intel`, `/baychat/v1/swarm/{id}/signals` |
| `MessageEnvelope` (TTL) | Intel distribution with hop-limited propagation |
| `useTransport()` hook | Workbench connects to swarm network for real-time intel |
| `useMessages()` hook | Speakeasy panels within workbench UI |
| `SentinelRequest` / `SentinelResponse` message types | Already defined — human asks sentinel to investigate |
| Fingerprint verification | Trust graph edges verified cryptographically |
| Peer discovery | Sentinel-to-sentinel discovery via `/baychat/v1/sentinels` global topic |

### Identity Unification

Sentinels should use **one identity** across all systems:

```
Sentinel Ed25519 keypair
  ├── Signs ClawdStrike receipts (via hush-core)
  ├── Signs Speakeasy messages (via @backbay/speakeasy)
  ├── Signs Intel artifacts (via IntelForge)
  ├── Signs Delegation tokens (via hush-multi-agent)
  └── Derives sigil + fingerprint for visual identity
```

### New Gossipsub Topics

```
/baychat/v1/swarm/{swarmId}/intel          # Published intel artifacts
/baychat/v1/swarm/{swarmId}/signals        # Shared signal stream (opt-in)
/baychat/v1/swarm/{swarmId}/detections     # Active detection rules
/baychat/v1/swarm/{swarmId}/reputation     # Reputation attestations
/baychat/v1/sentinel/{sentinelId}/status   # Sentinel heartbeat + status
```

---

## 6. Information Architecture

### Proposed Navigation (Streamlined)

**Primary navigation:**
```
Overview        — Sentinel health, active findings, swarm activity
Findings        — Triage, enrich, promote findings
Sentinels       — Create, configure, monitor autonomous defenders
Intel           — Browse, share, import portable knowledge
Swarms          — Trust network, shared detections, speakeasies
```

**Secondary (under existing sections or settings):**
```
Editor          — Policy creation (existing, keep)
Threat Lab      — Simulation/red-team (existing, keep)
Fleet           — Agent enrollment (evolves into sentinel registration)
Compliance      — Regulatory mapping (existing, keep)
```

**Within Swarms:**
```
Swarms/
├── Active Swarms        — Your swarms, membership, stats
├── Shared Detections    — Intel published to/from swarms
├── Speakeasies          — Private rooms (attached to findings, campaigns)
├── Trust Graph          — Peer trust visualization
└── Peer Directory       — Known sentinels and operators
```

### Design Principles

1. **Speakeasy is a sub-layer** inside the swarm/trust system, not a top-level nav item (unless brand emphasis desired)
2. **Signals are not the main UX** — users see Findings (conclusions), not raw signal noise
3. **Swarm is operational, not social** — shared detections and enrichment, not Discord for cyber agents
4. **Local-first first** — excellent with one user, zero federation. Swarm amplifies, never required.

---

## 7. Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        SENTINEL LOOP                            │
│                                                                 │
│  Sentinel ──creates──► Signal ──rolls up──► Finding             │
│     │                    │                     │                 │
│     │                    │ (scored,             │ (enriched,     │
│     │                    │  correlated,         │  annotated,    │
│     │                    │  deduplicated)       │  triaged)      │
│     │                    │                     │                 │
│     │                    ▼                     ▼                 │
│     │              Signal Pipeline        Finding Engine         │
│     │                                         │                 │
│     │                                         │ promote         │
│     │                                         ▼                 │
│     │                                      Intel                │
│     │                                   (signed, receipted)     │
│     │                                         │                 │
│     │                                         │ publish         │
│     │                                         ▼                 │
│     │                                      Swarm                │
│     │                                    (Gossipsub)            │
│     │                                         │                 │
│     │                                    ┌────┴────┐            │
│     │                                    ▼         ▼            │
│     │                              Shared      Speakeasy        │
│     │                            Detections   (if sensitive)    │
│     │                                    │                      │
│     │                                    │ feed back            │
│     ◄────────────────────────────────────┘                      │
│   (sentinel learns from                                         │
│    swarm intel, updates                                         │
│    memory & patterns)                                           │
└─────────────────────────────────────────────────────────────────┘
```

### Signal Lifecycle

```
Raw Event (guard result, anomaly, external feed)
  │
  ▼
Signal (attributed, scored, 0.0–1.0 confidence)
  │
  ├── TTL expires → garbage collected
  ├── Low confidence, no correlation → archive
  ├── Correlated with other signals → cluster
  │     │
  │     ▼
  │   Finding (emerging)
  │     │
  │     ├── Analyst/sentinel confirms → Finding (confirmed)
  │     ├── False positive → Finding (false_positive) → suppress pattern
  │     └── Promoted → Intel artifact (signed, receipted)
  │           │
  │           ├── Private → stays local
  │           ├── Swarm → published to trusted swarm
  │           └── Public → published to federated network
  │
  └── High confidence + matches known pattern → auto-Finding
```

### Provenance Chain

Every artifact carries cryptographic provenance:

```
Signal
  └── source.sentinelId + source.guardId + timestamp
       └── verifiable via sentinel's Ed25519 public key

Finding
  └── receipt: SignedReceipt (Clawdstrike receipt format)
       └── signs: signalIds + verdict + enrichment hash

Intel
  └── signature: Ed25519 over canonical content (RFC 8785)
  └── receipt: SignedReceipt linking to source Finding
       └── verifiable by any peer in the swarm
```

---

## 8. Phased Implementation Plan

### Phase 1: Make the Solo Product Undeniable

**Goal:** One user, zero network — still excellent.

| Task | Builds On | New/Modify |
|------|-----------|------------|
| Define `Signal` type | `AgentEvent` in `hunt-types.ts` | Extend with source, confidence, TTL, correlation |
| Define `Finding` type | `Investigation` in `hunt-types.ts` | Add signal rollup, enrichment, promotion |
| Define `Sentinel` type | Fleet agent concept | New type with modes, goals, memory, schedule |
| `SentinelManager` | `use-fleet-connection.ts` | New lib — CRUD, lifecycle, scheduling |
| `SignalPipeline` | `hunt-engine.ts` anomaly scoring | Extract + extend — ingest, score, correlate, dedup |
| `FindingEngine` | Investigation workflow | New lib — cluster signals, manage finding lifecycle |
| Sentinel page | Fleet dashboard | New component — create, configure, monitor |
| Findings page | Hunt investigation panel | New component — triage, enrich, promote |
| Wire receipts to Findings | `hush-core` receipts | Sign findings with sentinel identity |
| Local knowledge base | `SentinelMemory` | Per-sentinel pattern accumulation |
| Update navigation | Sidebar | Add Overview, Findings, Sentinels to primary nav |

### Phase 2: Add Trust-Aware Sharing

**Goal:** Private swarms, signed intel exchange, Speakeasy rooms.

| Task | Builds On | New/Modify |
|------|-----------|------------|
| Define `Intel` type | `HuntPattern` promotion | New type with signature, receipt, shareability |
| Define `Swarm` type | Delegation graph concepts | New type with members, trust, policies |
| `IntelForge` | Pattern mining in hunt-engine | New lib — promote findings, sign, package intel |
| `SwarmCoordinator` | — | New lib — membership, pub/sub, intel distribution |
| `SpeakeasyBridge` | `@backbay/speakeasy` hooks | New lib — integrate speakeasy with clawdstrike types |
| Intel page | Library gallery pattern | New component — browse, share, import |
| Swarm page | Delegation page pattern | New component — membership, trust graph |
| Speakeasy panels | `@backbay/speakeasy` React hooks | Inline rooms attached to findings/campaigns |
| Sentinel identity unification | Speakeasy identity + hush-core keypair | Single Ed25519 identity across all systems |
| Reputation tracking | — | New lib — score members by intel quality |
| Gossipsub topic design | Speakeasy transport | New topic families for swarm intel |
| Peer trust graph | Delegation graph engine | Extend force-graph with reputation edges |

### Phase 3: Unlock Network Effects

**Goal:** Federated discovery, shared detection packs, communities.

| Task | Builds On | New/Modify |
|------|-----------|------------|
| Federated swarm discovery | Speakeasy peer discovery | Extend `/baychat/v1/sentinels` for cross-org |
| Shared detection packs | Intel artifacts | Packaged, versioned, signed detection bundles |
| Intel marketplace | Swarm pub/sub | Subscribe to intel feeds, track provenance |
| Vertical communities | Swarm types | Sector-specific swarms (healthcare, finance, etc.) |
| Cross-swarm bridges | Origin bridge design | Controlled intel flow between swarms |
| Public-good sharing | Intel shareability | Opt-in anonymous contribution to global patterns |

---

## 9. Key File Reference

### Workbench — Types & State
| File | Purpose |
|------|---------|
| `apps/workbench/src/lib/workbench/types.ts` | Core policy + simulation types (529 lines) |
| `apps/workbench/src/lib/workbench/hunt-types.ts` | AgentEvent, Baseline, Investigation, Pattern (180 lines) |
| `apps/workbench/src/lib/workbench/delegation-types.ts` | Graph nodes/edges, capabilities (77 lines) |
| `apps/workbench/src/lib/workbench/approval-types.ts` | Approval requests + scopes (47 lines) |
| `apps/workbench/src/lib/workbench/multi-policy-store.tsx` | Global workbench state (400+ lines) |
| `apps/workbench/src/lib/workbench/use-fleet-connection.ts` | Fleet API + polling (392 lines) |
| `apps/workbench/src/lib/workbench/hunt-engine.ts` | Anomaly scoring, baselines, pattern mining (596 lines) |
| `apps/workbench/src/lib/workbench/simulation-engine.ts` | 13 guard simulators (1800+ lines) |
| `apps/workbench/src/lib/workbench/force-graph-engine.ts` | Delegation graph layout |
| `apps/workbench/src/lib/workbench/fleet-client.ts` | HTTP API wrapper |

### Workbench — Components
| File | Purpose |
|------|---------|
| `apps/workbench/src/App.tsx` | Root router, provider stack |
| `apps/workbench/src/components/workbench/workbench-sidebar.tsx` | Left navigation |
| `apps/workbench/src/components/workbench/hunt/hunt-layout.tsx` | Hunt Lab tabs + polling |
| `apps/workbench/src/components/workbench/hunt/activity-stream.tsx` | Live event stream |
| `apps/workbench/src/components/workbench/hunt/investigation.tsx` | Investigation workbench (1230 lines) |
| `apps/workbench/src/components/workbench/hunt/baselines.tsx` | Baseline viz + drift (1037 lines) |
| `apps/workbench/src/components/workbench/delegation/delegation-page.tsx` | Force-directed graph (1242 lines) |
| `apps/workbench/src/components/workbench/approvals/approval-queue.tsx` | Approval management (1091 lines) |
| `apps/workbench/src/components/workbench/hierarchy/hierarchy-page.tsx` | Scoped policy tree (1965 lines) |
| `apps/workbench/src/components/workbench/fleet/fleet-dashboard.tsx` | Agent dashboard |

### Rust Crates
| File | Purpose |
|------|---------|
| `crates/libs/clawdstrike/src/engine.rs` | HushEngine — main orchestrator |
| `crates/libs/clawdstrike/src/policy.rs` | Policy schema, guard configs |
| `crates/libs/clawdstrike/src/guards/mod.rs` | Guard trait + pipeline |
| `crates/libs/clawdstrike/src/spider_sense.rs` | Two-tier threat screening |
| `crates/libs/clawdstrike/src/origin.rs` | Origin-aware types |
| `crates/libs/hush-core/src/receipt.rs` | Receipt + SignedReceipt |
| `crates/libs/hush-multi-agent/src/token.rs` | Delegation tokens |
| `crates/libs/spine/src/envelope.rs` | Signed envelopes |
| `crates/libs/spine/src/checkpoint.rs` | Merkle checkpoints |
| `crates/libs/hunt-correlate/src/` | Alert, rules, reports, correlation |

### TS SDK
| File | Purpose |
|------|---------|
| `packages/sdk/hush-ts/src/index.ts` | SDK barrel exports |
| `packages/sdk/hush-ts/src/clawdstrike.ts` | Clawdstrike facade class |
| `packages/sdk/clawdstrike-hunt/src/` | Hunt engine, correlation, streaming |
| `packages/adapters/clawdstrike-adapter-core/src/types.ts` | Decision, PolicyEvent, EventData |
| `packages/adapters/clawdstrike-adapter-core/src/adapter.ts` | FrameworkAdapter, GenericToolCall |
| `packages/adapters/clawdstrike-origin-core/src/` | OriginContext, TrustAdapter |
| `packages/policy/clawdstrike-policy/src/engine.ts` | TS policy evaluator |

### Backbay SDK — Speakeasy
| File | Purpose |
|------|---------|
| `backbay-sdk/packages/speakeasy/src/core/types.ts` | All message + identity types |
| `backbay-sdk/packages/speakeasy/src/core/identity.ts` | Key generation, storage, recovery |
| `backbay-sdk/packages/speakeasy/src/core/signing.ts` | Message hashing, signing, verification |
| `backbay-sdk/packages/speakeasy/src/core/sigil.ts` | Sigil derivation, colors |
| `backbay-sdk/packages/speakeasy/src/transport/transport.ts` | libp2p node, Gossipsub |
| `backbay-sdk/packages/speakeasy/src/transport/topics.ts` | Topic naming conventions |
| `backbay-sdk/packages/speakeasy/src/react/useIdentity.ts` | Identity hook |
| `backbay-sdk/packages/speakeasy/src/react/useTransport.ts` | Transport hook |
| `backbay-sdk/packages/speakeasy/src/react/useMessages.ts` | Message store hook |

### Existing Plans & Docs
| File | Purpose |
|------|---------|
| `docs/plans/origin-enclaves/INDEX.md` | Origin enclave architecture (339 lines) |
| `docs/plans/origin-enclaves/ROADMAP.md` | 14-week phased origin implementation |
| `docs/plans/origin-enclaves/bridge-design.md` | Bridge model design (615 lines) |
| `docs/plans/siem-soar/` | SIEM/SOAR integration patterns |
| `docs/plans/multi-agent/` | Multi-agent coordination |
| `docs/research/architecture-vision.md` | 6-layer security stack vision |
| `THREAT_MODEL.md` | Security threat coverage |
| `apps/workbench/REALIZATION_ROADMAP.md` | Workbench phase 3-4 roadmap |

---

## 10. Open Questions

### Product
- Should Speakeasy be a top-level nav item for brand emphasis, or stay as a sub-layer under Swarms?
- How do sentinel modes (watcher/hunter/curator/liaison) manifest in the UI — tabs, filters, or distinct creation flows?
- What's the minimum viable swarm — just your own sentinels coordinating, or does it require at least 2 humans?
- Should Findings auto-promote to Intel at a confidence threshold, or always require human confirmation?
- How much of the signal stream should be visible vs. hidden behind "show raw signals" toggle?

### Technical
- Identity unification: can a Sentinel's Ed25519 keypair be shared between `@backbay/speakeasy` and `hush-core` signing, or do they need separate keys with cross-signing?
- Transport: should swarm intel use Speakeasy's Gossipsub, Spine's NATS, or both (Gossipsub for real-time, NATS for reliable delivery)?
- Storage: signals are high-volume — what's the retention strategy? (TTL, compression, off-heap, server-side?)
- How does the personal swarm work offline/local-only? (In-process message bus? Direct function calls between sentinel instances?)
- Should `hunt-correlate` (Rust) be compiled to WASM for client-side correlation, or stay server-side via hushd?

### Security
- Provenance: should every Signal carry an Ed25519 signature, or only Findings and Intel? (Perf vs. integrity tradeoff)
- Reputation: how to prevent Sybil attacks in federated swarms? (Proof-of-work? Invitation chains? Stake?)
- Compartmentalization: what classification levels for Speakeasy rooms? How does intel downgrade/sanitize for sharing?
- Share summaries by default: what's the redaction policy for raw evidence in shared intel?

---

## 11. Next-Wave Plans

The first sentinel-swarm PR established the ontology and core workbench surfaces.
The next wave turns those objects into runtime-backed principals with execution,
evidence, and federation.

- [NEXT-WAVE-ROADMAP.md](./NEXT-WAVE-ROADMAP.md) - sequencing, dependencies, milestones, and execution order for the full wave.
- [SENTINEL-RUNTIME.md](./SENTINEL-RUNTIME.md) - Sentinel Drivers, Claude Code Sentinel, OpenClaw Hunt Pod, runtime binding, and execution-mode contract.
- [MISSION-EVIDENCE-LOOP.md](./MISSION-EVIDENCE-LOOP.md) - Swarm Mission Control, Evidence-Native Signal Ingestion, and Policy Forge.
- [FEDERATED-INTEL.md](./FEDERATED-INTEL.md) - signed intel envelopes, reputation, witness/notary provenance, and swarm federation rollout.

Phase 1 execution on this branch starts with the shared sentinel runtime
contract in the workbench model and UI: driver selection, execution mode,
runtime targeting, and enforcement-tier visibility.
