# Sentinel Swarm — Data Model Specification

> Complete type definitions, relationships, migration paths, and storage strategy
> for the six core Sentinel Swarm objects.

**Status:** Design spec (implements Section 3 of [INDEX.md](./INDEX.md))
**Date:** 2026-03-12
**Branch:** `feat/sentinel-swarm`

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Naming & Style Conventions](#2-naming--style-conventions)
3. [Shared Enums & Constants](#3-shared-enums--constants)
4. [Core Types](#4-core-types)
   - [4.1 Sentinel](#41-sentinel)
   - [4.2 Signal](#42-signal)
   - [4.3 Finding](#43-finding)
   - [4.4 Intel](#44-intel)
   - [4.5 Swarm](#45-swarm)
   - [4.6 Speakeasy](#46-speakeasy)
5. [Relationship Map](#5-relationship-map)
6. [Migration Paths](#6-migration-paths)
7. [Storage Strategy](#7-storage-strategy)
8. [Serialization](#8-serialization)
9. [Validation Rules](#9-validation-rules)
10. [ID Generation](#10-id-generation)

---

## 1. Design Principles

1. **Backward-compatible extensions.** Every new type either extends an existing type with optional fields or lives alongside it. No existing field is removed or renamed. Old code reading old data keeps working.
2. **Local-first, swarm-optional.** Every type works with zero network. Swarm and Speakeasy fields are always optional until the user opts in.
3. **Fail-closed provenance.** Intel and Findings carry mandatory receipts and signatures. Unsigned artifacts cannot be published to a swarm.
4. **Match existing patterns.** Field naming follows the existing workbench convention: camelCase for TypeScript fields, snake_case for fields that mirror Rust serde structs (policy config, fleet API responses). ISO-8601 strings for timestamps in types that currently use strings; Unix ms (`number`) for new real-time types.
5. **Summaries by default.** Shared artifacts (Intel) carry derived summaries, not raw evidence. Raw signal data stays local unless the operator explicitly attaches it.

---

## 2. Naming & Style Conventions

| Convention | Rule | Example |
|-----------|------|---------|
| Type names | PascalCase, singular noun | `Sentinel`, `Signal`, `Finding` |
| Field names (TS-native types) | camelCase | `sentinelId`, `anomalyScore` |
| Field names (Rust-mirror types) | snake_case | `content_hash`, `policy_version` |
| Enum string literals | lowercase snake_case | `"watcher"`, `"policy_violation"` |
| ID format | `{prefix}_{ulid}` | `sen_01HXYZ...`, `sig_01HXYZ...` |
| Timestamps (new real-time types) | `number` (Unix ms) | `1741785600000` |
| Timestamps (existing/persistent) | `string` (ISO-8601) | `"2026-03-12T00:00:00Z"` |
| Optional fields | TypeScript `?` suffix | `schedule?: CronExpression` |
| Branded strings | Type alias with doc comment | `type SentinelId = string` |

### ID Prefixes

| Type | Prefix | Example |
|------|--------|---------|
| Sentinel | `sen_` | `sen_01HXK8M3N2...` |
| Signal | `sig_` | `sig_01HXK8M3N2...` |
| Finding | `fnd_` | `fnd_01HXK8M3N2...` |
| Intel | `int_` | `int_01HXK8M3N2...` |
| Swarm | `swm_` | `swm_01HXK8M3N2...` |
| Speakeasy | `spk_` | `spk_01HXK8M3N2...` |

---

## 3. Shared Enums & Constants

These enums are referenced across multiple core types.

```typescript
// ---------------------------------------------------------------------------
// Sentinel Swarm — Shared Enums
// ---------------------------------------------------------------------------

/** Sentinel operating modes. All modes are still "Sentinels" in the product. */
export type SentinelMode = "watcher" | "hunter" | "curator" | "liaison";

/** Sentinel lifecycle status. */
export type SentinelStatus = "active" | "paused" | "retired";

/** Signal type discriminator. */
export type SignalType =
  | "anomaly"           // Behavioral deviation from baseline
  | "detection"         // Guard or rule match
  | "indicator"         // Weak IOC or external feed match
  | "policy_violation"  // Policy enforcement event (deny/warn)
  | "behavioral";       // Sequence/pattern-level observation

/** Severity levels — superset of existing `Severity` in hunt-types.ts. */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** Finding lifecycle status. */
export type FindingStatus =
  | "emerging"       // Auto-created from signal correlation
  | "confirmed"      // Analyst or sentinel confirmed
  | "promoted"       // Promoted to Intel artifact
  | "dismissed"      // Not actionable
  | "false_positive"; // Confirmed FP; pattern added to suppression

/** Finding verdict — extends existing InvestigationVerdict. */
export type FindingVerdict =
  | "threat_confirmed"
  | "false_positive"
  | "policy_gap"
  | "inconclusive";

/** Actions taken on a finding — extends existing InvestigationAction. */
export type FindingAction =
  | "policy_updated"
  | "pattern_added"
  | "agent_revoked"
  | "escalated"
  | "intel_promoted"    // New: finding promoted to intel
  | "speakeasy_opened"; // New: private room opened for this finding

/** Intel artifact type. */
export type IntelType =
  | "detection_rule"    // Detection logic (Sigma, YARA, native correlation)
  | "pattern"           // Behavioral action sequence
  | "ioc"               // Indicators of compromise
  | "campaign"          // Multi-finding campaign narrative
  | "advisory"          // Human-readable summary/advisory
  | "policy_patch";     // Recommended policy delta

/** Intel shareability scope. */
export type IntelShareability = "private" | "swarm" | "public";

/** Swarm layer types. */
export type SwarmType = "personal" | "trusted" | "federated";

/** Swarm member roles. */
export type SwarmRole = "admin" | "contributor" | "observer";

/** Speakeasy room purpose. */
export type SpeakeasyPurpose =
  | "finding"        // Discussion about a specific finding
  | "campaign"       // Multi-finding campaign tracking
  | "incident"       // Active incident response
  | "coordination"   // General intel exchange
  | "mentoring";     // Human guides sentinel

/** Speakeasy classification level. */
export type SpeakeasyClassification = "routine" | "sensitive" | "restricted";

/** Signal provenance — how the signal was generated. */
export type SignalProvenance =
  | "guard_evaluation"    // Produced by a Clawdstrike guard
  | "anomaly_detection"   // Produced by baseline deviation scoring
  | "pattern_match"       // Produced by hunt pattern matching
  | "correlation_rule"    // Produced by hunt-correlate engine
  | "spider_sense"        // Produced by Spider Sense screening
  | "external_feed"       // Ingested from external threat feed
  | "swarm_intel"         // Received from a swarm peer
  | "manual";             // Manually created by operator

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum signals held in local store before eviction. */
export const SIGNAL_LOCAL_LIMIT = 10_000;

/** Default signal TTL in milliseconds (24 hours). */
export const SIGNAL_DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

/** Maximum findings held in local store. */
export const FINDING_LOCAL_LIMIT = 1_000;

/** Maximum intel artifacts held in local store. */
export const INTEL_LOCAL_LIMIT = 500;

/** Minimum confidence to auto-create a finding from correlated signals. */
export const AUTO_FINDING_CONFIDENCE_THRESHOLD = 0.75;

/** Default Gossipsub message TTL in hops. */
export const SWARM_MESSAGE_DEFAULT_TTL = 10;
```

---

## 4. Core Types

### 4.1 Sentinel

A persistent, user-owned autonomous defender with memory, goals, and policies.

**Evolves from:** Fleet `AgentInfo` (fleet-client.ts) + `AgentBaseline` (hunt-types.ts) concepts.

**Key relationship to existing types:**
- `AgentInfo.endpoint_agent_id` maps to `Sentinel.id` for fleet-enrolled sentinels
- `AgentBaseline` becomes `SentinelMemory.baselineProfiles[n]`
- `DelegationNode` (delegation-types.ts) with `kind: "Principal"` represents a sentinel in the trust graph
- Identity uses the same Ed25519 scheme as `BayChatIdentity` from `@backbay/speakeasy`

```typescript
// ---------------------------------------------------------------------------
// Sentinel
// ---------------------------------------------------------------------------

/**
 * Sentinel identity — Ed25519 keypair compatible with both
 * hush-core receipt signing and @backbay/speakeasy message signing.
 *
 * Mirrors BayChatIdentity from @backbay/speakeasy/core/types.ts:
 *   publicKey:   Ed25519 public key (32 bytes, hex)
 *   fingerprint: SHA256(publicKey) truncated to 16 hex chars
 *   sigil:       one of 8 sigil types, derived from fingerprint
 *
 * Secret key is stored in Tauri Stronghold (desktop) or IndexedDB (web).
 * It is NEVER serialized to localStorage or sent over the network.
 */
export interface SentinelIdentity {
  /** Ed25519 public key (32 bytes, hex encoded). */
  publicKey: string;
  /** SHA256(publicKey) truncated to 16 hex chars. Matches BayChatIdentity.fingerprint. */
  fingerprint: string;
  /**
   * Sigil type derived from fingerprint. Matches @backbay/speakeasy SpeakeasySigil.
   * Used for visual identity in the workbench UI.
   */
  sigil: "diamond" | "eye" | "wave" | "crown" | "spiral" | "key" | "star" | "moon";
}

/**
 * A persistent autonomous defender.
 *
 * Sentinel is the primary actor in the Sentinel Swarm model. Each sentinel
 * has its own Ed25519 identity, policy binding, goals, and accumulated memory.
 */
export interface Sentinel {
  /** Unique sentinel ID. Format: `sen_{ulid}`. */
  id: string;
  /** User-facing display name. 1–128 chars, non-empty. */
  name: string;
  /** Operating mode. Determines default goals and UI presentation. */
  mode: SentinelMode;
  /**
   * Owner fingerprint — the human operator who created this sentinel.
   * Matches SentinelIdentity.fingerprint of the operator's own identity.
   */
  owner: string;
  /** Sentinel's Ed25519 identity for signing and Speakeasy participation. */
  identity: SentinelIdentity;
  /** Reference to the policy governing this sentinel's actions. */
  policy: PolicyRef;
  /** Ordered list of goals defining what this sentinel does. */
  goals: SentinelGoal[];
  /** Accumulated knowledge — patterns, baselines, false-positive hashes. */
  memory: SentinelMemory;
  /**
   * Cron expression for recurring hunts. Only meaningful for mode: "hunter".
   * Uses standard 5-field cron syntax (minute hour day month weekday).
   * Null means continuous / event-driven operation.
   */
  schedule: string | null;
  /** Lifecycle status. */
  status: SentinelStatus;
  /** Swarms this sentinel participates in. Empty for solo operation. */
  swarms: SwarmMembership[];
  /** Lifetime performance metrics. */
  stats: SentinelStats;
  /**
   * Fleet agent ID, if this sentinel is backed by a fleet-enrolled agent.
   * Maps to AgentInfo.endpoint_agent_id from fleet-client.ts.
   * Null for local-only sentinels (no fleet connection).
   */
  fleetAgentId: string | null;
  /** Creation timestamp (Unix ms). */
  createdAt: number;
  /** Last update timestamp (Unix ms). */
  updatedAt: number;
}

/**
 * Reference to a policy by name, version, or saved-policy ID.
 * At least one of `policyId` or `policyName` must be set.
 */
export interface PolicyRef {
  /** SavedPolicy.id from multi-policy-store — for locally saved policies. */
  policyId?: string;
  /** WorkbenchPolicy.name — for named resolution. */
  policyName?: string;
  /** PolicySchemaVersion to pin. If omitted, uses latest. */
  version?: string;
  /**
   * Built-in ruleset name (e.g., "strict", "ai-agent", "spider-sense").
   * Mutually exclusive with policyId.
   */
  ruleset?: string;
}

/**
 * A single goal that drives sentinel behavior.
 */
export interface SentinelGoal {
  /** Goal type — what kind of work this goal represents. */
  type: "detect" | "hunt" | "monitor" | "enrich";
  /** Human-readable description of the goal. 1–512 chars. */
  description: string;
  /** Data sources this goal watches. */
  sources: DataSource[];
  /** Pattern references to look for. Optional — sentinel may discover new patterns. */
  patterns?: PatternRef[];
  /** Policy for when signals should be promoted to findings. */
  escalation: EscalationPolicy;
}

/**
 * Data source a sentinel watches.
 */
export interface DataSource {
  /** Source type. */
  type: "fleet_audit" | "hunt_stream" | "external_feed" | "spine_envelope" | "speakeasy_topic";
  /**
   * Source identifier. Semantics depend on type:
   * - fleet_audit: fleet URL or "local"
   * - hunt_stream: "live" or time range
   * - external_feed: feed URL
   * - spine_envelope: NATS subject pattern
   * - speakeasy_topic: Gossipsub topic string
   */
  identifier: string;
  /** Optional filter expression for this source. */
  filter?: Record<string, unknown>;
}

/**
 * Reference to a known detection pattern.
 */
export interface PatternRef {
  /** HuntPattern.id or Intel.id — depending on source. */
  id: string;
  /** Where this pattern came from. */
  source: "local" | "swarm" | "builtin";
}

/**
 * Policy that governs when a sentinel escalates signals to findings.
 */
export interface EscalationPolicy {
  /** Minimum confidence to auto-create a finding. 0.0–1.0. */
  minConfidence: number;
  /** Minimum severity to escalate. Signals below this are archived. */
  minSeverity: Severity;
  /** Number of correlated signals needed before auto-creating a finding. */
  minCorrelatedSignals: number;
  /** If true, always require human confirmation before creating a finding. */
  requireHumanConfirmation: boolean;
}

/**
 * Accumulated knowledge for a sentinel.
 *
 * Extends AgentBaseline (hunt-types.ts) by scoping baselines per-sentinel
 * and adding pattern knowledge and false-positive suppression.
 */
export interface SentinelMemory {
  /**
   * Known behavioral patterns accumulated over time.
   * Each entry mirrors PatternEntry from spider_sense.rs / hunt-correlate.
   */
  knownPatterns: MemoryPattern[];
  /**
   * Learned normal behavior profiles, one per monitored agent.
   * Each profile is an AgentBaseline (hunt-types.ts), unchanged.
   */
  baselineProfiles: import("./hunt-types").AgentBaseline[];
  /**
   * SHA-256 hashes of known false-positive signal payloads.
   * When a new signal's content hash matches, the sentinel suppresses it.
   */
  falsePositiveHashes: string[];
  /** Last time memory was updated (Unix ms). */
  lastUpdated: number;
}

/**
 * A pattern stored in sentinel memory. Lighter than HuntPattern —
 * carries only the detection-relevant fields for runtime matching.
 */
export interface MemoryPattern {
  /** Pattern ID. Matches HuntPattern.id or Intel content pattern ID. */
  id: string;
  /** Human-readable name. */
  name: string;
  /** Action sequence steps. Identical to PatternStep from hunt-types.ts. */
  sequence: import("./hunt-types").PatternStep[];
  /** How many times this pattern has matched for this sentinel. */
  localMatchCount: number;
  /** Source — where the sentinel learned this pattern. */
  source: "discovered" | "imported_intel" | "promoted_hunt_pattern" | "builtin";
  /** When the pattern was added to memory (Unix ms). */
  addedAt: number;
}

/**
 * A sentinel's membership in a swarm.
 */
export interface SwarmMembership {
  /** Swarm.id */
  swarmId: string;
  /** Role within the swarm. */
  role: SwarmRole;
  /** When this sentinel joined (Unix ms). */
  joinedAt: number;
}

/**
 * Lifetime metrics for a sentinel.
 */
export interface SentinelStats {
  /** Total signals generated. */
  signalsGenerated: number;
  /** Total findings created. */
  findingsCreated: number;
  /** Total intel artifacts produced. */
  intelProduced: number;
  /** Total false positives identified and suppressed. */
  falsePositivesSuppressed: number;
  /** Number of swarm intel items consumed. */
  swarmIntelConsumed: number;
  /** Uptime in milliseconds since creation. */
  uptimeMs: number;
  /** Last active timestamp (Unix ms). */
  lastActiveAt: number;
}
```

### 4.2 Signal

A raw clue, anomaly, event, or candidate detection. High volume, low certainty.

**Evolves from:** `AgentEvent` in hunt-types.ts. Backward-compatible — `AgentEvent` is a valid subset of `Signal` data.

**Key relationship to existing types:**
- `AgentEvent.id` maps to `Signal.id` for fleet-sourced signals
- `AgentEvent.guardResults` maps to `Signal.data.guardResults`
- `AgentEvent.anomalyScore` maps to `Signal.confidence`
- `AgentEvent.flags` maps to `Signal.data.flags`
- `EventFlag` (hunt-types.ts) is reused unchanged
- `AnomalyResult` / `AnomalyFactor` (hunt-types.ts) map to `Signal.data.anomaly`
- `GuardSimResult` (types.ts) reused in signal payload

```typescript
// ---------------------------------------------------------------------------
// Signal
// ---------------------------------------------------------------------------

/**
 * A raw clue, anomaly, event, or candidate detection.
 *
 * Extends the concept of AgentEvent (hunt-types.ts) with:
 * - Source attribution (which sentinel or guard produced it)
 * - Confidence score (0.0–1.0)
 * - TTL for automatic expiration of weak signals
 * - Correlation links to related signals
 * - Typed payload discriminated by signal type
 */
export interface Signal {
  /** Unique signal ID. Format: `sig_{ulid}`. */
  id: string;
  /** Signal type discriminator. Determines shape of `data`. */
  type: SignalType;
  /** Attribution — who/what generated this signal. */
  source: SignalSource;
  /** When the underlying event occurred (Unix ms). */
  timestamp: number;
  /** Assessed severity. */
  severity: Severity;
  /**
   * Confidence score, 0.0–1.0.
   * - For anomaly signals: maps from AgentEvent.anomalyScore
   * - For detection signals: derived from guard certainty
   * - For external feeds: provided by the feed
   */
  confidence: number;
  /** Typed payload. Shape depends on `type`. */
  data: SignalData;
  /** Context about the agent, session, and origin. */
  context: SignalContext;
  /**
   * IDs of related signals for correlation.
   * Populated by the SignalPipeline during dedup and clustering.
   */
  relatedSignals: string[];
  /**
   * Time-to-live in milliseconds from `timestamp`.
   * After expiry, the signal is eligible for garbage collection.
   * Null means the signal persists until manually archived.
   * Default: SIGNAL_DEFAULT_TTL_MS (24h) for info/low severity.
   */
  ttl: number | null;
  /**
   * If this signal has been rolled into a finding, the finding ID.
   * Set by FindingEngine when the signal is clustered.
   */
  findingId: string | null;
}

/**
 * Attribution for a signal — where it came from.
 */
export interface SignalSource {
  /** Sentinel that generated this signal, if sentinel-sourced. */
  sentinelId: string | null;
  /**
   * Guard that triggered, if this is a guard-sourced signal.
   * Matches GuardId from types.ts.
   */
  guardId: string | null;
  /** External feed identifier, if externally sourced. */
  externalFeed: string | null;
  /** How this signal was generated. */
  provenance: SignalProvenance;
}

/**
 * Typed signal payload. Discriminated by Signal.type.
 *
 * Each variant carries the minimum data needed for triage.
 * Full raw data is available through the receipt or source event.
 */
export type SignalData =
  | SignalDataAnomaly
  | SignalDataDetection
  | SignalDataIndicator
  | SignalDataPolicyViolation
  | SignalDataBehavioral;

/** Anomaly signal — behavioral deviation from baseline. */
export interface SignalDataAnomaly {
  kind: "anomaly";
  /** Anomaly result from the scoring engine. Reuses AnomalyResult from hunt-types.ts. */
  anomaly: import("./hunt-types").AnomalyResult;
  /**
   * Original AgentEvent ID, if derived from fleet audit.
   * Enables backward lookup to the full event.
   */
  sourceEventId?: string;
}

/** Detection signal — a guard or detection rule matched. */
export interface SignalDataDetection {
  kind: "detection";
  /** Guard results. Reuses GuardSimResult[] from types.ts. */
  guardResults: import("./types").GuardSimResult[];
  /** Detection rule name, if rule-sourced (hunt-correlate). */
  ruleName?: string;
  /** Receipt ID if the guard evaluation produced a signed receipt. */
  receiptId?: string;
  /** Original AgentEvent ID, if derived from fleet audit. */
  sourceEventId?: string;
}

/** Indicator signal — weak IOC match from feed or Spider Sense. */
export interface SignalDataIndicator {
  kind: "indicator";
  /** Indicator type (hash, domain, ip, url, email). */
  indicatorType: "hash" | "domain" | "ip" | "url" | "email" | "other";
  /** The indicator value. */
  value: string;
  /** Feed or database that produced the match. */
  feedSource: string;
  /**
   * Spider Sense match result, if this came from pattern screening.
   * Fields mirror ScreeningResult from spider_sense.rs.
   */
  spiderSenseMatch?: {
    patternId: string;
    similarity: number;
    verdict: "benign" | "suspicious" | "malicious";
  };
}

/** Policy violation signal — a policy enforcement deny or warn. */
export interface SignalDataPolicyViolation {
  kind: "policy_violation";
  /** Guard results from the policy evaluation. */
  guardResults: import("./types").GuardSimResult[];
  /** Policy name that was violated. */
  policyName: string;
  /** The action that was attempted. */
  actionType: import("./types").TestActionType;
  /** The target of the action. */
  target: string;
  /** Verdict that was applied. Only deny/warn — allow is not a violation. */
  verdict: "deny" | "warn";
  /** Original AgentEvent ID. */
  sourceEventId?: string;
}

/** Behavioral signal — a sequence-level pattern observation. */
export interface SignalDataBehavioral {
  kind: "behavioral";
  /** Pattern that matched. */
  patternId: string;
  /** Pattern name for display. */
  patternName: string;
  /** Session ID where the pattern was observed. */
  sessionId: string;
  /** Events in the session that matched the pattern. */
  matchedEventIds: string[];
}

/**
 * Context about the agent, session, and origin for a signal.
 * Carries forward the context fields from AgentEvent.
 */
export interface SignalContext {
  /** Agent ID (maps to AgentEvent.agentId). */
  agentId: string;
  /** Agent display name. */
  agentName: string;
  /** Team/org ID if available. */
  teamId?: string;
  /** Session ID (maps to AgentEvent.sessionId). */
  sessionId: string;
  /**
   * Origin context, if the signal came from an origin-aware evaluation.
   * Reuses OriginContext from types.ts (mirrors Rust OriginContext).
   */
  origin?: import("./types").OriginContext;
  /**
   * Event flags carried forward from AgentEvent.
   * Reuses EventFlag from hunt-types.ts.
   */
  flags: import("./hunt-types").EventFlag[];
}
```

### 4.3 Finding

A grouped, enriched, scored conclusion built from one or more signals.

**Evolves from:** `Investigation` in hunt-types.ts. Backward-compatible — Investigation fields are preserved with new optional extensions.

**Key relationship to existing types:**
- `Investigation.id` maps to `Finding.id` for migrated investigations
- `Investigation.eventIds` maps to `Finding.signalIds`
- `Investigation.annotations` reused unchanged as `Annotation` from hunt-types.ts
- `Investigation.status` maps to `Finding.status` (see migration table)
- `Investigation.verdict` maps to `Finding.verdict` (renamed values)
- `Investigation.actions` extended with new action types
- `Receipt` from types.ts used for `Finding.receipt`

```typescript
// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

/**
 * A grouped, enriched, scored conclusion built from one or more signals.
 *
 * Extends Investigation (hunt-types.ts) with:
 * - Signal rollup (signalIds[] + signalCount)
 * - Structured timeline
 * - Enrichment pipeline (MITRE, IOC, external)
 * - Promotion workflow to Intel
 * - Signed receipt for provenance
 */
export interface Finding {
  /** Unique finding ID. Format: `fnd_{ulid}`. */
  id: string;
  /** Human-readable title. 1–256 chars. */
  title: string;
  /** Lifecycle status. */
  status: FindingStatus;
  /** Assessed severity — can change as enrichment adds context. */
  severity: Severity;
  /**
   * Aggregate confidence score, 0.0–1.0.
   * Derived from contributing signals' confidences using weighted average.
   */
  confidence: number;
  /** IDs of signals that contribute to this finding. */
  signalIds: string[];
  /** Count of contributing signals (may exceed signalIds.length if signals expired). */
  signalCount: number;
  /**
   * Scope — agents, sessions, and time range involved.
   * Mirrors Investigation scope fields for backward compatibility.
   */
  scope: FindingScope;
  /** Chronological narrative of how this finding developed. */
  timeline: TimelineEntry[];
  /** External enrichments applied to this finding. */
  enrichments: Enrichment[];
  /**
   * Analyst and sentinel annotations.
   * Uses the existing Annotation type from hunt-types.ts.
   */
  annotations: import("./hunt-types").Annotation[];
  /** Final verdict, if determined. */
  verdict: FindingVerdict | null;
  /** Actions taken in response to this finding. */
  actions: FindingAction[];
  /**
   * Intel artifact ID if this finding was promoted.
   * Format: `int_{ulid}`.
   */
  promotedToIntel: string | null;
  /**
   * Signed receipt attesting to this finding's conclusions.
   * Signed by the sentinel or operator who confirmed the finding.
   * Uses the existing Receipt type from types.ts.
   */
  receipt: import("./types").Receipt | null;
  /**
   * Speakeasy room ID if a private room was opened for this finding.
   * Format: `spk_{ulid}`.
   */
  speakeasyId: string | null;
  /** Who created this finding — sentinel fingerprint or operator ID. */
  createdBy: string;
  /** Who last updated this finding. */
  updatedBy: string;
  /** Creation timestamp (Unix ms). */
  createdAt: number;
  /** Last update timestamp (Unix ms). */
  updatedAt: number;
}

/**
 * Finding scope — which agents, sessions, and time range are involved.
 * Mirrors Investigation scope fields from hunt-types.ts.
 */
export interface FindingScope {
  /** Agent IDs involved. Maps from Investigation.agentIds. */
  agentIds: string[];
  /** Session IDs involved. Maps from Investigation.sessionIds. */
  sessionIds: string[];
  /**
   * Time range of the finding.
   * Uses ISO-8601 strings for compatibility with Investigation.timeRange.
   */
  timeRange: { start: string; end: string };
}

/**
 * A chronological entry in the finding timeline.
 */
export interface TimelineEntry {
  /** When this entry occurred (Unix ms). */
  timestamp: number;
  /** Entry type. */
  type: "signal_added" | "enrichment_added" | "status_changed"
      | "annotation_added" | "verdict_set" | "action_taken"
      | "promoted" | "speakeasy_opened";
  /** Human-readable summary. */
  summary: string;
  /** Who caused this entry — sentinel fingerprint or operator ID. */
  actor: string;
  /** Optional reference ID (signal ID, enrichment ID, etc.). */
  refId?: string;
}

/**
 * External enrichment applied to a finding.
 */
export interface Enrichment {
  /** Enrichment ID (`enr_{ulid}`). */
  id: string;
  /** Enrichment type. */
  type: "mitre_attack" | "ioc_extraction" | "spider_sense" | "external_feed"
      | "swarm_corroboration" | "reputation" | "geolocation" | "whois" | "custom";
  /** Human-readable label. */
  label: string;
  /** Structured enrichment data. Shape depends on `type`. */
  data: EnrichmentData;
  /** When this enrichment was added (Unix ms). */
  addedAt: number;
  /** Source of the enrichment (feed name, API, sentinel ID). */
  source: string;
}

/** MITRE ATT&CK enrichment data. */
export interface MitreEnrichment {
  kind: "mitre_attack";
  /** Technique ID (e.g., "T1059.001"). */
  techniqueId: string;
  /** Technique name. */
  techniqueName: string;
  /** Tactic (e.g., "Execution"). */
  tactic: string;
  /** Sub-technique if applicable. */
  subTechnique?: string;
}

/** IOC lookup enrichment data. */
export interface IocEnrichment {
  kind: "ioc_lookup";
  /** Indicator type. */
  indicatorType: "hash" | "domain" | "ip" | "url" | "email";
  /** Indicator value. */
  value: string;
  /** Whether the IOC is known malicious. */
  malicious: boolean;
  /** Reputation score from the feed. */
  reputationScore?: number;
  /** Feed that reported the IOC. */
  feed: string;
}

/** Generic enrichment data for extensibility. */
export interface GenericEnrichment {
  kind: "generic";
  /** Arbitrary key-value data. */
  payload: Record<string, unknown>;
}

export type EnrichmentData = MitreEnrichment | IocEnrichment | GenericEnrichment;
```

### 4.4 Intel

A portable, shareable knowledge artifact derived from findings. Carries mandatory cryptographic provenance.

**Evolves from:** `HuntPattern` (hunt-types.ts) promotion workflow, extended with signing, receipts, and shareability.

**Key relationship to existing types:**
- `HuntPattern` with `status: "promoted"` becomes an Intel of `type: "pattern"`
- `HuntPattern.promotedToTrustprint` maps to `Intel.id`
- `PatternStep` (hunt-types.ts) reused in `IntelContentPattern.sequence`
- `Receipt` (types.ts) used for `Intel.receipt`
- `DetectionRuleCompilation` from hunt-correlate maps to `IntelContentDetectionRule`
- Signature format matches `@backbay/speakeasy` — Ed25519 over SHA-256 of canonical content

```typescript
// ---------------------------------------------------------------------------
// Intel
// ---------------------------------------------------------------------------

/**
 * A portable, shareable knowledge artifact derived from findings.
 *
 * Every Intel artifact carries:
 * 1. Ed25519 signature over canonical JSON (RFC 8785) content
 * 2. A SignedReceipt linking back to the source Finding
 * 3. Shareability scope controlling distribution
 *
 * Intel is the unit of exchange in swarms.
 */
export interface Intel {
  /** Unique intel ID. Format: `int_{ulid}`. */
  id: string;
  /** Artifact type — determines shape of `content`. */
  type: IntelType;
  /** Human-readable title. 1–256 chars. */
  title: string;
  /** Description of what this intel represents. 1–2048 chars. */
  description: string;
  /** The shareable artifact content. */
  content: IntelContent;
  /** Finding IDs this intel was derived from. */
  derivedFrom: string[];
  /** Aggregate confidence, 0.0–1.0. Inherited from source findings. */
  confidence: number;
  /** Free-form tags for categorization and search. */
  tags: string[];
  /** MITRE ATT&CK mappings, if applicable. */
  mitre: MitreMapping[];
  /** Who can see this intel. */
  shareability: IntelShareability;
  /**
   * Ed25519 signature over SHA-256 hash of canonical JSON (RFC 8785)
   * representation of { type, title, content, derivedFrom, confidence, tags, mitre }.
   * Hex-encoded, 128 chars.
   */
  signature: string;
  /**
   * Public key of the signer. Hex-encoded, 64 chars.
   * Must match either a sentinel identity or operator identity.
   */
  signerPublicKey: string;
  /**
   * Signed receipt attesting provenance — links to source findings
   * and the signing sentinel's decision chain.
   * Uses the existing Receipt type from types.ts.
   */
  receipt: import("./types").Receipt;
  /** Author's fingerprint (16 hex chars). Sentinel or human. */
  author: string;
  /** Creation timestamp (Unix ms). */
  createdAt: number;
  /**
   * Version counter. Incremented when the intel is updated.
   * Swarm members can detect stale intel by comparing versions.
   */
  version: number;
}

/**
 * MITRE ATT&CK mapping for an intel artifact.
 */
export interface MitreMapping {
  /** Technique ID (e.g., "T1059.001"). */
  techniqueId: string;
  /** Technique name. */
  techniqueName: string;
  /** Tactic name (e.g., "Execution", "Discovery"). */
  tactic: string;
}

/**
 * Intel content — the actual shareable artifact.
 * Discriminated union by `kind` field.
 */
export type IntelContent =
  | IntelContentPattern
  | IntelContentDetectionRule
  | IntelContentIoc
  | IntelContentCampaign
  | IntelContentAdvisory
  | IntelContentPolicyPatch;

/**
 * Behavioral pattern content.
 * Derived from HuntPattern (hunt-types.ts) when promoted.
 */
export interface IntelContentPattern {
  kind: "pattern";
  /** Action sequence steps. Reuses PatternStep from hunt-types.ts. */
  sequence: import("./hunt-types").PatternStep[];
  /** How many times this pattern has been observed. */
  matchCount: number;
  /** Human-readable description of what the pattern indicates. */
  narrative: string;
}

/**
 * Detection rule content.
 * Wraps a compiled detection rule from hunt-correlate.
 */
export interface IntelContentDetectionRule {
  kind: "detection_rule";
  /** Rule source format (sigma, yara, native_correlation, clawdstrike_policy). */
  sourceFormat: string;
  /** Rule source text. */
  sourceText: string;
  /** Human-readable description. */
  narrative: string;
}

/**
 * Indicators of compromise content.
 */
export interface IntelContentIoc {
  kind: "ioc";
  /** List of indicators. */
  indicators: IocIndicator[];
  /** Human-readable description. */
  narrative: string;
}

export interface IocIndicator {
  type: "hash" | "domain" | "ip" | "url" | "email" | "other";
  value: string;
  /** Optional context (where observed, when, related malware family). */
  context?: string;
}

/**
 * Campaign narrative — multi-finding summary.
 */
export interface IntelContentCampaign {
  kind: "campaign";
  /** Campaign name or identifier. */
  campaignName: string;
  /** Ordered list of finding IDs in this campaign. */
  findingIds: string[];
  /** Campaign narrative (Markdown). */
  narrative: string;
}

/**
 * Advisory content — human-readable summary.
 */
export interface IntelContentAdvisory {
  kind: "advisory";
  /** Advisory text (Markdown). */
  narrative: string;
  /** Recommended response actions. */
  recommendations: string[];
}

/**
 * Policy patch content — a recommended change to policy configuration.
 */
export interface IntelContentPolicyPatch {
  kind: "policy_patch";
  /**
   * JSON Merge Patch (RFC 7396) to apply to a WorkbenchPolicy.guards object.
   * For example: { "egress_allowlist": { "block": ["malicious.example.com"] } }
   */
  guardsPatch: Partial<import("./types").GuardConfigMap>;
  /** Explanation of what the patch does and why. */
  narrative: string;
  /** Which policy ruleset this patch is designed for (optional). */
  targetRuleset?: string;
}
```

### 4.5 Swarm

A coordination layer where sentinels and operators share intel.

**Evolves from:** `DelegationGraph` (delegation-types.ts) trust model + fleet enrollment concepts.

**Key relationship to existing types:**
- `DelegationNode` maps to `SwarmMember` — both represent trusted principals
- `DelegationEdge` with `kind: "IssuedGrant"` maps to `TrustEdge`
- `TrustLevel` (delegation-types.ts) maps to `ReputationScore.trustLevel`
- `Capability` (delegation-types.ts) reused in `SwarmPolicy.requiredCapabilities`

```typescript
// ---------------------------------------------------------------------------
// Swarm
// ---------------------------------------------------------------------------

/**
 * A coordination layer where sentinels and operators share intel.
 *
 * Three layers:
 * - personal:  your own sentinels coordinating (local, no network)
 * - trusted:   team, org, or invited peers (private swarm, Gossipsub)
 * - federated: cross-org, opt-in exchange (public discovery)
 */
export interface Swarm {
  /** Unique swarm ID. Format: `swm_{ulid}`. */
  id: string;
  /** Display name. 1–128 chars. */
  name: string;
  /** Swarm layer type. */
  type: SwarmType;
  /** Description of the swarm's purpose. */
  description: string;
  /** Members — both sentinels and operators. */
  members: SwarmMember[];
  /** References to intel artifacts published to this swarm. */
  sharedIntel: IntelRef[];
  /** Active detection rules distributed to swarm members. */
  sharedDetections: DetectionRef[];
  /**
   * Trust graph edges between members.
   * Extends the DelegationGraph concept (delegation-types.ts)
   * with reputation and intel-quality scoring.
   */
  trustGraph: TrustEdge[];
  /** Governance policies for the swarm. */
  policies: SwarmPolicy;
  /** Speakeasy rooms attached to this swarm. */
  speakeasies: SpeakeasyRef[];
  /** Swarm-level statistics. */
  stats: SwarmStats;
  /**
   * Gossipsub topic prefix for this swarm.
   * Follows the pattern: /baychat/v1/swarm/{swarmId}/
   * Sub-topics: intel, signals, detections, reputation
   */
  topicPrefix: string;
  /** Creation timestamp (Unix ms). */
  createdAt: number;
  /** Last activity timestamp (Unix ms). */
  lastActivityAt: number;
}

/**
 * A member of a swarm — either a sentinel or a human operator.
 */
export interface SwarmMember {
  /** Member type. */
  type: "sentinel" | "operator";
  /**
   * Public key fingerprint (16 hex chars).
   * For sentinels: matches SentinelIdentity.fingerprint.
   * For operators: matches the operator's BayChatIdentity.fingerprint.
   */
  fingerprint: string;
  /** Display name for the member. */
  displayName: string;
  /** Role within the swarm. */
  role: SwarmRole;
  /** Earned reputation. */
  reputation: ReputationScore;
  /** When this member joined (Unix ms). */
  joinedAt: number;
  /** Last seen timestamp (Unix ms). */
  lastSeenAt: number;
  /**
   * Sentinel ID, if this member is a sentinel.
   * Null for operator members.
   */
  sentinelId: string | null;
}

/**
 * Reputation score for a swarm member.
 * Earned over time based on intel quality, responsiveness, and accuracy.
 */
export interface ReputationScore {
  /** Overall score, 0.0–1.0. */
  overall: number;
  /**
   * Trust level derived from reputation.
   * Reuses TrustLevel from delegation-types.ts.
   */
  trustLevel: import("./delegation-types").TrustLevel;
  /** Number of intel artifacts contributed. */
  intelContributed: number;
  /** Number of confirmed true positives. */
  truePositives: number;
  /** Number of confirmed false positives. */
  falsePositives: number;
  /** Last reputation update (Unix ms). */
  lastUpdated: number;
}

/**
 * Reference to a shared intel artifact in the swarm.
 */
export interface IntelRef {
  /** Intel.id */
  intelId: string;
  /** Publisher fingerprint. */
  publishedBy: string;
  /** When published to the swarm (Unix ms). */
  publishedAt: number;
  /** Intel version at time of publication. */
  version: number;
}

/**
 * Reference to a shared detection rule in the swarm.
 */
export interface DetectionRef {
  /** Intel.id of the detection rule intel artifact. */
  intelId: string;
  /** Detection rule source format. */
  sourceFormat: string;
  /** Whether swarm members have auto-activated this detection. */
  autoActivated: boolean;
  /** When published (Unix ms). */
  publishedAt: number;
}

/**
 * A trust edge in the swarm trust graph.
 * Extends DelegationEdge (delegation-types.ts) with reputation context.
 */
export interface TrustEdge {
  /** Source member fingerprint. */
  from: string;
  /** Target member fingerprint. */
  to: string;
  /**
   * Trust level. Reuses TrustLevel from delegation-types.ts.
   * Derived from reputation + explicit trust assertions.
   */
  trustLevel: import("./delegation-types").TrustLevel;
  /** When this edge was last updated (Unix ms). */
  updatedAt: number;
  /**
   * Basis for trust — what evidence supports this edge.
   * Mirrors EdgeKind concepts from delegation-types.ts.
   */
  basis: "reputation" | "explicit_grant" | "delegation_chain" | "vouched";
}

/**
 * Governance rules for a swarm.
 */
export interface SwarmPolicy {
  /** Minimum reputation to publish intel. 0.0–1.0. Null = no minimum. */
  minReputationToPublish: number | null;
  /** Whether all shared artifacts must carry valid Ed25519 signatures. */
  requireSignatures: boolean;
  /** Whether confirmed detections auto-push to all members. */
  autoShareDetections: boolean;
  /** Whether intel is compartmentalized (need-to-know) by default. */
  compartmentalized: boolean;
  /**
   * Capabilities required to join this swarm.
   * Reuses Capability from delegation-types.ts.
   */
  requiredCapabilities: import("./delegation-types").Capability[];
  /** Maximum members. Null = unlimited. */
  maxMembers: number | null;
}

/**
 * Swarm-level statistics.
 */
export interface SwarmStats {
  /** Total members. */
  memberCount: number;
  /** Total sentinel members. */
  sentinelCount: number;
  /** Total operator members. */
  operatorCount: number;
  /** Total intel artifacts shared. */
  intelShared: number;
  /** Total active detections. */
  activeDetections: number;
  /** Total speakeasy rooms. */
  speakeasyCount: number;
  /** Average member reputation. */
  avgReputation: number;
}

/**
 * Reference to a Speakeasy room in a swarm.
 */
export interface SpeakeasyRef {
  /** ClawdstrikeSpeakeasy.id */
  speakeasyId: string;
  /** Room purpose. */
  purpose: SpeakeasyPurpose;
  /** What the room is attached to (finding ID, campaign ID, etc.). */
  attachedTo: string | null;
}
```

### 4.6 Speakeasy

A private signed room for sensitive collaboration and intel exchange.

**Extends:** `@backbay/speakeasy` primitives with Clawdstrike-specific purpose, classification, and attachment semantics.

**Key relationship to existing types:**
- `BayChatIdentity` from `@backbay/speakeasy` is the identity foundation
- `MessageEnvelope` from `@backbay/speakeasy/transport/types.ts` is the transport wrapper
- `SpeakeasyTopic` from `@backbay/speakeasy/transport/types.ts` is reused for topic naming
- `ApprovalRequest` (approval-types.ts) can be wired through a speakeasy for trust-gated approval
- `OriginContext` (approval-types.ts / types.ts) enriches speakeasy context

```typescript
// ---------------------------------------------------------------------------
// Speakeasy (Clawdstrike extension of @backbay/speakeasy)
// ---------------------------------------------------------------------------

/**
 * A private signed room for sensitive collaboration and intel exchange.
 *
 * Extends @backbay/speakeasy with:
 * - Purpose: why the room exists (finding, campaign, incident, etc.)
 * - Classification: sensitivity level governing data handling
 * - Attachment: links the room to a specific finding, campaign, or swarm
 * - Membership: sentinel and operator identities with roles
 *
 * Inherits from @backbay/speakeasy:
 * - Ed25519 signed membership
 * - Fingerprint-based trust verification
 * - Signed messages with nonce + timestamp verification
 * - Gossipsub transport with TTL-limited propagation
 * - Sigil-based visual identity
 */
export interface ClawdstrikeSpeakeasy {
  /** Unique speakeasy ID. Format: `spk_{ulid}`. */
  id: string;
  /** Parent swarm ID. Every speakeasy belongs to a swarm. */
  swarmId: string;
  /** Room name for display. */
  name: string;
  /** Why this room exists. */
  purpose: SpeakeasyPurpose;
  /** Sensitivity classification governing data handling rules. */
  classification: SpeakeasyClassification;
  /**
   * What this room is attached to.
   * - For purpose "finding": a Finding.id
   * - For purpose "campaign": an Intel.id of type "campaign"
   * - For purpose "incident": a Finding.id (critical severity)
   * - For purpose "coordination": null (general purpose)
   * - For purpose "mentoring": a Sentinel.id
   */
  attachedTo: string | null;
  /** Members of this room with their roles. */
  members: SpeakeasyMember[];
  /**
   * Gossipsub topics for this room.
   * Follows @backbay/speakeasy topic naming:
   *   /baychat/v1/speakeasy/{id}/messages
   *   /baychat/v1/speakeasy/{id}/presence
   *   /baychat/v1/speakeasy/{id}/typing
   */
  topics: {
    messages: string;
    presence: string;
    typing: string;
  };
  /** Creation timestamp (Unix ms). */
  createdAt: number;
  /** Last message timestamp (Unix ms). Null if no messages yet. */
  lastMessageAt: number | null;
  /**
   * Whether this room is archived.
   * Archived rooms are read-only and not subscribed to Gossipsub.
   */
  archived: boolean;
}

/**
 * A member of a Clawdstrike Speakeasy room.
 */
export interface SpeakeasyMember {
  /** Member type. */
  type: "sentinel" | "operator";
  /**
   * Public key fingerprint (16 hex chars).
   * Matches BayChatIdentity.fingerprint from @backbay/speakeasy.
   */
  fingerprint: string;
  /** Display name. */
  displayName: string;
  /**
   * Sigil type for visual identity.
   * Matches SpeakeasySigil from @backbay/speakeasy.
   */
  sigil: "diamond" | "eye" | "wave" | "crown" | "spiral" | "key" | "star" | "moon";
  /** Role in this room. */
  role: "moderator" | "participant" | "observer";
  /** When this member joined the room (Unix ms). */
  joinedAt: number;
}

/**
 * Clawdstrike-specific message types for Speakeasy.
 *
 * These extend the @backbay/speakeasy message types (ChatMessage,
 * SentinelRequest, SentinelResponse) with security-specific payloads.
 * They are sent as ChatMessage.content with a structured JSON payload,
 * keeping transport compatibility with the base Speakeasy protocol.
 */

/** Intel shared in a speakeasy room. */
export interface SpeakeasyIntelMessage {
  /** Discriminator for message routing. */
  messageType: "intel_shared";
  /** Intel.id being shared. */
  intelId: string;
  /** Intel type for display. */
  intelType: IntelType;
  /** Title for display. */
  title: string;
  /** Short summary. */
  summary: string;
  /** Signature of the intel artifact for verification. */
  intelSignature: string;
}

/** Finding escalation shared in a speakeasy room. */
export interface SpeakeasyFindingMessage {
  /** Discriminator for message routing. */
  messageType: "finding_escalated";
  /** Finding.id being escalated. */
  findingId: string;
  /** Severity for display. */
  severity: Severity;
  /** Title for display. */
  title: string;
  /** Summary of the finding. */
  summary: string;
}

/** Approval request routed through a speakeasy room. */
export interface SpeakeasyApprovalMessage {
  /** Discriminator for message routing. */
  messageType: "approval_request";
  /**
   * Approval request.
   * Reuses ApprovalRequest from approval-types.ts.
   */
  request: import("./approval-types").ApprovalRequest;
}

export type ClawdstrikeSpeakeasyMessage =
  | SpeakeasyIntelMessage
  | SpeakeasyFindingMessage
  | SpeakeasyApprovalMessage;
```

---

## 5. Relationship Map

```
┌────────────────────────────────────────────────────────────────────┐
│                        ENTITY RELATIONSHIPS                         │
│                                                                     │
│  Sentinel ──1:N──► Signal          "sentinel generates signals"     │
│  Sentinel ──1:N──► Finding         "sentinel creates findings"      │
│  Sentinel ──1:N──► Intel           "sentinel authors intel"         │
│  Sentinel ──M:N──► Swarm           "sentinel joins swarms"          │
│  Sentinel ──1:1──► SentinelMemory  "sentinel has memory"            │
│  Sentinel ──0:1──► AgentInfo       "optionally fleet-backed"        │
│                                                                     │
│  Signal ──N:1──► Sentinel          "attributed to sentinel"         │
│  Signal ──N:0..1──► Finding        "rolled into finding"            │
│  Signal ──M:N──► Signal            "correlated with signals"        │
│                                                                     │
│  Finding ──1:N──► Signal           "built from signals"             │
│  Finding ──0:1──► Intel            "promoted to intel"              │
│  Finding ──0:1──► Speakeasy        "discussed in speakeasy"         │
│  Finding ──0:1──► Receipt          "attested by receipt"            │
│                                                                     │
│  Intel ──N:M──► Finding            "derived from findings"          │
│  Intel ──1:1──► Receipt            "has receipt"                    │
│  Intel ──N:M──► Swarm              "shared in swarms"               │
│                                                                     │
│  Swarm ──1:N──► SwarmMember        "has members"                    │
│  Swarm ──1:N──► Speakeasy          "has rooms"                      │
│  Swarm ──M:N──► Intel              "shares intel"                   │
│  Swarm ──1:1──► SwarmPolicy        "governed by policy"             │
│                                                                     │
│  Speakeasy ──N:1──► Swarm          "belongs to swarm"               │
│  Speakeasy ──0:1──► Finding        "attached to finding"            │
│  Speakeasy ──0:1──► Intel          "attached to campaign"           │
│  Speakeasy ──0:1──► Sentinel       "attached for mentoring"         │
│  Speakeasy ──1:N──► SpeakeasyMember "has members"                   │
└────────────────────────────────────────────────────────────────────┘
```

### Foreign Key Index

| From Type | Field | References | Type of Reference |
|-----------|-------|------------|-------------------|
| `Signal.source.sentinelId` | `Sentinel.id` | Optional (null for external) |
| `Signal.findingId` | `Finding.id` | Optional (null until clustered) |
| `Signal.relatedSignals[n]` | `Signal.id` | 0..N |
| `Signal.data.sourceEventId` | `AgentEvent.id` | Optional (backward link) |
| `Finding.signalIds[n]` | `Signal.id` | 1..N |
| `Finding.promotedToIntel` | `Intel.id` | Optional |
| `Finding.speakeasyId` | `ClawdstrikeSpeakeasy.id` | Optional |
| `Intel.derivedFrom[n]` | `Finding.id` | 1..N |
| `Swarm.sharedIntel[n].intelId` | `Intel.id` | 0..N |
| `Swarm.speakeasies[n].speakeasyId` | `ClawdstrikeSpeakeasy.id` | 0..N |
| `SwarmMember.sentinelId` | `Sentinel.id` | Optional (null for operators) |
| `SwarmMembership.swarmId` | `Swarm.id` | Direct |
| `ClawdstrikeSpeakeasy.swarmId` | `Swarm.id` | Required |
| `ClawdstrikeSpeakeasy.attachedTo` | `Finding.id` / `Intel.id` / `Sentinel.id` | Polymorphic, context from `purpose` |
| `Sentinel.policy.policyId` | `SavedPolicy.id` | Optional |
| `Sentinel.fleetAgentId` | `AgentInfo.endpoint_agent_id` | Optional |

---

## 6. Migration Paths

### 6.1 AgentEvent → Signal

`AgentEvent` (hunt-types.ts) remains unchanged. The `Signal` type is a superset that the `SignalPipeline` produces from `AgentEvent` records.

```typescript
// Conversion: AgentEvent → Signal
function agentEventToSignal(event: AgentEvent, sentinelId: string | null): Signal {
  // Determine signal type from event characteristics
  const type: SignalType =
    event.verdict === "deny" ? "policy_violation" :
    (event.anomalyScore ?? 0) > 0.5 ? "anomaly" :
    event.flags.some(f => f.type === "pattern-match") ? "behavioral" :
    "detection";

  return {
    id: generateId("sig"),
    type,
    source: {
      sentinelId,
      guardId: event.guardResults[0]?.guardId ?? null,
      externalFeed: null,
      provenance: type === "anomaly" ? "anomaly_detection"
                : type === "behavioral" ? "pattern_match"
                : "guard_evaluation",
    },
    timestamp: new Date(event.timestamp).getTime(),
    severity: deriveSeverity(event),
    confidence: event.anomalyScore ?? (event.verdict === "deny" ? 0.9 : 0.5),
    data: buildSignalData(type, event),
    context: {
      agentId: event.agentId,
      agentName: event.agentName,
      teamId: event.teamId,
      sessionId: event.sessionId,
      flags: event.flags,
    },
    relatedSignals: [],
    ttl: deriveTtl(type, event),
    findingId: null,
  };
}
```

**Backward compatibility:** `AgentEvent` continues to be the transport type from fleet-client. The `auditEventToAgentEvent` function in hunt-engine.ts is unchanged. `SignalPipeline` wraps `AgentEvent` in `Signal` at the boundary.

### 6.2 Investigation → Finding

`Investigation` (hunt-types.ts) remains unchanged. Existing investigations are migrated to findings on first load.

| Investigation field | Finding field | Migration |
|--------------------|---------------|-----------|
| `id` | `id` | Prefix with `fnd_` if not already prefixed |
| `title` | `title` | Direct copy |
| `status: "open"` | `status: "emerging"` | Rename |
| `status: "in-progress"` | `status: "confirmed"` | Rename |
| `status: "resolved"` | `status: "confirmed"` | Rename (with verdict set) |
| `status: "false-positive"` | `status: "false_positive"` | Rename (hyphen to underscore) |
| `severity` | `severity` | Direct copy (same type) |
| `createdAt` (ISO string) | `createdAt` (Unix ms) | `new Date(iso).getTime()` |
| `updatedAt` (ISO string) | `updatedAt` (Unix ms) | `new Date(iso).getTime()` |
| `createdBy` | `createdBy` | Direct copy |
| `agentIds` | `scope.agentIds` | Nest under scope |
| `sessionIds` | `scope.sessionIds` | Nest under scope |
| `timeRange` | `scope.timeRange` | Nest under scope |
| `eventIds` | `signalIds` | Copy; events become signals |
| — | `signalCount` | `eventIds.length` |
| `annotations` | `annotations` | Direct copy (same type) |
| `verdict: "threat-confirmed"` | `verdict: "threat_confirmed"` | Hyphen to underscore |
| `verdict: "false-positive"` | `verdict: "false_positive"` | Hyphen to underscore |
| `verdict: "policy-gap"` | `verdict: "policy_gap"` | Hyphen to underscore |
| `verdict: "inconclusive"` | `verdict: "inconclusive"` | Unchanged |
| `actions: ["policy-updated"]` | `actions: ["policy_updated"]` | Hyphen to underscore |

**New fields default values on migration:**
- `confidence`: `0.7` (medium default for unmeasured investigations)
- `timeline`: single entry `{ type: "status_changed", summary: "Migrated from Investigation" }`
- `enrichments`: `[]`
- `promotedToIntel`: `null`
- `receipt`: `null`
- `speakeasyId`: `null`
- `updatedBy`: copy from `createdBy`

### 6.3 HuntPattern → Intel

`HuntPattern` (hunt-types.ts) remains unchanged. Patterns with `status: "promoted"` are converted to Intel artifacts via IntelForge.

| HuntPattern field | Intel field | Migration |
|------------------|-------------|-----------|
| `id` | `content.sequence` ID | Pattern ID preserved in content |
| `name` | `title` | Direct copy |
| `description` | `description` | Direct copy |
| `sequence` | `content.sequence` | Direct copy (same PatternStep type) |
| `matchCount` | `content.matchCount` | Direct copy |
| `status: "promoted"` | (always promoted) | Only promoted patterns become Intel |
| `promotedToTrustprint` | — | Replaced by Intel.id |
| `promotedToScenario` | — | Preserved in Intel.tags |

**New fields on promotion:**
- `type`: `"pattern"`
- `content.kind`: `"pattern"`
- `content.narrative`: auto-generated from pattern description
- `derivedFrom`: `[]` (or linked finding IDs if available)
- `confidence`: `0.8` (default for confirmed patterns)
- `tags`: extracted from pattern name + action types
- `mitre`: `[]` (populated by enrichment pass)
- `shareability`: `"private"` (default; operator upgrades)
- `signature`: computed on promotion
- `receipt`: signed on promotion

### 6.4 DelegationGraph → Swarm Trust Graph

The existing `DelegationGraph` (delegation-types.ts) is not replaced. The swarm trust graph is a parallel structure that can be rendered using the same force-graph engine.

| DelegationNode field | SwarmMember field | Mapping |
|--------------------|-------------------|---------|
| `id` | `fingerprint` | Node ID becomes fingerprint |
| `kind: "Principal"` | `type: "sentinel" \| "operator"` | Principals map to members |
| `label` | `displayName` | Direct copy |
| `trustLevel` | `reputation.trustLevel` | Reused enum |
| `capabilities` | (in SwarmPolicy) | Moved to swarm-level policy |

| DelegationEdge field | TrustEdge field | Mapping |
|--------------------|--------------------|---------|
| `from` | `from` | Fingerprint of source |
| `to` | `to` | Fingerprint of target |
| `kind: "IssuedGrant"` | `basis: "explicit_grant"` | Mapping |
| `kind: "ApprovedBy"` | `basis: "vouched"` | Mapping |

The force-graph-engine.ts can render both `DelegationGraph` (for delegation page) and `TrustEdge[]` (for swarm page) using the same layout algorithm.

---

## 7. Storage Strategy

### Storage Tiers

| Tier | Technology | Characteristics |
|------|-----------|-----------------|
| **Hot** | React state (Context + useReducer) | In-memory, lost on page reload |
| **Warm** | localStorage | 5–10 MB limit, synchronous, JSON strings |
| **Durable** | IndexedDB | 50+ MB, async, structured, indexed |
| **Secure** | Tauri Stronghold / IndexedDB encrypted | Secret keys only |
| **Remote** | Fleet API / hushd / control-api | Server-side, network-dependent |

### Per-Type Storage Assignment

| Type | Primary Store | Secondary Store | Rationale |
|------|--------------|----------------|-----------|
| **Sentinel** | IndexedDB `sentinels` | — | Moderate volume, rich structure, needs persistence across sessions. Too large for localStorage at scale. |
| **Sentinel secret keys** | Tauri Stronghold (desktop) / IndexedDB encrypted store (web) | — | Ed25519 private keys must never touch localStorage or plain IndexedDB. |
| **Signal** | IndexedDB `signals` with TTL index | React state (hot cache of recent 500) | High volume (up to 10K local). TTL-based eviction. IndexedDB indexes on `timestamp`, `sentinelId`, `findingId`, `type`. |
| **Finding** | IndexedDB `findings` | localStorage mirror of active findings (up to 100) | Medium volume. localStorage mirror enables quick hydration on load. |
| **Intel** | IndexedDB `intel` | — | Moderate volume. Contains signatures that must not be corrupted by localStorage string round-trips. |
| **Swarm** | IndexedDB `swarms` | localStorage mirror of swarm membership list (IDs + names only) | Low volume per user, but rich structure. |
| **Speakeasy** | IndexedDB `speakeasies` | — | Room config only. Messages are stored by `@backbay/speakeasy` useMessages hook (max 1000 per room). |

### localStorage Keys

Following the existing `clawdstrike_workbench_*` prefix pattern from multi-policy-store.tsx:

| Key | Content | Max Size |
|-----|---------|----------|
| `clawdstrike_sentinel_swarm_findings_active` | JSON array of active Finding summaries (id, title, status, severity) | ~50 KB |
| `clawdstrike_sentinel_swarm_swarm_membership` | JSON array of { swarmId, swarmName, role } | ~5 KB |
| `clawdstrike_sentinel_swarm_migration_v1` | `"1"` flag — set after Investigation→Finding migration | 1 byte |

### IndexedDB Schema

Database name: `clawdstrike_sentinel_swarm`
Version: `1`

```
Object Stores:
  sentinels    — keyPath: "id", indexes: [owner, status, mode]
  signals      — keyPath: "id", indexes: [timestamp, source.sentinelId, findingId, type, ttlExpiry]
  findings     — keyPath: "id", indexes: [status, severity, createdAt, updatedAt]
  intel        — keyPath: "id", indexes: [type, shareability, author, createdAt]
  swarms       — keyPath: "id", indexes: [type, createdAt]
  speakeasies  — keyPath: "id", indexes: [swarmId, purpose, attachedTo]
```

### Eviction Policy

| Store | Strategy | Trigger |
|-------|----------|---------|
| Signals | TTL-based: delete signals where `timestamp + ttl < now` | On every signal ingest batch (debounced to 1/min) |
| Signals | Count-based: keep newest `SIGNAL_LOCAL_LIMIT` (10K) | On every signal ingest batch |
| Findings with status `dismissed` or `false_positive` | Archive after 30 days | Daily sweep |
| Intel | No auto-eviction | Manual delete only |
| Sentinels with status `retired` | Archive after 90 days | Weekly sweep |

---

## 8. Serialization

### Canonical JSON (RFC 8785) — for signed artifacts

The following types MUST use canonical JSON (JCS per RFC 8785) when computing signatures:

| Type | Signed Fields | Used By |
|------|--------------|---------|
| `Intel` | `{ type, title, content, derivedFrom, confidence, tags, mitre }` | `Intel.signature` |
| `Finding.receipt` | Receipt body per hush-core format | Receipt signing |
| Speakeasy messages | `{ content, sender, timestamp, nonce }` per @backbay/speakeasy | Message signatures |

Canonical JSON requirements (matching hush-core implementation):
- Object keys sorted lexicographically
- No whitespace between tokens
- Numbers serialized without trailing zeros
- No `\uXXXX` escapes for ASCII-range characters
- UTF-8 encoding

### Regular JSON — for storage and non-signed transport

All other serialization uses standard `JSON.stringify` / `JSON.parse`:
- IndexedDB storage (structured clone handles this natively)
- localStorage persistence
- Gossipsub payloads (wrapped in MessageEnvelope which handles its own signing)
- REST API responses

### Timestamp Serialization

| Context | Format | Example |
|---------|--------|---------|
| New Sentinel Swarm types | Unix ms (`number`) | `1741785600000` |
| Existing types (AgentEvent, Investigation, etc.) | ISO-8601 (`string`) | `"2026-03-12T00:00:00.000Z"` |
| Receipt.timestamp | ISO-8601 (`string`) | Per hush-core convention |
| Gossipsub MessageEnvelope.created | Unix ms (`number`) | Per @backbay/speakeasy convention |

---

## 9. Validation Rules

### Sentinel

| Field | Rule |
|-------|------|
| `id` | Must match `^sen_[0-9A-Z]{26}$` (ULID after prefix) |
| `name` | 1–128 chars, non-empty after trim |
| `identity.publicKey` | 64 hex chars (32 bytes) |
| `identity.fingerprint` | 16 hex chars |
| `goals` | At least 1 goal required |
| `goals[n].escalation.minConfidence` | 0.0–1.0 |
| `goals[n].escalation.minCorrelatedSignals` | >= 1 |
| `schedule` | Valid 5-field cron or null |
| `policy` | At least one of `policyId`, `policyName`, or `ruleset` must be set |

### Signal

| Field | Rule |
|-------|------|
| `id` | Must match `^sig_[0-9A-Z]{26}$` |
| `confidence` | 0.0–1.0 |
| `timestamp` | Positive integer, not in the future by more than 5 minutes |
| `ttl` | Positive integer or null |
| `source` | At least one of `sentinelId`, `guardId`, or `externalFeed` must be non-null |
| `data.kind` | Must match `type` field (`"anomaly"` type requires `kind: "anomaly"` data) |

### Finding

| Field | Rule |
|-------|------|
| `id` | Must match `^fnd_[0-9A-Z]{26}$` |
| `confidence` | 0.0–1.0 |
| `signalIds` | At least 1 signal ID |
| `signalCount` | >= `signalIds.length` |
| `scope.timeRange.start` | Valid ISO-8601, before `end` |

### Intel

| Field | Rule |
|-------|------|
| `id` | Must match `^int_[0-9A-Z]{26}$` |
| `signature` | 128 hex chars (Ed25519 signature) |
| `signerPublicKey` | 64 hex chars |
| `receipt` | Must be a valid Receipt with non-empty signature |
| `content.kind` | Must match `type` field |
| `derivedFrom` | At least 1 finding ID for non-advisory types |
| `version` | Positive integer >= 1 |

### Swarm

| Field | Rule |
|-------|------|
| `id` | Must match `^swm_[0-9A-Z]{26}$` |
| `members` | At least 1 member (the creator) |
| `members[n].fingerprint` | 16 hex chars |
| `policies.minReputationToPublish` | 0.0–1.0 or null |
| `topicPrefix` | Must match `/baychat/v1/swarm/{id}/` |

### Speakeasy

| Field | Rule |
|-------|------|
| `id` | Must match `^spk_[0-9A-Z]{26}$` |
| `swarmId` | Must reference an existing swarm |
| `members` | At least 1 member |
| `members[n].fingerprint` | 16 hex chars |
| `attachedTo` | Required when `purpose` is `"finding"`, `"campaign"`, `"incident"`, or `"mentoring"`. Null only for `"coordination"`. |

---

## 10. ID Generation

All IDs use the format `{prefix}_{ulid}` where the ULID component provides:
- Timestamp-sortable ordering (first 48 bits = millisecond timestamp)
- Cryptographic randomness (last 80 bits)
- Case-insensitive Crockford Base32 encoding
- No coordination needed between clients

```typescript
import { ulid } from "ulid"; // or equivalent

type IdPrefix = "sen" | "sig" | "fnd" | "int" | "swm" | "spk" | "enr";

/**
 * Generate a prefixed ULID.
 * @param prefix - Type prefix (3 chars)
 * @returns Prefixed ID, e.g. "sen_01HXK8M3N2..."
 */
export function generateId(prefix: IdPrefix): string {
  return `${prefix}_${ulid()}`;
}
```

Dependency: the `ulid` package (already available in the Node ecosystem; 0 dependencies, <1 KB).

---

## Appendix: Type File Placement

New types should be added to the workbench lib directory following the existing pattern:

| File | Contents |
|------|----------|
| `apps/workbench/src/lib/workbench/sentinel-types.ts` | `Sentinel`, `SentinelIdentity`, `SentinelGoal`, `SentinelMemory`, `SentinelStats`, `PolicyRef`, `DataSource`, `PatternRef`, `EscalationPolicy`, `MemoryPattern`, `SwarmMembership` |
| `apps/workbench/src/lib/workbench/signal-types.ts` | `Signal`, `SignalSource`, `SignalData` variants, `SignalContext` |
| `apps/workbench/src/lib/workbench/finding-types.ts` | `Finding`, `FindingScope`, `TimelineEntry`, `Enrichment`, `EnrichmentData` variants |
| `apps/workbench/src/lib/workbench/intel-types.ts` | `Intel`, `IntelContent` variants, `MitreMapping`, `IocIndicator` |
| `apps/workbench/src/lib/workbench/swarm-types.ts` | `Swarm`, `SwarmMember`, `SwarmPolicy`, `SwarmStats`, `TrustEdge`, `ReputationScore`, `IntelRef`, `DetectionRef`, `SpeakeasyRef` |
| `apps/workbench/src/lib/workbench/speakeasy-types.ts` | `ClawdstrikeSpeakeasy`, `SpeakeasyMember`, `ClawdstrikeSpeakeasyMessage` variants |
| `apps/workbench/src/lib/workbench/sentinel-swarm-enums.ts` | All shared enums and constants from Section 3 |

Existing files are **not modified** — `hunt-types.ts`, `delegation-types.ts`, `approval-types.ts`, and `types.ts` remain unchanged. New types import from them where needed.
