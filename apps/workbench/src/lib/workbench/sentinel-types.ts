/**
 * Sentinel Swarm — Core Type Definitions
 *
 * This file contains ALL type definitions for the 6 core Sentinel Swarm objects:
 *   1. Sentinel — persistent autonomous defender
 *   2. Signal — raw clue, anomaly, event, or candidate detection
 *   3. Finding — grouped, enriched, scored conclusion from signals
 *   4. Intel — portable, shareable knowledge artifact
 *   5. Swarm — coordination layer for intel sharing
 *   6. Speakeasy — private signed room for collaboration
 *
 * Plus shared enums, constants, ID generation, type guards, and migration helpers.
 *
 * @see docs/plans/sentinel-swarm/DATA-MODEL.md
 */

import type { AgentBaseline, PatternStep, Annotation, EventFlag, AnomalyResult } from "./hunt-types";
import type { AgentEvent, Investigation, HuntPattern } from "./hunt-types";
import type { GuardSimResult, Receipt, OriginContext, TestActionType, GuardConfigMap } from "./types";
import type { TrustLevel, Capability } from "./delegation-types";
import type { ApprovalRequest } from "./approval-types";


/** Sentinel operating modes. All modes are still "Sentinels" in the product. */
export type SentinelMode = "watcher" | "hunter" | "curator" | "liaison";

/** Sentinel lifecycle status. */
export type SentinelStatus = "active" | "paused" | "retired";

/** Runtime backend bound to a sentinel. */
export type SentinelDriverKind =
  | "claude_code"
  | "openclaw"
  | "hushd_agent"
  | "openai_agent"
  | "mcp_worker";

/** Product-facing runtime posture. */
export type SentinelExecutionMode = "observe" | "assist" | "enforce";

/** Where the runtime lives. */
export type SentinelRuntimeEndpointType = "local" | "fleet" | "gateway" | "remote";

/** Current runtime health or bind status. */
export type SentinelRuntimeHealth = "planned" | "ready" | "degraded" | "offline";

/** Signal type discriminator. */
export type SignalType =
  | "anomaly"           // Behavioral deviation from baseline
  | "detection"         // Guard or rule match
  | "indicator"         // Weak IOC or external feed match
  | "policy_violation"  // Policy enforcement event (deny/warn)
  | "behavioral";       // Sequence/pattern-level observation

/** Severity levels — superset of existing Severity in hunt-types.ts. */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** Finding lifecycle status. */
export type FindingStatus =
  | "emerging"       // Auto-created from signal correlation
  | "confirmed"      // Analyst or sentinel confirmed
  | "promoted"       // Promoted to Intel artifact
  | "dismissed"      // Not actionable
  | "false_positive" // Confirmed FP; pattern added to suppression
  | "archived";      // Closed and archived for historical reference

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
  | "runtime_event"       // Produced by a bound runtime/tool session
  | "tool_receipt"        // Produced from a runtime receipt or transcript
  | "external_feed"       // Ingested from external threat feed
  | "swarm_intel"         // Received from a swarm peer
  | "manual";             // Manually created by operator


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


/** Valid ID prefixes for Sentinel Swarm objects. */
export type IdPrefix = "sen" | "sig" | "fnd" | "int" | "swm" | "spk" | "enr" | "msn";

/** Crockford Base32 encoding alphabet. */
const CROCKFORD_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * Encode a timestamp in milliseconds as a 10-character Crockford Base32 string.
 * Uses the ULID timestamp encoding: 48-bit big-endian millisecond value.
 */
function encodeTime(ms: number): string {
  let value = ms;
  const chars: string[] = new Array(10);
  for (let i = 9; i >= 0; i--) {
    chars[i] = CROCKFORD_BASE32[value & 0x1f]!;
    value = Math.floor(value / 32);
  }
  return chars.join("");
}

/**
 * Generate 16 random Crockford Base32 characters (80 bits of randomness).
 * Uses crypto.getRandomValues when available, falls back to Math.random.
 */
function encodeRandom(): string {
  const chars: string[] = new Array(16);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    for (let i = 0; i < 16; i++) {
      chars[i] = CROCKFORD_BASE32[bytes[i]! & 0x1f]!;
    }
  } else {
    for (let i = 0; i < 16; i++) {
      chars[i] = CROCKFORD_BASE32[Math.floor(Math.random() * 32)]!;
    }
  }
  return chars.join("");
}

/**
 * Generate a prefixed ULID.
 *
 * Format: `{prefix}_{ulid}` where the ULID component is 26 characters of
 * Crockford Base32 (10 timestamp + 16 random).
 *
 * @param prefix - Type prefix (3 chars)
 * @returns Prefixed ID, e.g. "sen_01HXK8M3N2..."
 */
export function generateId(prefix: IdPrefix): string {
  return `${prefix}_${encodeTime(Date.now())}${encodeRandom()}`;
}


/**
 * Sentinel identity — Ed25519 keypair compatible with both
 * hush-core receipt signing and @backbay/speakeasy message signing.
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
  /** Human-readable nickname derived from sentinel name. */
  nickname: string;
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
  /** User-facing display name. 1-128 chars, non-empty. */
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
  /** Runtime binding for execution, sessions, health, and receipts. */
  runtime: SentinelRuntimeBinding;
  /** Lifetime performance metrics. */
  stats: SentinelStats;
  /**
   * Fleet agent ID, if this sentinel is backed by a fleet-enrolled agent.
   * Maps to AgentInfo.endpoint_agent_id from fleet-client.ts.
   * Null for local-only sentinels (no fleet connection).
   */
  fleetAgentId: string | null;
  /**
   * Operator public key of the owner (64-char hex).
   * Present when the sentinel was created by an authenticated operator.
   */
  ownerPublicKey?: string;
  /**
   * Ed25519 signature + timestamp proving the owner controls the operator keypair.
   * Created via signOwnershipProof(sentinel.identity.publicKey, operatorSecretKey).
   * The proof includes a timestamp and expires after 24 hours (see OWNERSHIP_PROOF_MAX_AGE_MS).
   */
  ownershipProof?: import("./operator-crypto").OwnershipProof | null;
  /** Creation timestamp (Unix ms). */
  createdAt: number;
  /** Last update timestamp (Unix ms). */
  updatedAt: number;
}

/**
 * Runtime binding for a sentinel.
 *
 * This keeps the workbench local-first while exposing enough structure for:
 * - runtime registration in control-api
 * - mission assignment to concrete runtimes
 * - signal/finding receipt traceability
 */
export interface SentinelRuntimeBinding {
  /** Runtime backend this sentinel uses for execution. */
  driver: SentinelDriverKind;
  /** Operator-facing posture. */
  executionMode: SentinelExecutionMode;
  /** Contract-facing enforcement tier from enforcement-tiers.md. */
  enforcementTier: 0 | 1 | 2 | 3;
  /** Where the runtime is hosted. */
  endpointType: SentinelRuntimeEndpointType;
  /** Freeform runtime target reference (repo, gateway/node, fleet agent, etc). */
  targetRef: string | null;
  /** Runtime principal or registration ID from the control plane. */
  runtimeRef: string | null;
  /** Active session identifier when one exists. */
  sessionRef: string | null;
  /** Current runtime health. */
  health: SentinelRuntimeHealth;
  /** Whether this runtime emits receipts that can be attached to evidence. */
  receiptsEnabled: boolean;
  /** Whether tool/runtime activity should be promoted into signals. */
  emitsSignals: boolean;
  /** Last heartbeat timestamp, if reported by the runtime. */
  lastHeartbeatAt: number | null;
  /** Optional operator note about the binding target or constraints. */
  notes?: string;
}

/**
 * Reference to a policy by name, version, or saved-policy ID.
 * At least one of policyId or policyName must be set.
 */
export interface PolicyRef {
  /** SavedPolicy.id from policy-tabs-store — for locally saved policies. */
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
  /** Human-readable description of the goal. 1-512 chars. */
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
  /** Minimum confidence to auto-create a finding. 0.0-1.0. */
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
  baselineProfiles: AgentBaseline[];
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
  sequence: PatternStep[];
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


/**
 * A raw clue, anomaly, event, or candidate detection.
 *
 * Extends the concept of AgentEvent (hunt-types.ts) with:
 * - Source attribution (which sentinel or guard produced it)
 * - Confidence score (0.0-1.0)
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
   * Confidence score, 0.0-1.0.
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
  /** Discriminator for the anomaly signal data variant. */
  kind: "anomaly";
  /** Anomaly result from the scoring engine. Reuses AnomalyResult from hunt-types.ts. */
  anomaly: AnomalyResult;
  /**
   * Original AgentEvent ID, if derived from fleet audit.
   * Enables backward lookup to the full event.
   */
  sourceEventId?: string;
}

/** Detection signal — a guard or detection rule matched. */
export interface SignalDataDetection {
  /** Discriminator for the detection signal data variant. */
  kind: "detection";
  /** Guard results. Reuses GuardSimResult[] from types.ts. */
  guardResults: GuardSimResult[];
  /** Detection rule name, if rule-sourced (hunt-correlate). */
  ruleName?: string;
  /** Receipt ID if the guard evaluation produced a signed receipt. */
  receiptId?: string;
  /** Original AgentEvent ID, if derived from fleet audit. */
  sourceEventId?: string;
}

/** Indicator signal — weak IOC match from feed or Spider Sense. */
export interface SignalDataIndicator {
  /** Discriminator for the indicator signal data variant. */
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
    /** Pattern ID that matched. */
    patternId: string;
    /** Cosine similarity score. */
    similarity: number;
    /** Spider Sense screening verdict. */
    verdict: "benign" | "suspicious" | "malicious";
  };
}

/** Policy violation signal — a policy enforcement deny or warn. */
export interface SignalDataPolicyViolation {
  /** Discriminator for the policy violation signal data variant. */
  kind: "policy_violation";
  /** Guard results from the policy evaluation. */
  guardResults: GuardSimResult[];
  /** Policy name that was violated. */
  policyName: string;
  /** The action that was attempted. */
  actionType: TestActionType;
  /** The target of the action. */
  target: string;
  /** Verdict that was applied. Only deny/warn — allow is not a violation. */
  verdict: "deny" | "warn";
  /** Original AgentEvent ID. */
  sourceEventId?: string;
}

/** Behavioral signal — a sequence-level pattern observation. */
export interface SignalDataBehavioral {
  /** Discriminator for the behavioral signal data variant. */
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
  origin?: OriginContext;
  /**
   * Event flags carried forward from AgentEvent.
   * Reuses EventFlag from hunt-types.ts.
   */
  flags: EventFlag[];
}


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
  /** Human-readable title. 1-256 chars. */
  title: string;
  /** Lifecycle status. */
  status: FindingStatus;
  /** Assessed severity — can change as enrichment adds context. */
  severity: Severity;
  /**
   * Aggregate confidence score, 0.0-1.0.
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
  annotations: Annotation[];
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
  receipt: Receipt | null;
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
  /** Discriminator for the MITRE ATT&CK enrichment variant. */
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
  /** Discriminator for the IOC lookup enrichment variant. */
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
  /** Discriminator for the generic enrichment variant. */
  kind: "generic";
  /** Arbitrary key-value data. */
  payload: Record<string, unknown>;
}

/** Discriminated union of enrichment data variants. */
export type EnrichmentData = MitreEnrichment | IocEnrichment | GenericEnrichment;


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
  /** Human-readable title. 1-256 chars. */
  title: string;
  /** Description of what this intel represents. 1-2048 chars. */
  description: string;
  /** The shareable artifact content. */
  content: IntelContent;
  /** Finding IDs this intel was derived from. */
  derivedFrom: string[];
  /** Aggregate confidence, 0.0-1.0. Inherited from source findings. */
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
  receipt: Receipt;
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
  /** Discriminator for the pattern content variant. */
  kind: "pattern";
  /** Action sequence steps. Reuses PatternStep from hunt-types.ts. */
  sequence: PatternStep[];
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
  /** Discriminator for the detection rule content variant. */
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
  /** Discriminator for the IOC content variant. */
  kind: "ioc";
  /** List of indicators. */
  indicators: IocIndicator[];
  /** Human-readable description. */
  narrative: string;
}

/**
 * A single indicator of compromise entry.
 */
export interface IocIndicator {
  /** Indicator type. */
  type: "hash" | "domain" | "ip" | "url" | "email" | "other";
  /** Indicator value. */
  value: string;
  /** Optional context (where observed, when, related malware family). */
  context?: string;
}

/**
 * Campaign narrative — multi-finding summary.
 */
export interface IntelContentCampaign {
  /** Discriminator for the campaign content variant. */
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
  /** Discriminator for the advisory content variant. */
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
  /** Discriminator for the policy patch content variant. */
  kind: "policy_patch";
  /**
   * JSON Merge Patch (RFC 7396) to apply to a WorkbenchPolicy.guards object.
   * For example: { "egress_allowlist": { "block": ["malicious.example.com"] } }
   */
  guardsPatch: Partial<GuardConfigMap>;
  /** Explanation of what the patch does and why. */
  narrative: string;
  /** Which policy ruleset this patch is designed for (optional). */
  targetRuleset?: string;
}


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
  /** Display name. 1-128 chars. */
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
  /**
   * Fingerprint of the operator who invited this member.
   * Null for founding members or self-joined.
   */
  invitedBy?: string | null;
  /**
   * Depth in the invitation chain (0 = direct invite from admin).
   */
  invitationDepth?: number;
}

/**
 * Reputation score for a swarm member.
 * Earned over time based on intel quality, responsiveness, and accuracy.
 */
export interface ReputationScore {
  /** Overall score, 0.0-1.0. */
  overall: number;
  /**
   * Trust level derived from reputation.
   * Reuses TrustLevel from delegation-types.ts.
   */
  trustLevel: TrustLevel;
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
  trustLevel: TrustLevel;
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
  /** Minimum reputation to publish intel. 0.0-1.0. Null = no minimum. */
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
  requiredCapabilities: Capability[];
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
    /** Topic for chat messages. */
    messages: string;
    /** Topic for presence updates. */
    presence: string;
    /** Topic for typing indicators. */
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
 * Intel shared in a speakeasy room.
 * Sent as ChatMessage.content with a structured JSON payload.
 */
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

/**
 * Finding escalation shared in a speakeasy room.
 * Sent as ChatMessage.content with a structured JSON payload.
 */
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

/**
 * Approval request routed through a speakeasy room.
 * Sent as ChatMessage.content with a structured JSON payload.
 */
export interface SpeakeasyApprovalMessage {
  /** Discriminator for message routing. */
  messageType: "approval_request";
  /**
   * Approval request.
   * Reuses ApprovalRequest from approval-types.ts.
   */
  request: ApprovalRequest;
}

/** Discriminated union of Clawdstrike-specific speakeasy message types. */
export type ClawdstrikeSpeakeasyMessage =
  | SpeakeasyIntelMessage
  | SpeakeasyFindingMessage
  | SpeakeasyApprovalMessage;


/**
 * Check whether a value is a Sentinel by verifying its `id` prefix.
 */
export function isSentinel(value: unknown): value is Sentinel {
  return (
    typeof value === "object" &&
    value !== null &&
    "id" in value &&
    typeof (value as Sentinel).id === "string" &&
    (value as Sentinel).id.startsWith("sen_") &&
    "mode" in value &&
    "identity" in value
  );
}

/**
 * Check whether a value is a Signal by verifying its `id` prefix and required fields.
 */
export function isSignal(value: unknown): value is Signal {
  return (
    typeof value === "object" &&
    value !== null &&
    "id" in value &&
    typeof (value as Signal).id === "string" &&
    (value as Signal).id.startsWith("sig_") &&
    "type" in value &&
    "source" in value &&
    "data" in value
  );
}

/**
 * Check whether a value is a Finding by verifying its `id` prefix and required fields.
 */
export function isFinding(value: unknown): value is Finding {
  return (
    typeof value === "object" &&
    value !== null &&
    "id" in value &&
    typeof (value as Finding).id === "string" &&
    (value as Finding).id.startsWith("fnd_") &&
    "signalIds" in value &&
    "scope" in value
  );
}

/**
 * Check whether a value is an Intel artifact by verifying its `id` prefix and required fields.
 */
export function isIntel(value: unknown): value is Intel {
  return (
    typeof value === "object" &&
    value !== null &&
    "id" in value &&
    typeof (value as Intel).id === "string" &&
    (value as Intel).id.startsWith("int_") &&
    "content" in value &&
    "signature" in value
  );
}

/**
 * Check whether a value is a Swarm by verifying its `id` prefix and required fields.
 */
export function isSwarm(value: unknown): value is Swarm {
  return (
    typeof value === "object" &&
    value !== null &&
    "id" in value &&
    typeof (value as Swarm).id === "string" &&
    (value as Swarm).id.startsWith("swm_") &&
    "members" in value &&
    "topicPrefix" in value
  );
}

/**
 * Check whether a value is a ClawdstrikeSpeakeasy by verifying its `id` prefix and required fields.
 */
export function isSpeakeasy(value: unknown): value is ClawdstrikeSpeakeasy {
  return (
    typeof value === "object" &&
    value !== null &&
    "id" in value &&
    typeof (value as ClawdstrikeSpeakeasy).id === "string" &&
    (value as ClawdstrikeSpeakeasy).id.startsWith("spk_") &&
    "swarmId" in value &&
    "purpose" in value
  );
}


/**
 * Derive severity from an AgentEvent based on verdict and anomaly score.
 * Used internally by agentEventToSignal.
 */
function deriveSeverity(event: AgentEvent): Severity {
  if (event.verdict === "deny") {
    const score = event.anomalyScore ?? 0;
    if (score > 0.9) return "critical";
    if (score > 0.7) return "high";
    return "medium";
  }
  if (event.verdict === "warn") return "low";
  if ((event.anomalyScore ?? 0) > 0.5) return "medium";
  return "info";
}

/**
 * Derive TTL from signal type and event characteristics.
 * Used internally by agentEventToSignal.
 */
function deriveTtl(type: SignalType, event: AgentEvent): number | null {
  // Policy violations and high-anomaly signals persist longer
  if (type === "policy_violation") return null;
  if ((event.anomalyScore ?? 0) > 0.8) return null;
  return SIGNAL_DEFAULT_TTL_MS;
}

/**
 * Build the SignalData payload from an AgentEvent.
 * Used internally by agentEventToSignal.
 */
function buildSignalData(type: SignalType, event: AgentEvent): SignalData {
  switch (type) {
    case "anomaly":
      return {
        kind: "anomaly",
        anomaly: {
          score: event.anomalyScore ?? 0,
          factors: [],
        },
        sourceEventId: event.id,
      };
    case "policy_violation":
      return {
        kind: "policy_violation",
        guardResults: event.guardResults,
        policyName: event.policyVersion,
        actionType: event.actionType,
        target: event.target,
        verdict: event.verdict === "deny" ? "deny" : "warn",
        sourceEventId: event.id,
      };
    case "behavioral": {
      const patternFlag = event.flags.find(
        (f): f is Extract<EventFlag, { type: "pattern-match" }> => f.type === "pattern-match"
      );
      return {
        kind: "behavioral",
        patternId: patternFlag?.patternId ?? "unknown",
        patternName: patternFlag?.patternName ?? "Unknown Pattern",
        sessionId: event.sessionId,
        matchedEventIds: [event.id],
      };
    }
    case "detection":
    default:
      return {
        kind: "detection",
        guardResults: event.guardResults,
        sourceEventId: event.id,
      };
  }
}

/**
 * Convert an AgentEvent (hunt-types.ts) to a Signal.
 *
 * AgentEvent remains the transport type from fleet-client. The SignalPipeline
 * wraps AgentEvent in Signal at the boundary. AgentEvent is a valid subset
 * of Signal data.
 *
 * @param event - The source AgentEvent from fleet audit
 * @param sentinelId - The sentinel that observed this event, or null for unattributed
 * @returns A new Signal wrapping the event data
 */
export function agentEventToSignal(event: AgentEvent, sentinelId: string | null): Signal {
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

/**
 * Map an Investigation verdict (hyphenated) to a FindingVerdict (underscored).
 */
function mapInvestigationVerdict(
  verdict: "threat-confirmed" | "false-positive" | "policy-gap" | "inconclusive" | undefined,
): FindingVerdict | null {
  if (!verdict) return null;
  switch (verdict) {
    case "threat-confirmed": return "threat_confirmed";
    case "false-positive": return "false_positive";
    case "policy-gap": return "policy_gap";
    case "inconclusive": return "inconclusive";
  }
}

/**
 * Map an Investigation status (hyphenated) to a FindingStatus.
 */
function mapInvestigationStatus(
  status: "open" | "in-progress" | "resolved" | "false-positive",
): FindingStatus {
  switch (status) {
    case "open": return "emerging";
    case "in-progress": return "confirmed";
    case "resolved": return "confirmed";
    case "false-positive": return "false_positive";
  }
}

/**
 * Map Investigation actions (hyphenated) to FindingActions (underscored).
 */
function mapInvestigationActions(
  actions: ("policy-updated" | "pattern-added" | "agent-revoked" | "escalated")[] | undefined,
): FindingAction[] {
  if (!actions) return [];
  return actions.map((a) => {
    switch (a) {
      case "policy-updated": return "policy_updated";
      case "pattern-added": return "pattern_added";
      case "agent-revoked": return "agent_revoked";
      case "escalated": return "escalated";
    }
  });
}

/**
 * Convert an Investigation (hunt-types.ts) to a Finding.
 *
 * Investigation remains unchanged. Existing investigations are migrated to
 * findings on first load. The migration table in DATA-MODEL.md section 6.2
 * defines the field mappings.
 *
 * @param investigation - The source Investigation
 * @returns A new Finding with migrated fields and sensible defaults
 */
export function investigationToFinding(investigation: Investigation): Finding {
  const now = Date.now();
  const createdAt = new Date(investigation.createdAt).getTime();
  const updatedAt = new Date(investigation.updatedAt).getTime();

  return {
    id: investigation.id.startsWith("fnd_") ? investigation.id : `fnd_${investigation.id}`,
    title: investigation.title,
    status: mapInvestigationStatus(investigation.status),
    severity: investigation.severity as Severity,
    confidence: 0.7, // Medium default for unmeasured investigations
    signalIds: [...investigation.eventIds],
    signalCount: investigation.eventIds.length,
    scope: {
      agentIds: [...investigation.agentIds],
      sessionIds: [...investigation.sessionIds],
      timeRange: { ...investigation.timeRange },
    },
    timeline: [
      {
        timestamp: createdAt,
        type: "status_changed",
        summary: "Migrated from Investigation",
        actor: investigation.createdBy,
      },
    ],
    enrichments: [],
    annotations: [...investigation.annotations],
    verdict: mapInvestigationVerdict(investigation.verdict),
    actions: mapInvestigationActions(investigation.actions),
    promotedToIntel: null,
    receipt: null,
    speakeasyId: null,
    createdBy: investigation.createdBy,
    updatedBy: investigation.createdBy,
    createdAt: isNaN(createdAt) ? now : createdAt,
    updatedAt: isNaN(updatedAt) ? now : updatedAt,
  };
}

/**
 * Convert a HuntPattern (hunt-types.ts) with status "promoted" to an Intel artifact.
 *
 * HuntPattern remains unchanged. Patterns with status "promoted" are converted
 * to Intel artifacts via IntelForge. The migration table in DATA-MODEL.md
 * section 6.3 defines the field mappings.
 *
 * Note: The resulting Intel will have a placeholder signature and receipt.
 * The caller must sign the artifact with an Ed25519 key and attach a valid
 * receipt before publishing to a swarm.
 *
 * @param pattern - The source HuntPattern (should have status "promoted")
 * @param author - Fingerprint of the author (sentinel or operator)
 * @param receipt - Signed receipt attesting provenance
 * @returns A new Intel artifact wrapping the pattern
 */
export function huntPatternToIntel(
  pattern: HuntPattern,
  author: string,
  receipt: Receipt,
): Intel {
  const tags: string[] = [];

  // Extract tags from pattern name and action types
  const nameTokens = pattern.name.toLowerCase().split(/[\s_-]+/);
  tags.push(...nameTokens.filter((t) => t.length > 2));

  const actionTypes = new Set(pattern.sequence.map((s) => s.actionType));
  actionTypes.forEach((at) => {
    tags.push(at);
  });

  // Preserve promotedToScenario as a tag if present
  if (pattern.promotedToScenario) {
    tags.push(`scenario:${pattern.promotedToScenario}`);
  }

  return {
    id: generateId("int"),
    type: "pattern",
    title: pattern.name,
    description: pattern.description,
    content: {
      kind: "pattern",
      sequence: [...pattern.sequence],
      matchCount: pattern.matchCount,
      narrative: pattern.description,
    },
    derivedFrom: [],
    confidence: 0.8, // Default for confirmed patterns
    tags,
    mitre: [], // Populated by enrichment pass
    shareability: "private", // Default; operator upgrades
    signature: "", // Must be computed by caller
    signerPublicKey: "", // Must be set by caller
    receipt,
    author,
    createdAt: Date.now(),
    version: 1,
  };
}
