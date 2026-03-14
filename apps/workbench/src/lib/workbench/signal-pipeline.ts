/**
 * Signal Pipeline — ingestion, scoring, deduplication, and correlation.
 *
 * Normalizes events from four source families (guard results, anomaly detector,
 * external feeds, swarm intel) into canonical Signal objects, scores them, deduplicates,
 * and clusters related signals for downstream Finding creation.
 *
 * All algorithms run client-side. No server dependency beyond optional hushd enrichment.
 */

import type { AuditEvent } from "./fleet-client";
import type {
  AgentEvent,
  AgentBaseline,
  AnomalyResult,
  HuntPattern,
  Severity,
} from "./hunt-types";
import type { TestActionType, Verdict, GuardSimResult } from "./types";
import type {
  SignalType,
  SignalProvenance,
  SignalSource,
} from "./sentinel-types";
import {
  scoreAnomaly,
  computeBaseline,
  matchPatternInSession,
  discoverPatterns,
  detectAnomalyClusters,
  auditEventToAgentEvent,
} from "./hunt-engine";

// Re-export canonical types so downstream consumers (finding-engine, stores) still work.
export type { SignalType, SignalProvenance, SignalSource };

// Pipeline-specific types
//
// SignalContext, SignalData, and Signal use flat/optional-field shapes that
// diverge from the canonical discriminated-union types in sentinel-types.ts.
// These pipeline-local definitions are intentional: they allow the ingestion
// functions to construct signals from heterogeneous sources without matching
// the strict canonical shape.  The canonical types are the system-of-record
// for serialized/persisted signals; these are the *construction-time* types.

/** Context about the agent, session, and origin for a signal. */
export interface SignalContext {
  agentId: string;
  agentName: string;
  teamId?: string;
  sessionId: string;
  flags: Array<{ type: string; reason?: string; score?: number }>;
}

/** Signal data — typed payload discriminated by kind. */
export interface SignalData {
  kind: string;
  /** Human-readable summary for triage display. */
  summary?: string;
  /** Action type, if applicable. */
  actionType?: TestActionType;
  /** Guard results from the evaluation. */
  guardResults?: GuardSimResult[];
  /** Anomaly scoring result. */
  anomaly?: AnomalyResult;
  /** IOC match info. */
  matchedIocs?: Array<{ indicator: string; iocType: string; source: string }>;
  /** Matched field name for IOC. */
  matchField?: string;
  /** Source event ID for backward lookup. */
  sourceEventId?: string;
  /** Pattern ID if behavioral. */
  patternId?: string;
  /** Pattern name if behavioral. */
  patternName?: string;
  /** Matched event IDs if behavioral. */
  matchedEventIds?: string[];
  /** Baseline ID for anomaly context. */
  baselineId?: string;
  /** Anomaly scoring factors. */
  factors?: Array<{ name: string; weight: number; zScore: number; description: string }>;
  /** Intel ID if swarm-sourced. */
  intelId?: string;
  /** Author fingerprint for swarm-sourced signals. */
  authorFingerprint?: string;
  /** Signature for swarm-sourced signals. */
  signature?: string;
  /** Policy name for policy violation signals. */
  policyName?: string;
  /** Target of the action. */
  target?: string;
  /** Verdict applied. */
  verdict?: "deny" | "warn";
  /** Arbitrary extra data. */
  [key: string]: unknown;
}

/** A raw clue, anomaly, event, or candidate detection. */
export interface Signal {
  id: string;
  type: SignalType;
  source: SignalSource;
  timestamp: number;
  severity: Severity;
  confidence: number;
  data: SignalData;
  context: SignalContext;
  relatedSignals: string[];
  ttl: number | null;
  findingId: string | null;
}

/** Signal impact categories for severity derivation. */
export type SignalImpact =
  | "data_access"
  | "code_execution"
  | "network_egress"
  | "privilege_escalation"
  | "persistence"
  | "credential_access";

/** IOC match result from external feed matching. */
export interface IocMatch {
  matchedIocs: Array<{ indicator: string; iocType: string; source: string }>;
  matchField: string;
  event?: AgentEvent;
}

/** Swarm intel envelope (simplified for pipeline ingestion). */
export interface SwarmIntelEnvelope {
  swarmId: string;
  payload: {
    type: string;
    severity: Severity;
    confidence: number;
    intelId?: string;
    authorFingerprint?: string;
    signature?: string;
    summary?: string;
  };
  peerReputation: number;
}

/** A cluster of correlated signals. */
export interface SignalCluster {
  id: string;
  signalIds: string[];
  maxConfidence: number;
  strategies: CorrelationStrategyName[];
  createdAt: number;
}

export type CorrelationStrategyName =
  | "time_window"
  | "agent_affinity"
  | "pattern_match"
  | "mitre_grouping";


const SIGNAL_DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

/** Default deduplication window in ms. */
const DEDUP_WINDOW_MS = 5_000;

/** Default correlation time window in ms (5 minutes). */
const CORRELATION_WINDOW_MS = 5 * 60 * 1000;

/** Composite confidence weights — sum to 1.0. */
const W_SOURCE = 0.35;
const W_ANOMALY = 0.25;
const W_PATTERN = 0.20;
const W_CORR = 0.15;
const W_REP = 0.05;

/** Impact multipliers for severity derivation. */
const IMPACT_WEIGHTS: Record<string, number> = {
  data_access: 0.8,
  code_execution: 1.2,
  network_egress: 0.9,
  privilege_escalation: 1.4,
  persistence: 1.1,
  credential_access: 1.3,
};

/** Agent-affinity correlation scores. */
const AFFINITY_SAME_AGENT = 0.3;
const AFFINITY_SAME_SESSION = 0.6;

/** Affinity decay period in hours. */
const AFFINITY_DECAY_HOURS = 24;

/** MITRE kill-chain correlation boost. */
const MITRE_CHAIN_BOOST = 0.4;

let signalCounter = 0;


/**
 * Generate a signal ID with the `sig_` prefix.
 * Uses a monotonic counter + timestamp for uniqueness within a session.
 */
export function generateSignalId(): string {
  const ts = Date.now().toString(36);
  const seq = (++signalCounter).toString(36).padStart(4, "0");
  return `sig_${ts}${seq}`;
}


/**
 * Convert a guard evaluation result and its parent AgentEvent into a Signal.
 *
 * deny -> policy_violation with confidence 1.0
 * warn -> detection with confidence 0.7
 */
export function guardResultToSignal(
  event: AgentEvent,
  guardResult: GuardSimResult,
): Signal {
  const isDeny = guardResult.verdict === "deny";
  const signalType: SignalType = isDeny ? "policy_violation" : "detection";
  const confidence = isDeny ? 1.0 : 0.7;

  return {
    id: generateSignalId(),
    type: signalType,
    source: {
      sentinelId: null,
      guardId: guardResult.guardId,
      externalFeed: null,
      provenance: "guard_evaluation",
    },
    timestamp: new Date(event.timestamp).getTime(),
    severity: deriveSeverity(confidence, inferImpact(event)),
    confidence,
    data: {
      kind: isDeny ? "policy_violation" : "detection",
      summary: guardResult.message,
      guardResults: [guardResult],
      actionType: event.actionType,
      target: event.target,
      verdict: isDeny ? "deny" : "warn",
      policyName: event.policyVersion,
      sourceEventId: event.id,
    },
    context: {
      agentId: event.agentId,
      agentName: event.agentName,
      teamId: event.teamId,
      sessionId: event.sessionId,
      flags: event.flags.map((f) => ({ ...f })),
    },
    relatedSignals: [],
    ttl: isDeny ? null : SIGNAL_DEFAULT_TTL_MS,
    findingId: null,
  };
}

/**
 * Convert an anomaly scoring result into a Signal.
 *
 * anomalyResult.score IS the confidence (direct mapping).
 * Type is "anomaly" when score <= 0.9, "behavioral" when
 * the anomaly represents a sequence-level observation.
 */
export function anomalyToSignal(
  event: AgentEvent,
  anomalyResult: AnomalyResult,
  sentinelId?: string,
  baselineId?: string,
): Signal {
  const score = anomalyResult.score;
  const severity: Severity =
    score > 0.9 ? "high" : score > 0.7 ? "medium" : "low";

  return {
    id: generateSignalId(),
    type: "anomaly",
    source: {
      sentinelId: sentinelId ?? null,
      guardId: null,
      externalFeed: null,
      provenance: "anomaly_detection",
    },
    timestamp: new Date(event.timestamp).getTime(),
    severity,
    confidence: score,
    data: {
      kind: "anomaly",
      summary: anomalyResult.factors.map((f) => f.description).join("; "),
      anomaly: anomalyResult,
      factors: anomalyResult.factors,
      baselineId: baselineId ?? event.agentId,
      sourceEventId: event.id,
    },
    context: {
      agentId: event.agentId,
      agentName: event.agentName,
      teamId: event.teamId,
      sessionId: event.sessionId,
      flags: event.flags.map((f) => ({ ...f })),
    },
    relatedSignals: [],
    ttl: severity === "low" ? SIGNAL_DEFAULT_TTL_MS : null,
    findingId: null,
  };
}

/**
 * Convert an IOC match result into a Signal.
 *
 * Confidence is 0.8 (IOC feeds carry staleness uncertainty).
 * Severity depends on indicator type: hash -> high, domain/IP -> medium.
 */
export function iocMatchToSignal(
  iocMatch: IocMatch,
  sentinelId?: string,
): Signal {
  const firstIoc = iocMatch.matchedIocs[0];
  const severity = iocTypeSeverity(iocMatch);

  return {
    id: generateSignalId(),
    type: "indicator",
    source: {
      sentinelId: sentinelId ?? null,
      guardId: null,
      externalFeed: firstIoc?.source ?? "unknown",
      provenance: "external_feed",
    },
    timestamp: Date.now(),
    severity,
    confidence: 0.8,
    data: {
      kind: "indicator",
      summary: `IOC match: ${firstIoc?.indicator ?? "unknown"} (${firstIoc?.iocType ?? "unknown"})`,
      matchedIocs: iocMatch.matchedIocs,
      matchField: iocMatch.matchField,
      sourceEventId: iocMatch.event?.id,
    },
    context: {
      agentId: iocMatch.event?.agentId ?? "unknown",
      agentName: iocMatch.event?.agentName ?? "unknown",
      teamId: iocMatch.event?.teamId,
      sessionId: iocMatch.event?.sessionId ?? "unknown",
      flags: [],
    },
    relatedSignals: [],
    ttl: null,
    findingId: null,
  };
}

/**
 * Convert a swarm intel envelope into a Signal.
 *
 * Confidence is attenuated by peer reputation.
 * Type is inherited from the intel artifact type.
 */
export function swarmIntelToSignal(
  envelope: SwarmIntelEnvelope,
): Signal {
  const attenuatedConfidence = clamp(
    0,
    1,
    envelope.payload.confidence * envelope.peerReputation,
  );

  return {
    id: generateSignalId(),
    type: envelope.payload.type === "ioc" ? "indicator" : "detection",
    source: {
      sentinelId: null,
      guardId: null,
      externalFeed: `swarm:${envelope.swarmId}`,
      provenance: "swarm_intel",
    },
    timestamp: Date.now(),
    severity: envelope.payload.severity,
    confidence: attenuatedConfidence,
    data: {
      kind: envelope.payload.type === "ioc" ? "indicator" : "detection",
      summary: envelope.payload.summary ?? `Swarm intel from ${envelope.swarmId}`,
      intelId: envelope.payload.intelId,
      authorFingerprint: envelope.payload.authorFingerprint,
      signature: envelope.payload.signature,
    },
    context: {
      agentId: "swarm",
      agentName: `swarm:${envelope.swarmId}`,
      sessionId: "swarm",
      flags: [],
    },
    relatedSignals: [],
    ttl: null,
    findingId: null,
  };
}


/**
 * Derive a severity classification from confidence and impact.
 *
 * Confidence (0-1) is multiplied by the impact weight, then mapped
 * to severity bands: critical >= 0.9, high >= 0.7, medium >= 0.4,
 * low >= 0.2, else info.
 */
export function deriveSeverity(
  confidence: number,
  impact?: SignalImpact,
): Severity {
  const impactMultiplier = impact ? (IMPACT_WEIGHTS[impact] ?? 1.0) : 1.0;
  const adjustedScore = confidence * impactMultiplier;

  if (adjustedScore >= 0.9) return "critical";
  if (adjustedScore >= 0.7) return "high";
  if (adjustedScore >= 0.4) return "medium";
  if (adjustedScore >= 0.2) return "low";
  return "info";
}

/**
 * Derive severity from an IOC match based on indicator type.
 * Hash matches are high; domain/IP are medium; everything else is low.
 */
export function iocTypeSeverity(iocMatch: IocMatch): Severity {
  const types = iocMatch.matchedIocs.map((i) => i.iocType);
  if (types.includes("hash")) return "high";
  if (types.includes("domain") || types.includes("ip")) return "medium";
  return "low";
}

/**
 * Infer a signal impact category from an AgentEvent's action type.
 */
function inferImpact(event: AgentEvent): SignalImpact {
  switch (event.actionType) {
    case "file_access":
      return "data_access";
    case "file_write":
      return "persistence";
    case "network_egress":
      return "network_egress";
    case "shell_command":
      return "code_execution";
    case "mcp_tool_call":
      return "code_execution";
    case "patch_apply":
      return "code_execution";
    case "user_input":
      return "data_access";
    default:
      return "data_access";
  }
}


/**
 * Compute a deduplication hash for a signal.
 *
 * Key: type + agentId + sessionId + timestamp_truncated_to_1s + data_kind.
 * Uses a simple string hash since we are client-side (no crypto import needed
 * for dedup — SHA-256 is specified in the spec but a fast hash suffices
 * for the 5-second dedup window).
 */
export function computeSignalHash(signal: Signal): string {
  const tsTruncated = Math.floor(signal.timestamp / 1000);
  const raw = [
    signal.type,
    signal.context.agentId,
    signal.context.sessionId,
    tsTruncated.toString(),
    signal.data.kind,
    signal.data.sourceEventId ?? "",
    signal.source.guardId ?? "",
  ].join("|");
  return fastStringHash(raw);
}

/**
 * Fast 53-bit string hash (djb2 variant). Sufficient for dedup within a
 * short time window — not cryptographic.
 */
function fastStringHash(str: string): string {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) + hash + str.charCodeAt(i)) | 0;
  }
  return (hash >>> 0).toString(36);
}

/**
 * Signal deduplicator. Maintains a set of recent signal hashes and
 * evicts entries older than the dedup window (default 5s).
 */
export class SignalDeduplicator {
  private seen: Map<string, number> = new Map();
  private windowMs: number;

  constructor(windowMs: number = DEDUP_WINDOW_MS) {
    this.windowMs = windowMs;
  }

  /**
   * Check whether a signal is a duplicate of one seen within the window.
   * If not a duplicate, records the signal hash for future checks.
   */
  isDuplicate(signal: Signal): boolean {
    const hash = computeSignalHash(signal);
    const now = Date.now();

    // Evict stale entries
    for (const [k, ts] of this.seen) {
      if (now - ts > this.windowMs) this.seen.delete(k);
    }

    if (this.seen.has(hash)) return true;
    this.seen.set(hash, now);
    return false;
  }

  /** Reset the deduplicator state. */
  clear(): void {
    this.seen.clear();
  }

  /** Number of hashes currently tracked. */
  get size(): number {
    return this.seen.size;
  }
}


/** Inputs for the composite confidence calculation. */
export interface ConfidenceInputs {
  /** Inherent source reliability (0-1). */
  sourceConfidence: number;
  /** Anomaly score (0-1). 0 if not anomaly-sourced. */
  anomalyScore: number;
  /** Pattern match score (0-1). 0 if no pattern match. */
  patternMatchScore: number;
  /** Correlation boost (0-1). 0 if uncorrelated. */
  correlationBoost: number;
  /** Peer reputation factor (0-1). 1.0 for local signals. */
  reputationFactor: number;
}

/**
 * Compute composite signal confidence from 5 weighted factors.
 *
 * confidence_final = clamp(0, 1,
 *   w_source * source_confidence +
 *   w_anomaly * anomaly_score +
 *   w_pattern * pattern_match_score +
 *   w_corr * correlation_boost +
 *   w_rep * reputation_factor
 * )
 */
export function computeSignalConfidence(inputs: ConfidenceInputs): number {
  const raw =
    W_SOURCE * inputs.sourceConfidence +
    W_ANOMALY * inputs.anomalyScore +
    W_PATTERN * inputs.patternMatchScore +
    W_CORR * inputs.correlationBoost +
    W_REP * inputs.reputationFactor;

  return clamp(0, 1, raw);
}

/**
 * Recalculate a signal's confidence, incorporating correlation context.
 * Returns a new Signal with the updated confidence and severity.
 */
export function recalculateSignalConfidence(
  signal: Signal,
  correlationBoost: number,
  patternMatchScore: number = 0,
  reputationFactor: number = 1.0,
): Signal {
  const inputs: ConfidenceInputs = {
    sourceConfidence: signal.confidence,
    anomalyScore: signal.data.anomaly?.score ?? 0,
    patternMatchScore,
    correlationBoost,
    reputationFactor,
  };

  const newConfidence = computeSignalConfidence(inputs);
  const newSeverity = deriveSeverity(newConfidence, inferImpactFromSignal(signal));

  return {
    ...signal,
    confidence: newConfidence,
    severity: newSeverity,
  };
}


/**
 * Check whether a signal should be suppressed based on known false-positive
 * hashes. Returns true if the signal's content hash is in the FP set.
 */
export function isFalsePositiveSuppressed(
  signal: Signal,
  falsePositiveHashes: Set<string>,
): boolean {
  const hash = computeSignalHash(signal);
  return falsePositiveHashes.has(hash);
}

/**
 * Check whether a signal matches a suppressed pattern.
 * Patterns with `suppress: true` in sentinel memory prevent pattern-score
 * contribution (w_pattern = 0).
 */
export function isPatternSuppressed(
  signal: Signal,
  suppressedPatternIds: Set<string>,
): boolean {
  const patternId = signal.data.patternId;
  if (!patternId) return false;
  return suppressedPatternIds.has(patternId);
}


/**
 * Time-window correlation: group signals from the same agent/session
 * arriving within the configured time window.
 */
export function correlateByTimeWindow(
  signals: Signal[],
  windowMs: number = CORRELATION_WINDOW_MS,
): SignalCluster[] {
  const sorted = [...signals].sort((a, b) => a.timestamp - b.timestamp);
  const clusters: SignalCluster[] = [];
  const assigned = new Set<string>();

  for (let i = 0; i < sorted.length; i++) {
    const anchor = sorted[i];
    if (assigned.has(anchor.id)) continue;

    const clusterSignals: Signal[] = [anchor];
    assigned.add(anchor.id);

    for (let j = i + 1; j < sorted.length; j++) {
      const candidate = sorted[j];
      if (candidate.timestamp - anchor.timestamp > windowMs) break;
      if (assigned.has(candidate.id)) continue;

      // Same agent or same session
      if (
        candidate.context.agentId === anchor.context.agentId ||
        candidate.context.sessionId === anchor.context.sessionId
      ) {
        clusterSignals.push(candidate);
        assigned.add(candidate.id);
      }
    }

    if (clusterSignals.length >= 2) {
      clusters.push({
        id: `cluster_tw_${anchor.id}`,
        signalIds: clusterSignals.map((s) => s.id),
        maxConfidence: Math.max(...clusterSignals.map((s) => s.confidence)),
        strategies: ["time_window"],
        createdAt: Date.now(),
      });
    }
  }

  return clusters;
}

/**
 * Agent-affinity correlation: signals from the same agent receive a
 * correlation bonus even outside the time window.
 *
 * - 0.6 for same session
 * - 0.3 for same agent, different session
 * - Decays linearly over 24 hours
 */
export function correlateByAgentAffinity(
  signals: Signal[],
): SignalCluster[] {
  // Group by agentId
  const byAgent = new Map<string, Signal[]>();
  for (const s of signals) {
    const agentId = s.context.agentId;
    const existing = byAgent.get(agentId);
    if (existing) {
      existing.push(s);
    } else {
      byAgent.set(agentId, [s]);
    }
  }

  const clusters: SignalCluster[] = [];

  for (const [agentId, agentSignals] of byAgent) {
    if (agentSignals.length < 2) continue;

    // Within this agent's signals, group those with sufficient affinity
    const sorted = [...agentSignals].sort((a, b) => a.timestamp - b.timestamp);
    const clusterIds: string[] = [];

    for (let i = 0; i < sorted.length; i++) {
      for (let j = i + 1; j < sorted.length; j++) {
        const a = sorted[i];
        const b = sorted[j];
        const elapsedHours =
          Math.abs(b.timestamp - a.timestamp) / (1000 * 60 * 60);
        const decay = Math.max(0, 1 - elapsedHours / AFFINITY_DECAY_HOURS);

        const baseAffinity =
          a.context.sessionId === b.context.sessionId
            ? AFFINITY_SAME_SESSION
            : AFFINITY_SAME_AGENT;
        const affinity = baseAffinity * decay;

        // Threshold: affinity must be non-trivial
        if (affinity > 0.1) {
          if (!clusterIds.includes(a.id)) clusterIds.push(a.id);
          if (!clusterIds.includes(b.id)) clusterIds.push(b.id);
        }
      }
    }

    if (clusterIds.length >= 2) {
      const clusterSignals = agentSignals.filter((s) =>
        clusterIds.includes(s.id),
      );
      clusters.push({
        id: `cluster_aa_${agentId}`,
        signalIds: clusterIds,
        maxConfidence: Math.max(...clusterSignals.map((s) => s.confidence)),
        strategies: ["agent_affinity"],
        createdAt: Date.now(),
      });
    }
  }

  return clusters;
}

/**
 * Compute the affinity score between two signals.
 * Used for recalculating correlation boost.
 */
export function computeAffinityScore(a: Signal, b: Signal): number {
  const elapsedHours =
    Math.abs(b.timestamp - a.timestamp) / (1000 * 60 * 60);
  const decay = Math.max(0, 1 - elapsedHours / AFFINITY_DECAY_HOURS);

  if (a.context.sessionId === b.context.sessionId) {
    return AFFINITY_SAME_SESSION * decay;
  }
  if (a.context.agentId === b.context.agentId) {
    return AFFINITY_SAME_AGENT * decay;
  }
  return 0;
}

/**
 * Pattern-match correlation: signals that match the same HuntPattern
 * sequence are automatically clustered.
 *
 * When a signal matches step N of a pattern, searches open clusters
 * for signals matching steps 1..N-1 in the same session.
 */
export function correlateByPatternMatch(
  signals: Signal[],
  patterns: HuntPattern[],
  sessionEventsMap: Map<string, AgentEvent[]>,
): SignalCluster[] {
  const clusters: SignalCluster[] = [];

  for (const pattern of patterns) {
    // Find sessions that match this pattern
    const matchingSignalIds: string[] = [];

    for (const [sessionKey, sessionEvents] of sessionEventsMap) {
      if (!matchPatternInSession(sessionEvents, pattern)) continue;

      // Find all signals from this session
      for (const signal of signals) {
        const signalSessionKey = `${signal.context.agentId}:${signal.context.sessionId}`;
        if (signalSessionKey === sessionKey) {
          matchingSignalIds.push(signal.id);
        }
      }
    }

    if (matchingSignalIds.length >= 2) {
      const matchingSignals = signals.filter((s) =>
        matchingSignalIds.includes(s.id),
      );
      clusters.push({
        id: `cluster_pm_${pattern.id}`,
        signalIds: matchingSignalIds,
        maxConfidence: Math.max(...matchingSignals.map((s) => s.confidence)),
        strategies: ["pattern_match"],
        createdAt: Date.now(),
      });
    }
  }

  return clusters;
}

/**
 * MITRE technique grouping: signals that map to the same technique
 * or tactic chain are correlated.
 *
 * Signals in the same kill-chain progression receive a 0.4 correlation boost.
 */
export function correlateByMitreTechnique(
  signals: Signal[],
  signalMitreMap: Map<string, string[]>,
): SignalCluster[] {
  // Group signals by MITRE technique
  const byTechnique = new Map<string, string[]>();

  for (const signal of signals) {
    const techniques = signalMitreMap.get(signal.id) ?? [];
    for (const tech of techniques) {
      const existing = byTechnique.get(tech);
      if (existing) {
        existing.push(signal.id);
      } else {
        byTechnique.set(tech, [signal.id]);
      }
    }
  }

  const clusters: SignalCluster[] = [];

  for (const [technique, signalIds] of byTechnique) {
    if (signalIds.length < 2) continue;

    const matchingSignals = signals.filter((s) => signalIds.includes(s.id));
    clusters.push({
      id: `cluster_mt_${technique}`,
      signalIds,
      maxConfidence: Math.max(...matchingSignals.map((s) => s.confidence)),
      strategies: ["mitre_grouping"],
      createdAt: Date.now(),
    });
  }

  return clusters;
}


/**
 * Merge overlapping clusters. Two clusters merge if they share at least
 * one signal ID. The merged cluster inherits the union of all signal IDs
 * and the maximum confidence.
 */
export function clusterSignals(clusters: SignalCluster[]): SignalCluster[] {
  if (clusters.length === 0) return [];

  // Build a union-find for cluster merging
  const parent = new Map<number, number>();

  function find(i: number): number {
    if (!parent.has(i)) parent.set(i, i);
    let p = parent.get(i)!;
    while (p !== parent.get(p)!) {
      parent.set(p, parent.get(parent.get(p)!)!);
      p = parent.get(p)!;
    }
    return p;
  }

  function union(a: number, b: number): void {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(ra, rb);
  }

  // Initialize parent for all clusters
  for (let i = 0; i < clusters.length; i++) {
    parent.set(i, i);
  }

  // Build signal -> cluster index mapping
  const signalToCluster = new Map<string, number[]>();
  for (let i = 0; i < clusters.length; i++) {
    for (const sigId of clusters[i].signalIds) {
      const existing = signalToCluster.get(sigId);
      if (existing) {
        existing.push(i);
      } else {
        signalToCluster.set(sigId, [i]);
      }
    }
  }

  // Union clusters that share signals
  for (const [, clusterIndices] of signalToCluster) {
    for (let i = 1; i < clusterIndices.length; i++) {
      union(clusterIndices[0], clusterIndices[i]);
    }
  }

  // Group clusters by their root
  const groups = new Map<number, number[]>();
  for (let i = 0; i < clusters.length; i++) {
    const root = find(i);
    const existing = groups.get(root);
    if (existing) {
      existing.push(i);
    } else {
      groups.set(root, [i]);
    }
  }

  // Build merged clusters
  const merged: SignalCluster[] = [];
  for (const [, indices] of groups) {
    const allSignalIds = new Set<string>();
    const allStrategies = new Set<CorrelationStrategyName>();
    let maxConfidence = 0;
    let earliestCreatedAt = Infinity;

    for (const idx of indices) {
      const c = clusters[idx];
      for (const id of c.signalIds) allSignalIds.add(id);
      for (const s of c.strategies) allStrategies.add(s);
      if (c.maxConfidence > maxConfidence) maxConfidence = c.maxConfidence;
      if (c.createdAt < earliestCreatedAt) earliestCreatedAt = c.createdAt;
    }

    merged.push({
      id: `cluster_merged_${indices[0]}`,
      signalIds: Array.from(allSignalIds),
      maxConfidence,
      strategies: Array.from(allStrategies),
      createdAt: earliestCreatedAt,
    });
  }

  return merged;
}


/** Options for the correlation pipeline. */
export interface CorrelationOptions {
  windowMs?: number;
  patterns?: HuntPattern[];
  sessionEventsMap?: Map<string, AgentEvent[]>;
  signalMitreMap?: Map<string, string[]>;
}

/**
 * Run all four correlation strategies in parallel, then merge results.
 *
 * Returns merged, deduplicated signal clusters ready for Finding creation.
 */
export function correlateSignals(
  signals: Signal[],
  options: CorrelationOptions = {},
): SignalCluster[] {
  const allClusters: SignalCluster[] = [];

  // Strategy 1: Time-window correlation
  allClusters.push(
    ...correlateByTimeWindow(signals, options.windowMs),
  );

  // Strategy 2: Agent-affinity correlation
  allClusters.push(...correlateByAgentAffinity(signals));

  // Strategy 3: Pattern-match correlation
  if (options.patterns && options.sessionEventsMap) {
    allClusters.push(
      ...correlateByPatternMatch(
        signals,
        options.patterns,
        options.sessionEventsMap,
      ),
    );
  }

  // Strategy 4: MITRE technique grouping
  if (options.signalMitreMap) {
    allClusters.push(
      ...correlateByMitreTechnique(signals, options.signalMitreMap),
    );
  }

  // Merge overlapping clusters
  return clusterSignals(allClusters);
}


/**
 * Full signal ingestion pipeline state.
 * Maintains the deduplicator, signal buffer, and false-positive set.
 */
export interface SignalPipelineState {
  signals: Signal[];
  deduplicator: SignalDeduplicator;
  falsePositiveHashes: Set<string>;
  suppressedPatternIds: Set<string>;
}

/**
 * Create a fresh pipeline state.
 */
export function createPipelineState(): SignalPipelineState {
  return {
    signals: [],
    deduplicator: new SignalDeduplicator(),
    falsePositiveHashes: new Set(),
    suppressedPatternIds: new Set(),
  };
}

/**
 * Ingest a signal into the pipeline.
 *
 * Steps:
 * 1. Check false-positive suppression
 * 2. Check deduplication
 * 3. Add to signal buffer
 *
 * Returns the updated pipeline state and the signal (or null if suppressed/deduped).
 */
export function ingestSignal(
  state: SignalPipelineState,
  signal: Signal,
): { state: SignalPipelineState; signal: Signal | null } {
  // Step 1: FP suppression
  if (isFalsePositiveSuppressed(signal, state.falsePositiveHashes)) {
    return { state, signal: null };
  }

  // Step 2: Deduplication
  if (state.deduplicator.isDuplicate(signal)) {
    return { state, signal: null };
  }

  // Step 3: Add to buffer
  const newSignals = [...state.signals, signal];
  return {
    state: { ...state, signals: newSignals },
    signal,
  };
}

/**
 * Ingest a raw audit event: convert to AgentEvent, generate signals
 * from guard results and anomaly scoring, and feed through the pipeline.
 *
 * Returns all non-suppressed signals produced from this event.
 */
export function ingestAuditEvent(
  state: SignalPipelineState,
  auditEvent: AuditEvent,
  baselines: Map<string, AgentBaseline>,
  sentinelId?: string,
): { state: SignalPipelineState; signals: Signal[] } {
  const agentEvent = auditEventToAgentEvent(auditEvent);
  const produced: Signal[] = [];
  let currentState = state;

  // Produce signals from guard results
  for (const gr of agentEvent.guardResults) {
    if (gr.verdict === "allow") continue; // Only deny/warn produce signals
    const signal = guardResultToSignal(agentEvent, gr);
    const result = ingestSignal(currentState, signal);
    currentState = result.state;
    if (result.signal) produced.push(result.signal);
  }

  // Produce anomaly signal if score exceeds threshold
  const baseline = baselines.get(agentEvent.agentId) ?? null;
  const anomalyResult = scoreAnomaly(agentEvent, baseline);
  if (anomalyResult.score > 0.3) {
    const signal = anomalyToSignal(agentEvent, anomalyResult, sentinelId);
    const result = ingestSignal(currentState, signal);
    currentState = result.state;
    if (result.signal) produced.push(result.signal);
  }

  return { state: currentState, signals: produced };
}

/**
 * Evict expired signals from the pipeline buffer.
 * Returns the updated state and the count of evicted signals.
 */
export function evictExpiredSignals(
  state: SignalPipelineState,
  now: number = Date.now(),
): { state: SignalPipelineState; evicted: number } {
  const before = state.signals.length;
  const remaining = state.signals.filter((s) => {
    if (s.ttl === null) return true;
    return now - s.timestamp < s.ttl;
  });

  return {
    state: { ...state, signals: remaining },
    evicted: before - remaining.length,
  };
}

/**
 * Evict low-priority signals when under memory pressure.
 * Drops info-severity signals with confidence < 0.3 first.
 */
export function evictLowPrioritySignals(
  state: SignalPipelineState,
  maxSignals: number,
): SignalPipelineState {
  if (state.signals.length <= maxSignals) return state;

  // Sort by priority: higher severity and confidence survive
  const scored = state.signals.map((s) => ({
    signal: s,
    priority: severityToNumber(s.severity) * 0.6 + s.confidence * 0.4,
  }));

  scored.sort((a, b) => b.priority - a.priority);
  const remaining = scored.slice(0, maxSignals).map((s) => s.signal);

  return { ...state, signals: remaining };
}


function clamp(min: number, max: number, value: number): number {
  return Math.max(min, Math.min(max, value));
}

function severityToNumber(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    case "info":
      return 1;
    default:
      return 0;
  }
}

function inferImpactFromSignal(signal: Signal): SignalImpact {
  const actionType = signal.data.actionType;
  if (!actionType) return "data_access";

  switch (actionType) {
    case "file_access":
      return "data_access";
    case "file_write":
      return "persistence";
    case "network_egress":
      return "network_egress";
    case "shell_command":
      return "code_execution";
    case "mcp_tool_call":
      return "code_execution";
    case "patch_apply":
      return "code_execution";
    case "user_input":
      return "data_access";
    default:
      return "data_access";
  }
}
