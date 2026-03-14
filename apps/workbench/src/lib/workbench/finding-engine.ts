/**
 * Finding Engine — lifecycle state machine, enrichment, and promotion.
 *
 * Manages the lifecycle of Findings from signal clusters through triage,
 * enrichment, and promotion to Intel. All methods are pure functions that
 * take state in and return new state out — matching the hunt-engine.ts pattern.
 *
 * State machine:
 *   emerging -> confirmed -> promoted (terminal)
 *   emerging -> dismissed (terminal)
 *   emerging -> archived (auto-expire, terminal)
 *   confirmed -> promoted (terminal)
 *   confirmed -> false_positive (terminal)
 */

import type {
  Severity,
  Annotation,
} from "./hunt-types";
import type { Receipt } from "./types";
import type {
  FindingStatus,
  FindingVerdict,
  FindingAction,
  FindingScope,
  TimelineEntry,
  SignalProvenance,
} from "./sentinel-types";

import type {
  Signal,
  SignalCluster,
} from "./signal-pipeline";

// Re-export canonical types so downstream consumers (finding-store, etc.) still work.
export type {
  FindingStatus,
  FindingVerdict,
  FindingAction,
  FindingScope,
  TimelineEntry,
  SignalProvenance,
};

// Enrichment uses `data: Record<string, unknown>` rather than the canonical
// discriminated-union from sentinel-types.ts, because the enrichment pipeline
// constructs payloads with shapes that don't match the strict canonical variants.

export interface Enrichment {
  id: string;
  type:
    | "mitre_attack"
    | "ioc_extraction"
    | "spider_sense"
    | "external_feed"
    | "swarm_corroboration"
    | "reputation"
    | "geolocation"
    | "whois"
    | "custom";
  label: string;
  data: Record<string, unknown>;
  addedAt: number;
  source: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  subTechnique?: string;
}

export interface Finding {
  id: string;
  title: string;
  status: FindingStatus;
  severity: Severity;
  confidence: number;
  signalIds: string[];
  signalCount: number;
  scope: FindingScope;
  timeline: TimelineEntry[];
  enrichments: Enrichment[];
  annotations: Annotation[];
  verdict: FindingVerdict | null;
  actions: FindingAction[];
  promotedToIntel: string | null;
  receipt: Receipt | null;
  speakeasyId: string | null;
  createdBy: string;
  updatedBy: string;
  createdAt: number;
  updatedAt: number;
}

export interface AutoPromotionRules {
  autoConfirmThresholds: {
    minSignals: number;
    minConfidence: number;
    minSeverity: Severity;
    requireMitreMapping: boolean;
  };
  autoPromoteThresholds: {
    minConfidence: number;
    minSeverity: Severity;
    requireCorroboration: boolean;
  };
}

export interface ExtractedIoc {
  indicator: string;
  iocType: string;
  source?: string;
}

export interface SpiderSenseResult {
  verdict: "deny" | "ambiguous" | "allow";
  topScore: number;
  threshold: number;
  topMatches: Array<{
    category: string;
    label: string;
    score: number;
  }>;
}

const MIN_CLUSTER_SIGNALS = 2;
const MIN_CLUSTER_CONFIDENCE = 0.3;

const DEFAULT_AUTO_CONFIRM: AutoPromotionRules["autoConfirmThresholds"] = {
  minSignals: 5,
  minConfidence: 0.8,
  minSeverity: "high",
  requireMitreMapping: true,
};

const DEFAULT_AUTO_PROMOTE: AutoPromotionRules["autoPromoteThresholds"] = {
  minConfidence: 0.9,
  minSeverity: "critical",
  requireCorroboration: true,
};

export const DEFAULT_AUTO_PROMOTION_RULES: AutoPromotionRules = {
  autoConfirmThresholds: DEFAULT_AUTO_CONFIRM,
  autoPromoteThresholds: DEFAULT_AUTO_PROMOTE,
};

const TERMINAL_STATES: ReadonlySet<FindingStatus> = new Set([
  "promoted",
  "dismissed",
  "false_positive",
  "archived",
]);

const VALID_TRANSITIONS: Record<string, FindingStatus[]> = {
  emerging: ["confirmed", "dismissed", "archived"],
  confirmed: ["promoted", "dismissed", "false_positive"],
};

let findingCounter = 0;
let enrichmentCounter = 0;

export function generateFindingId(): string {
  const ts = Date.now().toString(36);
  const seq = (++findingCounter).toString(36).padStart(4, "0");
  return `fnd_${ts}${seq}`;
}

export function generateEnrichmentId(): string {
  const ts = Date.now().toString(36);
  const seq = (++enrichmentCounter).toString(36).padStart(4, "0");
  return `enr_${ts}${seq}`;
}

/** Returns null if the cluster has < 2 signals or confidence <= 0.3. */
export function createFromCluster(
  cluster: SignalCluster,
  signals: Signal[],
  createdBy: string,
): Finding | null {
  if (cluster.signalIds.length < MIN_CLUSTER_SIGNALS) return null;
  if (cluster.maxConfidence < MIN_CLUSTER_CONFIDENCE) return null;

  const clusterSignals = signals.filter((s) =>
    cluster.signalIds.includes(s.id),
  );
  if (clusterSignals.length === 0) return null;

  const scope = computeScope(clusterSignals);
  const severity = computeAggregateSeverity(clusterSignals);
  const confidence = computeAggregateConfidence(clusterSignals);
  const title = generateFindingTitle(clusterSignals);
  const now = Date.now();

  const finding: Finding = {
    id: generateFindingId(),
    title,
    status: "emerging",
    severity,
    confidence,
    signalIds: cluster.signalIds,
    signalCount: cluster.signalIds.length,
    scope,
    timeline: [
      {
        timestamp: now,
        type: "signal_added",
        summary: `Finding created from ${cluster.signalIds.length} correlated signals (strategies: ${cluster.strategies.join(", ")})`,
        actor: createdBy,
      },
    ],
    enrichments: [],
    annotations: [],
    verdict: null,
    actions: [],
    promotedToIntel: null,
    receipt: null,
    speakeasyId: null,
    createdBy,
    updatedBy: createdBy,
    createdAt: now,
    updatedAt: now,
  };

  return finding;
}

export function addSignals(
  finding: Finding,
  newSignals: Signal[],
  actor: string,
): Finding {
  if (TERMINAL_STATES.has(finding.status)) return finding;

  const newSignalIds = newSignals
    .map((s) => s.id)
    .filter((id) => !finding.signalIds.includes(id));

  if (newSignalIds.length === 0) return finding;

  const allSignalIds = [...finding.signalIds, ...newSignalIds];
  const scope = mergeScope(finding.scope, computeScope(newSignals));
  const confidence = recomputeConfidence(finding, newSignals);
  const severity = computeAggregateSeverityFromFindings(
    finding.severity,
    newSignals,
  );
  const now = Date.now();

  return {
    ...finding,
    signalIds: allSignalIds,
    signalCount: allSignalIds.length,
    scope,
    confidence,
    severity,
    timeline: [
      ...finding.timeline,
      {
        timestamp: now,
        type: "signal_added",
        summary: `${newSignalIds.length} new signal(s) added`,
        actor,
        refId: newSignalIds[0],
      },
    ],
    updatedBy: actor,
    updatedAt: now,
  };
}

/** Returns an error message if the transition is invalid, or null if valid. */
export function validateTransition(
  currentStatus: FindingStatus,
  targetStatus: FindingStatus,
): string | null {
  if (TERMINAL_STATES.has(currentStatus)) {
    return `Cannot transition from terminal state "${currentStatus}"`;
  }

  const allowed = VALID_TRANSITIONS[currentStatus];
  if (!allowed || !allowed.includes(targetStatus)) {
    return `Invalid transition: "${currentStatus}" -> "${targetStatus}". Allowed: ${(allowed ?? []).join(", ")}`;
  }

  return null;
}

/** emerging -> confirmed */
export function confirm(
  finding: Finding,
  actor: string,
): Finding | { error: string } {
  const error = validateTransition(finding.status, "confirmed");
  if (error) return { error };

  const now = Date.now();
  return {
    ...finding,
    status: "confirmed",
    timeline: [
      ...finding.timeline,
      {
        timestamp: now,
        type: "status_changed",
        summary: "Finding confirmed",
        actor,
      },
    ],
    updatedBy: actor,
    updatedAt: now,
  };
}

/** emerging -> dismissed OR confirmed -> dismissed */
export function dismiss(
  finding: Finding,
  actor: string,
  reason?: string,
): Finding | { error: string } {
  const error = validateTransition(finding.status, "dismissed");
  if (error) return { error };

  const now = Date.now();
  return {
    ...finding,
    status: "dismissed",
    timeline: [
      ...finding.timeline,
      {
        timestamp: now,
        type: "status_changed",
        summary: reason ? `Finding dismissed: ${reason}` : "Finding dismissed",
        actor,
      },
    ],
    updatedBy: actor,
    updatedAt: now,
  };
}

/**
 * confirmed -> false_positive. Caller should fold contributing signal
 * patterns into the sentinel's FP hash set.
 */
export function markFalsePositive(
  finding: Finding,
  actor: string,
  reason?: string,
): Finding | { error: string } {
  const error = validateTransition(finding.status, "false_positive");
  if (error) return { error };

  const now = Date.now();
  return {
    ...finding,
    status: "false_positive",
    verdict: "false_positive",
    timeline: [
      ...finding.timeline,
      {
        timestamp: now,
        type: "status_changed",
        summary: reason
          ? `Marked as false positive: ${reason}`
          : "Marked as false positive",
        actor,
      },
      {
        timestamp: now,
        type: "verdict_set",
        summary: "Verdict set: false_positive",
        actor,
      },
    ],
    updatedBy: actor,
    updatedAt: now,
  };
}

/** confirmed -> promoted. Requires an intel artifact ID to link to. */
export function promote(
  finding: Finding,
  actor: string,
  intelId: string,
): Finding | { error: string } {
  const error = validateTransition(finding.status, "promoted");
  if (error) return { error };

  const now = Date.now();
  return {
    ...finding,
    status: "promoted",
    promotedToIntel: intelId,
    actions: [...finding.actions, "intel_promoted"],
    timeline: [
      ...finding.timeline,
      {
        timestamp: now,
        type: "promoted",
        summary: `Promoted to Intel artifact ${intelId}`,
        actor,
        refId: intelId,
      },
      {
        timestamp: now,
        type: "action_taken",
        summary: "intel_promoted",
        actor,
        refId: intelId,
      },
    ],
    updatedBy: actor,
    updatedAt: now,
  };
}

/** emerging -> archived (TTL expired). */
export function archive(
  finding: Finding,
  actor: string = "system",
): Finding | { error: string } {
  const error = validateTransition(finding.status, "archived");
  if (error) return { error };

  const now = Date.now();
  return {
    ...finding,
    status: "archived",
    timeline: [
      ...finding.timeline,
      {
        timestamp: now,
        type: "status_changed",
        summary: "Finding auto-archived (TTL expired without confirmation)",
        actor,
      },
    ],
    updatedBy: actor,
    updatedAt: now,
  };
}

/** Sets verdict without changing status. */
export function setVerdict(
  finding: Finding,
  verdict: FindingVerdict,
  actor: string,
): Finding {
  if (TERMINAL_STATES.has(finding.status)) return finding;

  const now = Date.now();
  return {
    ...finding,
    verdict,
    timeline: [
      ...finding.timeline,
      {
        timestamp: now,
        type: "verdict_set",
        summary: `Verdict set: ${verdict}`,
        actor,
      },
    ],
    updatedBy: actor,
    updatedAt: now,
  };
}

export function recordAction(
  finding: Finding,
  action: FindingAction,
  actor: string,
  summary?: string,
): Finding {
  const now = Date.now();
  return {
    ...finding,
    actions: [...finding.actions, action],
    timeline: [
      ...finding.timeline,
      {
        timestamp: now,
        type: "action_taken",
        summary: summary ?? action,
        actor,
      },
    ],
    updatedBy: actor,
    updatedAt: now,
  };
}

export function checkAutoConfirm(
  finding: Finding,
  rules: AutoPromotionRules = DEFAULT_AUTO_PROMOTION_RULES,
): boolean {
  if (finding.status !== "emerging") return false;

  const thresholds = rules.autoConfirmThresholds;

  if (finding.signalCount < thresholds.minSignals) return false;
  if (finding.confidence < thresholds.minConfidence) return false;
  if (severityToNumber(finding.severity) < severityToNumber(thresholds.minSeverity)) {
    return false;
  }

  if (thresholds.requireMitreMapping) {
    const hasMitre = finding.enrichments.some((e) => e.type === "mitre_attack");
    if (!hasMitre) return false;
  }

  return true;
}

export function checkAutoPromote(
  finding: Finding,
  signals: Signal[],
  rules: AutoPromotionRules = DEFAULT_AUTO_PROMOTION_RULES,
): boolean {
  if (finding.status !== "confirmed") return false;

  const thresholds = rules.autoPromoteThresholds;

  if (finding.confidence < thresholds.minConfidence) return false;
  if (severityToNumber(finding.severity) < severityToNumber(thresholds.minSeverity)) {
    return false;
  }

  if (thresholds.requireCorroboration) {
    if (!isCorroborated(finding, signals)) return false;
  }

  return true;
}

export function checkAutoPromotion(
  finding: Finding,
  signals: Signal[],
  rules: AutoPromotionRules = DEFAULT_AUTO_PROMOTION_RULES,
  actor: string = "sentinel_auto",
): Finding {
  // Check auto-confirm first
  if (finding.status === "emerging" && checkAutoConfirm(finding, rules)) {
    const result = confirm(finding, actor);
    if ("error" in result) return finding;
    finding = result;
  }

  // Then check auto-promote (only if now confirmed)
  if (finding.status === "confirmed" && checkAutoPromote(finding, signals, rules)) {
    // Auto-promote requires an Intel ID — return the finding as ready-to-promote.
    // The actual promotion happens when the Intel artifact is created by the caller.
    // We annotate the finding to signal readiness.
    const now = Date.now();
    return {
      ...finding,
      timeline: [
        ...finding.timeline,
        {
          timestamp: now,
          type: "status_changed",
          summary: "Auto-promotion criteria met; awaiting Intel artifact creation",
          actor,
        },
      ],
      updatedBy: actor,
      updatedAt: now,
    };
  }

  return finding;
}

/** Signals from at least two distinct source families. */
export function isCorroborated(
  finding: Finding,
  signals: Signal[],
): boolean {
  const findingSignals = signals.filter((s) =>
    finding.signalIds.includes(s.id),
  );

  const sourceFamilies = new Set<string>();
  for (const s of findingSignals) {
    sourceFamilies.add(provenanceToFamily(s.source.provenance));
  }

  return sourceFamilies.size >= 2;
}

function provenanceToFamily(provenance: SignalProvenance): string {
  switch (provenance) {
    case "guard_evaluation":
      return "guard";
    case "anomaly_detection":
      return "anomaly";
    case "pattern_match":
      return "anomaly";
    case "correlation_rule":
      return "guard";
    case "spider_sense":
      return "anomaly";
    case "external_feed":
      return "external";
    case "swarm_intel":
      return "swarm";
    case "manual":
      return "manual";
    default:
      return "unknown";
  }
}

/** Idempotent: replaces existing enrichment of same type+source. */
export function addEnrichment(
  finding: Finding,
  enrichment: Enrichment,
  actor: string,
): Finding {
  // Replace existing enrichment of same type+source, or append
  const existingIdx = finding.enrichments.findIndex(
    (e) => e.type === enrichment.type && e.source === enrichment.source,
  );

  const enrichments =
    existingIdx >= 0
      ? [
          ...finding.enrichments.slice(0, existingIdx),
          enrichment,
          ...finding.enrichments.slice(existingIdx + 1),
        ]
      : [...finding.enrichments, enrichment];

  const now = Date.now();
  return {
    ...finding,
    enrichments,
    timeline: [
      ...finding.timeline,
      {
        timestamp: now,
        type: "enrichment_added",
        summary: `${enrichment.type} enrichment added from ${enrichment.source}`,
        actor,
        refId: enrichment.id,
      },
    ],
    updatedBy: actor,
    updatedAt: now,
  };
}

export function enrichWithMitre(
  finding: Finding,
  techniques: MitreTechnique[],
  actor: string = "enrichment_pipeline",
): Finding {
  if (techniques.length === 0) return finding;

  const seen = new Set<string>();
  const deduped: MitreTechnique[] = [];
  for (const tech of techniques) {
    if (!seen.has(tech.id)) {
      seen.add(tech.id);
      deduped.push(tech);
    }
  }

  const tactics = new Set(deduped.map((t) => t.tactic));

  const enrichment: Enrichment = {
    id: generateEnrichmentId(),
    type: "mitre_attack",
    label: `MITRE ATT&CK: ${deduped.length} technique(s), ${tactics.size} tactic(s)`,
    data: {
      kind: "mitre_attack",
      techniques: deduped,
      killChainDepth: tactics.size,
      tactics: Array.from(tactics),
    },
    addedAt: Date.now(),
    source: actor,
  };

  return addEnrichment(finding, enrichment, actor);
}

export function enrichWithIocs(
  finding: Finding,
  extractedIocs: ExtractedIoc[],
  actor: string = "enrichment_pipeline",
): Finding {
  if (extractedIocs.length === 0) return finding;

  // Deduplicate IOCs by value
  const seen = new Set<string>();
  const deduped: ExtractedIoc[] = [];
  for (const ioc of extractedIocs) {
    if (!seen.has(ioc.indicator)) {
      seen.add(ioc.indicator);
      deduped.push(ioc);
    }
  }

  const enrichment: Enrichment = {
    id: generateEnrichmentId(),
    type: "ioc_extraction",
    label: `${deduped.length} IOC(s) extracted`,
    data: {
      kind: "ioc_lookup",
      indicators: deduped,
      count: deduped.length,
    },
    addedAt: Date.now(),
    source: actor,
  };

  return addEnrichment(finding, enrichment, actor);
}

export function enrichWithSpiderSense(
  finding: Finding,
  result: SpiderSenseResult,
  actor: string = "spider_sense",
): Finding {
  const enrichment: Enrichment = {
    id: generateEnrichmentId(),
    type: "spider_sense",
    label: `Spider Sense: ${result.verdict} (score: ${result.topScore.toFixed(3)})`,
    data: {
      verdict: result.verdict,
      topScore: result.topScore,
      threshold: result.threshold,
      topMatches: result.topMatches,
    },
    addedAt: Date.now(),
    source: actor,
  };

  return addEnrichment(finding, enrichment, actor);
}

/** Boosts confidence by 0.05 (capped at 1.0) for peer corroboration. */
export function enrichWithSwarmCorroboration(
  finding: Finding,
  peerFingerprint: string,
  peerFindingId: string,
  peerConfidence: number,
  actor: string = "swarm_coordinator",
): Finding {
  const enrichment: Enrichment = {
    id: generateEnrichmentId(),
    type: "swarm_corroboration",
    label: `Corroborated by peer ${peerFingerprint.slice(0, 8)}...`,
    data: {
      peerFingerprint,
      peerFindingId,
      peerConfidence,
    },
    addedAt: Date.now(),
    source: actor,
  };

  // Boost confidence slightly for corroboration
  const boostedConfidence = Math.min(1.0, finding.confidence + 0.05);
  const enrichedFinding = addEnrichment(finding, enrichment, actor);

  return {
    ...enrichedFinding,
    confidence: boostedConfidence,
  };
}

export function runEnrichmentPipeline(
  finding: Finding,
  options: {
    mitreTechniques?: MitreTechnique[];
    extractedIocs?: ExtractedIoc[];
    spiderSenseResult?: SpiderSenseResult;
  },
  actor: string = "enrichment_pipeline",
): Finding {
  let enriched = finding;

  if (options.mitreTechniques && options.mitreTechniques.length > 0) {
    enriched = enrichWithMitre(enriched, options.mitreTechniques, actor);
  }

  if (options.extractedIocs && options.extractedIocs.length > 0) {
    enriched = enrichWithIocs(enriched, options.extractedIocs, actor);
  }

  if (options.spiderSenseResult) {
    enriched = enrichWithSpiderSense(enriched, options.spiderSenseResult, actor);
  }

  return enriched;
}

/** Build a chronological narrative timeline merging signals and existing entries. */
export function buildFindingTimeline(
  finding: Finding,
  signals: Signal[],
): TimelineEntry[] {
  const entries: TimelineEntry[] = [];

  // Add signal-based entries
  const findingSignals = signals
    .filter((s) => finding.signalIds.includes(s.id))
    .sort((a, b) => a.timestamp - b.timestamp);

  for (const signal of findingSignals) {
    entries.push({
      timestamp: signal.timestamp,
      type: "signal_added",
      summary: signalToNarrative(signal),
      actor: signal.source.sentinelId ?? signal.source.guardId ?? "system",
      refId: signal.id,
    });
  }

  // Merge with existing timeline entries (from state transitions, enrichments)
  const allEntries = [...entries, ...finding.timeline];

  // Sort chronologically
  allEntries.sort((a, b) => a.timestamp - b.timestamp);

  // Deduplicate by refId + type
  const seen = new Set<string>();
  const deduped: TimelineEntry[] = [];
  for (const entry of allEntries) {
    const key = `${entry.type}:${entry.refId ?? entry.timestamp}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(entry);
    }
  }

  return deduped;
}

function signalToNarrative(signal: Signal): string {
  if (signal.data.summary) return signal.data.summary;

  switch (signal.type) {
    case "anomaly":
      return `Anomaly detected (score: ${signal.confidence.toFixed(2)})`;
    case "detection":
      return `Detection: ${signal.source.guardId ?? "unknown guard"}`;
    case "indicator":
      return `IOC match: ${signal.data.matchedIocs?.[0]?.indicator ?? "unknown"}`;
    case "policy_violation":
      return `Policy violation: ${signal.data.verdict ?? "deny"} by ${signal.source.guardId ?? "guard"}`;
    case "behavioral":
      return `Behavioral pattern: ${signal.data.patternName ?? signal.data.patternId ?? "unknown"}`;
    default:
      return `Signal ${signal.id}`;
  }
}

export function addAnnotation(
  finding: Finding,
  annotation: Annotation,
): Finding {
  const now = Date.now();
  return {
    ...finding,
    annotations: [...finding.annotations, annotation],
    timeline: [
      ...finding.timeline,
      {
        timestamp: now,
        type: "annotation_added",
        summary: `Annotation by ${annotation.createdBy}: ${annotation.text.slice(0, 80)}${annotation.text.length > 80 ? "..." : ""}`,
        actor: annotation.createdBy,
        refId: annotation.id,
      },
    ],
    updatedBy: annotation.createdBy,
    updatedAt: now,
  };
}

/** Archive emerging findings whose TTL has expired (default 24h). */
export function archiveExpiredFindings(
  findings: Finding[],
  ttlMs: number = 24 * 60 * 60 * 1000,
  now: number = Date.now(),
): Finding[] {
  return findings.map((f) => {
    if (f.status !== "emerging") return f;
    if (now - f.createdAt < ttlMs) return f;

    const result = archive(f);
    return "error" in result ? f : result;
  });
}

function computeScope(signals: Signal[]): FindingScope {
  const agentIds = new Set<string>();
  const sessionIds = new Set<string>();
  let minTs = Infinity;
  let maxTs = -Infinity;

  for (const s of signals) {
    agentIds.add(s.context.agentId);
    sessionIds.add(s.context.sessionId);
    if (s.timestamp < minTs) minTs = s.timestamp;
    if (s.timestamp > maxTs) maxTs = s.timestamp;
  }

  return {
    agentIds: Array.from(agentIds),
    sessionIds: Array.from(sessionIds),
    timeRange: {
      start: new Date(minTs === Infinity ? Date.now() : minTs).toISOString(),
      end: new Date(maxTs === -Infinity ? Date.now() : maxTs).toISOString(),
    },
  };
}

function mergeScope(a: FindingScope, b: FindingScope): FindingScope {
  const agentIds = Array.from(new Set([...a.agentIds, ...b.agentIds]));
  const sessionIds = Array.from(new Set([...a.sessionIds, ...b.sessionIds]));

  const startA = new Date(a.timeRange.start).getTime();
  const startB = new Date(b.timeRange.start).getTime();
  const endA = new Date(a.timeRange.end).getTime();
  const endB = new Date(b.timeRange.end).getTime();

  return {
    agentIds,
    sessionIds,
    timeRange: {
      start: new Date(Math.min(startA, startB)).toISOString(),
      end: new Date(Math.max(endA, endB)).toISOString(),
    },
  };
}

function computeAggregateSeverity(signals: Signal[]): Severity {
  let maxSev = 0;
  for (const s of signals) {
    const n = severityToNumber(s.severity);
    if (n > maxSev) maxSev = n;
  }
  return numberToSeverity(maxSev);
}

function computeAggregateSeverityFromFindings(
  currentSeverity: Severity,
  newSignals: Signal[],
): Severity {
  let maxSev = severityToNumber(currentSeverity);
  for (const s of newSignals) {
    const n = severityToNumber(s.severity);
    if (n > maxSev) maxSev = n;
  }
  return numberToSeverity(maxSev);
}

/** Severity-weighted average confidence. */
function computeAggregateConfidence(signals: Signal[]): number {
  if (signals.length === 0) return 0;

  let weightedSum = 0;
  let totalWeight = 0;

  for (const s of signals) {
    const weight = severityToNumber(s.severity);
    weightedSum += s.confidence * weight;
    totalWeight += weight;
  }

  return totalWeight > 0 ? weightedSum / totalWeight : 0;
}

function recomputeConfidence(
  finding: Finding,
  newSignals: Signal[],
): number {
  // Weighted average of existing finding confidence and new signal confidences
  const existingWeight = finding.signalCount * severityToNumber(finding.severity);
  const existingWeightedConf = finding.confidence * existingWeight;

  let newWeightedSum = existingWeightedConf;
  let totalWeight = existingWeight;

  for (const s of newSignals) {
    const weight = severityToNumber(s.severity);
    newWeightedSum += s.confidence * weight;
    totalWeight += weight;
  }

  return totalWeight > 0 ? newWeightedSum / totalWeight : finding.confidence;
}

function generateFindingTitle(signals: Signal[]): string {
  // Determine the dominant signal type
  const typeCounts = new Map<string, number>();
  for (const s of signals) {
    typeCounts.set(s.type, (typeCounts.get(s.type) ?? 0) + 1);
  }

  let dominantType = "anomaly";
  let maxCount = 0;
  for (const [type, count] of typeCounts) {
    if (count > maxCount) {
      maxCount = count;
      dominantType = type;
    }
  }

  // Determine the primary agent
  const agentIds = new Set(signals.map((s) => s.context.agentId));
  const agentSuffix =
    agentIds.size === 1
      ? ` on ${signals[0].context.agentName}`
      : ` across ${agentIds.size} agents`;

  const typeLabels: Record<string, string> = {
    anomaly: "Anomalous behavior",
    detection: "Security detection",
    indicator: "Indicator match",
    policy_violation: "Policy violation cluster",
    behavioral: "Behavioral pattern",
  };

  const label = typeLabels[dominantType] ?? "Security finding";
  return `${label}${agentSuffix}`;
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

function numberToSeverity(n: number): Severity {
  if (n >= 5) return "critical";
  if (n >= 4) return "high";
  if (n >= 3) return "medium";
  if (n >= 2) return "low";
  return "info";
}
