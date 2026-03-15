/**
 * Coverage Gap Engine — Active Coverage Gap Discovery (W4.1).
 *
 * Consumes Hunt data (events, investigations, patterns) and produces
 * ranked CoverageGapCandidate[] by comparing observed techniques and
 * data sources against known detection coverage (open documents +
 * published manifests).
 */

import type { AgentEvent, Investigation, HuntPattern } from "../hunt-types";
import type { FileType } from "../file-type-registry";
import type { CoverageGapCandidate } from "./shared-types";
import {
  inferDataSourceHints,
  inferTechniqueHints,
  recommendFormats,
} from "./draft-mappers";
import type { DraftSeed } from "./shared-types";

// ---- Input Types ----

export interface DocumentCoverageEntry {
  documentId: string;
  fileType: FileType;
  techniques: string[];
  dataSources: string[];
}

export interface CoverageGapInput {
  events?: AgentEvent[];
  investigations?: Investigation[];
  patterns?: HuntPattern[];
  openDocumentCoverage?: DocumentCoverageEntry[];
  publishedCoverage?: DocumentCoverageEntry[];
}

// ---- Data Source Families ----

/**
 * First-wave data source family vocabulary.
 * Maps raw data source hints to canonical families.
 */
const DATA_SOURCE_FAMILIES: Record<string, string> = {
  process: "process",
  command: "process",
  file: "file",
  network: "network",
  tool: "tool",
  prompt: "prompt",
  binary: "file",
  artifact: "file",
  normalized_finding: "normalized_finding",
};

function canonicalizeDataSource(hint: string): string {
  return DATA_SOURCE_FAMILIES[hint] ?? hint;
}

// ---- Internal Intermediate Type ----

interface RawGap {
  techniqueId: string;
  dataSourceFamily: string;
  sourceKind: CoverageGapCandidate["sourceKind"];
  sourceIds: string[];
  confidence: number;
  eventCount: number;
  rationale: string;
  allDataSourceHints: string[];
  allTechniqueHints: string[];
}

// ---- Core Functions ----

/**
 * Analyze inputs and produce gap candidates.
 *
 * Discovery logic:
 *  1. Extract observed techniques and data sources from events/investigations/patterns
 *  2. Compare against known coverage (open documents + published manifests)
 *  3. Techniques observed in events but not covered by any detection -> gap candidate
 *  4. Patterns with high anomaly scores but no matching detection -> gap candidate
 */
export function discoverCoverageGaps(input: CoverageGapInput): CoverageGapCandidate[] {
  const rawGaps: RawGap[] = [];
  const knownCoverage = [
    ...(input.openDocumentCoverage ?? []),
    ...(input.publishedCoverage ?? []),
  ];

  // 1. Process events
  if (input.events && input.events.length > 0) {
    const eventGaps = discoverEventGaps(input.events);
    rawGaps.push(...eventGaps);
  }

  // 2. Process investigations
  if (input.investigations && input.investigations.length > 0) {
    const investigationGaps = discoverInvestigationGaps(input.investigations);
    rawGaps.push(...investigationGaps);
  }

  // 3. Process patterns
  if (input.patterns && input.patterns.length > 0) {
    const patternGaps = discoverPatternGaps(input.patterns);
    rawGaps.push(...patternGaps);
  }

  // Convert raw gaps to candidates
  const candidates = rawGaps.map((raw) => rawGapToCandidate(raw, input.events?.length ?? 0));

  return deduplicateGaps(candidates, knownCoverage);
}

/**
 * Deduplicate candidates against known coverage.
 *
 * Rules:
 * - Candidate already covered by open document -> suppress
 * - Candidate already covered by published manifest -> suppress
 * - Same technique + same data source family -> merge (keep highest confidence)
 */
export function deduplicateGaps(
  candidates: CoverageGapCandidate[],
  knownCoverage: DocumentCoverageEntry[],
): CoverageGapCandidate[] {
  const coveredPairs = collectKnownCoveragePairs(knownCoverage);

  const filtered = candidates.filter((candidate) => {
    return !isCandidateCovered(candidate, coveredPairs);
  });

  return mergeRawCandidates(filtered);
}

/**
 * Score and rank candidates by severity then confidence (descending).
 */
export function rankGaps(candidates: CoverageGapCandidate[]): CoverageGapCandidate[] {
  const severityOrder: Record<string, number> = { high: 3, medium: 2, low: 1 };
  return [...candidates].sort((a, b) => {
    const sevDiff = (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0);
    if (sevDiff !== 0) return sevDiff;
    return b.confidence - a.confidence;
  });
}

/**
 * Suppress repeated low-confidence candidates from the same source.
 *
 * If multiple candidates share the same sourceKind and have confidence below
 * the suppression threshold, only keep the highest-confidence one per sourceKind.
 */
export function suppressNoisyGaps(
  candidates: CoverageGapCandidate[],
  suppressionThreshold: number = 0.4,
): CoverageGapCandidate[] {
  const highConfidence: CoverageGapCandidate[] = [];
  const lowBySourceKind = new Map<string, CoverageGapCandidate[]>();

  for (const candidate of candidates) {
    if (candidate.confidence >= suppressionThreshold) {
      highConfidence.push(candidate);
    } else {
      const existing = lowBySourceKind.get(candidate.sourceKind);
      if (existing) {
        existing.push(candidate);
      } else {
        lowBySourceKind.set(candidate.sourceKind, [candidate]);
      }
    }
  }

  // For each source kind group of low-confidence candidates, keep only the best
  for (const [, group] of lowBySourceKind) {
    const best = group.reduce((a, b) => (a.confidence >= b.confidence ? a : b));
    highConfidence.push(best);
  }

  return highConfidence;
}

// ---- Internal Helpers ----

function coverageKey(techniqueId: string, dataSourceFamily: string): string {
  const technique = techniqueId || "__no_technique__";
  const dataSource = canonicalizeDataSource(dataSourceFamily || "__no_ds__");
  return `${technique}::${dataSource}`;
}

function candidateMergeKey(candidate: Pick<CoverageGapCandidate, "techniqueHints" | "dataSourceHints">): string {
  return coverageKey(candidate.techniqueHints[0] ?? "", candidate.dataSourceHints[0] ?? "");
}

function collectKnownCoveragePairs(entries: DocumentCoverageEntry[]): Set<string> {
  const covered = new Set<string>();
  for (const entry of entries) {
    const techniques = entry.techniques.length > 0 ? entry.techniques : [""];
    const dataSources = entry.dataSources.length > 0
      ? entry.dataSources.map(canonicalizeDataSource)
      : [""];

    for (const technique of techniques) {
      for (const dataSource of dataSources) {
        covered.add(coverageKey(technique, dataSource));
      }
    }
  }
  return covered;
}

function isCandidateCovered(candidate: CoverageGapCandidate, coveredPairs: Set<string>): boolean {
  const techniques = candidate.techniqueHints.length > 0 ? candidate.techniqueHints : [""];
  const dataSources = candidate.dataSourceHints.length > 0
    ? candidate.dataSourceHints.map(canonicalizeDataSource)
    : [""];

  return techniques.every((technique) =>
    dataSources.every((dataSource) => coveredPairs.has(coverageKey(technique, dataSource))),
  );
}

function discoverEventGaps(events: AgentEvent[]): RawGap[] {
  const gaps: RawGap[] = [];
  const techniques = inferTechniqueHints(events);
  const dataSources = inferDataSourceHints(events);

  // Group events by technique
  const techniqueEvents = new Map<string, AgentEvent[]>();
  for (const event of events) {
    const eventTechniques = inferTechniqueHints([event]);
    for (const tech of eventTechniques) {
      const existing = techniqueEvents.get(tech);
      if (existing) {
        existing.push(event);
      } else {
        techniqueEvents.set(tech, [event]);
      }
    }
  }

  // Find uncovered techniques
  for (const tech of techniques) {
    const matchingEvents = techniqueEvents.get(tech) ?? [];
    const eventCount = matchingEvents.length;
    const maxAnomaly = Math.max(0, ...matchingEvents.map((e) => e.anomalyScore ?? 0));

    gaps.push({
      techniqueId: tech,
      dataSourceFamily: dataSources.length > 0 ? canonicalizeDataSource(dataSources[0]) : "process",
      sourceKind: "event",
      sourceIds: matchingEvents.map((e) => e.id).slice(0, 20),
      confidence: computeEventConfidence(eventCount, maxAnomaly),
      eventCount,
      rationale: buildEventRationale(tech, eventCount, maxAnomaly),
      allDataSourceHints: dataSources,
      allTechniqueHints: [tech],
    });
  }

  // Check for high-anomaly events without any technique match
  const highAnomalyEvents = events.filter(
    (e) => (e.anomalyScore ?? 0) > 0.7 && inferTechniqueHints([e]).length === 0,
  );
  if (highAnomalyEvents.length > 0) {
    const dsHints = inferDataSourceHints(highAnomalyEvents);
    gaps.push({
      techniqueId: "",
      dataSourceFamily: dsHints.length > 0 ? canonicalizeDataSource(dsHints[0]) : "process",
      sourceKind: "event",
      sourceIds: highAnomalyEvents.map((e) => e.id).slice(0, 20),
      confidence: Math.min(0.5 + highAnomalyEvents.length * 0.05, 0.85),
      eventCount: highAnomalyEvents.length,
      rationale: `${highAnomalyEvents.length} high-anomaly event${highAnomalyEvents.length !== 1 ? "s" : ""} detected without matching technique — potential novel threat activity requiring detection coverage.`,
      allDataSourceHints: dsHints,
      allTechniqueHints: [],
    });
  }

  return gaps;
}

function discoverInvestigationGaps(
  investigations: Investigation[],
): RawGap[] {
  const gaps: RawGap[] = [];

  for (const inv of investigations) {
    // Extract technique hints from annotations
    const techniques: string[] = [];
    for (const annotation of inv.annotations) {
      const matches = annotation.text.match(/T\d{4}(?:\.\d{3})?/g);
      if (matches) {
        for (const m of matches) {
          if (!techniques.includes(m)) {
            techniques.push(m);
          }
        }
      }
    }

    if (techniques.length === 0 && inv.verdict === "policy-gap") {
      // Investigation flagged as policy gap but no specific techniques — still a gap
      gaps.push({
        techniqueId: "",
        dataSourceFamily: "process",
        sourceKind: "investigation",
        sourceIds: [inv.id],
        confidence: severityToConfidence(inv.severity),
        eventCount: inv.eventIds.length,
        rationale: `Investigation "${inv.title}" flagged as policy gap. ${inv.eventIds.length} event${inv.eventIds.length !== 1 ? "s" : ""} in scope need detection coverage.`,
        allDataSourceHints: [],
        allTechniqueHints: [],
      });
    }

    for (const tech of techniques) {
      gaps.push({
        techniqueId: tech,
        dataSourceFamily: "process",
        sourceKind: "investigation",
        sourceIds: [inv.id],
        confidence: severityToConfidence(inv.severity),
        eventCount: inv.eventIds.length,
        rationale: `Investigation "${inv.title}" (${inv.severity}) references technique ${tech} which lacks detection coverage.`,
        allDataSourceHints: [],
        allTechniqueHints: [tech],
      });
    }
  }

  return gaps;
}

function discoverPatternGaps(patterns: HuntPattern[]): RawGap[] {
  const gaps: RawGap[] = [];

  for (const pattern of patterns) {
    // Skip dismissed patterns
    if (pattern.status === "dismissed") continue;

    // Infer data source hints from pattern steps
    const dsHints: string[] = [];
    for (const step of pattern.sequence) {
      const mapped = actionToDataSource(step.actionType);
      for (const h of mapped) {
        if (!dsHints.includes(h)) dsHints.push(h);
      }
    }

    // Patterns with high match counts and no matching detection -> gap
    const isHighMatchCount = pattern.matchCount > 5;
    const isPromoted = pattern.status === "promoted";
    const isConfirmed = pattern.status === "confirmed";

    // Build a synthetic seed to use recommendFormats
    const confidence = isPromoted ? 0.9 : isConfirmed ? 0.8 : isHighMatchCount ? 0.7 : 0.5;

    if (isHighMatchCount || isConfirmed || isPromoted) {
      gaps.push({
        techniqueId: "",
        dataSourceFamily: dsHints.length > 0 ? canonicalizeDataSource(dsHints[0]) : "process",
        sourceKind: "pattern",
        sourceIds: [pattern.id],
        confidence,
        eventCount: pattern.matchCount,
        rationale: `Pattern "${pattern.name}" observed ${pattern.matchCount} times across sessions. Status: ${pattern.status}. No matching detection rule found.`,
        allDataSourceHints: dsHints,
        allTechniqueHints: [],
      });
    }
  }

  return gaps;
}

function rawGapToCandidate(raw: RawGap, totalEvents: number): CoverageGapCandidate {
  // Compute severity based on event proportion
  const eventProportion = totalEvents > 0 ? raw.eventCount / totalEvents : 0;
  let severity: CoverageGapCandidate["severity"];
  if (eventProportion > 0.20) {
    severity = "high";
  } else if (eventProportion > 0.05) {
    severity = "medium";
  } else {
    severity = "low";
  }

  // For investigations and patterns, base severity on confidence
  if (raw.sourceKind === "investigation" || raw.sourceKind === "pattern") {
    if (raw.confidence >= 0.8) severity = "high";
    else if (raw.confidence >= 0.6) severity = "medium";
    else severity = "low";
  }

  // Build a minimal seed to get format recommendations
  const seed: DraftSeed = {
    id: crypto.randomUUID(),
    kind: raw.sourceKind === "event" ? "hunt_event" : raw.sourceKind === "investigation" ? "investigation" : "hunt_pattern",
    sourceEventIds: raw.sourceKind === "event" ? raw.sourceIds.slice(0, 5) : [],
    preferredFormats: [],
    techniqueHints: raw.allTechniqueHints,
    dataSourceHints: raw.allDataSourceHints,
    extractedFields: {},
    createdAt: new Date().toISOString(),
    confidence: raw.confidence,
  };

  return {
    id: coverageKey(raw.techniqueId, raw.dataSourceFamily),
    sourceKind: raw.sourceKind,
    sourceIds: raw.sourceIds,
    severity,
    confidence: Math.round(raw.confidence * 100) / 100,
    suggestedFormats: recommendFormats(seed),
    techniqueHints: raw.allTechniqueHints,
    dataSourceHints: raw.allDataSourceHints.map(canonicalizeDataSource),
    rationale: raw.rationale,
  };
}

function mergeRawCandidates(candidates: CoverageGapCandidate[]): CoverageGapCandidate[] {
  const merged = new Map<string, CoverageGapCandidate>();

  for (const candidate of candidates) {
    const key = candidateMergeKey(candidate);

    const existing = merged.get(key);
    if (existing) {
      // Keep highest confidence
      if (candidate.confidence > existing.confidence) {
        merged.set(key, {
          ...candidate,
          id: key,
          sourceIds: [...new Set([...existing.sourceIds, ...candidate.sourceIds])],
          techniqueHints: [...new Set([...existing.techniqueHints, ...candidate.techniqueHints])],
          dataSourceHints: [...new Set([...existing.dataSourceHints, ...candidate.dataSourceHints])],
        });
      } else {
        merged.set(key, {
          ...existing,
          id: key,
          sourceIds: [...new Set([...existing.sourceIds, ...candidate.sourceIds])],
          techniqueHints: [...new Set([...existing.techniqueHints, ...candidate.techniqueHints])],
          dataSourceHints: [...new Set([...existing.dataSourceHints, ...candidate.dataSourceHints])],
        });
      }
    } else {
      merged.set(key, candidate);
    }
  }

  return Array.from(merged.values());
}

function computeEventConfidence(eventCount: number, maxAnomaly: number): number {
  let confidence = 0.4;
  if (eventCount >= 10) confidence += 0.25;
  else if (eventCount >= 5) confidence += 0.2;
  else if (eventCount >= 2) confidence += 0.1;

  if (maxAnomaly > 0.7) confidence += 0.2;
  else if (maxAnomaly > 0.4) confidence += 0.1;

  return Math.min(confidence, 0.95);
}

function buildEventRationale(technique: string, eventCount: number, maxAnomaly: number): string {
  const parts: string[] = [];
  parts.push(`Technique ${technique} observed in ${eventCount} event${eventCount !== 1 ? "s" : ""}`);
  parts.push("but not covered by any open detection or published manifest.");

  if (maxAnomaly > 0.7) {
    parts.push(`Highest anomaly score: ${maxAnomaly.toFixed(2)} (elevated).`);
  }

  return parts.join(" ");
}

function severityToConfidence(severity: string): number {
  switch (severity) {
    case "critical": return 0.95;
    case "high": return 0.85;
    case "medium": return 0.7;
    case "low": return 0.5;
    case "info": return 0.3;
    default: return 0.5;
  }
}

const ACTION_TO_DATA_SOURCE: Record<string, string[]> = {
  shell_command: ["process", "command"],
  file_access: ["file"],
  file_write: ["file"],
  network_egress: ["network"],
  mcp_tool_call: ["tool"],
  patch_apply: ["file"],
  user_input: ["prompt"],
};

function actionToDataSource(actionType: string): string[] {
  return ACTION_TO_DATA_SOURCE[actionType] ?? [];
}
