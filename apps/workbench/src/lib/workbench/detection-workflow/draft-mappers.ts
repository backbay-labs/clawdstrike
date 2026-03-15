/**
 * Draft Mappers — canonical event projection for draft generation.
 *
 * Normalizes Hunt events, investigations, and discovered patterns into
 * DraftSeed structures that per-format adapters can consume. This is the
 * entry point for the Detection Lab's "seed generation" workstream (W1.1).
 */

import type { FileType } from "../file-type-registry";
import type { TestActionType } from "../types";
import type {
  AgentEvent,
  Investigation,
  HuntPattern,
  PatternStep,
} from "../hunt-types";
import type { CoverageGapCandidate, DraftSeed, DraftSeedKind } from "./shared-types";

// ---- Options ----

export interface MapEventsOptions {
  /** Override the seed kind (defaults to "hunt_event"). */
  kind?: DraftSeedKind;
  /** Additional technique hints to merge. */
  extraTechniqueHints?: string[];
  /** Additional data source hints to merge. */
  extraDataSourceHints?: string[];
  /** Override preferred formats (otherwise inferred). */
  preferredFormats?: FileType[];
}

// ---- Action → Data Source Mapping ----

const ACTION_TO_DATA_SOURCE: Record<TestActionType, string[]> = {
  shell_command: ["process", "command"],
  file_access: ["file"],
  file_write: ["file"],
  network_egress: ["network"],
  mcp_tool_call: ["tool"],
  patch_apply: ["file"],
  user_input: ["prompt"],
};

// ---- Technique Inference ----

/** Known MITRE ATT&CK technique patterns in targets and content. */
const TECHNIQUE_PATTERNS: Array<{ pattern: RegExp; technique: string }> = [
  // Execution
  { pattern: /powershell|pwsh/i, technique: "T1059.001" },
  { pattern: /cmd\.exe|cmd\s/i, technique: "T1059.003" },
  { pattern: /\bbash\b|\bsh\b/i, technique: "T1059.004" },
  { pattern: /python|python3/i, technique: "T1059.006" },
  { pattern: /curl.*\|\s*(bash|sh)/i, technique: "T1059" },

  // Persistence / credential access
  { pattern: /\.ssh|id_rsa|id_ed25519/i, technique: "T1552.004" },
  { pattern: /\.aws|credentials/i, technique: "T1552.001" },
  { pattern: /\/etc\/shadow|\/etc\/passwd/i, technique: "T1003.008" },
  { pattern: /\.env/i, technique: "T1552.001" },

  // Defense evasion
  { pattern: /base64/i, technique: "T1140" },
  { pattern: /chmod\s+777/i, technique: "T1222" },

  // Discovery
  { pattern: /whoami/i, technique: "T1033" },
  { pattern: /ifconfig|ipconfig|ip\s+addr/i, technique: "T1016" },

  // Lateral movement / exfiltration
  { pattern: /nc\s+-e|\/dev\/tcp\//i, technique: "T1095" },
  { pattern: /curl|wget/i, technique: "T1105" },
];

// ---- Public API ----

/**
 * Map selected Hunt events to a DraftSeed.
 *
 * Extracts data source hints and technique hints from the events, then
 * recommends formats based on the resulting seed shape.
 */
export function mapEventsToDraftSeed(
  events: AgentEvent[],
  options: MapEventsOptions = {},
): DraftSeed {
  const sourceEventIds = events.map((e) => e.id);
  const dataSourceHints = inferDataSourceHints(events);
  const techniqueHints = inferTechniqueHints(events);

  // Merge extra hints from options
  if (options.extraDataSourceHints) {
    for (const h of options.extraDataSourceHints) {
      if (!dataSourceHints.includes(h)) dataSourceHints.push(h);
    }
  }
  if (options.extraTechniqueHints) {
    for (const h of options.extraTechniqueHints) {
      if (!techniqueHints.includes(h)) techniqueHints.push(h);
    }
  }

  // Extract fields from events
  const extractedFields: Record<string, unknown> = {};
  const actionTypes = new Set<string>();
  const targets: string[] = [];
  const commands: string[] = [];
  const paths: string[] = [];
  const domains: string[] = [];
  const verdicts = new Set<string>();
  const agentIds = new Set<string>();

  for (const event of events) {
    actionTypes.add(event.actionType);
    targets.push(event.target);
    verdicts.add(event.verdict);
    agentIds.add(event.agentId);

    if (event.actionType === "shell_command") {
      commands.push(event.target);
    } else if (
      event.actionType === "file_access" ||
      event.actionType === "file_write" ||
      event.actionType === "patch_apply"
    ) {
      paths.push(event.target);
    } else if (event.actionType === "network_egress") {
      domains.push(event.target);
    }

    // Store per-event extracted data
    extractedFields[event.id] = {
      actionType: event.actionType,
      target: event.target,
      verdict: event.verdict,
      content: event.content,
    };
  }

  // Set aggregate fields
  const primaryAction = [...actionTypes][0];
  if (primaryAction) extractedFields["actionType"] = primaryAction;
  if (paths.length > 0) extractedFields["paths"] = paths;
  if (domains.length > 0) extractedFields["domains"] = domains;
  if (commands.length > 0) extractedFields["commands"] = commands;
  extractedFields["targets"] = targets;
  extractedFields["verdicts"] = [...verdicts];
  extractedFields["agentIds"] = [...agentIds];

  const seed: DraftSeed = {
    id: crypto.randomUUID(),
    kind: options.kind ?? "hunt_event",
    sourceEventIds,
    preferredFormats: options.preferredFormats ?? [],
    techniqueHints,
    dataSourceHints,
    extractedFields,
    createdAt: new Date().toISOString(),
    confidence: computeConfidence(events),
  };

  // If no explicit preferred formats, infer them
  if (seed.preferredFormats.length === 0) {
    seed.preferredFormats = recommendFormats(seed);
  }

  return seed;
}

export function mapInvestigationToDraftSeed(
  investigation: Investigation,
  scopeEvents: AgentEvent[] = [],
  selectedGap?: CoverageGapCandidate,
): DraftSeed {
  const eventSeed =
    scopeEvents.length > 0
      ? mapEventsToDraftSeed(scopeEvents, { kind: "investigation" })
      : null;

  const textTechniqueHints = inferTechniqueHintsFromText([
    investigation.title,
    ...investigation.annotations.map((annotation) => annotation.text),
    ...(investigation.actions ?? []),
  ]);

  const techniqueHints = uniqueStrings([
    ...(eventSeed?.techniqueHints ?? []),
    ...textTechniqueHints,
    ...(selectedGap?.techniqueHints ?? []),
  ]);

  const dataSourceHints = uniqueStrings([
    ...(eventSeed?.dataSourceHints ?? []),
    ...(selectedGap?.dataSourceHints ?? []),
  ]);

  const extractedFields: Record<string, unknown> = {
    ...(eventSeed?.extractedFields ?? {}),
    title: investigation.title,
    severity: investigation.severity,
    status: investigation.status,
    agentIds: investigation.agentIds,
    verdict: investigation.verdict,
    eventIds: investigation.eventIds,
    actions: investigation.actions,
    annotationTexts: investigation.annotations.map((annotation) => annotation.text),
  };

  const seed: DraftSeed = {
    id: crypto.randomUUID(),
    kind: "investigation",
    sourceEventIds: investigation.eventIds,
    investigationId: investigation.id,
    preferredFormats: selectedGap?.suggestedFormats ?? eventSeed?.preferredFormats ?? [],
    techniqueHints,
    dataSourceHints,
    extractedFields,
    createdAt: new Date().toISOString(),
    confidence: Math.max(
      severityToConfidence(investigation.severity),
      eventSeed?.confidence ?? 0,
      selectedGap?.confidence ?? 0,
    ),
  };

  if (seed.preferredFormats.length === 0) {
    seed.preferredFormats = recommendFormats(seed);
  }

  return seed;
}

/**
 * Map a discovered Hunt pattern to a DraftSeed.
 */
export function mapPatternToDraftSeed(
  pattern: HuntPattern,
  selectedGap?: CoverageGapCandidate,
): DraftSeed {
  const dataSourceHints = inferDataSourceHintsFromSteps(pattern.sequence);
  const techniqueHints = uniqueStrings([
    ...inferTechniqueHintsFromText([
      pattern.name,
      pattern.description,
      ...pattern.sequence.map((step) => step.targetPattern),
    ]),
    ...(selectedGap?.techniqueHints ?? []),
  ]);
  const mergedDataSourceHints = uniqueStrings([
    ...dataSourceHints,
    ...(selectedGap?.dataSourceHints ?? []),
  ]);
  const targets = pattern.sequence.map((step) => step.targetPattern);
  const commands = pattern.sequence
    .filter((step) => step.actionType === "shell_command")
    .map((step) => step.targetPattern);
  const paths = pattern.sequence
    .filter((step) =>
      step.actionType === "file_access" || step.actionType === "file_write" || step.actionType === "patch_apply",
    )
    .map((step) => step.targetPattern);
  const domains = pattern.sequence
    .filter((step) => step.actionType === "network_egress")
    .map((step) => step.targetPattern);

  const extractedFields: Record<string, unknown> = {
    name: pattern.name,
    patternName: pattern.name,
    description: pattern.description,
    matchCount: pattern.matchCount,
    status: pattern.status,
    agentIds: pattern.agentIds,
    sequence: pattern.sequence.map((step) => ({
      step: step.step,
      actionType: step.actionType,
      targetPattern: step.targetPattern,
      timeWindow: step.timeWindow,
    })),
    targets,
    ...(commands.length > 0 ? { commands } : {}),
    ...(paths.length > 0 ? { paths } : {}),
    ...(domains.length > 0 ? { domains } : {}),
  };

  // Set primary action type from the first step
  if (pattern.sequence.length > 0) {
    extractedFields["actionType"] = pattern.sequence[0].actionType;
  }

  const seed: DraftSeed = {
    id: crypto.randomUUID(),
    kind: "hunt_pattern",
    sourceEventIds: [],
    patternId: pattern.id,
    preferredFormats: selectedGap?.suggestedFormats ?? [],
    techniqueHints,
    dataSourceHints: mergedDataSourceHints,
    extractedFields,
    createdAt: new Date().toISOString(),
    confidence: Math.max(
      pattern.matchCount > 5 ? 0.9 : pattern.matchCount > 1 ? 0.7 : 0.5,
      selectedGap?.confidence ?? 0,
    ),
  };

  seed.preferredFormats = recommendFormats(seed);

  return seed;
}

/**
 * Infer data source family from AgentEvent action types.
 */
export function inferDataSourceHints(events: AgentEvent[]): string[] {
  const hints = new Set<string>();
  for (const event of events) {
    const mapped = ACTION_TO_DATA_SOURCE[event.actionType];
    if (mapped) {
      for (const h of mapped) hints.add(h);
    }

    // Check content for binary/artifact indicators
    if (event.content) {
      if (looksLikeBinaryContent(event.content)) {
        hints.add("binary");
        hints.add("artifact");
      }
    }
  }
  return [...hints];
}

/**
 * Extract MITRE ATT&CK technique hints from events.
 */
export function inferTechniqueHints(events: AgentEvent[]): string[] {
  const techniques = new Set<string>();
  for (const event of events) {
    // Check target
    for (const { pattern, technique } of TECHNIQUE_PATTERNS) {
      if (pattern.test(event.target)) {
        techniques.add(technique);
      }
    }
    // Check content if present
    if (event.content) {
      for (const { pattern, technique } of TECHNIQUE_PATTERNS) {
        if (pattern.test(event.content)) {
          techniques.add(technique);
        }
      }
    }
    // Check flags for pattern matches
    for (const flag of event.flags) {
      if (flag.type === "pattern-match") {
        techniques.add(flag.patternName);
      }
      if (flag.type === "tag" && flag.label.match(/T\d{4}/)) {
        techniques.add(flag.label);
      }
    }
  }
  return [...techniques];
}

function inferTechniqueHintsFromText(texts: string[]): string[] {
  const techniques = new Set<string>();
  for (const text of texts) {
    if (!text) continue;
    const directMatches = text.match(/T\d{4}(?:\.\d{3})?/gi) ?? [];
    for (const match of directMatches) {
      techniques.add(match.toUpperCase());
    }
    for (const { pattern, technique } of TECHNIQUE_PATTERNS) {
      if (pattern.test(text)) {
        techniques.add(technique);
      }
    }
  }
  return [...techniques];
}

/**
 * Recommend FileType[] based on the seed shape.
 *
 * Format recommendation mapping:
 * | Hunt signal shape                           | Preferred | Fallbacks                           |
 * |---------------------------------------------|-----------|-------------------------------------|
 * | Structured process or shell telemetry       | sigma     | clawdstrike_policy, ocsf_event      |
 * | File or network event with stable metadata  | sigma     | ocsf_event                          |
 * | Binary, string-rich, or artifact evidence   | yara      | sigma                               |
 * | Event normalization or finding publication   | ocsf      | sigma                               |
 */
export function recommendFormats(seed: DraftSeed): FileType[] {
  const hints = seed.dataSourceHints;
  const hasBinary = hints.includes("binary") || hints.includes("artifact");
  const hasProcess = hints.includes("process") || hints.includes("command");
  const hasFile = hints.includes("file");
  const hasNetwork = hints.includes("network");
  const hasPrompt = hints.includes("prompt");
  const hasTool = hints.includes("tool");

  // Binary, string-rich, or artifact-centric evidence -> YARA first
  if (hasBinary) {
    return ["yara_rule", "sigma_rule"];
  }

  // Structured process or shell telemetry -> Sigma first
  if (hasProcess) {
    return ["sigma_rule", "clawdstrike_policy", "ocsf_event"];
  }

  // File or network event with stable metadata -> Sigma first
  if (hasFile || hasNetwork) {
    return ["sigma_rule", "ocsf_event"];
  }

  // Tool or prompt -> OCSF for normalization, Sigma fallback
  if (hasTool || hasPrompt) {
    return ["ocsf_event", "sigma_rule"];
  }

  // Investigation or pattern without specific hints -> OCSF for finding
  if (seed.kind === "investigation") {
    return ["ocsf_event", "sigma_rule"];
  }

  // Default: Sigma is the most general-purpose format
  return ["sigma_rule", "clawdstrike_policy"];
}

// ---- Helpers ----

function inferDataSourceHintsFromSteps(steps: PatternStep[]): string[] {
  const hints = new Set<string>();
  for (const step of steps) {
    const mapped = ACTION_TO_DATA_SOURCE[step.actionType];
    if (mapped) {
      for (const h of mapped) hints.add(h);
    }
  }
  return [...hints];
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.length > 0))];
}

function computeConfidence(events: AgentEvent[]): number {
  if (events.length === 0) return 0;

  let score = 0.5;

  // More events → higher confidence
  if (events.length >= 5) score += 0.2;
  else if (events.length >= 2) score += 0.1;

  // Events with anomaly scores boost confidence
  const maxAnomaly = Math.max(
    ...events.map((e) => e.anomalyScore ?? 0),
  );
  if (maxAnomaly > 0.7) score += 0.2;
  else if (maxAnomaly > 0.3) score += 0.1;

  return Math.min(score, 1);
}

function severityToConfidence(severity: string): number {
  switch (severity) {
    case "critical":
      return 0.95;
    case "high":
      return 0.85;
    case "medium":
      return 0.7;
    case "low":
      return 0.5;
    case "info":
      return 0.3;
    default:
      return 0.5;
  }
}

function looksLikeBinaryContent(content: string): boolean {
  // Check for hex patterns or base64-encoded blobs
  if (/^[0-9a-fA-F\s]+$/.test(content.slice(0, 200))) return true;
  if (/^[A-Za-z0-9+/=]{40,}$/.test(content.slice(0, 200))) return true;
  // Check for null bytes or non-printable characters
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0e-\x1f]/.test(content.slice(0, 200))) return true;
  return false;
}
