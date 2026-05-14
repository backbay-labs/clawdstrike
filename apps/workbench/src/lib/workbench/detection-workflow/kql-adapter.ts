import type { DetectionWorkflowAdapter } from "./adapters";
import { registerAdapter } from "./adapters";
import { registerFileType } from "../file-type-registry";
import type {
  DraftSeed,
  DetectionDocumentRef,
  EvidencePack,
  EvidenceItem,
  LabRun,
  LabCaseResult,
  ExplainabilityTrace,
  EvidenceDatasetKind,
} from "./shared-types";
import { createEmptyDatasets } from "./shared-types";
import type {
  DetectionExecutionRequest,
  DetectionExecutionResult,
  DraftBuildResult,
  PublicationRequest,
  PublicationBuildResult,
  ReportArtifact,
} from "./execution-types";
import { translateField } from "./field-mappings";


async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}


/**
 * A single KQL where-clause condition, parsed from a `| where` segment.
 */
export interface KqlWhereClause {
  /** The field name on the left-hand side. */
  field: string;
  /** The KQL operator (==, !=, contains, startswith, endswith, has, in, matches regex, etc.). */
  operator: string;
  /** The right-hand side value (unquoted). */
  value: string;
  /** The raw text of the where clause (after "| where "). */
  raw: string;
}

/**
 * Structured representation of a parsed KQL query.
 */
export interface KqlParsedQuery {
  /** The table name (first line before any pipe operators). */
  tableName: string;
  /** All extracted where-clause conditions. */
  whereClauses: KqlWhereClause[];
  /** Columns listed in `| project` segments. */
  projectColumns: string[];
  /** Raw expressions from `| extend` segments. */
  extendExpressions: string[];
  /** All raw lines of the query. */
  rawLines: string[];
  /** Comment lines (lines starting with //). */
  comments: string[];
}

const KQL_OPERATORS = [
  "matches regex",
  "!startswith",
  "!endswith",
  "!contains",
  "startswith",
  "endswith",
  "contains",
  "!has",
  "has",
  "!in",
  "in",
  "!=",
  "==",
  "=~",
] as const;

/**
 * Parse a single where-clause expression into field, operator, and value.
 * Returns null if the expression cannot be parsed.
 */
function parseWhereExpression(raw: string): KqlWhereClause | null {
  const trimmed = raw.trim();

  for (const op of KQL_OPERATORS) {
    // Build a regex that finds the operator with surrounding whitespace
    const escaped = op.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pattern = new RegExp(`^(.+?)\\s+${escaped}\\s+(.+)$`, "i");
    const match = trimmed.match(pattern);
    if (match) {
      const field = match[1].trim();
      let value = match[2].trim();
      // Strip surrounding quotes
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      // Strip @"..." regex quoting
      if (value.startsWith('@"') && value.endsWith('"')) {
        value = value.slice(2, -1);
      }
      return { field, operator: op.toLowerCase(), value, raw: trimmed };
    }
  }

  // Fallback: try splitting on common two-char operators without whitespace requirement
  for (const op of ["==", "!="]) {
    const idx = trimmed.indexOf(op);
    if (idx > 0) {
      const field = trimmed.slice(0, idx).trim();
      let value = trimmed.slice(idx + op.length).trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      return { field, operator: op, value, raw: trimmed };
    }
  }

  return null;
}

/**
 * Parse a KQL query string into its structured components.
 *
 * KQL structure: `TableName | where ... | where ... | project ... | extend ...`
 * Splits on pipe-at-start-of-line (`\n| `) and classifies segments by operator keyword.
 */
export function parseKqlQuery(source: string): KqlParsedQuery {
  const rawLines = source.split(/\r?\n/);
  const comments: string[] = [];
  const nonCommentLines: string[] = [];

  for (const line of rawLines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("//")) {
      comments.push(trimmed);
    } else if (trimmed.length > 0) {
      nonCommentLines.push(trimmed);
    }
  }

  // Rejoin non-comment lines and split on pipe operators
  // KQL uses `\n| ` pattern but we also handle `| ` at line start
  const joined = nonCommentLines.join("\n");
  // Split on pipe at start of line or after first segment
  const segments: string[] = [];
  let tableName = "";

  // First pass: split the joined text on "| " that appears at line start
  const pipePattern = /\n\s*\|\s*/g;
  const parts = joined.split(pipePattern);

  if (parts.length > 0) {
    // The first part before any pipe is the table name (possibly with inline pipe)
    const firstPart = parts[0].trim();
    // Check if the first part itself contains " | " (inline pipe)
    const inlinePipeIdx = firstPart.indexOf(" | ");
    if (inlinePipeIdx > 0) {
      tableName = firstPart.slice(0, inlinePipeIdx).trim();
      segments.push(firstPart.slice(inlinePipeIdx + 3).trim());
    } else {
      // Also check for "| " at start (single-line queries like "Table | where ...")
      const pipeAtStartIdx = firstPart.indexOf("| ");
      if (pipeAtStartIdx > 0) {
        tableName = firstPart.slice(0, pipeAtStartIdx).trim();
        segments.push(firstPart.slice(pipeAtStartIdx + 2).trim());
      } else {
        tableName = firstPart;
      }
    }
    // Remaining parts are pipe segments
    for (let i = 1; i < parts.length; i++) {
      segments.push(parts[i].trim());
    }
  }

  const whereClauses: KqlWhereClause[] = [];
  const projectColumns: string[] = [];
  const extendExpressions: string[] = [];

  for (const segment of segments) {
    const lower = segment.toLowerCase();

    if (lower.startsWith("where ")) {
      const expr = segment.slice(6).trim();
      // Handle compound conditions joined by "and"
      const andParts = expr.split(/\s+and\s+/i);
      for (const part of andParts) {
        const clause = parseWhereExpression(part.trim());
        if (clause) {
          whereClauses.push(clause);
        }
      }
    } else if (lower.startsWith("project ")) {
      const cols = segment.slice(8).trim();
      for (const col of cols.split(",")) {
        const c = col.trim();
        if (c) projectColumns.push(c);
      }
    } else if (lower.startsWith("extend ")) {
      extendExpressions.push(segment.slice(7).trim());
    }
  }

  return {
    tableName,
    whereClauses,
    projectColumns,
    extendExpressions,
    rawLines,
    comments,
  };
}

/**
 * Convenience wrapper: extract only the where-clauses from a KQL source string.
 */
export function extractKqlWhereFields(source: string): KqlWhereClause[] {
  return parseKqlQuery(source).whereClauses;
}

/**
 * Client-side KQL matching: check if a payload record satisfies all where-clauses.
 * All clauses must match (AND logic).
 */
export function clientSideKqlMatch(
  payload: Record<string, unknown>,
  whereClauses: KqlWhereClause[],
): boolean {
  if (whereClauses.length === 0) return false;

  for (const clause of whereClauses) {
    const eventValue = payload[clause.field];
    if (eventValue === undefined) {
      // For negated operators, undefined means the clause trivially passes
      if (clause.operator.startsWith("!")) continue;
      return false;
    }

    const eventStr = String(eventValue).toLowerCase();
    const clauseValue = clause.value.toLowerCase();

    switch (clause.operator) {
      case "==":
      case "=~":
        if (eventStr !== clauseValue) return false;
        break;

      case "!=":
        if (eventStr === clauseValue) return false;
        break;

      case "contains":
        if (!eventStr.includes(clauseValue)) return false;
        break;

      case "!contains":
        if (eventStr.includes(clauseValue)) return false;
        break;

      case "startswith":
        if (!eventStr.startsWith(clauseValue)) return false;
        break;

      case "!startswith":
        if (eventStr.startsWith(clauseValue)) return false;
        break;

      case "endswith":
        if (!eventStr.endsWith(clauseValue)) return false;
        break;

      case "!endswith":
        if (eventStr.endsWith(clauseValue)) return false;
        break;

      case "has": {
        // Whole-word match (word boundary check)
        const wordPattern = new RegExp(`\\b${clauseValue.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");
        if (!wordPattern.test(String(eventValue))) return false;
        break;
      }

      case "!has": {
        const wordPattern = new RegExp(`\\b${clauseValue.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");
        if (wordPattern.test(String(eventValue))) return false;
        break;
      }

      case "matches regex": {
        try {
          const re = new RegExp(clause.value, "i");
          if (!re.test(String(eventValue))) return false;
        } catch {
          // Invalid regex -- fail match
          return false;
        }
        break;
      }

      case "in": {
        // Parse parenthesized list: in ("val1", "val2", ...)
        const listContent = clause.value.replace(/^\(/, "").replace(/\)$/, "");
        const items = listContent.split(",").map((item) => {
          let v = item.trim();
          if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
            v = v.slice(1, -1);
          }
          return v.toLowerCase();
        });
        if (!items.includes(eventStr)) return false;
        break;
      }

      case "!in": {
        const listContent = clause.value.replace(/^\(/, "").replace(/\)$/, "");
        const items = listContent.split(",").map((item) => {
          let v = item.trim();
          if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
            v = v.slice(1, -1);
          }
          return v.toLowerCase();
        });
        if (items.includes(eventStr)) return false;
        break;
      }

      default:
        // Unknown operator -- treat as no match
        return false;
    }
  }

  return true;
}


const KQL_STARTER_TEMPLATE = `// KQL Detection Rule
// Table: SecurityEvent
// Description: Detects suspicious process creation
SecurityEvent
| where EventID == 4688
| where CommandLine contains "powershell"
| project TimeGenerated, Computer, CommandLine, ParentProcessName
`;

/**
 * Content-based detection for KQL. Checks for table name + pipe operator patterns
 * typical of KQL, while avoiding false positives with Sigma YAML or SPL.
 */
function detectKqlContent(_filename: string, content: string): boolean {
  // KQL false-positive guards: not Sigma YAML, not SPL
  if (content.includes("detection:") && content.includes("logsource:")) return false;
  if (content.includes("guards:") || content.includes("schema_version:")) return false;
  if (content.trimStart().startsWith("search ")) return false;

  // KQL pipe operators
  const kqlPipeOps = /\|\s*(?:where|project|extend|summarize|join|union|let|render)\b/;
  if (!kqlPipeOps.test(content)) return false;

  // Must have a table name (a word at the start of a non-comment, non-empty line)
  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("//")) continue;
    // First non-comment, non-empty line should be a table name or start with a pipe
    if (/^[A-Za-z_][A-Za-z0-9_]*/.test(trimmed)) return true;
    break;
  }

  return false;
}

registerFileType({
  id: "kql_rule",
  label: "Microsoft Sentinel KQL Rule",
  shortLabel: "KQL",
  extensions: [".kql"],
  iconColor: "#0078d4",
  testable: true,
  convertibleTo: ["sigma_rule"],
  defaultContent: KQL_STARTER_TEMPLATE,
  detect: detectKqlContent,
});


function inferSentinelTable(dataSourceHints: string[]): { table: string; eventIdClause: string | null } {
  if (dataSourceHints.includes("process") || dataSourceHints.includes("command")) {
    return { table: "SecurityEvent", eventIdClause: "EventID == 4688" };
  }
  if (dataSourceHints.includes("file")) {
    return { table: "SecurityEvent", eventIdClause: "EventID == 4663" };
  }
  if (dataSourceHints.includes("network")) {
    return { table: "CommonSecurityLog", eventIdClause: null };
  }
  if (dataSourceHints.includes("authentication")) {
    return { table: "SigninLogs", eventIdClause: null };
  }
  return { table: "SecurityEvent", eventIdClause: null };
}


function sigmaModifierToKqlOperator(modifier: string | undefined): string {
  switch (modifier) {
    case "contains":
      return "contains";
    case "startswith":
      return "startswith";
    case "endswith":
      return "endswith";
    case "re":
      return "matches regex";
    default:
      return "==";
  }
}


function normalizeEventPayloadForKql(
  eventData: Record<string, unknown> | undefined,
): Record<string, unknown> {
  if (!eventData) return {};

  const normalized: Record<string, unknown> = { ...eventData };
  const actionType = eventData.actionType;
  const target = typeof eventData.target === "string" ? eventData.target : "";

  // Map common workbench event fields to Sentinel equivalents
  if (actionType === "shell_command" && !("CommandLine" in normalized)) {
    normalized.CommandLine = target;
  }
  if (
    (actionType === "file_access" || actionType === "file_write" || actionType === "patch_apply") &&
    !("TargetFilename" in normalized)
  ) {
    normalized.TargetFilename = target;
  }
  if (actionType === "network_egress" && !("DestinationHostname" in normalized)) {
    normalized.DestinationHostname = target;
  }

  return normalized;
}


function findKqlSourceLineHints(source: string, matchedFields: string[]): number[] {
  const lines = source.split(/\r?\n/);
  const hints = new Set<number>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/\|\s*where\b/i.test(line)) {
      for (const field of matchedFields) {
        if (field && line.includes(field)) {
          hints.add(i + 1);
        }
      }
    }
  }

  return [...hints].sort((a, b) => a - b);
}


const kqlAdapter: DetectionWorkflowAdapter = {
  fileType: "kql_rule",

  canDraftFrom(seed: DraftSeed): boolean {
    const relevantHints = ["process", "file", "network", "authentication"];
    return (
      seed.dataSourceHints.some((h) => relevantHints.includes(h)) ||
      seed.preferredFormats.includes("kql_rule")
    );
  },

  buildDraft(seed: DraftSeed): DraftBuildResult {
    const { table, eventIdClause } = inferSentinelTable(seed.dataSourceHints);
    const title = `Detection: ${seed.kind} ${seed.id.slice(0, 8)}`;

    const whereClauses: string[] = [];

    if (eventIdClause) {
      whereClauses.push(eventIdClause);
    }

    const actionType = seed.extractedFields["actionType"] as string | undefined;
    const targets = seed.extractedFields["targets"] as string[] | undefined;
    const commands = seed.extractedFields["commands"] as string[] | undefined;
    const paths = seed.extractedFields["paths"] as string[] | undefined;
    const domains = seed.extractedFields["domains"] as string[] | undefined;

    if (actionType === "shell_command" && commands && commands.length > 0) {
      const sigmaField = "CommandLine";
      const sentinelField = translateField(sigmaField, "sentinelField") ?? sigmaField;
      for (const cmd of commands) {
        whereClauses.push(`${sentinelField} contains "${cmd}"`);
      }
    } else if (
      (actionType === "file_access" || actionType === "file_write") &&
      paths &&
      paths.length > 0
    ) {
      const sigmaField = "TargetFilename";
      const sentinelField = translateField(sigmaField, "sentinelField") ?? sigmaField;
      for (const p of paths) {
        whereClauses.push(`${sentinelField} contains "${p}"`);
      }
    } else if (actionType === "network_egress" && domains && domains.length > 0) {
      const sigmaField = "DestinationHostname";
      const sentinelField = translateField(sigmaField, "sentinelField") ?? sigmaField;
      for (const d of domains) {
        whereClauses.push(`${sentinelField} contains "${d}"`);
      }
    } else if (targets && targets.length > 0) {
      const sigmaField = "CommandLine";
      const sentinelField = translateField(sigmaField, "sentinelField") ?? sigmaField;
      for (const t of targets) {
        whereClauses.push(`${sentinelField} contains "${t}"`);
      }
    } else {
      whereClauses.push(`CommandLine contains "suspicious"`);
    }

    const projectCols = ["TimeGenerated", "Computer"];
    // Add any mapped fields from seed.extractedFields
    for (const key of Object.keys(seed.extractedFields)) {
      if (key === "actionType" || key === "targets" || key === "commands" || key === "paths" || key === "domains") {
        continue;
      }
      const mapped = translateField(key, "sentinelField");
      if (mapped && !projectCols.includes(mapped)) {
        projectCols.push(mapped);
      }
    }

    const lines: string[] = [];
    lines.push(`// ${title}`);
    lines.push(`// Generated from ${seed.kind} seed`);
    lines.push(table);
    for (const wc of whereClauses) {
      lines.push(`| where ${wc}`);
    }
    lines.push(`| project ${projectCols.join(", ")}`);

    const source = lines.join("\n") + "\n";

    return {
      source,
      fileType: "kql_rule",
      name: title,
      techniqueHints: seed.techniqueHints,
    };
  },

  buildStarterEvidence(seed: DraftSeed, document: DetectionDocumentRef): EvidencePack {
    const datasets = createEmptyDatasets();

    for (const eventId of seed.sourceEventIds) {
      const eventData = seed.extractedFields[eventId] as Record<string, unknown> | undefined;
      const item: EvidenceItem = {
        id: crypto.randomUUID(),
        kind: "structured_event",
        format: "json",
        payload: eventData
          ? normalizeEventPayloadForKql(eventData)
          : { eventId, source: seed.kind },
        expected: "match",
        sourceEventId: eventId,
      };
      datasets.positive.push(item);
    }

    // Add a negative baseline
    if (seed.sourceEventIds.length > 0) {
      const baselineItem: EvidenceItem = {
        id: crypto.randomUUID(),
        kind: "structured_event",
        format: "json",
        payload: { baseline: true, actionType: "benign_action", target: "safe_target" },
        expected: "no_match",
      };
      datasets.negative.push(baselineItem);
    }

    return {
      id: crypto.randomUUID(),
      documentId: document.documentId,
      fileType: "kql_rule",
      title: `KQL starter pack from ${seed.kind}`,
      createdAt: new Date().toISOString(),
      derivedFromSeedId: seed.id,
      datasets,
      redactionState: "clean",
    };
  },

  async runLab(request: DetectionExecutionRequest): Promise<DetectionExecutionResult> {
    const { document, evidencePack } = request;
    const source = request.adapterRunConfig?.["kqlSource"] as string | undefined;
    const startedAt = new Date().toISOString();

    if (!source) {
      const completedAt = new Date().toISOString();
      const run: LabRun = {
        id: crypto.randomUUID(),
        documentId: document.documentId,
        evidencePackId: evidencePack.id,
        fileType: "kql_rule",
        startedAt,
        completedAt,
        summary: { totalCases: 0, passed: 0, failed: 0, matched: 0, missed: 0, falsePositives: 0, engine: "client" },
        results: [],
        explainability: [],
      };
      return {
        run,
        coverage: null,
        reportArtifacts: [{ id: crypto.randomUUID(), kind: "summary", title: "No KQL source provided in adapterRunConfig" }],
      };
    }

    const parsed = parseKqlQuery(source);
    const whereClauses = parsed.whereClauses;

    const allItems: Array<{ item: EvidenceItem; dataset: EvidenceDatasetKind }> = [];
    for (const [datasetKind, items] of Object.entries(evidencePack.datasets)) {
      for (const item of items) {
        allItems.push({ item, dataset: datasetKind as EvidenceDatasetKind });
      }
    }

    const eventItems = allItems.filter(
      ({ item }) => item.kind === "structured_event" || item.kind === "ocsf_event",
    );

    const results: LabCaseResult[] = [];
    const traces: ExplainabilityTrace[] = [];

    for (const { item, dataset } of eventItems) {
      const caseId = item.id;
      const expectedMatch = item.kind === "structured_event" ? item.expected === "match" : item.expected === "valid";

      let didMatch = false;
      if (item.kind === "structured_event" || item.kind === "ocsf_event") {
        didMatch = clientSideKqlMatch(item.payload, whereClauses);
      }

      const passed = expectedMatch === didMatch;
      const traceId = crypto.randomUUID();

      results.push({
        caseId,
        dataset,
        status: passed ? "pass" : "fail",
        expected: expectedMatch ? "match" : "no_match",
        actual: didMatch ? "match" : "no_match",
        explanationRefIds: [traceId],
      });

      const matchedClauses: string[] = [];
      const unmatchedClauses: string[] = [];
      const matchedFields: Array<{ path: string; value: string }> = [];

      if (item.kind === "structured_event" || item.kind === "ocsf_event") {
        for (const clause of whereClauses) {
          const val = item.payload[clause.field];
          if (val !== undefined && clientSideKqlMatch(item.payload, [clause])) {
            matchedClauses.push(clause.raw);
            matchedFields.push({ path: clause.field, value: String(val) });
          } else {
            unmatchedClauses.push(clause.raw);
          }
        }
      }

      traces.push({
        id: traceId,
        kind: "plugin_trace",
        caseId,
        traceType: "kql_where_match",
        data: {
          tableName: parsed.tableName,
          matchedClauses,
          unmatchedClauses,
          matchedFields: matchedFields.map((f) => f.path),
        },
        sourceLineHints: findKqlSourceLineHints(source, matchedFields.map((f) => f.path)),
      });
    }

    const passedCount = results.filter((r) => r.status === "pass").length;
    const failed = results.filter((r) => r.status === "fail").length;
    const matched = results.filter((r) => r.actual === "match").length;
    const missed = results.filter((r) => r.expected === "match" && r.actual === "no_match").length;
    const falsePositives = results.filter((r) => r.expected === "no_match" && r.actual === "match").length;

    const completedAt = new Date().toISOString();
    const run: LabRun = {
      id: crypto.randomUUID(),
      documentId: document.documentId,
      evidencePackId: evidencePack.id,
      fileType: "kql_rule",
      startedAt,
      completedAt,
      summary: {
        totalCases: results.length,
        passed: passedCount,
        failed,
        matched,
        missed,
        falsePositives,
        engine: "client",
      },
      results,
      explainability: traces,
    };

    const reportArtifacts: ReportArtifact[] = [
      {
        id: crypto.randomUUID(),
        kind: "summary",
        title: `KQL lab: ${passedCount}/${results.length} passed (engine: client)`,
        data: {
          engine: "client",
          tableName: parsed.tableName,
          whereClauseCount: whereClauses.length,
        },
      },
    ];

    return { run, coverage: null, reportArtifacts };
  },

  buildExplainability(run: LabRun): ExplainabilityTrace[] {
    return run.explainability;
  },

  async buildPublication(request: PublicationRequest): Promise<PublicationBuildResult> {
    const { source } = request;

    if (request.targetFormat === "kql") {
      // Identity: output raw KQL source
      const sourceHash = await sha256Hex(source);
      const outputHash = await sha256Hex(source);

      return {
        manifest: {
          documentId: request.document.documentId,
          sourceFileType: "kql_rule",
          target: "kql",
          sourceHash,
          outputHash,
          validationSnapshot: { valid: true, diagnosticCount: 0 },
          runSnapshot:
            request.labRunId && request.evidencePackId
              ? {
                  evidencePackId: request.evidencePackId,
                  labRunId: request.labRunId,
                  passed: true,
                }
              : null,
          coverageSnapshot: null,
          converter: { id: "kql-identity", version: "1.0.0" },
          signer: null,
          provenance: null,
        },
        outputContent: source,
        outputHash,
      };
    }

    if (request.targetFormat === "json_export") {
      // Wrap KQL in Sentinel Analytics Rule JSON structure
      const parsed = parseKqlQuery(source);

      // Extract title from first comment line if present
      let displayName = "Detection Rule";
      for (const comment of parsed.comments) {
        const stripped = comment.replace(/^\/\/\s*/, "").trim();
        if (stripped.length > 0 && !stripped.toLowerCase().startsWith("table:") && !stripped.toLowerCase().startsWith("description:")) {
          displayName = stripped;
          break;
        }
      }

      // Extract severity from comments or default to Medium
      let severity = "Medium";
      for (const comment of parsed.comments) {
        const lower = comment.toLowerCase();
        if (lower.includes("severity:")) {
          const parts = comment.split(/severity:\s*/i);
          if (parts[1]) {
            const s = parts[1].trim().toLowerCase();
            if (["high", "medium", "low", "informational"].includes(s)) {
              severity = s.charAt(0).toUpperCase() + s.slice(1);
            }
          }
        }
      }

      // Extract MITRE tactics from comments if present
      const tactics: string[] = [];
      for (const comment of parsed.comments) {
        const tacticMatch = comment.match(/attack\.(\w+)/gi);
        if (tacticMatch) {
          for (const t of tacticMatch) {
            const tactic = t.replace("attack.", "");
            if (!tactics.includes(tactic)) {
              tactics.push(tactic);
            }
          }
        }
      }

      const analyticsRule = {
        _meta: {
          converter: "kql-to-analytics-rule",
          converterVersion: "1.0.0",
          exportedAt: new Date().toISOString(),
        },
        analyticsRule: {
          displayName,
          query: source,
          queryFrequency: "PT5H",
          queryPeriod: "PT5H",
          triggerOperator: "GreaterThan",
          triggerThreshold: 0,
          severity,
          tactics,
          entityMappings: [],
        },
      };

      const outputContent = JSON.stringify(analyticsRule, null, 2);
      const sourceHash = await sha256Hex(source);
      const outputHash = await sha256Hex(outputContent);

      return {
        manifest: {
          documentId: request.document.documentId,
          sourceFileType: "kql_rule",
          target: "json_export",
          sourceHash,
          outputHash,
          validationSnapshot: { valid: true, diagnosticCount: 0 },
          runSnapshot:
            request.labRunId && request.evidencePackId
              ? {
                  evidencePackId: request.evidencePackId,
                  labRunId: request.labRunId,
                  passed: true,
                }
              : null,
          coverageSnapshot: null,
          converter: { id: "kql-to-analytics-rule", version: "1.0.0" },
          signer: null,
          provenance: null,
        },
        outputContent,
        outputHash,
      };
    }

    throw new Error(`Unsupported KQL publish target "${request.targetFormat}"`);
  },
};


registerAdapter(kqlAdapter);

export { kqlAdapter };
