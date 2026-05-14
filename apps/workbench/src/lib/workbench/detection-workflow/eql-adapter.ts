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
import {
  parseEql,
  generateEql,
  getEventCategoryForHint,
  extractEqlFields,
  type EqlCondition,
  type EqlSingleQuery,
  type EqlSequenceQuery,
  type EqlSequenceStep,
  type EqlEventCategory,
} from "./eql-parser";


async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}


const EQL_STARTER_TEMPLATE = `// Elastic EQL Detection Rule
// Event category prefix: process, file, network, registry, dns
process where process.name == "powershell.exe"
  and process.command_line : "*-encodedcommand*"
`;

registerFileType({
  id: "eql_rule",
  label: "Elastic EQL Rule",
  shortLabel: "EQL",
  extensions: [".eql"],
  iconColor: "#f04e98",
  defaultContent: EQL_STARTER_TEMPLATE,
  testable: true,
  convertibleTo: ["sigma_rule"],
  detect: (filename: string, content: string) => {
    if (filename.endsWith(".eql")) return true;
    const trimmed = content.trim();
    return (
      /^(process|file|network|registry|dns|any)\s+where\b/i.test(trimmed) ||
      /^sequence\s+by\b/i.test(trimmed)
    );
  },
});


/**
 * Infer level / risk_score from seed confidence.
 */
function inferSeverity(seed: DraftSeed): { severity: string; riskScore: number } {
  if (seed.confidence >= 0.9) return { severity: "high", riskScore: 73 };
  if (seed.confidence >= 0.7) return { severity: "medium", riskScore: 50 };
  return { severity: "low", riskScore: 21 };
}

/**
 * Build MITRE tags from technique hints.
 */
function buildMitreTags(techniqueHints: string[]): string[] {
  const tags: string[] = [];
  for (const hint of techniqueHints) {
    const normalized = hint.toLowerCase().replace(/^t/, "t");
    tags.push(`attack.${normalized}`);
  }
  if (tags.length === 0) {
    tags.push("attack.execution");
  }
  return tags;
}

/**
 * Map a Sigma field name to its ECS equivalent, returning the original if unmapped.
 */
function toEcsField(sigmaField: string): string {
  return translateField(sigmaField, "ecsField") ?? sigmaField;
}

/**
 * Build EQL conditions from a DraftSeed's extracted fields.
 */
function buildConditionsFromSeed(
  seed: DraftSeed,
  category: EqlEventCategory,
): EqlCondition[] {
  const conditions: EqlCondition[] = [];
  const actionType = seed.extractedFields["actionType"] as string | undefined;
  const targets = seed.extractedFields["targets"] as string[] | undefined;
  const commands = seed.extractedFields["commands"] as string[] | undefined;
  const paths = seed.extractedFields["paths"] as string[] | undefined;
  const domains = seed.extractedFields["domains"] as string[] | undefined;

  if (actionType === "shell_command" && commands && commands.length > 0) {
    for (const cmd of commands) {
      conditions.push({
        field: toEcsField("CommandLine"),
        operator: ":",
        value: `*${cmd}*`,
        negated: false,
      });
    }
  } else if (
    (actionType === "file_access" || actionType === "file_write") &&
    paths &&
    paths.length > 0
  ) {
    for (const p of paths) {
      conditions.push({
        field: toEcsField("TargetFilename"),
        operator: ":",
        value: `*${p}*`,
        negated: false,
      });
    }
  } else if (actionType === "network_egress" && domains && domains.length > 0) {
    for (const d of domains) {
      conditions.push({
        field: toEcsField("DestinationHostname"),
        operator: ":",
        value: `*${d}*`,
        negated: false,
      });
    }
  } else if (targets && targets.length > 0) {
    // Generic fallback: use wildcard match on command line
    for (const t of targets) {
      conditions.push({
        field: toEcsField("CommandLine"),
        operator: ":",
        value: `*${t}*`,
        negated: false,
      });
    }
  } else {
    // Absolute fallback
    const defaultField =
      category === "file"
        ? toEcsField("TargetFilename")
        : category === "network"
          ? toEcsField("DestinationHostname")
          : toEcsField("CommandLine");
    conditions.push({
      field: defaultField,
      operator: ":",
      value: "*suspicious*",
      negated: false,
    });
  }

  return conditions;
}


/**
 * Normalize an event payload to include ECS field names alongside any existing fields.
 */
function normalizeEventPayloadForEql(
  eventData: Record<string, unknown> | undefined,
): Record<string, unknown> {
  if (!eventData) return {};
  const normalized: Record<string, unknown> = { ...eventData };
  const actionType = eventData.actionType;
  const target = typeof eventData.target === "string" ? eventData.target : "";

  // Map to ECS fields
  if (actionType === "shell_command" && !("process.command_line" in normalized)) {
    normalized["process.command_line"] = target;
    if (!("process.name" in normalized)) {
      // Extract first word as process name
      const firstWord = target.split(/\s+/)[0];
      if (firstWord) normalized["process.name"] = firstWord;
    }
  }

  if (
    (actionType === "file_access" || actionType === "file_write" || actionType === "patch_apply") &&
    !("file.path" in normalized)
  ) {
    normalized["file.path"] = target;
  }

  if (actionType === "network_egress" && !("destination.domain" in normalized)) {
    normalized["destination.domain"] = target;
  }

  return normalized;
}


/**
 * Resolve a dotted field path from a payload object.
 * Supports both flat dotted keys ("process.name") and nested objects.
 *
 * @param obj - The object to traverse
 * @param path - Dotted field path (e.g. "process.command_line")
 * @returns The resolved value, or undefined if the path does not exist
 */
function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  // Try flat key first (our normalized payloads use flat dotted keys)
  if (path in obj) return obj[path];

  // Try nested resolution by splitting on "."
  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== "object") {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

/**
 * Evaluate a single EQL condition against an event payload.
 *
 * Resolves the dotted field path from the payload, converts both sides to
 * strings for comparison, then switches on the operator. Handles wildcard
 * (:), regex (~), numeric comparisons (>= <= > <), in-list, and equality.
 * Applies negation if condition.negated is true.
 *
 * @param condition - The EQL condition to evaluate
 * @param payload - The event payload to evaluate against
 * @returns true if the condition matches
 */
function evaluateEqlCondition(
  condition: EqlCondition,
  payload: Record<string, unknown>,
): boolean {
  const eventValue = getNestedValue(payload, condition.field);
  if (eventValue === undefined || eventValue === null) {
    return condition.negated; // Missing field: match is false, but negated flips it
  }

  const eventStr = String(eventValue).toLowerCase();
  let matched = false;

  switch (condition.operator) {
    case "==":
      matched = eventStr === String(condition.value).toLowerCase();
      break;
    case "!=":
      matched = eventStr !== String(condition.value).toLowerCase();
      break;
    case ":": {
      // Wildcard match (case-insensitive). Convert * to regex .*, anchor with ^...$
      const pattern = String(condition.value).toLowerCase();
      const regex = new RegExp(
        "^" + pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\\*/g, ".*") + "$",
      );
      matched = regex.test(eventStr);
      break;
    }
    case "~": {
      // Regex match using new RegExp(value, "i")
      try {
        const re = new RegExp(String(condition.value), "i");
        matched = re.test(eventStr);
      } catch {
        matched = false;
      }
      break;
    }
    case "in": {
      // Check if eventValue is in the value array (case-insensitive)
      const values = Array.isArray(condition.value) ? condition.value : [String(condition.value)];
      matched = values.some((v) => v.toLowerCase() === eventStr);
      break;
    }
    case ">=":
      matched = parseFloat(eventStr) >= parseFloat(String(condition.value));
      break;
    case "<=":
      matched = parseFloat(eventStr) <= parseFloat(String(condition.value));
      break;
    case ">":
      matched = parseFloat(eventStr) > parseFloat(String(condition.value));
      break;
    case "<":
      matched = parseFloat(eventStr) < parseFloat(String(condition.value));
      break;
  }

  return condition.negated ? !matched : matched;
}

/**
 * Match a single-event EQL query against an event payload.
 *
 * Checks event category (if present in payload), then evaluates all conditions
 * with AND/OR logic. Returns whether the query matched and which fields
 * matched vs did not.
 */
function matchSingleQuery(
  query: EqlSingleQuery,
  payload: Record<string, unknown>,
): { matched: boolean; matchedFields: string[]; unmatchedFields: string[] } {
  // Check event category if payload has one
  if (query.eventCategory !== "any") {
    const payloadCategory = getNestedValue(payload, "event.category");
    if (payloadCategory !== undefined && payloadCategory !== null) {
      const categoryStr = String(payloadCategory).toLowerCase();
      if (categoryStr !== query.eventCategory) {
        // Category mismatch -- all fields are unmatched
        return {
          matched: false,
          matchedFields: [],
          unmatchedFields: query.conditions.map((c) => c.field),
        };
      }
    }
  }

  // Evaluate all conditions
  const matchedFields: string[] = [];
  const unmatchedFields: string[] = [];

  for (const cond of query.conditions) {
    if (evaluateEqlCondition(cond, payload)) {
      matchedFields.push(cond.field);
    } else {
      unmatchedFields.push(cond.field);
    }
  }

  // Determine overall match based on logic operator
  let matched: boolean;
  if (query.conditions.length === 0) {
    matched = false;
  } else if (query.logicOperator === "and") {
    matched = unmatchedFields.length === 0;
  } else {
    // "or" logic: at least one condition must pass
    matched = matchedFields.length > 0;
  }

  return { matched, matchedFields, unmatchedFields };
}

/**
 * Match a sequence EQL query against a set of events.
 *
 * For each step in the sequence, finds events whose payload matches the step's
 * conditions. Client-side approximation: each step is matched independently
 * against all events (no temporal ordering enforcement). A sequence "matches"
 * if every step found at least one matching event.
 */
function matchSequenceQuery(
  query: EqlSequenceQuery,
  events: Array<{ item: EvidenceItem; index: number }>,
): {
  perStepResults: Array<{
    stepIndex: number;
    matchedEventIndices: number[];
    matchedFields: string[][];
  }>;
  overallMatched: boolean;
} {
  const perStepResults: Array<{
    stepIndex: number;
    matchedEventIndices: number[];
    matchedFields: string[][];
  }> = [];

  for (let stepIndex = 0; stepIndex < query.steps.length; stepIndex++) {
    const step = query.steps[stepIndex];
    const matchedEventIndices: number[] = [];
    const matchedFieldsPerEvent: string[][] = [];

    for (const { item, index } of events) {
      if (item.kind !== "structured_event" && item.kind !== "ocsf_event") continue;
      const payload = item.payload;

      // Check event category for this step
      const stepQuery: EqlSingleQuery = {
        type: "single",
        eventCategory: step.eventCategory,
        conditions: step.conditions,
        logicOperator: step.logicOperator,
      };

      const result = matchSingleQuery(stepQuery, payload);
      if (result.matched) {
        matchedEventIndices.push(index);
        matchedFieldsPerEvent.push(result.matchedFields);
      }
    }

    perStepResults.push({
      stepIndex,
      matchedEventIndices,
      matchedFields: matchedFieldsPerEvent,
    });
  }

  // A sequence "matches" if every step found at least one matching event
  const overallMatched = perStepResults.every((r) => r.matchedEventIndices.length > 0);

  return { perStepResults, overallMatched };
}

/**
 * Find source line hints for matched fields in EQL source text.
 *
 * Searches source lines for occurrences of the field names and returns
 * matching 1-indexed line numbers.
 */
function findEqlSourceLineHints(source: string, fields: string[]): number[] {
  const lines = source.split(/\r?\n/);
  const hints = new Set<number>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/\bwhere\b/i.test(line)) {
      hints.add(i + 1);
    }
    for (const field of fields) {
      if (field && line.includes(field)) {
        hints.add(i + 1);
      }
    }
  }

  return [...hints].sort((a, b) => a - b);
}


const eqlAdapter: DetectionWorkflowAdapter = {
  fileType: "eql_rule",

  canDraftFrom(seed: DraftSeed): boolean {
    const relevantHints = ["process", "command", "file", "network", "registry"];
    return (
      seed.dataSourceHints.some((h) => relevantHints.includes(h)) ||
      seed.preferredFormats.includes("eql_rule")
    );
  },

  buildDraft(seed: DraftSeed): DraftBuildResult {
    // Determine primary event category
    const primaryHint = seed.dataSourceHints[0] ?? "process";
    const category = getEventCategoryForHint(primaryHint);

    // Check if we should build a sequence query
    const shouldSequence =
      seed.sourceEventIds.length > 1 &&
      seed.dataSourceHints.length > 1 &&
      new Set(seed.dataSourceHints.map(getEventCategoryForHint)).size > 1;

    let source: string;

    if (shouldSequence) {
      // Build sequence query with one step per unique category
      const seenCategories = new Set<EqlEventCategory>();
      const steps: Array<{
        category: EqlEventCategory;
        conditions: EqlCondition[];
      }> = [];

      for (const hint of seed.dataSourceHints) {
        const cat = getEventCategoryForHint(hint);
        if (seenCategories.has(cat)) continue;
        seenCategories.add(cat);

        // Build conditions scoped to this category
        const conditions = buildConditionsFromSeed(seed, cat);
        steps.push({ category: cat, conditions });
      }

      const ast = {
        type: "sequence" as const,
        byFields: ["host.id"],
        steps: steps.map((s) => ({
          eventCategory: s.category,
          conditions: s.conditions,
          logicOperator: "and" as const,
        })),
        maxspan: "5m",
      };

      source = generateEql(ast);
    } else {
      // Single-event query
      const conditions = buildConditionsFromSeed(seed, category);
      const ast: EqlSingleQuery = {
        type: "single",
        eventCategory: category,
        conditions,
        logicOperator: "and",
      };
      source = generateEql(ast);
    }

    // Add comment header
    const header = [
      "// Elastic EQL Detection Rule",
      `// Auto-generated from ${seed.kind} seed ${seed.id.slice(0, 8)}`,
      seed.techniqueHints.length > 0
        ? `// Techniques: ${seed.techniqueHints.join(", ")}`
        : null,
      "",
    ]
      .filter((l) => l !== null)
      .join("\n");

    return {
      source: header + source + "\n",
      fileType: "eql_rule",
      name: `Detection: ${seed.kind} ${seed.id.slice(0, 8)}`,
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
          ? normalizeEventPayloadForEql(eventData)
          : { eventId, source: seed.kind, "event.category": "process" },
        expected: "match",
        sourceEventId: eventId,
      };
      datasets.positive.push(item);
    }

    // Add a negative baseline event
    if (seed.sourceEventIds.length > 0) {
      const baselineItem: EvidenceItem = {
        id: crypto.randomUUID(),
        kind: "structured_event",
        format: "json",
        payload: {
          "process.name": "notepad.exe",
          "process.command_line": "notepad.exe document.txt",
          "event.category": "process",
          baseline: true,
        },
        expected: "no_match",
      };
      datasets.negative.push(baselineItem);
    }

    return {
      id: crypto.randomUUID(),
      documentId: document.documentId,
      fileType: "eql_rule",
      title: `EQL starter pack from ${seed.kind}`,
      createdAt: new Date().toISOString(),
      derivedFromSeedId: seed.id,
      datasets,
      redactionState: "clean",
    };
  },

  async runLab(request: DetectionExecutionRequest): Promise<DetectionExecutionResult> {
    const { document, evidencePack } = request;
    const source = (request.adapterRunConfig?.["eqlSource"] as string | undefined) ?? "";
    const startedAt = new Date().toISOString();

    // Early return: no EQL source
    if (!source) {
      const completedAt = new Date().toISOString();
      const run: LabRun = {
        id: crypto.randomUUID(),
        documentId: document.documentId,
        evidencePackId: evidencePack.id,
        fileType: "eql_rule",
        startedAt,
        completedAt,
        summary: { totalCases: 0, passed: 0, failed: 0, matched: 0, missed: 0, falsePositives: 0, engine: "client" },
        results: [],
        explainability: [],
      };
      return {
        run,
        coverage: null,
        reportArtifacts: [
          { id: crypto.randomUUID(), kind: "summary", title: "No EQL source provided in adapterRunConfig" },
        ],
      };
    }

    // Parse EQL source
    const parseResult = parseEql(source);

    if (!parseResult.ast) {
      const completedAt = new Date().toISOString();
      const run: LabRun = {
        id: crypto.randomUUID(),
        documentId: document.documentId,
        evidencePackId: evidencePack.id,
        fileType: "eql_rule",
        startedAt,
        completedAt,
        summary: { totalCases: 0, passed: 0, failed: 0, matched: 0, missed: 0, falsePositives: 0, engine: "client" },
        results: [],
        explainability: [],
      };
      return {
        run,
        coverage: null,
        reportArtifacts: [
          {
            id: crypto.randomUUID(),
            kind: "summary",
            title: `EQL parse error: ${parseResult.errors.join("; ")}`,
          },
        ],
      };
    }

    const ast = parseResult.ast;

    // Collect all structured_event evidence items across datasets
    const allItems: Array<{ item: EvidenceItem; dataset: EvidenceDatasetKind }> = [];
    for (const [datasetKind, items] of Object.entries(evidencePack.datasets)) {
      for (const item of items) {
        allItems.push({ item, dataset: datasetKind as EvidenceDatasetKind });
      }
    }

    const eventItems = allItems.filter(
      (
        entry,
      ): entry is {
        item:
          | Extract<EvidenceItem, { kind: "structured_event" }>
          | Extract<EvidenceItem, { kind: "ocsf_event" }>;
        dataset: EvidenceDatasetKind;
      } => entry.item.kind === "structured_event" || entry.item.kind === "ocsf_event",
    );

    const results: LabCaseResult[] = [];
    const traces: ExplainabilityTrace[] = [];

    if (ast.type === "single") {
      for (const { item, dataset } of eventItems) {
        const caseId = item.id;
        const expectedMatch =
          item.kind === "structured_event" ? item.expected === "match" : item.expected === "valid";

        const payload = item.payload;
        const queryResult = matchSingleQuery(ast, payload);
        const didMatch = queryResult.matched;

        // Collect matched field values for trace data
        const matchedFieldEntries: Array<{ path: string; value: string }> = [];
        for (const field of queryResult.matchedFields) {
          const val = getNestedValue(payload, field);
          if (val !== undefined && val !== null) {
            matchedFieldEntries.push({ path: field, value: String(val) });
          }
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

        // Emit plugin_trace with eql_match traceType
        traces.push({
          id: traceId,
          kind: "plugin_trace",
          caseId,
          traceType: "eql_match",
          data: {
            matched: didMatch,
            queryType: "single",
            eventCategory: ast.eventCategory,
            matchedFields: matchedFieldEntries,
            unmatchedFields: queryResult.unmatchedFields,
          },
          sourceLineHints: findEqlSourceLineHints(
            source,
            queryResult.matchedFields,
          ),
        });
      }
    } else {
      const indexedEvents = eventItems.map(({ item }, index) => ({ item, index }));
      const seqResult = matchSequenceQuery(ast, indexedEvents);

      // For each evidence item, determine which sequence step(s) it matched
      for (let eventIdx = 0; eventIdx < eventItems.length; eventIdx++) {
        const { item, dataset } = eventItems[eventIdx];
        const caseId = item.id;
        const expectedMatch =
          item.kind === "structured_event" ? item.expected === "match" : item.expected === "valid";

        // Check if this event matched any step
        const matchedSteps: Array<{
          stepIndex: number;
          matchedFields: string[];
        }> = [];

        for (const stepResult of seqResult.perStepResults) {
          const posInStep = stepResult.matchedEventIndices.indexOf(eventIdx);
          if (posInStep !== -1) {
            matchedSteps.push({
              stepIndex: stepResult.stepIndex,
              matchedFields: stepResult.matchedFields[posInStep] ?? [],
            });
          }
        }

        const didMatch = matchedSteps.length > 0;
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

        // Build per-step trace data
        const payload = item.payload;
        const allMatchedFields = matchedSteps.flatMap((s) => s.matchedFields);
        const matchedFieldEntries: Array<{ path: string; value: string }> = [];
        for (const field of allMatchedFields) {
          const val = getNestedValue(payload, field);
          if (val !== undefined && val !== null) {
            matchedFieldEntries.push({ path: field, value: String(val) });
          }
        }

        const unmatchedFields: string[] = [];
        if (matchedSteps.length > 0) {
          const stepIdx = matchedSteps[0].stepIndex;
          const step = ast.steps[stepIdx];
          for (const cond of step.conditions) {
            if (!allMatchedFields.includes(cond.field)) {
              unmatchedFields.push(cond.field);
            }
          }
        }

        // Emit plugin_trace with eql_sequence_match traceType
        traces.push({
          id: traceId,
          kind: "plugin_trace",
          caseId,
          traceType: "eql_sequence_match",
          data: {
            stepIndex: matchedSteps.length > 0 ? matchedSteps[0].stepIndex : -1,
            totalSteps: ast.steps.length,
            stepCategory: matchedSteps.length > 0
              ? ast.steps[matchedSteps[0].stepIndex].eventCategory
              : null,
            matchedFields: matchedFieldEntries,
            unmatchedFields,
            sequenceComplete: seqResult.overallMatched,
            queryType: "sequence",
          },
          sourceLineHints: findEqlSourceLineHints(
            source,
            allMatchedFields,
          ),
        });
      }
    }

    const totalCases = results.length;
    const passed = results.filter((r) => r.status === "pass").length;
    const failed = results.filter((r) => r.status === "fail").length;
    const matched = results.filter((r) => r.actual === "match").length;
    const missed = results.filter((r) => r.expected === "match" && r.actual === "no_match").length;
    const falsePositives = results.filter(
      (r) => r.expected === "no_match" && r.actual === "match",
    ).length;

    const completedAt = new Date().toISOString();
    const run: LabRun = {
      id: crypto.randomUUID(),
      documentId: document.documentId,
      evidencePackId: evidencePack.id,
      fileType: "eql_rule",
      startedAt,
      completedAt,
      summary: {
        totalCases,
        passed,
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
        title: `EQL lab: ${passed}/${totalCases} passed (engine: client)`,
      },
    ];

    return { run, coverage: null, reportArtifacts };
  },

  buildExplainability(run: LabRun): ExplainabilityTrace[] {
    return run.explainability;
  },

  async buildPublication(request: PublicationRequest): Promise<PublicationBuildResult> {
    const { severity } = inferSeverity({
      confidence: 0.5,
      // Minimal seed for severity inference
    } as DraftSeed);

    const target = request.targetFormat;

    if (target === "eql") {
      // Raw EQL with comment header
      const header = [
        `// Rule: ${request.document.name}`,
        `// Author: Detection Lab`,
        `// Severity: ${severity}`,
        `// Exported: ${new Date().toISOString()}`,
        "",
      ].join("\n");
      const output = header + request.source;

      const sourceHash = await sha256Hex(request.source);
      const outputHash = await sha256Hex(output);

      return {
        manifest: {
          documentId: request.document.documentId,
          sourceFileType: "eql_rule",
          target: "eql",
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
          converter: { id: "eql-export", version: "1.0.0" },
          signer: null,
          provenance: null,
        },
        outputContent: output,
        outputHash,
      };
    }

    if (target === "json_export") {
      // NDJSON detection rule format
      const parseResult = parseEql(request.source);
      const tags = buildMitreTags(
        parseResult.ast ? extractEqlFields(parseResult.ast).filter((f) => f.startsWith("attack.")) : [],
      );

      const { riskScore } = inferSeverity({ confidence: 0.5 } as DraftSeed);

      const ruleDoc = {
        _meta: {
          converter: "eql-export",
          converterVersion: "1.0.0",
          exportedAt: new Date().toISOString(),
        },
        rule: {
          type: "eql",
          language: "eql",
          query: request.source.trim(),
          name: request.document.name,
          risk_score: riskScore,
          severity,
          tags,
          threat: [
            {
              framework: "MITRE ATT&CK",
              technique: tags.map((t) => ({
                id: t.replace("attack.", "").toUpperCase(),
                name: t.replace("attack.", ""),
              })),
            },
          ],
        },
      };

      const output = JSON.stringify(ruleDoc, null, 2);
      const sourceHash = await sha256Hex(request.source);
      const outputHash = await sha256Hex(output);

      return {
        manifest: {
          documentId: request.document.documentId,
          sourceFileType: "eql_rule",
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
          converter: { id: "eql-export", version: "1.0.0" },
          signer: null,
          provenance: null,
        },
        outputContent: output,
        outputHash,
      };
    }

    throw new Error(`Unsupported EQL publish target "${target}"`);
  },
};


registerAdapter(eqlAdapter);

export { eqlAdapter };
