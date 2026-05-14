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
import { createEmptyDatasets, registerPublishTarget } from "./shared-types";
import type {
  DetectionExecutionRequest,
  DetectionExecutionResult,
  DraftBuildResult,
  PublicationRequest,
  PublicationBuildResult,
  ReportArtifact,
} from "./execution-types";
import { translateField } from "./field-mappings";

// Side-effect import: registers YARA-L translation provider
import "./yaral-translation";


async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}


const YARAL_STARTER_TEMPLATE = `rule untitled_rule {
  meta:
    author = "Detection Lab"
    description = ""
    severity = "MEDIUM"
    created = "YYYY-MM-DD"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.command_line = /suspicious/ nocase

  condition:
    $e
}
`;

registerFileType({
  id: "yaral_rule",
  label: "Chronicle YARA-L Rule",
  shortLabel: "YARA-L",
  extensions: [".yaral"],
  iconColor: "#4285f4",
  defaultContent: YARAL_STARTER_TEMPLATE,
  testable: true,
  convertibleTo: ["sigma_rule"],
  detect: (_filename: string, content: string): boolean => {
    // Must have a rule block structure
    if (!/rule\s+\w+\s*\{/.test(content)) return false;
    // Must have at least one YARA-L specific indicator
    return (
      content.includes("events:") ||
      content.includes("condition:") ||
      /\$\w+\.metadata\./.test(content) ||
      /\$\w+\.target\./.test(content) ||
      /\$\w+\.principal\./.test(content)
    );
  },
});


/** Local fallback lookup for common Sigma -> UDM field paths. */
const LOCAL_UDM_FALLBACKS: Record<string, string> = {
  CommandLine: "target.process.command_line",
  Image: "target.process.file.full_path",
  ParentImage: "principal.process.file.full_path",
  ParentCommandLine: "principal.process.command_line",
  User: "principal.user.userid",
  TargetFilename: "target.file.full_path",
  SourceIp: "principal.ip",
  DestinationIp: "target.ip",
  DestinationHostname: "target.hostname",
  DestinationPort: "target.port",
  QueryName: "network.dns.questions.name",
  LogonType: "extensions.auth.type",
  TargetUserName: "target.user.userid",
};

/**
 * Translate a Sigma field name to a UDM path.
 * Tries the central field mapping registry first, falls back to local table.
 */
function sigmaToUdm(sigmaField: string): string | null {
  const fromRegistry = translateField(sigmaField, "udmPath");
  if (fromRegistry) return fromRegistry;
  return LOCAL_UDM_FALLBACKS[sigmaField] ?? null;
}

/** Infer UDM event type from data source hints. */
function inferEventType(dataSourceHints: string[]): string {
  for (const hint of dataSourceHints) {
    const lower = hint.toLowerCase();
    if (lower === "process" || lower === "command") return "PROCESS_LAUNCH";
    if (lower === "file") return "FILE_CREATION";
    if (lower === "network") return "NETWORK_CONNECTION";
    if (lower === "dns") return "NETWORK_DNS";
    if (lower === "authentication") return "USER_LOGIN";
  }
  return "GENERIC_EVENT";
}

/** Infer YARA-L severity from confidence score. */
function inferSeverity(confidence: number): string {
  if (confidence >= 0.9) return "HIGH";
  if (confidence >= 0.7) return "MEDIUM";
  if (confidence >= 0.5) return "LOW";
  return "INFORMATIONAL";
}


export interface YaralEventPredicate {
  variable: string;
  fieldPath: string;
  operator: "=" | "!=" | ">" | "<" | ">=" | "<=";
  value: string;
  isRegex: boolean;
  nocase: boolean;
}

export interface ParsedYaralRule {
  ruleName: string;
  meta: Record<string, string>;
  events: YaralEventPredicate[];
  condition: string;
  hasMatchSection: boolean;
  hasOutcomeSection: boolean;
}

/**
 * Best-effort regex parser for YARA-L rule text.
 * Extracts rule name, meta section, event predicates, and condition.
 * Not a full grammar -- sufficient for client-side simulation.
 */
export function parseYaralRule(source: string): ParsedYaralRule | null {
  // Extract rule name
  const ruleNameMatch = source.match(/rule\s+(\w+)\s*\{/);
  if (!ruleNameMatch) return null;
  const ruleName = ruleNameMatch[1];

  // Split into sections by looking for section headers
  const lines = source.split(/\r?\n/);

  let currentSection: "none" | "meta" | "events" | "condition" | "match" | "outcome" = "none";
  const metaLines: string[] = [];
  const eventLines: string[] = [];
  const conditionLines: string[] = [];
  let hasMatchSection = false;
  let hasOutcomeSection = false;

  for (const line of lines) {
    const trimmed = line.trim();
    // Skip empty lines and the rule header/closing brace
    if (trimmed === "" || trimmed === "}") continue;
    if (/^rule\s+\w+\s*\{/.test(trimmed)) continue;

    // Detect section headers
    if (trimmed === "meta:") { currentSection = "meta"; continue; }
    if (trimmed === "events:") { currentSection = "events"; continue; }
    if (trimmed === "condition:") { currentSection = "condition"; continue; }
    if (trimmed === "match:") { currentSection = "match"; hasMatchSection = true; continue; }
    if (trimmed === "outcome:") { currentSection = "outcome"; hasOutcomeSection = true; continue; }

    switch (currentSection) {
      case "meta": metaLines.push(trimmed); break;
      case "events": eventLines.push(trimmed); break;
      case "condition": conditionLines.push(trimmed); break;
    }
  }

  // Parse meta: key = "value" or key = value
  const meta: Record<string, string> = {};
  for (const line of metaLines) {
    const metaMatch = line.match(/^(\w+)\s*=\s*"?([^"]*)"?$/);
    if (metaMatch) {
      meta[metaMatch[1]] = metaMatch[2];
    }
  }

  // Parse events: $varName.field.path <op> "value" or /regex/ [nocase]
  const events: YaralEventPredicate[] = [];
  for (const line of eventLines) {
    // Match: $var.field.path <operator> <value>
    const eventMatch = line.match(
      /^(\$\w+)\.(\S+)\s*(!=|>=|<=|>|<|=)\s*(.+)$/,
    );
    if (eventMatch) {
      const variable = eventMatch[1];
      const fieldPath = eventMatch[2];
      const operator = eventMatch[3] as YaralEventPredicate["operator"];
      let valueStr = eventMatch[4].trim();

      let isRegex = false;
      let nocase = false;

      // Check for nocase modifier
      if (valueStr.endsWith(" nocase")) {
        nocase = true;
        valueStr = valueStr.slice(0, -7).trim();
      }

      // Check if regex: /pattern/
      if (valueStr.startsWith("/") && valueStr.endsWith("/")) {
        isRegex = true;
        valueStr = valueStr.slice(1, -1);
      } else if (valueStr.startsWith("/")) {
        // Regex with trailing flags removed
        const regexEnd = valueStr.lastIndexOf("/");
        if (regexEnd > 0) {
          isRegex = true;
          valueStr = valueStr.slice(1, regexEnd);
        }
      }

      // Strip quotes from string values
      if (valueStr.startsWith('"') && valueStr.endsWith('"')) {
        valueStr = valueStr.slice(1, -1);
      }

      events.push({ variable, fieldPath, operator, value: valueStr, isRegex, nocase });
    }
  }

  const condition = conditionLines.join(" ").trim();

  return { ruleName, meta, events, condition, hasMatchSection, hasOutcomeSection };
}


/**
 * Resolve a dot-notation field path against a nested object.
 * e.g. "target.process.command_line" -> payload.target.process.command_line
 */
function resolveFieldPath(payload: Record<string, unknown>, fieldPath: string): unknown {
  const parts = fieldPath.split(".");
  let current: unknown = payload;
  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== "object") {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

/**
 * Build an inverse mapping from UDM paths to Sigma field names,
 * so we can try flat field lookups on evidence payloads.
 */
const UDM_TO_SIGMA: Record<string, string> = {};
for (const [sigmaField, udmPath] of Object.entries(LOCAL_UDM_FALLBACKS)) {
  UDM_TO_SIGMA[udmPath] = sigmaField;
}

/**
 * Match a single YARA-L predicate against an evidence payload.
 */
function matchPredicateAgainstEvidence(
  predicate: YaralEventPredicate,
  payload: Record<string, unknown>,
): boolean {
  // Try dot-path traversal first
  let fieldValue = resolveFieldPath(payload, predicate.fieldPath);

  // Fallback: try flat field lookup via inverse UDM mapping
  if (fieldValue === undefined) {
    const sigmaField = UDM_TO_SIGMA[predicate.fieldPath];
    if (sigmaField) {
      fieldValue = payload[sigmaField];
    }
  }

  if (fieldValue === undefined || fieldValue === null) return false;

  const fieldStr = String(fieldValue);
  const predicateValue = predicate.value;

  if (predicate.isRegex) {
    try {
      const flags = predicate.nocase ? "i" : "";
      const re = new RegExp(predicateValue, flags);
      return re.test(fieldStr);
    } catch {
      return false;
    }
  }

  // Equality comparison
  if (predicate.nocase) {
    return fieldStr.toLowerCase() === predicateValue.toLowerCase();
  }
  return fieldStr === predicateValue;
}


function findSourceLineHints(source: string, fieldPaths: string[]): number[] {
  const lines = source.split(/\r?\n/);
  const lineHints = new Set<number>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes("condition:")) {
      lineHints.add(i + 1);
    }
    for (const fp of fieldPaths) {
      if (fp && line.includes(fp)) {
        lineHints.add(i + 1);
      }
    }
  }

  return [...lineHints].sort((a, b) => a - b);
}


function normalizeEventPayloadForYaral(
  eventData: Record<string, unknown> | undefined,
  dataSourceHints: string[],
): Record<string, unknown> {
  if (!eventData) return {};

  const normalized: Record<string, unknown> = { ...eventData };

  // Ensure metadata.event_type exists based on dataSourceHints
  if (!resolveFieldPath(normalized, "metadata.event_type")) {
    const eventType = inferEventType(dataSourceHints);
    if (!normalized.metadata || typeof normalized.metadata !== "object") {
      normalized.metadata = {};
    }
    (normalized.metadata as Record<string, unknown>).event_type = eventType;
  }

  return normalized;
}


const yaralAdapter: DetectionWorkflowAdapter = {
  fileType: "yaral_rule",

  canDraftFrom(seed: DraftSeed): boolean {
    const relevantHints = ["process", "command", "file", "network", "dns", "authentication"];
    return (
      seed.dataSourceHints.some((h) => relevantHints.includes(h)) ||
      seed.preferredFormats.includes("yaral_rule")
    );
  },

  buildDraft(seed: DraftSeed): DraftBuildResult {
    const eventType = inferEventType(seed.dataSourceHints);
    const severity = inferSeverity(seed.confidence);
    const today = new Date().toISOString().slice(0, 10);
    const ruleName = `detection_${seed.id.slice(0, 8).toLowerCase().replace(/[^a-z0-9]/g, "_")}`;

    // Build meta section
    const metaLines: string[] = [
      `    author = "Detection Lab"`,
      `    description = "Auto-generated YARA-L rule from ${seed.kind} seed"`,
      `    severity = "${severity}"`,
      `    created = "${today}"`,
    ];
    if (seed.techniqueHints.length > 0) {
      metaLines.push(`    mitre_attack = "${seed.techniqueHints.join(", ")}"`);
    }

    // Build events section
    const eventLines: string[] = [
      `    $e.metadata.event_type = "${eventType}"`,
    ];

    // Add predicates from extracted fields
    for (const [key, value] of Object.entries(seed.extractedFields)) {
      if (key === "actionType" || key === "targets" || key === "commands" || key === "paths" || key === "domains") {
        // Handle aggregate field types
        if (key === "commands" && Array.isArray(value)) {
          for (const cmd of value) {
            eventLines.push(`    $e.target.process.command_line = /${String(cmd)}/ nocase`);
          }
        } else if (key === "paths" && Array.isArray(value)) {
          for (const p of value) {
            eventLines.push(`    $e.target.file.full_path = /${String(p)}/ nocase`);
          }
        } else if (key === "domains" && Array.isArray(value)) {
          for (const d of value) {
            eventLines.push(`    $e.target.hostname = "${String(d)}"`);
          }
        } else if (key === "targets" && Array.isArray(value)) {
          for (const t of value) {
            eventLines.push(`    $e.target.process.command_line = /${String(t)}/ nocase`);
          }
        }
      } else if (typeof value === "string" || typeof value === "number") {
        // Try to map sigma field name to UDM path
        const udmPath = sigmaToUdm(key);
        if (udmPath) {
          if (typeof value === "string") {
            eventLines.push(`    $e.${udmPath} = /${String(value)}/ nocase`);
          } else {
            eventLines.push(`    $e.${udmPath} = "${String(value)}"`);
          }
        }
      }
    }

    // Build the rule source
    const source = [
      `rule ${ruleName} {`,
      `  meta:`,
      ...metaLines,
      ``,
      `  events:`,
      ...eventLines,
      ``,
      `  condition:`,
      `    $e`,
      `}`,
      ``,
    ].join("\n");

    const name = `Detection: ${seed.kind} ${seed.id.slice(0, 8)}`;

    return {
      source,
      fileType: "yaral_rule",
      name,
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
          ? normalizeEventPayloadForYaral(eventData, seed.dataSourceHints)
          : { eventId, source: seed.kind, metadata: { event_type: inferEventType(seed.dataSourceHints) } },
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
        payload: { metadata: { event_type: "GENERIC_EVENT" }, baseline: true },
        expected: "no_match",
      };
      datasets.negative.push(baselineItem);
    }

    return {
      id: crypto.randomUUID(),
      documentId: document.documentId,
      fileType: "yaral_rule",
      title: `YARA-L starter pack from ${seed.kind}`,
      createdAt: new Date().toISOString(),
      derivedFromSeedId: seed.id,
      datasets,
      redactionState: "clean",
    };
  },

  async runLab(request: DetectionExecutionRequest): Promise<DetectionExecutionResult> {
    const { document, evidencePack } = request;
    const source = request.adapterRunConfig?.["yaralSource"] as string | undefined;
    const startedAt = new Date().toISOString();

    if (!source) {
      const completedAt = new Date().toISOString();
      const run: LabRun = {
        id: crypto.randomUUID(),
        documentId: document.documentId,
        evidencePackId: evidencePack.id,
        fileType: "yaral_rule",
        startedAt,
        completedAt,
        summary: { totalCases: 0, passed: 0, failed: 0, matched: 0, missed: 0, falsePositives: 0, engine: "client" },
        results: [],
        explainability: [],
      };
      return {
        run,
        coverage: null,
        reportArtifacts: [{ id: crypto.randomUUID(), kind: "summary", title: "No YARA-L source provided in adapterRunConfig" }],
      };
    }

    const parsed = parseYaralRule(source);
    if (!parsed) {
      const completedAt = new Date().toISOString();
      const run: LabRun = {
        id: crypto.randomUUID(),
        documentId: document.documentId,
        evidencePackId: evidencePack.id,
        fileType: "yaral_rule",
        startedAt,
        completedAt,
        summary: { totalCases: 0, passed: 0, failed: 0, matched: 0, missed: 0, falsePositives: 0, engine: "client" },
        results: [],
        explainability: [],
      };
      return {
        run,
        coverage: null,
        reportArtifacts: [{ id: crypto.randomUUID(), kind: "summary", title: "Failed to parse YARA-L rule" }],
      };
    }

    const allItems: Array<{ item: EvidenceItem; dataset: EvidenceDatasetKind }> = [];
    for (const [datasetKind, items] of Object.entries(evidencePack.datasets)) {
      for (const item of items) {
        allItems.push({ item, dataset: datasetKind as EvidenceDatasetKind });
      }
    }

    const eventItems = allItems.filter(
      ({ item }) => item.kind === "structured_event" || item.kind === "ocsf_event",
    );

    const predicatesByVar = new Map<string, YaralEventPredicate[]>();
    for (const pred of parsed.events) {
      const existing = predicatesByVar.get(pred.variable) ?? [];
      existing.push(pred);
      predicatesByVar.set(pred.variable, existing);
    }

    const results: LabCaseResult[] = [];
    const traces: ExplainabilityTrace[] = [];

    for (const { item, dataset } of eventItems) {
      const caseId = item.id;
      const expectedMatch = item.kind === "structured_event" ? item.expected === "match" : item.expected === "valid";

      let didMatch = false;
      const matchedVariables: Array<{ variable: string; matchedPredicates: Array<{ fieldPath: string; value: string }> }> = [];
      const unmatchedPredicates: Array<{ fieldPath: string; expectedValue: string; actualValue: string }> = [];

      if (item.kind === "structured_event" || item.kind === "ocsf_event") {
        const payload = item.payload;

        if (predicatesByVar.size === 0) {
          // No predicates means no match
          didMatch = false;
        } else if (predicatesByVar.size === 1) {
          // Single variable: all predicates must match (AND)
          const [varName, predicates] = [...predicatesByVar.entries()][0];
          let allMatched = true;
          const matched: Array<{ fieldPath: string; value: string }> = [];

          for (const pred of predicates) {
            if (matchPredicateAgainstEvidence(pred, payload)) {
              const resolvedValue = resolveFieldPath(payload, pred.fieldPath);
              matched.push({ fieldPath: pred.fieldPath, value: String(resolvedValue ?? "") });
            } else {
              allMatched = false;
              const resolvedValue = resolveFieldPath(payload, pred.fieldPath);
              unmatchedPredicates.push({
                fieldPath: pred.fieldPath,
                expectedValue: pred.value,
                actualValue: String(resolvedValue ?? "<undefined>"),
              });
            }
          }

          if (allMatched && predicates.length > 0) {
            didMatch = true;
            matchedVariables.push({ variable: varName, matchedPredicates: matched });
          }
        } else {
          // Multi-variable: at least one variable's predicates must all match
          for (const [varName, predicates] of predicatesByVar) {
            let allMatched = true;
            const matched: Array<{ fieldPath: string; value: string }> = [];

            for (const pred of predicates) {
              if (matchPredicateAgainstEvidence(pred, payload)) {
                const resolvedValue = resolveFieldPath(payload, pred.fieldPath);
                matched.push({ fieldPath: pred.fieldPath, value: String(resolvedValue ?? "") });
              } else {
                allMatched = false;
                const resolvedValue = resolveFieldPath(payload, pred.fieldPath);
                unmatchedPredicates.push({
                  fieldPath: pred.fieldPath,
                  expectedValue: pred.value,
                  actualValue: String(resolvedValue ?? "<undefined>"),
                });
              }
            }

            if (allMatched && predicates.length > 0) {
              didMatch = true;
              matchedVariables.push({ variable: varName, matchedPredicates: matched });
            }
          }
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

      const matchedFieldPaths = matchedVariables.flatMap((mv) => mv.matchedPredicates.map((mp) => mp.fieldPath));

      traces.push({
        id: traceId,
        kind: "plugin_trace",
        caseId,
        traceType: "yaral_match",
        data: {
          ruleName: parsed.ruleName,
          matchedVariables,
          unmatchedPredicates,
        },
        sourceLineHints: findSourceLineHints(source, matchedFieldPaths),
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
      fileType: "yaral_rule",
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
        title: `YARA-L lab: ${passedCount}/${results.length} passed (engine: client)`,
        data: {
          engine: "client",
          ruleName: parsed.ruleName,
          predicateCount: parsed.events.length,
          variableCount: predicatesByVar.size,
        },
      },
    ];

    return { run, coverage: null, reportArtifacts };
  },

  buildExplainability(run: LabRun): ExplainabilityTrace[] {
    return run.explainability;
  },

  async buildPublication(request: PublicationRequest): Promise<PublicationBuildResult> {
    const target = request.targetFormat;

    if (target === "yaral") {
      // Raw YARA-L text output
      const sourceHash = await sha256Hex(request.source);
      const outputHash = await sha256Hex(request.source);

      return {
        manifest: {
          documentId: request.document.documentId,
          sourceFileType: "yaral_rule",
          target: "yaral",
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
          converter: { id: "yaral-identity", version: "1.0.0" },
          signer: null,
          provenance: null,
        },
        outputContent: request.source,
        outputHash,
      };
    }

    if (target === "json_export") {
      // Chronicle-style JSON envelope
      const parsed = parseYaralRule(request.source);

      const severityToRiskScore: Record<string, number> = {
        HIGH: 85,
        MEDIUM: 50,
        LOW: 25,
        INFORMATIONAL: 10,
      };

      const severity = parsed?.meta.severity ?? "MEDIUM";
      const riskScore = severityToRiskScore[severity.toUpperCase()] ?? 50;

      const envelope = {
        type: "yaral_rule",
        ruleName: parsed?.ruleName ?? "unknown_rule",
        ruleText: request.source,
        metadata: {
          severity: severity,
          riskScore,
          author: parsed?.meta.author ?? "",
          description: parsed?.meta.description ?? "",
          mitreTactics: parsed?.meta.mitre_attack
            ? parsed.meta.mitre_attack.split(",").map((t) => t.trim())
            : [],
          created: parsed?.meta.created ?? "",
        },
      };

      const outputContent = JSON.stringify(envelope, null, 2);
      const sourceHash = await sha256Hex(request.source);
      const outputHash = await sha256Hex(outputContent);

      return {
        manifest: {
          documentId: request.document.documentId,
          sourceFileType: "yaral_rule",
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
          converter: { id: "yaral-json-export", version: "1.0.0" },
          signer: null,
          provenance: null,
        },
        outputContent,
        outputHash,
      };
    }

    throw new Error(`Unsupported YARA-L publish target "${target}"`);
  },
};


registerPublishTarget({ id: "yaral", label: "YARA-L Rule", formatGroup: "siem" });


registerAdapter(yaralAdapter);

export { yaralAdapter };
