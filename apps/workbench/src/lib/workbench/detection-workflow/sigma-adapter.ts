/**
 * Sigma workflow adapter — implements DetectionWorkflowAdapter for sigma_rule.
 *
 * Generates Sigma YAML stubs from DraftSeeds, builds starter evidence packs
 * with structured event items, and provides stub implementations for lab
 * execution (requires Tauri backend) and publication.
 */

import YAML from "yaml";
import type { DetectionWorkflowAdapter } from "./adapters";
import { registerAdapter } from "./adapters";
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
import { testSigmaRuleNative } from "@/lib/tauri-commands";
import { convertSigmaToPolicy, convertSigmaToQuery } from "./sigma-conversion";
import { parseSigmaYaml } from "../sigma-types";
import { extractSigmaTechniques } from "../mitre-attack-data";

// ---- SHA-256 ----

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---- Logsource Mapping ----

interface LogsourceSpec {
  category: string;
  product?: string;
}

function inferLogsource(dataSourceHints: string[]): LogsourceSpec {
  if (dataSourceHints.includes("process") || dataSourceHints.includes("command")) {
    return { category: "process_creation", product: "windows" };
  }
  if (dataSourceHints.includes("file")) {
    return { category: "file_event" };
  }
  if (dataSourceHints.includes("network")) {
    return { category: "network_connection" };
  }
  // Default
  return { category: "process_creation" };
}

// ---- Selection Builder ----

function buildSelection(seed: DraftSeed): Record<string, unknown> {
  const selection: Record<string, unknown> = {};
  const actionType = seed.extractedFields["actionType"] as string | undefined;
  const targets = seed.extractedFields["targets"] as string[] | undefined;
  const commands = seed.extractedFields["commands"] as string[] | undefined;
  const paths = seed.extractedFields["paths"] as string[] | undefined;
  const domains = seed.extractedFields["domains"] as string[] | undefined;

  if (actionType === "shell_command" && commands && commands.length > 0) {
    selection["CommandLine|contains"] = commands.length === 1 ? commands[0] : commands;
  } else if (
    (actionType === "file_access" || actionType === "file_write") &&
    paths &&
    paths.length > 0
  ) {
    selection["TargetFilename|contains"] = paths.length === 1 ? paths[0] : paths;
  } else if (actionType === "network_egress" && domains && domains.length > 0) {
    selection["DestinationHostname|contains"] = domains.length === 1 ? domains[0] : domains;
  } else if (targets && targets.length > 0) {
    // Generic fallback: use targets
    selection["CommandLine|contains"] = targets.length === 1 ? targets[0] : targets;
  } else {
    selection["CommandLine|contains"] = "suspicious";
  }

  return selection;
}

// ---- Tags Builder ----

function buildTags(techniqueHints: string[]): string[] {
  const tags: string[] = [];
  for (const hint of techniqueHints) {
    // Normalize to attack.tXXXX format
    const normalized = hint.toLowerCase().replace(/^t/, "t");
    tags.push(`attack.${normalized}`);
  }
  if (tags.length === 0) {
    tags.push("attack.execution");
  }
  return tags;
}

// ---- Level Inference ----

function inferLevel(seed: DraftSeed): string {
  if (seed.confidence >= 0.9) return "high";
  if (seed.confidence >= 0.7) return "medium";
  return "low";
}

function normalizeEventPayloadForSigma(
  eventData: Record<string, unknown> | undefined,
): Record<string, unknown> {
  if (!eventData) return {};

  const normalized: Record<string, unknown> = { ...eventData };
  const actionType = eventData.actionType;
  const target = typeof eventData.target === "string" ? eventData.target : "";

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

// ---- Client-Side Sigma Matching ----

interface SigmaSelectionField {
  fieldName: string;
  modifier: string | null;
  values: unknown[];
}

/**
 * Extract selection fields from Sigma YAML source.
 * This is an approximate parser for client-side fallback, not a full Sigma engine.
 */
export function extractSigmaSelectionFields(source: string): SigmaSelectionField[] {
  const fields: SigmaSelectionField[] = [];
  try {
    const parsed = YAML.parse(source) as Record<string, unknown>;
    const detection = parsed["detection"] as Record<string, unknown> | undefined;
    if (!detection) return fields;

    const selection = detection["selection"] as Record<string, unknown> | undefined;
    if (!selection) return fields;

    for (const [key, value] of Object.entries(selection)) {
      const parts = key.split("|");
      const fieldName = parts[0];
      const modifier = parts.length > 1 ? parts.slice(1).join("|") : null;
      const values = Array.isArray(value) ? value : [value];
      fields.push({ fieldName, modifier, values });
    }
  } catch {
    // Parse error — return empty fields
  }
  return fields;
}

function extractTechniqueHints(source: string): string[] {
  const { rule } = parseSigmaYaml(source);
  return extractSigmaTechniques(rule?.tags ?? []);
}

function findSourceLineHints(source: string, fields: string[]): number[] {
  const lines = source.split(/\r?\n/);
  const lineHints = new Set<number>();

  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    if (line.includes("condition:")) {
      lineHints.add(index + 1);
    }
    for (const field of fields) {
      if (field && line.includes(field)) {
        lineHints.add(index + 1);
      }
    }
  }

  return [...lineHints].sort((a, b) => a - b);
}

/**
 * Client-side approximate Sigma match: check if an event payload contains
 * fields matching the selection criteria.
 */
export function clientSideMatch(
  payload: Record<string, unknown>,
  selectionFields: SigmaSelectionField[],
): boolean {
  if (selectionFields.length === 0) return false;

  // All selection fields must match (AND logic within selection)
  for (const sf of selectionFields) {
    const eventValue = payload[sf.fieldName];
    if (eventValue === undefined) return false;

    const eventStr = String(eventValue).toLowerCase();

    // Check if any of the selection values match
    const hasMatch = sf.values.some((v) => {
      const valStr = String(v).toLowerCase();
      if (sf.modifier === "contains") {
        return eventStr.includes(valStr);
      }
      if (sf.modifier === "startswith") {
        return eventStr.startsWith(valStr);
      }
      if (sf.modifier === "endswith") {
        return eventStr.endsWith(valStr);
      }
      // Exact or no modifier: case-insensitive equals
      return eventStr === valStr;
    });

    if (!hasMatch) return false;
  }

  return true;
}

// ---- Sigma Adapter ----

const sigmaAdapter: DetectionWorkflowAdapter = {
  fileType: "sigma_rule",

  canDraftFrom(seed: DraftSeed): boolean {
    const relevantHints = ["process", "command", "file", "network"];
    return (
      seed.dataSourceHints.some((h) => relevantHints.includes(h)) ||
      seed.preferredFormats.includes("sigma_rule")
    );
  },

  buildDraft(seed: DraftSeed): DraftBuildResult {
    const logsource = inferLogsource(seed.dataSourceHints);
    const selection = buildSelection(seed);
    const tags = buildTags(seed.techniqueHints);
    const level = inferLevel(seed);
    const today = new Date().toISOString().slice(0, 10).replace(/-/g, "/");

    const ruleObj: Record<string, unknown> = {
      title: `Detection: ${seed.kind} ${seed.id.slice(0, 8)}`,
      id: crypto.randomUUID(),
      status: "test",
      description: `Auto-generated Sigma rule from ${seed.kind} seed. ${seed.techniqueHints.length > 0 ? `Techniques: ${seed.techniqueHints.join(", ")}` : ""}`.trim(),
      author: "Detection Lab",
      date: today,
      tags,
      logsource,
      detection: {
        selection,
        condition: "selection",
      },
      falsepositives: ["Unknown"],
      level,
    };

    const source = YAML.stringify(ruleObj, { lineWidth: 120 });
    const name = ruleObj.title as string;

    return {
      source,
      fileType: "sigma_rule",
      name,
      techniqueHints: seed.techniqueHints,
    };
  },

  buildStarterEvidence(seed: DraftSeed, document: DetectionDocumentRef): EvidencePack {
    const datasets = createEmptyDatasets();

    // Build structured_event items from source events
    for (const eventId of seed.sourceEventIds) {
      const eventData = seed.extractedFields[eventId] as Record<string, unknown> | undefined;
      const item: EvidenceItem = {
        id: crypto.randomUUID(),
        kind: "structured_event",
        format: "json",
        payload: eventData
          ? normalizeEventPayloadForSigma(eventData)
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
      fileType: "sigma_rule",
      title: `Sigma starter pack from ${seed.kind}`,
      createdAt: new Date().toISOString(),
      derivedFromSeedId: seed.id,
      datasets,
      redactionState: "clean",
    };
  },

  async runLab(request: DetectionExecutionRequest): Promise<DetectionExecutionResult> {
    const { document, evidencePack } = request;
    const source = request.adapterRunConfig?.["sigmaSource"] as string | undefined;
    const startedAt = new Date().toISOString();

    if (!source) {
      const completedAt = new Date().toISOString();
      const run: LabRun = {
        id: crypto.randomUUID(),
        documentId: document.documentId,
        evidencePackId: evidencePack.id,
        fileType: "sigma_rule",
        startedAt,
        completedAt,
        summary: { totalCases: 0, passed: 0, failed: 0, matched: 0, missed: 0, falsePositives: 0, engine: "client" },
        results: [],
        explainability: [],
      };
      return {
        run,
        coverage: null,
        reportArtifacts: [{ id: crypto.randomUUID(), kind: "summary", title: "No Sigma source provided in adapterRunConfig" }],
      };
    }

    // Collect all evidence items across datasets
    const allItems: Array<{ item: EvidenceItem; dataset: EvidenceDatasetKind }> = [];
    for (const [datasetKind, items] of Object.entries(evidencePack.datasets)) {
      for (const item of items) {
        allItems.push({ item, dataset: datasetKind as EvidenceDatasetKind });
      }
    }

    // Build events JSON from structured_event / ocsf_event items
    const eventItems = allItems.filter(
      ({ item }) => item.kind === "structured_event" || item.kind === "ocsf_event",
    );
    const events = eventItems.map(({ item }) => {
      if (item.kind === "structured_event" || item.kind === "ocsf_event") {
        return item.payload;
      }
      return {};
    });

    // Try native execution first
    const nativeResult = await testSigmaRuleNative(source, JSON.stringify(events));

    const results: LabCaseResult[] = [];
    const traces: ExplainabilityTrace[] = [];
    let engine: "native" | "client" | "mixed" = "client";

    const ruleTechniqueHints = extractTechniqueHints(source);

    if (nativeResult) {
      const hasIndexedFindings = nativeResult.findings.some((finding) => finding.event_index != null);
      engine = hasIndexedFindings ? "native" : "mixed";

      if (hasIndexedFindings) {
        for (let i = 0; i < eventItems.length; i++) {
          const { item, dataset } = eventItems[i];
          const caseId = item.id;
          const expectedMatch = item.kind === "structured_event" ? item.expected === "match" : item.expected === "valid";
          const matchingFindings = nativeResult.findings.filter((f) => f.event_index === i);
          const didMatch = matchingFindings.length > 0;
          const passed = expectedMatch === didMatch;
          const traceId = didMatch ? crypto.randomUUID() : undefined;
          const allEvidenceRefs = matchingFindings.flatMap((f) => f.evidence_refs);

          results.push({
            caseId,
            dataset,
            status: passed ? "pass" : "fail",
            expected: expectedMatch ? "match" : "no_match",
            actual: didMatch ? "match" : "no_match",
            explanationRefIds: traceId ? [traceId] : [],
          });

          if (didMatch && traceId) {
            const matchedFields = allEvidenceRefs.map((ref) => ({
              path: ref,
              value: String((events[i] as Record<string, unknown>)?.[ref] ?? ""),
            }));
            traces.push({
              id: traceId,
              kind: "sigma_match",
              caseId,
              matchedSelectors: matchingFindings.map((finding) => ({
                name: finding.title,
                fields: finding.evidence_refs,
              })),
              matchedFields,
              techniqueHints: ruleTechniqueHints,
              sourceLineHints: findSourceLineHints(
                source,
                matchedFields.map((field) => field.path),
              ),
            });
          }
        }
      }
    }

    if (results.length === 0) {
      const selectionFields = extractSigmaSelectionFields(source);

      for (let i = 0; i < eventItems.length; i++) {
        const { item, dataset } = eventItems[i];
        const caseId = item.id;
        const expectedMatch = item.kind === "structured_event" ? item.expected === "match" : item.expected === "valid";

        let didMatch = false;
        if (item.kind === "structured_event" || item.kind === "ocsf_event") {
          didMatch = clientSideMatch(item.payload, selectionFields);
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

        const matchedFieldEntries: Array<{ path: string; value: string }> = [];
        if (didMatch && (item.kind === "structured_event" || item.kind === "ocsf_event")) {
          for (const sf of selectionFields) {
            const val = item.payload[sf.fieldName];
            if (val !== undefined) {
              matchedFieldEntries.push({ path: sf.fieldName, value: String(val) });
            }
          }
        }

        traces.push({
          id: traceId,
          kind: "sigma_match",
          caseId,
          matchedSelectors: didMatch ? [{ name: "selection", fields: matchedFieldEntries.map((f) => f.path) }] : [],
          matchedFields: matchedFieldEntries,
          techniqueHints: ruleTechniqueHints,
          sourceLineHints: findSourceLineHints(
            source,
            matchedFieldEntries.map((field) => field.path),
          ),
        });
      }
    }

    const passed = results.filter((r) => r.status === "pass").length;
    const failed = results.filter((r) => r.status === "fail").length;
    const matched = results.filter((r) => r.actual === "match").length;
    const missed = results.filter((r) => r.expected === "match" && r.actual === "no_match").length;
    const falsePositives = results.filter((r) => r.expected === "no_match" && r.actual === "match").length;

    const completedAt = new Date().toISOString();
    const run: LabRun = {
      id: crypto.randomUUID(),
      documentId: document.documentId,
      evidencePackId: evidencePack.id,
      fileType: "sigma_rule",
      startedAt,
      completedAt,
      summary: {
        totalCases: results.length,
        passed,
        failed,
        matched,
        missed,
        falsePositives,
        engine,
      },
      results,
      explainability: traces,
    };

    const reportArtifacts: ReportArtifact[] = [
      {
        id: crypto.randomUUID(),
        kind: "summary",
        title: `Sigma lab: ${passed}/${results.length} passed (engine: ${engine})`,
        data: {
          engine,
          eventsTestedNative: nativeResult?.events_tested ?? null,
          eventsMatchedNative: nativeResult?.events_matched ?? null,
          attributionMode:
            nativeResult && engine === "mixed"
              ? "client_selector_matching"
              : "native_event_index",
        },
      },
    ];

    return { run, coverage: null, reportArtifacts };
  },

  buildExplainability(run: LabRun): ExplainabilityTrace[] {
    return run.explainability;
  },

  async buildPublication(request: PublicationRequest): Promise<PublicationBuildResult> {
    // For native_policy / fleet_deploy targets, convert Sigma to policy YAML
    if (request.targetFormat === "native_policy" || request.targetFormat === "fleet_deploy") {
      const conversion = convertSigmaToPolicy(request.source);
      if (!conversion.success || !conversion.policyYaml) {
        const msgs = conversion.diagnostics
          .filter((d) => d.severity === "error")
          .map((d) => d.message)
          .join("; ");
        throw new Error(`Sigma to policy conversion failed: ${msgs}`);
      }

      const sourceHash = await sha256Hex(request.source);
      const outputHash = await sha256Hex(conversion.policyYaml);

      return {
        manifest: {
          documentId: request.document.documentId,
          sourceFileType: "sigma_rule",
          target: request.targetFormat,
          sourceHash,
          outputHash,
        validationSnapshot: {
          valid: true,
          diagnosticCount: conversion.diagnostics.filter((d) => d.severity === "warning").length,
        },
        runSnapshot:
            request.labRunId && request.evidencePackId
              ? {
                  evidencePackId: request.evidencePackId,
                  labRunId: request.labRunId,
                  passed: true,
                }
              : null,
        coverageSnapshot: null,
        converter: {
          id: "sigma-to-policy",
          version: conversion.converterVersion,
        },
        signer: null,
        provenance: null,
      },
      outputContent: conversion.policyYaml,
      outputHash,
    };
  }

    const target = request.targetFormat;
    if (target !== "spl" && target !== "kql" && target !== "esql" && target !== "json_export") {
      throw new Error(`Unsupported Sigma publish target "${target}"`);
    }

    const queryConversion = convertSigmaToQuery(request.source, target);
    if (!queryConversion.success || !queryConversion.output) {
      const errors = queryConversion.diagnostics
        .filter((diagnostic) => diagnostic.severity === "error")
        .map((diagnostic) => diagnostic.message)
        .join("; ");
      throw new Error(errors || `Sigma conversion failed for ${target}`);
    }

    const sourceHash = await sha256Hex(request.source);
    const outputHash = await sha256Hex(queryConversion.output);

    return {
      manifest: {
        documentId: request.document.documentId,
        sourceFileType: "sigma_rule",
        target,
        sourceHash,
        outputHash,
        validationSnapshot: {
          valid: true,
          diagnosticCount: queryConversion.diagnostics.length,
        },
        runSnapshot:
          request.labRunId && request.evidencePackId
            ? {
                evidencePackId: request.evidencePackId,
                labRunId: request.labRunId,
                passed: true,
              }
              : null,
        coverageSnapshot: null,
        converter: {
          id: queryConversion.converterId,
          version: queryConversion.converterVersion,
        },
        signer: null,
        provenance: null,
      },
      outputContent: queryConversion.output,
      outputHash,
    };
  },
};

// ---- Auto-register ----

registerAdapter(sigmaAdapter);

export { sigmaAdapter };
