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
import {
  parseSplPipeChain,
  parseSplFieldConditions,
  matchSplConditions,
  buildSplFromSeed,
  findSplSourceLineHints,
} from "./spl-parser";
import { translateField } from "./field-mappings";


async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}


const SPL_DEFAULT_CONTENT = `// Untitled SPL Detection Rule
// Author: Detection Lab
// Description: Detects suspicious activity
index=main sourcetype=WinEventLog:Security EventCode=4688
| where process="*suspicious*"
| table _time, ComputerName, process, CommandLine
`;


registerFileType({
  id: "splunk_spl",
  label: "Splunk SPL Rule",
  shortLabel: "SPL",
  extensions: [".spl"],
  iconColor: "#65a637",
  defaultContent: SPL_DEFAULT_CONTENT,
  testable: true,
  convertibleTo: ["sigma_rule"],
  detect: (filename: string, content: string) => {
    // Extension-based detection
    if (filename.endsWith(".spl")) return true;
    // Content-based detection: pipe chains, index=, sourcetype=
    const lower = content.toLowerCase();
    return (
      (lower.includes("index=") && lower.includes("sourcetype=")) ||
      (lower.includes("| where") && lower.includes("| stats")) ||
      (lower.includes("| search") && lower.includes("|"))
    );
  },
});


function mapFieldToCIM(sigmaField: string): string {
  return translateField(sigmaField, "splunkCIM") ?? sigmaField;
}

/**
 * Map extracted fields from a seed to CIM equivalents.
 */
function mapPayloadToCIM(payload: Record<string, unknown>): Record<string, unknown> {
  const mapped: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload)) {
    const cimKey = mapFieldToCIM(key);
    mapped[cimKey] = value;
  }
  return mapped;
}


const splAdapter: DetectionWorkflowAdapter = {
  fileType: "splunk_spl",

  canDraftFrom(seed: DraftSeed): boolean {
    const relevantHints = ["process", "command", "file", "network", "registry"];
    return (
      seed.dataSourceHints.some((h) => relevantHints.includes(h)) ||
      seed.preferredFormats.includes("splunk_spl")
    );
  },

  buildDraft(seed: DraftSeed): DraftBuildResult {
    const source = buildSplFromSeed(seed, (sigmaField) =>
      translateField(sigmaField, "splunkCIM"),
    );
    const name = `Detection: ${seed.kind} ${seed.id.slice(0, 8)}`;

    return {
      source,
      fileType: "splunk_spl",
      name,
      techniqueHints: seed.techniqueHints,
    };
  },

  buildStarterEvidence(seed: DraftSeed, document: DetectionDocumentRef): EvidencePack {
    const datasets = createEmptyDatasets();

    for (const eventId of seed.sourceEventIds) {
      const eventData = seed.extractedFields[eventId] as Record<string, unknown> | undefined;
      const payload = eventData ? mapPayloadToCIM(eventData) : { eventId, source: seed.kind };
      const item: EvidenceItem = {
        id: crypto.randomUUID(),
        kind: "structured_event",
        format: "json",
        payload,
        expected: "match",
        sourceEventId: eventId,
      };
      datasets.positive.push(item);
    }

    // Add a negative baseline with CIM field names
    if (seed.sourceEventIds.length > 0) {
      const baselineItem: EvidenceItem = {
        id: crypto.randomUUID(),
        kind: "structured_event",
        format: "json",
        payload: { baseline: true, process: "benign.exe", ComputerName: "WORKSTATION01" },
        expected: "no_match",
      };
      datasets.negative.push(baselineItem);
    }

    return {
      id: crypto.randomUUID(),
      documentId: document.documentId,
      fileType: "splunk_spl",
      title: `SPL starter pack from ${seed.kind}`,
      createdAt: new Date().toISOString(),
      derivedFromSeedId: seed.id,
      datasets,
      redactionState: "clean",
    };
  },

  async runLab(request: DetectionExecutionRequest): Promise<DetectionExecutionResult> {
    const { document, evidencePack } = request;
    const source = request.adapterRunConfig?.["splSource"] as string | undefined;
    const startedAt = new Date().toISOString();

    if (!source) {
      const completedAt = new Date().toISOString();
      const run: LabRun = {
        id: crypto.randomUUID(),
        documentId: document.documentId,
        evidencePackId: evidencePack.id,
        fileType: "splunk_spl",
        startedAt,
        completedAt,
        summary: {
          totalCases: 0,
          passed: 0,
          failed: 0,
          matched: 0,
          missed: 0,
          falsePositives: 0,
          engine: "client",
        },
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
            title: "No SPL source provided in adapterRunConfig",
          },
        ],
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

    const conditions = parseSplFieldConditions(source);
    const commandChain = parseSplPipeChain(source).map((c) => c.command);

    const results: LabCaseResult[] = [];
    const traces: ExplainabilityTrace[] = [];

    for (const { item, dataset } of eventItems) {
      const caseId = item.id;
      const expectedMatch =
        item.kind === "structured_event" ? item.expected === "match" : item.expected === "valid";

      let didMatch = false;
      let matchDetails: Array<{ field: string; value: string; matched: boolean }> = [];

      if (item.kind === "structured_event" || item.kind === "ocsf_event") {
        const result = matchSplConditions(item.payload, conditions);
        didMatch = result.matched;
        matchDetails = result.matchedFields;
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

      const matchedFieldNames = matchDetails
        .filter((f) => f.matched)
        .map((f) => f.field);
      const unmatchedFieldNames = matchDetails
        .filter((f) => !f.matched)
        .map((f) => f.field);

      traces.push({
        id: traceId,
        kind: "plugin_trace",
        caseId,
        traceType: "spl_match",
        data: {
          matchedFields: matchDetails.filter((f) => f.matched),
          unmatchedFields: matchDetails.filter((f) => !f.matched),
          commandChain,
        },
        sourceLineHints: findSplSourceLineHints(source, [
          ...matchedFieldNames,
          ...unmatchedFieldNames,
        ]),
      });
    }

    const passed = results.filter((r) => r.status === "pass").length;
    const failed = results.filter((r) => r.status === "fail").length;
    const matched = results.filter((r) => r.actual === "match").length;
    const missed = results.filter(
      (r) => r.expected === "match" && r.actual === "no_match",
    ).length;
    const falsePositives = results.filter(
      (r) => r.expected === "no_match" && r.actual === "match",
    ).length;

    const completedAt = new Date().toISOString();
    const run: LabRun = {
      id: crypto.randomUUID(),
      documentId: document.documentId,
      evidencePackId: evidencePack.id,
      fileType: "splunk_spl",
      startedAt,
      completedAt,
      summary: {
        totalCases: results.length,
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
        title: `SPL lab: ${passed}/${results.length} passed (engine: client)`,
      },
    ];

    return { run, coverage: null, reportArtifacts };
  },

  buildExplainability(run: LabRun): ExplainabilityTrace[] {
    return run.explainability;
  },

  async buildPublication(request: PublicationRequest): Promise<PublicationBuildResult> {
    const target = request.targetFormat;

    if (target === "spl") {
      // Identity output: raw SPL source as-is
      const sourceHash = await sha256Hex(request.source);
      const outputHash = await sha256Hex(request.source);

      return {
        manifest: {
          documentId: request.document.documentId,
          sourceFileType: "splunk_spl",
          target: "spl",
          sourceHash,
          outputHash,
          validationSnapshot: {
            valid: true,
            diagnosticCount: 0,
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
            id: "splunk-spl-identity",
            version: "1.0.0",
          },
          signer: null,
          provenance: null,
        },
        outputContent: request.source,
        outputHash,
      };
    }

    if (target === "json_export") {
      // Wrap SPL in a structured JSON export
      const pipeChain = parseSplPipeChain(request.source);

      const techniqueHints: string[] = [];
      const lines = request.source.split(/\r?\n/);
      for (const line of lines) {
        const trimmed = line.trimStart();
        if (trimmed.startsWith("//") || trimmed.startsWith("#")) {
          const techMatch = trimmed.match(/techniques?:\s*(.+)/i);
          if (techMatch) {
            const techs = techMatch[1].split(",").map((t) => t.trim()).filter(Boolean);
            techniqueHints.push(...techs);
          }
        }
      }

      const exportObj = {
        _meta: {
          converter: "spl-to-json",
          converterVersion: "1.0.0",
          exportedAt: new Date().toISOString(),
        },
        rule: {
          commands: pipeChain.map((c) => ({
            command: c.command,
            args: c.args,
          })),
          source: request.source,
          techniqueHints,
        },
      };

      const outputContent = JSON.stringify(exportObj, null, 2);
      const sourceHash = await sha256Hex(request.source);
      const outputHash = await sha256Hex(outputContent);

      return {
        manifest: {
          documentId: request.document.documentId,
          sourceFileType: "splunk_spl",
          target: "json_export",
          sourceHash,
          outputHash,
          validationSnapshot: {
            valid: true,
            diagnosticCount: 0,
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
            id: "spl-to-json",
            version: "1.0.0",
          },
          signer: null,
          provenance: null,
        },
        outputContent,
        outputHash,
      };
    }

    throw new Error(`Unsupported SPL publish target "${target}"`);
  },
};


registerAdapter(splAdapter);

export { splAdapter };
