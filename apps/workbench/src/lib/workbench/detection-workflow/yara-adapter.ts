/**
 * YARA workflow adapter — implements DetectionWorkflowAdapter for yara_rule.
 *
 * Generates YARA rule stubs from DraftSeeds that contain binary or artifact
 * evidence. Provides stub implementations for lab execution (requires the
 * yara-x backend) and publication.
 */

import type { DetectionWorkflowAdapter } from "./adapters";
import { registerAdapter } from "./adapters";
import type {
  DraftSeed,
  DetectionDocumentRef,
  EvidencePack,
  EvidenceItem,
  LabRun,
  ExplainabilityTrace,
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

// ---- SHA-256 ----

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---- Rule Name Sanitization ----

function sanitizeRuleName(id: string): string {
  // YARA rule names: alphanumeric + underscore, must start with letter or _
  return (
    "rule_" +
    id
      .replace(/[^a-zA-Z0-9_]/g, "_")
      .replace(/_+/g, "_")
      .slice(0, 48)
  );
}

// ---- String Pattern Extraction ----

interface YaraString {
  name: string;
  value: string;
  isHex: boolean;
}

function extractStrings(seed: DraftSeed): YaraString[] {
  const strings: YaraString[] = [];
  let idx = 1;

  const targets = seed.extractedFields["targets"] as string[] | undefined;
  const commands = seed.extractedFields["commands"] as string[] | undefined;
  const paths = seed.extractedFields["paths"] as string[] | undefined;

  // Extract string patterns from commands/targets
  const candidates = [
    ...(commands ?? []),
    ...(paths ?? []),
    ...(targets ?? []),
  ];

  const seen = new Set<string>();
  for (const candidate of candidates) {
    if (!candidate || seen.has(candidate) || candidate.length < 3) continue;
    seen.add(candidate);

    // Check if it looks like hex
    if (/^[0-9a-fA-F\s]+$/.test(candidate) && candidate.length >= 4) {
      strings.push({
        name: `$h${idx}`,
        value: candidate.replace(/\s+/g, " ").trim(),
        isHex: true,
      });
    } else {
      strings.push({
        name: `$s${idx}`,
        value: candidate,
        isHex: false,
      });
    }
    idx++;

    // Limit to 10 strings
    if (idx > 10) break;
  }

  // If no strings were extracted, add a placeholder
  if (strings.length === 0) {
    strings.push({ name: "$s1", value: "pattern", isHex: false });
  }

  return strings;
}

// ---- Meta Builder ----

function buildMeta(seed: DraftSeed): string {
  const lines: string[] = [];
  const today = new Date().toISOString().slice(0, 10);

  lines.push(`        author = "Detection Lab"`);
  lines.push(
    `        description = "Auto-generated YARA rule from ${seed.kind} seed"`,
  );
  lines.push(`        date = "${today}"`);

  if (seed.techniqueHints.length > 0) {
    lines.push(
      `        technique = "${seed.techniqueHints.join(", ")}"`,
    );
  }

  return lines.join("\n");
}

// ---- YARA Adapter ----

const yaraAdapter: DetectionWorkflowAdapter = {
  fileType: "yara_rule",

  canDraftFrom(seed: DraftSeed): boolean {
    // True ONLY when byte or artifact evidence exists
    const hints = seed.dataSourceHints;
    return (
      hints.includes("binary") ||
      hints.includes("artifact") ||
      (hints.includes("file") && hasByteContent(seed))
    );
  },

  buildDraft(seed: DraftSeed): DraftBuildResult {
    const ruleName = sanitizeRuleName(seed.id);
    const meta = buildMeta(seed);
    const strings = extractStrings(seed);

    // Build strings section
    const stringsSection = strings
      .map((s) => {
        if (s.isHex) {
          return `        ${s.name} = { ${s.value} }`;
        }
        // Escape quotes in string values
        const escaped = s.value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
        return `        ${s.name} = "${escaped}"`;
      })
      .join("\n");

    const source = `rule ${ruleName} {
    meta:
${meta}

    strings:
${stringsSection}

    condition:
        any of them
}
`;

    return {
      source,
      fileType: "yara_rule",
      name: ruleName,
      techniqueHints: seed.techniqueHints,
    };
  },

  buildStarterEvidence(seed: DraftSeed, document: DetectionDocumentRef): EvidencePack {
    const datasets = createEmptyDatasets();

    // Check if we have byte content in extracted fields
    const hasByteSources = seed.dataSourceHints.includes("binary") ||
      seed.dataSourceHints.includes("artifact");

    if (hasByteSources) {
      // Create bytes items from source events
      for (const eventId of seed.sourceEventIds) {
        const eventData = seed.extractedFields[eventId] as Record<string, unknown> | undefined;
        const content = eventData?.["content"] as string | undefined;

        if (content) {
          const item: EvidenceItem = {
            id: crypto.randomUUID(),
            kind: "bytes",
            encoding: "utf8",
            payload: content,
            expected: "match",
            sourceArtifactPath: eventData?.["target"] as string | undefined,
          };
          datasets.positive.push(item);
        }
      }
    }

    // If no byte items were created, fall back to structured events
    if (datasets.positive.length === 0) {
      for (const eventId of seed.sourceEventIds) {
        const eventData = seed.extractedFields[eventId] as Record<string, unknown> | undefined;
        const item: EvidenceItem = {
          id: crypto.randomUUID(),
          kind: "structured_event",
          format: "json",
          payload: eventData ?? { eventId, source: seed.kind },
          expected: "match",
          sourceEventId: eventId,
        };
        datasets.positive.push(item);
      }
    }

    return {
      id: crypto.randomUUID(),
      documentId: document.documentId,
      fileType: "yara_rule",
      title: `YARA starter pack from ${seed.kind}`,
      createdAt: new Date().toISOString(),
      derivedFromSeedId: seed.id,
      datasets,
      redactionState: "clean",
    };
  },

  async runLab(request: DetectionExecutionRequest): Promise<DetectionExecutionResult> {
    // Stub — YARA execution requires yara-x backend
    const startedAt = new Date().toISOString();
    const completedAt = new Date().toISOString();

    const run: LabRun = {
      id: crypto.randomUUID(),
      documentId: request.document.documentId,
      evidencePackId: request.evidencePack.id,
      fileType: "yara_rule",
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

    const reportArtifacts: ReportArtifact[] = [
      {
        id: crypto.randomUUID(),
        kind: "summary",
        title: "YARA lab execution requires yara-x backend (not implemented in browser)",
      },
    ];

    return { run, coverage: null, reportArtifacts };
  },

  buildExplainability(run: LabRun): ExplainabilityTrace[] {
    return run.explainability;
  },

  async buildPublication(request: PublicationRequest): Promise<PublicationBuildResult> {
    const sourceHash = await sha256Hex(request.source);
    const outputHash = await sha256Hex(request.source);

    return {
      manifest: {
        documentId: request.document.documentId,
        sourceFileType: "yara_rule",
        target: request.targetFormat,
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
        converter: {
          id: "yara-identity",
          version: "1.0.0",
        },
        signer: null,
      },
      outputContent: request.source,
      outputHash,
    };
  },
};

// ---- Helper ----

function hasByteContent(seed: DraftSeed): boolean {
  for (const eventId of seed.sourceEventIds) {
    const eventData = seed.extractedFields[eventId] as Record<string, unknown> | undefined;
    if (eventData?.["content"] && typeof eventData["content"] === "string") {
      const content = eventData["content"] as string;
      // Check for binary-looking content
      if (/^[0-9a-fA-F\s]+$/.test(content.slice(0, 200))) return true;
      // eslint-disable-next-line no-control-regex
      if (/[\x00-\x08\x0e-\x1f]/.test(content.slice(0, 200))) return true;
    }
  }
  return false;
}

// ---- Auto-register ----

registerAdapter(yaraAdapter);

export { yaraAdapter };
