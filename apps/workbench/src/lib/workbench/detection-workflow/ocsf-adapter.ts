/**
 * OCSF workflow adapter — implements DetectionWorkflowAdapter for ocsf_event.
 *
 * Generates OCSF JSON event stubs from DraftSeeds, mapping data source hints
 * to OCSF class UIDs. Provides stub implementations for lab execution and
 * publication.
 */

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
import { normalizeOcsfEventNative } from "@/lib/tauri-commands";

// ---- SHA-256 ----

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---- OCSF Class UID Mapping ----

/**
 * OCSF class UID mapping:
 * - 1001: File Activity
 * - 1007: Process Activity
 * - 2004: Detection Finding
 * - 4001: Network Activity
 * - 4003: DNS Activity
 * - 6003: API Activity
 */
function inferClassUid(seed: DraftSeed): number {
  const hints = seed.dataSourceHints;

  if (hints.includes("process") || hints.includes("command")) {
    return 1007; // Process Activity
  }
  if (hints.includes("network")) {
    return 4001; // Network Activity
  }
  if (hints.includes("file")) {
    return 1001; // File Activity
  }
  if (hints.includes("tool") || hints.includes("prompt")) {
    return 6003; // API Activity
  }

  // Default: Detection Finding — good for investigations and patterns
  return 2004;
}

function inferCategoryUid(classUid: number): number {
  if (classUid === 1001 || classUid === 1007) return 1; // System Activity
  if (classUid === 2004) return 2; // Findings
  if (classUid === 4001 || classUid === 4003) return 4; // Network Activity
  if (classUid === 6003) return 6; // Application Activity
  return 2; // Default to Findings
}

function inferActivityId(seed: DraftSeed): number {
  const actionType = seed.extractedFields["actionType"] as string | undefined;
  if (actionType === "file_write" || actionType === "patch_apply") return 2; // Update
  if (actionType === "file_access") return 1; // Read
  if (actionType === "network_egress") return 4; // Traffic
  return 1; // Default: Create / General
}

function inferSeverityId(seed: DraftSeed): number {
  if (seed.confidence >= 0.9) return 4; // High
  if (seed.confidence >= 0.7) return 3; // Medium
  if (seed.confidence >= 0.5) return 2; // Low
  return 1; // Informational
}

function buildOcsfMetadata(): Record<string, unknown> {
  return {
    version: "1.4.0",
    product: {
      name: "ClawdStrike Detection Lab",
      uid: "clawdstrike-detection-lab",
      vendor_name: "Backbay Labs",
    },
  };
}

function buildFindingInfo(uid: string, title: string, techniqueHints: string[]): Record<string, unknown> {
  return {
    uid,
    title,
    analytic: {
      name: "ClawdStrike Detection Lab",
      type_id: 1,
      type: "Rule",
    },
    ...(techniqueHints.length > 0 ? { types: techniqueHints } : {}),
  };
}

function buildBaseOcsfEvent(
  classUid: number,
  activityId: number,
  severityId: number,
  message: string,
): Record<string, unknown> {
  return {
    class_uid: classUid,
    category_uid: inferCategoryUid(classUid),
    type_uid: classUid * 100 + activityId,
    activity_id: activityId,
    severity_id: severityId,
    status_id: 1,
    time: Date.now(),
    message,
    metadata: buildOcsfMetadata(),
  };
}

function asRecord(candidate: unknown): Record<string, unknown> | null {
  return candidate && typeof candidate === "object" && !Array.isArray(candidate)
    ? candidate as Record<string, unknown>
    : null;
}

function validateOcsfPayloadFallback(payload: Record<string, unknown>): {
  valid: boolean;
  classUid: number | null;
  missingFields: string[];
  invalidFields: string[];
} {
  const missingFields: string[] = [];
  const invalidFields: string[] = [];

  const readUnsignedInteger = (field: string): number | null => {
    const current = payload[field];
    if (current === undefined || current === null) {
      missingFields.push(field);
      return null;
    }
    if (typeof current !== "number" || !Number.isInteger(current) || current < 0) {
      invalidFields.push(`${field}: expected unsigned integer`);
      return null;
    }
    return current;
  };

  const readInteger = (field: string): number | null => {
    const current = payload[field];
    if (current === undefined || current === null) {
      missingFields.push(field);
      return null;
    }
    if (typeof current !== "number" || !Number.isInteger(current)) {
      invalidFields.push(`${field}: expected integer`);
      return null;
    }
    return current;
  };

  const classUid = readUnsignedInteger("class_uid");
  const activityId = readUnsignedInteger("activity_id");
  const typeUid = readUnsignedInteger("type_uid");
  const severityId = readUnsignedInteger("severity_id");
  readUnsignedInteger("status_id");
  readInteger("time");
  readUnsignedInteger("category_uid");

  const metadata = asRecord(payload.metadata);
  if (!metadata) {
    missingFields.push("metadata");
  } else {
    if (typeof metadata.version !== "string" || metadata.version.trim() === "") {
      missingFields.push("metadata.version");
    }

    const product = asRecord(metadata.product);
    if (!product) {
      missingFields.push("metadata.product");
    } else {
      if (typeof product.name !== "string" || product.name.trim() === "") {
        missingFields.push("metadata.product.name");
      }
      if (typeof product.vendor_name !== "string" || product.vendor_name.trim() === "") {
        missingFields.push("metadata.product.vendor_name");
      }
    }
  }

  if (classUid !== null && activityId !== null && typeUid !== null && typeUid !== classUid * 100 + activityId) {
    invalidFields.push(`type_uid: expected ${classUid * 100 + activityId}, got ${typeUid}`);
  }

  if (severityId !== null && severityId > 6 && severityId !== 99) {
    invalidFields.push(`severity_id: value ${severityId} is not a valid OCSF severity (0-6, 99)`);
  }

  if (classUid === 2004) {
    const findingInfo = asRecord(payload.finding_info);
    if (!findingInfo) {
      missingFields.push("finding_info");
    } else {
      if (typeof findingInfo.uid !== "string" || findingInfo.uid.trim() === "") {
        missingFields.push("finding_info.uid");
      }
      if (typeof findingInfo.title !== "string" || findingInfo.title.trim() === "") {
        missingFields.push("finding_info.title");
      }
      if (findingInfo.analytic === undefined || findingInfo.analytic === null) {
        missingFields.push("finding_info.analytic");
      }
    }

    readUnsignedInteger("action_id");
    readUnsignedInteger("disposition_id");
  }

  return {
    valid: missingFields.length === 0 && invalidFields.length === 0,
    classUid,
    missingFields,
    invalidFields,
  };
}

// ---- OCSF Event Builder ----

function buildOcsfEvent(seed: DraftSeed): Record<string, unknown> {
  const classUid = inferClassUid(seed);
  const activityId = inferActivityId(seed);
  const severityId = inferSeverityId(seed);
  const event: Record<string, unknown> = buildBaseOcsfEvent(
    classUid,
    activityId,
    severityId,
    `Detection from ${seed.kind}: ${seed.id.slice(0, 8)}`,
  );

  // Populate format-specific fields based on class
  if (classUid === 1001) {
    // File Activity
    const paths = seed.extractedFields["paths"] as string[] | undefined;
    event["file"] = {
      name: paths?.[0] ?? "",
      path: paths?.[0] ?? "",
    };
  } else if (classUid === 1007) {
    // Process Activity
    const commands = seed.extractedFields["commands"] as string[] | undefined;
    event["process"] = {
      cmd_line: commands?.[0] ?? "",
      name: "",
    };
  } else if (classUid === 4001) {
    // Network Activity
    const domains = seed.extractedFields["domains"] as string[] | undefined;
    event["dst_endpoint"] = {
      hostname: domains?.[0] ?? "",
    };
  } else if (classUid === 2004) {
    // Detection Finding
    event["action_id"] = 2;
    event["disposition_id"] = 2;
    event["finding_info"] = buildFindingInfo(seed.id, `Finding from ${seed.kind}`, seed.techniqueHints);
  }

  // Add technique hints as enrichments
  if (seed.techniqueHints.length > 0) {
    event["enrichments"] = seed.techniqueHints.map((t) => ({
      name: "mitre_attack",
      value: t,
    }));
  }

  return event;
}

// ---- OCSF Adapter ----

const ocsfAdapter: DetectionWorkflowAdapter = {
  fileType: "ocsf_event",

  canDraftFrom(seed: DraftSeed): boolean {
    // True for event normalization or finding data, or when OCSF is preferred
    return (
      seed.preferredFormats.includes("ocsf_event") ||
      seed.kind === "investigation" ||
      seed.dataSourceHints.includes("tool") ||
      seed.dataSourceHints.includes("prompt") ||
      seed.dataSourceHints.length > 0
    );
  },

  buildDraft(seed: DraftSeed): DraftBuildResult {
    const event = buildOcsfEvent(seed);
    const source = JSON.stringify(event, null, 2) + "\n";
    const name = `OCSF ${seed.kind} ${seed.id.slice(0, 8)}`;

    return {
      source,
      fileType: "ocsf_event",
      name,
      techniqueHints: seed.techniqueHints,
    };
  },

  buildStarterEvidence(seed: DraftSeed, document: DetectionDocumentRef): EvidencePack {
    const datasets = createEmptyDatasets();

    // Build ocsf_event items from source events
    for (const eventId of seed.sourceEventIds) {
      const eventData = seed.extractedFields[eventId] as Record<string, unknown> | undefined;
      const classUid = inferClassUid(seed);

      const ocsfPayload: Record<string, unknown> = {
        ...buildBaseOcsfEvent(
          classUid,
          1,
          inferSeverityId(seed),
          `Event ${eventId}`,
        ),
        ...spreadEventData(eventData),
      };

      if (classUid === 2004) {
        ocsfPayload["action_id"] = 2;
        ocsfPayload["disposition_id"] = 2;
        ocsfPayload["finding_info"] = buildFindingInfo(
          eventId,
          `Finding from ${seed.kind}`,
          seed.techniqueHints,
        );
      }

      const item: EvidenceItem = {
        id: crypto.randomUUID(),
        kind: "ocsf_event",
        payload: ocsfPayload,
        expected: "valid",
        sourceEventId: eventId,
      };
      datasets.positive.push(item);
    }

    // Add an invalid baseline for negative testing
    if (seed.sourceEventIds.length > 0) {
      const invalidItem: EvidenceItem = {
        id: crypto.randomUUID(),
        kind: "ocsf_event",
        payload: {
          class_uid: 0,
          category_uid: 0,
          activity_id: 0,
          severity_id: 0,
          status_id: 0,
          time: 0,
          message: "Invalid baseline event",
        },
        expected: "invalid",
      };
      datasets.negative.push(invalidItem);
    }

    return {
      id: crypto.randomUUID(),
      documentId: document.documentId,
      fileType: "ocsf_event",
      title: `OCSF starter pack from ${seed.kind}`,
      createdAt: new Date().toISOString(),
      derivedFromSeedId: seed.id,
      datasets,
      redactionState: "clean",
    };
  },

  async runLab(request: DetectionExecutionRequest): Promise<DetectionExecutionResult> {
    const { document, evidencePack } = request;
    const startedAt = new Date().toISOString();

    // Collect all evidence items across datasets
    const allItems: Array<{ item: EvidenceItem; dataset: EvidenceDatasetKind }> = [];
    for (const [datasetKind, items] of Object.entries(evidencePack.datasets)) {
      for (const item of items) {
        allItems.push({ item, dataset: datasetKind as EvidenceDatasetKind });
      }
    }

    const results: LabCaseResult[] = [];
    const traces: ExplainabilityTrace[] = [];
    let usedNative = false;

    for (const { item, dataset } of allItems) {
      if (item.kind !== "ocsf_event") continue;

      const caseId = item.id;
      const expectedValid = item.expected === "valid";
      const payload = item.payload;

      // Try native normalization first
      const nativeResult = await normalizeOcsfEventNative(JSON.stringify(payload));

      let isValid: boolean;
      let classUid: number | null = null;
      let missingFields: string[] = [];
      let invalidFields: string[] = [];

      if (nativeResult) {
        usedNative = true;
        isValid = nativeResult.valid;
        classUid = nativeResult.class_uid;
        missingFields = nativeResult.missing_fields;
        invalidFields = nativeResult.invalid_fields.map((f) => `${f.field}: ${f.error}`);
      } else {
        const fallback = validateOcsfPayloadFallback(payload);
        isValid = fallback.valid;
        classUid = fallback.classUid;
        missingFields = fallback.missingFields;
        invalidFields = fallback.invalidFields;
      }

      const passed = expectedValid === isValid;
      const traceId = crypto.randomUUID();

      results.push({
        caseId,
        dataset,
        status: passed ? "pass" : "fail",
        expected: expectedValid ? "valid" : "invalid",
        actual: isValid ? "valid" : "invalid",
        explanationRefIds: [traceId],
      });

      traces.push({
        id: traceId,
        kind: "ocsf_validation",
        caseId,
        classUid,
        missingFields,
        invalidFields,
        sourceLineHints: [],
      });
    }

    const passedCount = results.filter((r) => r.status === "pass").length;
    const failedCount = results.filter((r) => r.status === "fail").length;
    const engine: "native" | "client" = usedNative ? "native" : "client";

    const completedAt = new Date().toISOString();
    const run: LabRun = {
      id: crypto.randomUUID(),
      documentId: document.documentId,
      evidencePackId: evidencePack.id,
      fileType: "ocsf_event",
      startedAt,
      completedAt,
      summary: {
        totalCases: results.length,
        passed: passedCount,
        failed: failedCount,
        matched: results.filter((r) => r.actual === "valid").length,
        missed: 0,
        falsePositives: 0,
        engine,
      },
      results,
      explainability: traces,
    };

    const reportArtifacts: ReportArtifact[] = [
      {
        id: crypto.randomUUID(),
        kind: "summary",
        title: `OCSF lab: ${passedCount}/${results.length} passed (engine: ${engine})`,
        data: { engine },
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
        sourceFileType: "ocsf_event",
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
        coverageSnapshot: null,
        converter: {
          id: "ocsf-identity",
          version: "1.0.0",
        },
        signer: null,
        provenance: null,
      },
      outputContent: request.source,
      outputHash,
    };
  },
};

// ---- Helpers ----

/** Spread event data into OCSF-compatible fields. */
function spreadEventData(
  eventData: Record<string, unknown> | undefined,
): Record<string, unknown> {
  if (!eventData) return {};

  const result: Record<string, unknown> = {};
  const actionType = eventData["actionType"] as string | undefined;
  const target = eventData["target"] as string | undefined;

  if (actionType === "shell_command" && target) {
    result["process"] = { cmd_line: target };
  } else if (
    (actionType === "file_access" || actionType === "file_write") &&
    target
  ) {
    result["file"] = { path: target, name: target.split("/").pop() ?? target };
  } else if (actionType === "network_egress" && target) {
    result["dst_endpoint"] = { hostname: target };
  }

  return result;
}

// ---- Auto-register ----

registerAdapter(ocsfAdapter);

export { ocsfAdapter };
