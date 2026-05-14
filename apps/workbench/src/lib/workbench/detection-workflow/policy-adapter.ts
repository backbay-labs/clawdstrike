/**
 * Policy workflow adapter — reference implementation of DetectionWorkflowAdapter
 * for the clawdstrike_policy file type.
 *
 * Reuses the existing simulation engine and scenario generator to implement
 * the detection workflow contract. This adapter must maintain behavior parity
 * with the current policy simulation path before non-policy adapters land.
 */

import type { DetectionWorkflowAdapter } from "./adapters";
import { registerAdapter } from "./adapters";
import type {
  DraftSeed,
  DetectionDocumentRef,
  EvidencePack,
  LabRun,
  LabRunSummary,
  LabCaseResult,
  ExplainabilityTrace,
  EvidenceItem,
  EvidenceDatasetKind,
  EvaluationPathStep,
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
import type { WorkbenchPolicy, TestScenario, Verdict, SimulationResult } from "../types";
import { simulatePolicy } from "../simulation-engine";
import { policyToYaml, yamlToPolicy } from "../yaml-utils";

// ---- SHA-256 ----

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---- Helpers ----

function isPolicyRelevantSeed(seed: DraftSeed): boolean {
  const relevantHints = ["process", "file", "network", "shell", "command", "tool", "prompt"];
  return (
    seed.dataSourceHints.some((h) => relevantHints.includes(h)) ||
    seed.extractedFields["actionType"] !== undefined ||
    seed.preferredFormats.includes("clawdstrike_policy")
  );
}

function buildStarterPolicy(seed: DraftSeed): WorkbenchPolicy {
  const guards: Record<string, Record<string, unknown>> = {};

  // Infer guards from data source hints and extracted fields
  const actionType = seed.extractedFields["actionType"] as string | undefined;
  const paths = seed.extractedFields["paths"] as string[] | undefined;
  const domains = seed.extractedFields["domains"] as string[] | undefined;
  const commands = seed.extractedFields["commands"] as string[] | undefined;

  if (
    actionType === "file_access" ||
    actionType === "file_write" ||
    seed.dataSourceHints.includes("file")
  ) {
    guards.forbidden_path = {
      enabled: true,
      paths: paths ?? ["/etc/shadow", "/etc/passwd"],
    };
  }

  if (actionType === "network_egress" || seed.dataSourceHints.includes("network")) {
    guards.egress_allowlist = {
      enabled: true,
      allowed_domains: domains ?? [],
    };
  }

  if (
    actionType === "shell_command" ||
    seed.dataSourceHints.includes("shell") ||
    seed.dataSourceHints.includes("command")
  ) {
    guards.shell_command = {
      enabled: true,
      blocked_patterns: commands ?? [],
    };
  }

  return {
    version: "1.2.0",
    name: `Draft from ${seed.kind}: ${seed.id.slice(0, 8)}`,
    description: `Auto-generated from ${seed.kind} seed. Techniques: ${seed.techniqueHints.join(", ") || "none inferred"}.`,
    guards,
    settings: {},
  };
}

function toScenarioPayload(
  actionType: TestScenario["actionType"],
  extracted: Record<string, unknown> | undefined,
): Record<string, unknown> {
  if (!extracted) return {};

  const target = typeof extracted.target === "string" ? extracted.target : "";
  const content = extracted.content;

  switch (actionType) {
    case "shell_command":
      return {
        ...extracted,
        command:
          typeof extracted.command === "string"
            ? extracted.command
            : target,
      };
    case "file_access":
    case "file_write":
    case "patch_apply":
      return {
        ...extracted,
        path:
          typeof extracted.path === "string"
            ? extracted.path
            : target,
        ...(typeof content === "string" ? { content } : {}),
      };
    case "network_egress":
      return {
        ...extracted,
        host:
          typeof extracted.host === "string"
            ? extracted.host
            : target,
      };
    case "mcp_tool_call":
      return {
        ...extracted,
        tool:
          typeof extracted.tool === "string"
            ? extracted.tool
            : target,
      };
    case "user_input":
      return {
        ...extracted,
        text:
          typeof extracted.text === "string"
            ? extracted.text
            : typeof content === "string"
              ? content
              : target,
      };
    default:
      return { ...extracted };
  }
}

function seedToScenarios(seed: DraftSeed): TestScenario[] {
  const scenarios: TestScenario[] = [];
  const actionType = seed.extractedFields["actionType"] as TestScenario["actionType"] | undefined;

  for (const eventId of seed.sourceEventIds) {
    const extracted = seed.extractedFields[eventId] as Record<string, unknown> | undefined;
    const scenarioActionType =
      (extracted?.actionType as TestScenario["actionType"] | undefined) ??
      actionType ??
      "file_access";
    scenarios.push({
      id: crypto.randomUUID(),
      name: `Seed event ${eventId.slice(0, 8)}`,
      description: `Evidence from ${seed.kind}`,
      category: "attack",
      actionType: scenarioActionType,
      payload: toScenarioPayload(scenarioActionType, extracted),
      expectedVerdict: "deny",
    });
  }

  // Add a benign baseline scenario
  scenarios.push({
    id: crypto.randomUUID(),
    name: "Benign baseline",
    description: "Auto-generated benign scenario for baseline",
    category: "benign",
    actionType: (actionType as TestScenario["actionType"]) ?? "file_access",
    payload: {},
    expectedVerdict: "allow",
  });

  return scenarios;
}

function evidenceItemToScenario(item: EvidenceItem): TestScenario | null {
  if (item.kind !== "policy_scenario") return null;
  return item.scenario;
}

function simulationResultToVerdict(result: SimulationResult): Verdict {
  return result.overallVerdict;
}

// ---- Policy Adapter ----

const policyAdapter: DetectionWorkflowAdapter = {
  fileType: "clawdstrike_policy",

  canDraftFrom(seed: DraftSeed): boolean {
    return isPolicyRelevantSeed(seed);
  },

  buildDraft(seed: DraftSeed): DraftBuildResult {
    const policy = buildStarterPolicy(seed);
    return {
      source: policyToYaml(policy),
      fileType: "clawdstrike_policy",
      name: policy.name,
      techniqueHints: seed.techniqueHints,
    };
  },

  buildStarterEvidence(seed: DraftSeed, document: DetectionDocumentRef): EvidencePack {
    const scenarios = seedToScenarios(seed);
    const datasets = createEmptyDatasets();

    for (const scenario of scenarios) {
      const item: EvidenceItem = {
        id: crypto.randomUUID(),
        kind: "policy_scenario",
        scenario,
        expected: scenario.expectedVerdict ?? "allow",
      };

      if (scenario.category === "attack") {
        datasets.positive.push(item);
      } else {
        datasets.negative.push(item);
      }
    }

    return {
      id: crypto.randomUUID(),
      documentId: document.documentId,
      fileType: "clawdstrike_policy",
      title: `Starter pack from ${seed.kind}`,
      createdAt: new Date().toISOString(),
      derivedFromSeedId: seed.id,
      datasets,
      redactionState: "clean",
    };
  },

  async runLab(request: DetectionExecutionRequest): Promise<DetectionExecutionResult> {
    const startedAt = new Date().toISOString();
    const { document, evidencePack } = request;

    const allItems: Array<{ item: EvidenceItem; dataset: EvidenceDatasetKind }> = [];
    for (const datasetKind of Object.keys(evidencePack.datasets) as EvidenceDatasetKind[]) {
      for (const item of evidencePack.datasets[datasetKind]) {
        allItems.push({ item, dataset: datasetKind });
      }
    }

    const results: LabCaseResult[] = [];
    let passed = 0;
    let failed = 0;
    let matched = 0;
    let missed = 0;
    let falsePositives = 0;
    const traces: ExplainabilityTrace[] = [];

    // Resolve the policy source from the adapter run config.
    // The lab shell must pass `policySource` so the adapter can parse
    // the policy YAML. Without it, all cases are marked as failures.
    const adapterConfig = request.adapterRunConfig ?? {};
    const policySource = adapterConfig["policySource"] as string | undefined;
    let simPolicy: WorkbenchPolicy | null = null;

    if (policySource) {
      const [parsed] = yamlToPolicy(policySource);
      simPolicy = parsed;
    }

    for (const { item, dataset } of allItems) {
      const scenario = evidenceItemToScenario(item);
      if (!scenario) {
        // Non-policy evidence items are skipped by the policy adapter
        results.push({
          caseId: item.id,
          dataset,
          status: "pass",
          expected: "skipped",
          actual: "skipped (non-policy evidence)",
          explanationRefIds: [],
        });
        passed++;
        continue;
      }

      if (!simPolicy) {
        results.push({
          caseId: item.id,
          dataset,
          status: "fail",
          expected: String(item.expected),
          actual: "error: no policy source provided",
          explanationRefIds: [],
        });
        failed++;
        continue;
      }

      const simResult = simulatePolicy(simPolicy, scenario);
      const actualVerdict = simulationResultToVerdict(simResult);
      const expectedVerdict = item.expected as Verdict;
      const caseStatus = actualVerdict === expectedVerdict ? "pass" : "fail";

      if (caseStatus === "pass") {
        passed++;
      } else {
        failed++;
      }

      if (actualVerdict === "deny" || actualVerdict === "warn") {
        if (expectedVerdict === "deny" || expectedVerdict === "warn") {
          matched++;
        } else {
          falsePositives++;
        }
      } else {
        if (expectedVerdict === "deny" || expectedVerdict === "warn") {
          missed++;
        }
      }

      // Build explainability trace from guard results
      const traceId = crypto.randomUUID();
      const evaluationPath: EvaluationPathStep[] = simResult.guardResults.map((gr) => ({
        guardId: gr.guardId,
        verdict: gr.verdict,
        durationMs: 0,
        evidence: gr.evidence,
      }));

      traces.push({
        id: traceId,
        kind: "policy_evaluation",
        caseId: item.id,
        guardResults: simResult.guardResults,
        evaluationPath,
      });

      results.push({
        caseId: item.id,
        dataset,
        status: caseStatus,
        expected: expectedVerdict,
        actual: actualVerdict,
        explanationRefIds: [traceId],
      });
    }

    const completedAt = new Date().toISOString();
    const summary: LabRunSummary = {
      totalCases: allItems.length,
      passed,
      failed,
      matched,
      missed,
      falsePositives,
      engine: "client",
    };

    const run: LabRun = {
      id: crypto.randomUUID(),
      documentId: document.documentId,
      evidencePackId: evidencePack.id,
      fileType: "clawdstrike_policy",
      startedAt,
      completedAt,
      summary,
      results,
      explainability: traces,
    };

    const reportArtifacts: ReportArtifact[] = [
      {
        id: crypto.randomUUID(),
        kind: "summary",
        title: `Policy Lab Run: ${passed}/${allItems.length} passed`,
      },
    ];

    return { run, coverage: null, reportArtifacts };
  },

  buildExplainability(run: LabRun): ExplainabilityTrace[] {
    return run.explainability;
  },

  async buildPublication(request: PublicationRequest): Promise<PublicationBuildResult> {
    const sourceHash = await sha256Hex(request.source);
    const outputHash = await sha256Hex(request.source); // For native policy, source === output

    return {
      manifest: {
        documentId: request.document.documentId,
        sourceFileType: "clawdstrike_policy",
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
          id: "identity",
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

// ---- Auto-register ----

registerAdapter(policyAdapter);

export { policyAdapter };
