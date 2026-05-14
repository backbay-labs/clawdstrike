import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
// Import policy adapter to trigger auto-registration
import "../detection-workflow/policy-adapter";
import { getAdapter, hasAdapter, registerAdapter } from "../detection-workflow/adapters";
import type { DetectionWorkflowAdapter } from "../detection-workflow/adapters";
import type { LabRun } from "../detection-workflow/shared-types";
import type {
  DetectionExecutionRequest,
  DetectionExecutionResult,
} from "../detection-workflow/execution-types";
import type { FileType } from "../file-type-registry";

// ---- Mock adapters module to control registration ----

// We test the adapter lookup logic directly (not the React hook,
// since hooks require a React render context). The hook delegates
// to getAdapter/hasAdapter, so testing those exercises the core logic.

describe("Lab execution adapter lookup", () => {
  it("canExecute is true for registered adapters (policy)", () => {
    // The policy adapter auto-registers on import
    expect(hasAdapter("clawdstrike_policy")).toBe(true);
  });

  it("canExecute is false for unregistered formats", () => {
    expect(hasAdapter("sigma_rule")).toBe(false);
    expect(hasAdapter("yara_rule")).toBe(false);
    expect(hasAdapter("ocsf_event")).toBe(false);
  });

  it("getAdapter returns the adapter for registered types", () => {
    const adapter = getAdapter("clawdstrike_policy");
    expect(adapter).not.toBeNull();
    expect(adapter!.fileType).toBe("clawdstrike_policy");
  });

  it("getAdapter returns null for unregistered types", () => {
    expect(getAdapter("sigma_rule")).toBeNull();
    expect(getAdapter("yara_rule")).toBeNull();
  });
});

describe("Lab execution via adapter", () => {
  it("executeRun calls the adapter and produces a result", async () => {
    const adapter = getAdapter("clawdstrike_policy");
    expect(adapter).not.toBeNull();

    const policyYaml = `version: "1.5.0"
name: Test
guards:
  shell_command:
    enabled: true
settings: {}`;

    const request: DetectionExecutionRequest = {
      document: {
        documentId: "doc-test",
        fileType: "clawdstrike_policy",
        filePath: null,
        name: "Test Policy",
        sourceHash: "abc",
      },
      evidencePack: {
        id: "pack-1",
        documentId: "doc-test",
        fileType: "clawdstrike_policy",
        title: "Test Pack",
        createdAt: new Date().toISOString(),
        datasets: {
          positive: [
            {
              id: "case-1",
              kind: "policy_scenario",
              scenario: {
                id: "s1",
                name: "Shell test",
                description: "test",
                category: "attack",
                actionType: "shell_command",
                payload: { command: "rm -rf /" },
                expectedVerdict: "deny",
              },
              expected: "deny",
            },
          ],
          negative: [],
          regression: [],
          false_positive: [],
        },
        redactionState: "clean",
      },
      adapterRunConfig: { policySource: policyYaml },
    };

    const result = await adapter!.runLab(request);
    expect(result.run).toBeDefined();
    expect(result.run.documentId).toBe("doc-test");
    expect(result.run.fileType).toBe("clawdstrike_policy");
    expect(result.run.summary.totalCases).toBe(1);
    expect(result.reportArtifacts.length).toBeGreaterThan(0);
  });

  it("handles adapter errors gracefully — missing policy source", async () => {
    const adapter = getAdapter("clawdstrike_policy");
    expect(adapter).not.toBeNull();

    const request: DetectionExecutionRequest = {
      document: {
        documentId: "doc-err",
        fileType: "clawdstrike_policy",
        filePath: null,
        name: "Error Test",
        sourceHash: "abc",
      },
      evidencePack: {
        id: "pack-err",
        documentId: "doc-err",
        fileType: "clawdstrike_policy",
        title: "Error Pack",
        createdAt: new Date().toISOString(),
        datasets: {
          positive: [
            {
              id: "case-err",
              kind: "policy_scenario",
              scenario: {
                id: "s-err",
                name: "Shell test",
                description: "test",
                category: "attack",
                actionType: "shell_command",
                payload: { command: "rm -rf /" },
                expectedVerdict: "deny",
              },
              expected: "deny",
            },
          ],
          negative: [],
          regression: [],
          false_positive: [],
        },
        redactionState: "clean",
      },
      // No policySource — adapter should handle gracefully
      adapterRunConfig: {},
    };

    const result = await adapter!.runLab(request);
    // Should still return a result, but cases should fail due to missing source
    expect(result.run).toBeDefined();
    expect(result.run.summary.failed).toBe(1);
  });
});

describe("Mock adapter registration", () => {
  // Store reference to test cleanup
  let mockAdapter: DetectionWorkflowAdapter;

  beforeEach(() => {
    mockAdapter = {
      fileType: "sigma_rule" as FileType,
      canDraftFrom: () => true,
      buildDraft: () => ({
        source: "title: Test",
        fileType: "sigma_rule" as FileType,
        name: "Test Sigma",
        techniqueHints: [],
      }),
      buildStarterEvidence: () => ({
        id: "ep-1",
        documentId: "doc-1",
        fileType: "sigma_rule" as FileType,
        title: "Test",
        createdAt: new Date().toISOString(),
        datasets: { positive: [], negative: [], regression: [], false_positive: [] },
        redactionState: "clean" as const,
      }),
      runLab: async (req: DetectionExecutionRequest): Promise<DetectionExecutionResult> => ({
        run: {
          id: "run-mock",
          documentId: req.document.documentId,
          evidencePackId: req.evidencePack.id,
          fileType: "sigma_rule" as FileType,
          startedAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
          summary: {
            totalCases: 1,
            passed: 1,
            failed: 0,
            matched: 1,
            missed: 0,
            falsePositives: 0,
            engine: "client",
          },
          results: [],
          explainability: [],
        },
        coverage: null,
        reportArtifacts: [],
      }),
      buildExplainability: () => [],
      buildPublication: async () => ({
        manifest: {
          documentId: "doc-1",
          sourceFileType: "sigma_rule" as FileType,
          target: "json_export" as const,
          sourceHash: "abc",
          outputHash: "def",
          validationSnapshot: { valid: true, diagnosticCount: 0 },
          runSnapshot: null,
          coverageSnapshot: null,
          converter: { id: "test", version: "1.0.0" },
          signer: null,
          provenance: null,
        },
        outputContent: "{}",
        outputHash: "def",
      }),
    };

    registerAdapter(mockAdapter);
  });

  it("registered mock adapter is discoverable", () => {
    expect(hasAdapter("sigma_rule")).toBe(true);
    expect(getAdapter("sigma_rule")).not.toBeNull();
    expect(getAdapter("sigma_rule")!.fileType).toBe("sigma_rule");
  });

  it("mock adapter runLab produces expected result", async () => {
    const adapter = getAdapter("sigma_rule")!;
    const result = await adapter.runLab({
      document: {
        documentId: "doc-sigma",
        fileType: "sigma_rule",
        filePath: null,
        name: "Sigma Test",
        sourceHash: "abc",
      },
      evidencePack: {
        id: "pack-sigma",
        documentId: "doc-sigma",
        fileType: "sigma_rule",
        title: "Sigma Pack",
        createdAt: new Date().toISOString(),
        datasets: { positive: [], negative: [], regression: [], false_positive: [] },
        redactionState: "clean",
      },
    });

    expect(result.run.documentId).toBe("doc-sigma");
    expect(result.run.fileType).toBe("sigma_rule");
    expect(result.run.summary.passed).toBe(1);
    expect(result.run.summary.failed).toBe(0);
  });
});
