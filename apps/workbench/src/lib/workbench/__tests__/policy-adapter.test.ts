import { describe, it, expect } from "vitest";
import { policyAdapter } from "../detection-workflow/policy-adapter";
import type { DraftSeed, DetectionDocumentRef, EvidencePack } from "../detection-workflow/shared-types";
import { createEmptyDatasets } from "../detection-workflow/shared-types";
import type { DetectionExecutionRequest } from "../detection-workflow/execution-types";

function makeSeed(overrides: Partial<DraftSeed> = {}): DraftSeed {
  return {
    id: crypto.randomUUID(),
    kind: "hunt_event",
    sourceEventIds: ["evt-1", "evt-2"],
    preferredFormats: ["clawdstrike_policy"],
    techniqueHints: ["T1059"],
    dataSourceHints: ["shell"],
    extractedFields: {
      actionType: "shell_command",
    },
    createdAt: new Date().toISOString(),
    confidence: 0.8,
    ...overrides,
  };
}

function makeDocRef(overrides: Partial<DetectionDocumentRef> = {}): DetectionDocumentRef {
  return {
    documentId: "doc-test",
    fileType: "clawdstrike_policy",
    filePath: null,
    name: "Test Policy",
    sourceHash: "abc123",
    ...overrides,
  };
}

describe("policyAdapter", () => {
  it("has correct fileType", () => {
    expect(policyAdapter.fileType).toBe("clawdstrike_policy");
  });

  describe("canDraftFrom", () => {
    it("returns true for shell-related seeds", () => {
      expect(policyAdapter.canDraftFrom(makeSeed({ dataSourceHints: ["shell"] }))).toBe(true);
    });

    it("returns true for file-related seeds", () => {
      expect(policyAdapter.canDraftFrom(makeSeed({ dataSourceHints: ["file"] }))).toBe(true);
    });

    it("returns true for network-related seeds", () => {
      expect(policyAdapter.canDraftFrom(makeSeed({ dataSourceHints: ["network"] }))).toBe(true);
    });

    it("returns true when preferredFormats includes policy", () => {
      expect(
        policyAdapter.canDraftFrom(
          makeSeed({
            dataSourceHints: [],
            preferredFormats: ["clawdstrike_policy"],
            extractedFields: {},
          }),
        ),
      ).toBe(true);
    });

    it("returns false for seeds with no relevant indicators", () => {
      expect(
        policyAdapter.canDraftFrom(
          makeSeed({
            dataSourceHints: ["binary_artifact"],
            preferredFormats: ["yara_rule"],
            extractedFields: {},
          }),
        ),
      ).toBe(false);
    });
  });

  describe("buildDraft", () => {
    it("produces valid policy YAML for shell seed", () => {
      const seed = makeSeed({ dataSourceHints: ["shell"], extractedFields: { actionType: "shell_command" } });
      const result = policyAdapter.buildDraft(seed);
      expect(result.fileType).toBe("clawdstrike_policy");
      expect(result.source).toContain("version:");
      expect(result.source).toContain("name:");
      expect(result.techniqueHints).toEqual(["T1059"]);
    });

    it("produces YAML with shell_command guard for shell seeds", () => {
      const seed = makeSeed({
        dataSourceHints: ["shell"],
        extractedFields: { actionType: "shell_command" },
      });
      const result = policyAdapter.buildDraft(seed);
      expect(result.source).toContain("shell_command");
    });

    it("produces YAML with forbidden_path guard for file seeds", () => {
      const seed = makeSeed({
        dataSourceHints: ["file"],
        extractedFields: { actionType: "file_access" },
      });
      const result = policyAdapter.buildDraft(seed);
      expect(result.source).toContain("forbidden_path");
    });
  });

  describe("buildStarterEvidence", () => {
    it("creates an evidence pack with datasets", () => {
      const seed = makeSeed();
      const doc = makeDocRef();
      const pack = policyAdapter.buildStarterEvidence(seed, doc);

      expect(pack.documentId).toBe("doc-test");
      expect(pack.fileType).toBe("clawdstrike_policy");
      expect(pack.derivedFromSeedId).toBe(seed.id);
      expect(pack.datasets.positive.length).toBeGreaterThan(0);
      expect(pack.datasets.negative.length).toBeGreaterThan(0);
    });

    it("includes scenarios derived from source events", () => {
      const seed = makeSeed({
        sourceEventIds: ["e1", "e2", "e3"],
        extractedFields: {
          actionType: "shell_command",
          e1: { actionType: "shell_command", target: "whoami" },
          e2: { actionType: "file_access", target: "/etc/shadow" },
          e3: { actionType: "network_egress", target: "evil.example" },
        },
      });
      const doc = makeDocRef();
      const pack = policyAdapter.buildStarterEvidence(seed, doc);

      // One per source event in positive, plus one benign baseline in negative
      expect(pack.datasets.positive).toHaveLength(3);
      expect(pack.datasets.negative).toHaveLength(1);

      const [shellCase, fileCase, networkCase] = pack.datasets.positive;
      if (shellCase?.kind === "policy_scenario") {
        expect(shellCase.scenario.actionType).toBe("shell_command");
        expect(shellCase.scenario.payload.command).toBe("whoami");
      }
      if (fileCase?.kind === "policy_scenario") {
        expect(fileCase.scenario.actionType).toBe("file_access");
        expect(fileCase.scenario.payload.path).toBe("/etc/shadow");
      }
      if (networkCase?.kind === "policy_scenario") {
        expect(networkCase.scenario.actionType).toBe("network_egress");
        expect(networkCase.scenario.payload.host).toBe("evil.example");
      }
    });
  });

  describe("runLab", () => {
    it("runs policy scenarios against the policy from adapterRunConfig", async () => {
      const policyYaml = `version: "1.5.0"
name: Test
guards:
  shell_command:
    enabled: true
settings: {}`;

      const doc = makeDocRef();
      const pack: EvidencePack = {
        id: "pack-1",
        documentId: "doc-test",
        fileType: "clawdstrike_policy",
        title: "Test Pack",
        createdAt: new Date().toISOString(),
        datasets: {
          ...createEmptyDatasets(),
          positive: [
            {
              id: "case-1",
              kind: "policy_scenario",
              scenario: {
                id: "s1",
                name: "Dangerous shell",
                description: "rm -rf test",
                category: "attack",
                actionType: "shell_command",
                payload: { command: "rm -rf /" },
                expectedVerdict: "deny",
              },
              expected: "deny",
            },
          ],
          negative: [
            {
              id: "case-2",
              kind: "policy_scenario",
              scenario: {
                id: "s2",
                name: "Safe echo",
                description: "echo hello",
                category: "benign",
                actionType: "shell_command",
                payload: { command: "echo hello" },
                expectedVerdict: "allow",
              },
              expected: "allow",
            },
          ],
        },
        redactionState: "clean",
      };

      const request: DetectionExecutionRequest = {
        document: doc,
        evidencePack: pack,
        adapterRunConfig: { policySource: policyYaml },
      };

      const result = await policyAdapter.runLab(request);
      expect(result.run.documentId).toBe("doc-test");
      expect(result.run.summary.totalCases).toBe(2);
      expect(result.run.results).toHaveLength(2);
      expect(result.reportArtifacts.length).toBeGreaterThan(0);
    });

    it("skips non-policy evidence items", async () => {
      const doc = makeDocRef();
      const pack: EvidencePack = {
        id: "pack-2",
        documentId: "doc-test",
        fileType: "clawdstrike_policy",
        title: "Mixed Pack",
        createdAt: new Date().toISOString(),
        datasets: {
          ...createEmptyDatasets(),
          positive: [
            {
              id: "case-sigma",
              kind: "structured_event",
              format: "json",
              payload: { CommandLine: "test" },
              expected: "match",
            },
          ],
        },
        redactionState: "clean",
      };

      const request: DetectionExecutionRequest = {
        document: doc,
        evidencePack: pack,
        adapterRunConfig: {},
      };

      const result = await policyAdapter.runLab(request);
      // Non-policy items should be skipped (marked as passed)
      expect(result.run.results[0].actual).toContain("skipped");
    });
  });

  describe("buildExplainability", () => {
    it("returns explainability traces from a run", () => {
      const run = {
        id: "run-1",
        documentId: "doc-1",
        evidencePackId: "pack-1",
        fileType: "clawdstrike_policy" as const,
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        summary: {
          totalCases: 1,
          passed: 1,
          failed: 0,
          matched: 0,
          missed: 0,
          falsePositives: 0,
          engine: "client" as const,
        },
        results: [],
        explainability: [
          {
            id: "trace-1",
            kind: "policy_evaluation" as const,
            caseId: "case-1",
            guardResults: [],
          },
        ],
      };

      const traces = policyAdapter.buildExplainability(run);
      expect(traces).toHaveLength(1);
      expect(traces[0].kind).toBe("policy_evaluation");
    });
  });

  describe("buildPublication", () => {
    it("produces a manifest with correct hashes", async () => {
      const result = await policyAdapter.buildPublication({
        document: makeDocRef(),
        source: "version: '1.5.0'\nname: Published\nguards: {}\nsettings: {}",
        targetFormat: "native_policy",
      });

      expect(result.manifest.sourceFileType).toBe("clawdstrike_policy");
      expect(result.manifest.target).toBe("native_policy");
      expect(result.manifest.sourceHash).toBeDefined();
      expect(result.manifest.sourceHash.length).toBe(64); // SHA-256 hex
      expect(result.outputHash).toBe(result.manifest.outputHash);
      expect(result.manifest.converter.id).toBe("identity");
    });

    it("includes run snapshot when provided", async () => {
      const result = await policyAdapter.buildPublication({
        document: makeDocRef(),
        source: "version: '1.5.0'\nname: Pub\nguards: {}\nsettings: {}",
        targetFormat: "fleet_deploy",
        evidencePackId: "pack-1",
        labRunId: "run-1",
      });

      expect(result.manifest.runSnapshot).not.toBeNull();
      expect(result.manifest.runSnapshot!.evidencePackId).toBe("pack-1");
      expect(result.manifest.runSnapshot!.labRunId).toBe("run-1");
    });
  });
});
