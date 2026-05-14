import { describe, it, expect, beforeAll } from "vitest";
import { sigmaAdapter } from "../detection-workflow/sigma-adapter";
import { ocsfAdapter } from "../detection-workflow/ocsf-adapter";
import {
  extractSigmaSelectionFields,
  clientSideMatch,
} from "../detection-workflow/sigma-adapter";
import type { EvidencePack } from "../detection-workflow/shared-types";
import { createEmptyDatasets } from "../detection-workflow/shared-types";
import type {
  DetectionExecutionRequest,
} from "../detection-workflow/execution-types";

// ---- Helpers ----

function makeDocRef(fileType: "sigma_rule" | "ocsf_event") {
  return {
    documentId: "doc-test",
    fileType,
    filePath: null,
    name: "Test Doc",
    sourceHash: "abc123",
  };
}

function makeSigmaSource(selection: Record<string, unknown> = {}): string {
  return `title: Test Sigma Rule
id: 12345678-1234-1234-1234-123456789012
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
${Object.entries(selection)
  .map(([k, v]) => {
    if (Array.isArray(v)) {
      return `    ${k}:\n${v.map((val) => `      - "${val}"`).join("\n")}`;
    }
    return `    ${k}: "${v}"`;
  })
  .join("\n")}
  condition: selection
level: medium
`;
}

function makeValidOcsfPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const classUid = typeof overrides.class_uid === "number" ? overrides.class_uid : 1007;
  const activityId = typeof overrides.activity_id === "number" ? overrides.activity_id : 1;
  const categoryUid = classUid === 2004 ? 2 : classUid === 4001 || classUid === 4003 ? 4 : 1;
  const metadata = overrides.metadata ?? {
    version: "1.4.0",
    product: {
      name: "ClawdStrike Detection Lab",
      vendor_name: "Backbay Labs",
    },
  };

  const findingFields = classUid === 2004
    ? {
        action_id: overrides.action_id ?? 2,
        disposition_id: overrides.disposition_id ?? 2,
        finding_info: overrides.finding_info ?? {
          uid: "finding-1",
          title: "Finding",
          analytic: {
            name: "ClawdStrike Detection Lab",
            type_id: 1,
            type: "Rule",
          },
        },
      }
    : {};

  return {
    class_uid: classUid,
    category_uid: overrides.category_uid ?? categoryUid,
    type_uid: overrides.type_uid ?? classUid * 100 + activityId,
    activity_id: activityId,
    severity_id: overrides.severity_id ?? 3,
    status_id: overrides.status_id ?? 1,
    time: overrides.time ?? Date.now(),
    message: overrides.message ?? "OCSF test event",
    metadata,
    ...findingFields,
    ...overrides,
  };
}

// Ensure adapters are imported (side-effect registration)
beforeAll(() => {
  void sigmaAdapter;
  void ocsfAdapter;
});

// ---- Sigma Adapter runLab Tests ----

describe("sigma adapter runLab", () => {
  it("returns error result when no sigmaSource is provided", async () => {
    const doc = makeDocRef("sigma_rule");
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-test",
      fileType: "sigma_rule",
      title: "Test Pack",
      createdAt: new Date().toISOString(),
      datasets: createEmptyDatasets(),
      redactionState: "clean",
    };

    const request: DetectionExecutionRequest = {
      document: doc,
      evidencePack: pack,
      adapterRunConfig: {},
    };

    const result = await sigmaAdapter.runLab(request);
    expect(result.run.summary.totalCases).toBe(0);
    expect(result.reportArtifacts[0].title).toContain("No Sigma source");
  });

  it("matches structured events against selection fields (client-side)", async () => {
    const source = makeSigmaSource({ "CommandLine|contains": "whoami" });
    const doc = makeDocRef("sigma_rule");
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-test",
      fileType: "sigma_rule",
      title: "Test Pack",
      createdAt: new Date().toISOString(),
      datasets: {
        ...createEmptyDatasets(),
        positive: [
          {
            id: "case-match",
            kind: "structured_event",
            format: "json",
            payload: { CommandLine: "whoami /all", User: "admin" },
            expected: "match",
          },
        ],
      },
      redactionState: "clean",
    };

    const request: DetectionExecutionRequest = {
      document: doc,
      evidencePack: pack,
      adapterRunConfig: { sigmaSource: source },
    };

    const result = await sigmaAdapter.runLab(request);
    expect(result.run.summary.totalCases).toBe(1);
    expect(result.run.summary.passed).toBe(1);
    expect(result.run.results[0].status).toBe("pass");
    expect(result.run.results[0].actual).toBe("match");
    expect(result.run.summary.engine).toBe("client");
  });

  it("correctly identifies non-matching events (client-side)", async () => {
    const source = makeSigmaSource({ "CommandLine|contains": "whoami" });
    const doc = makeDocRef("sigma_rule");
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-test",
      fileType: "sigma_rule",
      title: "Test Pack",
      createdAt: new Date().toISOString(),
      datasets: {
        ...createEmptyDatasets(),
        negative: [
          {
            id: "case-nomatch",
            kind: "structured_event",
            format: "json",
            payload: { CommandLine: "echo hello", User: "user" },
            expected: "no_match",
          },
        ],
      },
      redactionState: "clean",
    };

    const request: DetectionExecutionRequest = {
      document: doc,
      evidencePack: pack,
      adapterRunConfig: { sigmaSource: source },
    };

    const result = await sigmaAdapter.runLab(request);
    expect(result.run.summary.totalCases).toBe(1);
    expect(result.run.summary.passed).toBe(1);
    expect(result.run.results[0].status).toBe("pass");
    expect(result.run.results[0].actual).toBe("no_match");
  });

  it("reports failure when expected match does not occur", async () => {
    const source = makeSigmaSource({ "CommandLine|contains": "malicious" });
    const doc = makeDocRef("sigma_rule");
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-test",
      fileType: "sigma_rule",
      title: "Test Pack",
      createdAt: new Date().toISOString(),
      datasets: {
        ...createEmptyDatasets(),
        positive: [
          {
            id: "case-miss",
            kind: "structured_event",
            format: "json",
            payload: { CommandLine: "echo hello" },
            expected: "match",
          },
        ],
      },
      redactionState: "clean",
    };

    const request: DetectionExecutionRequest = {
      document: doc,
      evidencePack: pack,
      adapterRunConfig: { sigmaSource: source },
    };

    const result = await sigmaAdapter.runLab(request);
    expect(result.run.summary.totalCases).toBe(1);
    expect(result.run.summary.failed).toBe(1);
    expect(result.run.results[0].status).toBe("fail");
  });

  it("handles empty evidence packs", async () => {
    const source = makeSigmaSource({ "CommandLine|contains": "test" });
    const doc = makeDocRef("sigma_rule");
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-test",
      fileType: "sigma_rule",
      title: "Empty Pack",
      createdAt: new Date().toISOString(),
      datasets: createEmptyDatasets(),
      redactionState: "clean",
    };

    const request: DetectionExecutionRequest = {
      document: doc,
      evidencePack: pack,
      adapterRunConfig: { sigmaSource: source },
    };

    const result = await sigmaAdapter.runLab(request);
    expect(result.run.summary.totalCases).toBe(0);
    expect(result.run.results).toHaveLength(0);
  });

  it("produces explainability traces for matched events", async () => {
    const source = makeSigmaSource({ "CommandLine|contains": "whoami" });
    const doc = makeDocRef("sigma_rule");
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-test",
      fileType: "sigma_rule",
      title: "Test Pack",
      createdAt: new Date().toISOString(),
      datasets: {
        ...createEmptyDatasets(),
        positive: [
          {
            id: "case-1",
            kind: "structured_event",
            format: "json",
            payload: { CommandLine: "whoami /all" },
            expected: "match",
          },
        ],
      },
      redactionState: "clean",
    };

    const request: DetectionExecutionRequest = {
      document: doc,
      evidencePack: pack,
      adapterRunConfig: { sigmaSource: source },
    };

    const result = await sigmaAdapter.runLab(request);
    expect(result.run.explainability).toHaveLength(1);
    expect(result.run.explainability[0].kind).toBe("sigma_match");

    if (result.run.explainability[0].kind === "sigma_match") {
      expect(result.run.explainability[0].matchedSelectors).toHaveLength(1);
      expect(result.run.explainability[0].matchedSelectors[0].name).toBe("selection");
      expect(result.run.explainability[0].matchedFields.length).toBeGreaterThan(0);
      expect(result.run.explainability[0].matchedFields[0].path).toBe("CommandLine");
    }
  });

  it("handles mixed positive and negative datasets", async () => {
    const source = makeSigmaSource({ "CommandLine|contains": "whoami" });
    const doc = makeDocRef("sigma_rule");
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-test",
      fileType: "sigma_rule",
      title: "Mixed Pack",
      createdAt: new Date().toISOString(),
      datasets: {
        ...createEmptyDatasets(),
        positive: [
          {
            id: "case-pos",
            kind: "structured_event",
            format: "json",
            payload: { CommandLine: "whoami" },
            expected: "match",
          },
        ],
        negative: [
          {
            id: "case-neg",
            kind: "structured_event",
            format: "json",
            payload: { CommandLine: "echo hello" },
            expected: "no_match",
          },
        ],
      },
      redactionState: "clean",
    };

    const request: DetectionExecutionRequest = {
      document: doc,
      evidencePack: pack,
      adapterRunConfig: { sigmaSource: source },
    };

    const result = await sigmaAdapter.runLab(request);
    expect(result.run.summary.totalCases).toBe(2);
    expect(result.run.summary.passed).toBe(2);
    expect(result.run.summary.matched).toBe(1);
  });
});

// ---- Sigma Client-Side Matching Helpers ----

describe("extractSigmaSelectionFields", () => {
  it("extracts simple selection fields", () => {
    const source = `
detection:
  selection:
    CommandLine|contains: "whoami"
  condition: selection
`;
    const fields = extractSigmaSelectionFields(source);
    expect(fields).toHaveLength(1);
    expect(fields[0].fieldName).toBe("CommandLine");
    expect(fields[0].modifier).toBe("contains");
    expect(fields[0].values).toEqual(["whoami"]);
  });

  it("extracts fields without modifiers", () => {
    const source = `
detection:
  selection:
    User: "admin"
  condition: selection
`;
    const fields = extractSigmaSelectionFields(source);
    expect(fields).toHaveLength(1);
    expect(fields[0].fieldName).toBe("User");
    expect(fields[0].modifier).toBeNull();
    expect(fields[0].values).toEqual(["admin"]);
  });

  it("returns empty array for invalid YAML", () => {
    const fields = extractSigmaSelectionFields("not: valid: yaml: {{}}");
    expect(fields).toEqual([]);
  });

  it("returns empty array when no detection block", () => {
    const fields = extractSigmaSelectionFields("title: No detection\nlevel: low\n");
    expect(fields).toEqual([]);
  });
});

describe("clientSideMatch", () => {
  it("matches contains modifier", () => {
    const fields = [{ fieldName: "CommandLine", modifier: "contains", values: ["whoami"] }];
    expect(clientSideMatch({ CommandLine: "whoami /all" }, fields)).toBe(true);
    expect(clientSideMatch({ CommandLine: "echo hello" }, fields)).toBe(false);
  });

  it("matches startswith modifier", () => {
    const fields = [{ fieldName: "Path", modifier: "startswith", values: ["/etc/"] }];
    expect(clientSideMatch({ Path: "/etc/shadow" }, fields)).toBe(true);
    expect(clientSideMatch({ Path: "/tmp/etc" }, fields)).toBe(false);
  });

  it("matches endswith modifier", () => {
    const fields = [{ fieldName: "File", modifier: "endswith", values: [".exe"] }];
    expect(clientSideMatch({ File: "malware.exe" }, fields)).toBe(true);
    expect(clientSideMatch({ File: "malware.txt" }, fields)).toBe(false);
  });

  it("performs exact match when no modifier", () => {
    const fields = [{ fieldName: "User", modifier: null, values: ["admin"] }];
    expect(clientSideMatch({ User: "admin" }, fields)).toBe(true);
    expect(clientSideMatch({ User: "Admin" }, fields)).toBe(true); // case-insensitive
    expect(clientSideMatch({ User: "user" }, fields)).toBe(false);
  });

  it("requires all fields to match (AND logic)", () => {
    const fields = [
      { fieldName: "CommandLine", modifier: "contains", values: ["whoami"] },
      { fieldName: "User", modifier: null, values: ["admin"] },
    ];
    expect(clientSideMatch({ CommandLine: "whoami", User: "admin" }, fields)).toBe(true);
    expect(clientSideMatch({ CommandLine: "whoami", User: "user" }, fields)).toBe(false);
    expect(clientSideMatch({ CommandLine: "echo", User: "admin" }, fields)).toBe(false);
  });

  it("returns false for empty selection fields", () => {
    expect(clientSideMatch({ CommandLine: "test" }, [])).toBe(false);
  });

  it("returns false when field is missing from payload", () => {
    const fields = [{ fieldName: "MissingField", modifier: "contains", values: ["test"] }];
    expect(clientSideMatch({ CommandLine: "test" }, fields)).toBe(false);
  });

  it("matches any value in multi-value selection (OR within field)", () => {
    const fields = [{ fieldName: "CommandLine", modifier: "contains", values: ["whoami", "id"] }];
    expect(clientSideMatch({ CommandLine: "whoami /all" }, fields)).toBe(true);
    expect(clientSideMatch({ CommandLine: "id" }, fields)).toBe(true);
    expect(clientSideMatch({ CommandLine: "echo hello" }, fields)).toBe(false);
  });
});

// ---- OCSF Adapter runLab Tests ----

describe("ocsf adapter runLab", () => {
  it("validates valid OCSF events as valid (client-side)", async () => {
    const doc = makeDocRef("ocsf_event");
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-test",
      fileType: "ocsf_event",
      title: "Test Pack",
      createdAt: new Date().toISOString(),
      datasets: {
        ...createEmptyDatasets(),
        positive: [
          {
            id: "case-valid",
            kind: "ocsf_event",
            payload: makeValidOcsfPayload({ message: "Process creation" }),
            expected: "valid",
          },
        ],
      },
      redactionState: "clean",
    };

    const request: DetectionExecutionRequest = {
      document: doc,
      evidencePack: pack,
    };

    const result = await ocsfAdapter.runLab(request);
    expect(result.run.summary.totalCases).toBe(1);
    expect(result.run.summary.passed).toBe(1);
    expect(result.run.results[0].status).toBe("pass");
    expect(result.run.results[0].actual).toBe("valid");
    expect(result.run.summary.engine).toBe("client");
  });

  it("validates invalid OCSF events expected invalid as pass (client-side)", async () => {
    const doc = makeDocRef("ocsf_event");
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-test",
      fileType: "ocsf_event",
      title: "Test Pack",
      createdAt: new Date().toISOString(),
      datasets: {
        ...createEmptyDatasets(),
        negative: [
          {
            id: "case-invalid",
            kind: "ocsf_event",
            payload: {
              class_uid: 0,
              category_uid: 0,
              activity_id: 0,
              severity_id: 0,
              status_id: 0,
              time: 0,
              message: "Invalid baseline",
            },
            expected: "invalid",
          },
        ],
      },
      redactionState: "clean",
    };

    const request: DetectionExecutionRequest = {
      document: doc,
      evidencePack: pack,
    };

    const result = await ocsfAdapter.runLab(request);
    expect(result.run.summary.totalCases).toBe(1);
    expect(result.run.summary.passed).toBe(1);
    expect(result.run.results[0].status).toBe("pass");
    expect(result.run.results[0].actual).toBe("invalid");
  });

  it("handles missing required fields", async () => {
    const doc = makeDocRef("ocsf_event");
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-test",
      fileType: "ocsf_event",
      title: "Test Pack",
      createdAt: new Date().toISOString(),
      datasets: {
        ...createEmptyDatasets(),
        positive: [
          {
            id: "case-missing",
            kind: "ocsf_event",
            payload: {
              message: "Missing required fields",
            },
            expected: "valid",
          },
        ],
      },
      redactionState: "clean",
    };

    const request: DetectionExecutionRequest = {
      document: doc,
      evidencePack: pack,
    };

    const result = await ocsfAdapter.runLab(request);
    expect(result.run.summary.totalCases).toBe(1);
    expect(result.run.summary.failed).toBe(1);
    expect(result.run.results[0].status).toBe("fail");
    expect(result.run.results[0].actual).toBe("invalid");
  });

  it("produces ocsf_validation explainability traces", async () => {
    const doc = makeDocRef("ocsf_event");
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-test",
      fileType: "ocsf_event",
      title: "Test Pack",
      createdAt: new Date().toISOString(),
      datasets: {
        ...createEmptyDatasets(),
        positive: [
          {
            id: "case-1",
            kind: "ocsf_event",
            payload: makeValidOcsfPayload({ severity_id: 2 }),
            expected: "valid",
          },
        ],
      },
      redactionState: "clean",
    };

    const request: DetectionExecutionRequest = {
      document: doc,
      evidencePack: pack,
    };

    const result = await ocsfAdapter.runLab(request);
    expect(result.run.explainability).toHaveLength(1);
    expect(result.run.explainability[0].kind).toBe("ocsf_validation");

    if (result.run.explainability[0].kind === "ocsf_validation") {
      expect(result.run.explainability[0].classUid).toBe(1007);
      expect(result.run.explainability[0].missingFields).toEqual([]);
    }
  });

  it("handles empty evidence packs", async () => {
    const doc = makeDocRef("ocsf_event");
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-test",
      fileType: "ocsf_event",
      title: "Empty Pack",
      createdAt: new Date().toISOString(),
      datasets: createEmptyDatasets(),
      redactionState: "clean",
    };

    const request: DetectionExecutionRequest = {
      document: doc,
      evidencePack: pack,
    };

    const result = await ocsfAdapter.runLab(request);
    expect(result.run.summary.totalCases).toBe(0);
    expect(result.run.results).toHaveLength(0);
    expect(result.run.explainability).toHaveLength(0);
  });

  it("skips non-ocsf_event items", async () => {
    const doc = makeDocRef("ocsf_event");
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-test",
      fileType: "ocsf_event",
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
    };

    const result = await ocsfAdapter.runLab(request);
    // structured_event items should be skipped by OCSF adapter
    expect(result.run.summary.totalCases).toBe(0);
  });

  it("handles mixed valid and invalid events", async () => {
    const doc = makeDocRef("ocsf_event");
    const pack: EvidencePack = {
      id: "pack-1",
      documentId: "doc-test",
      fileType: "ocsf_event",
      title: "Mixed Pack",
      createdAt: new Date().toISOString(),
      datasets: {
        ...createEmptyDatasets(),
        positive: [
          {
            id: "case-valid",
            kind: "ocsf_event",
            payload: makeValidOcsfPayload({ class_uid: 2004, severity_id: 4 }),
            expected: "valid",
          },
        ],
        negative: [
          {
            id: "case-invalid",
            kind: "ocsf_event",
            payload: {
              class_uid: 0,
              activity_id: 0,
              severity_id: 0,
            },
            expected: "invalid",
          },
        ],
      },
      redactionState: "clean",
    };

    const request: DetectionExecutionRequest = {
      document: doc,
      evidencePack: pack,
    };

    const result = await ocsfAdapter.runLab(request);
    expect(result.run.summary.totalCases).toBe(2);
    expect(result.run.summary.passed).toBe(2);
    expect(result.run.explainability).toHaveLength(2);
  });
});
