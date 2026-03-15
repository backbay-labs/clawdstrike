import { describe, it, expect } from "vitest";
import {
  extractTraces,
  compareRuns,
  groupTracesByOutcome,
  getSourceLineRange,
} from "../detection-workflow/explainability";
import type {
  LabRun,
  LabCaseResult,
  ExplainabilityTrace,
  LabRunSummary,
} from "../detection-workflow/shared-types";

// ---- Factories ----

function makeLabRun(overrides: Partial<LabRun> = {}): LabRun {
  return {
    id: "run-1",
    documentId: "doc-1",
    evidencePackId: "pack-1",
    fileType: "clawdstrike_policy",
    startedAt: "2026-03-15T00:00:00Z",
    completedAt: "2026-03-15T00:00:01Z",
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
    ...overrides,
  };
}

function makeSummary(overrides: Partial<LabRunSummary> = {}): LabRunSummary {
  return {
    totalCases: 4,
    passed: 3,
    failed: 1,
    matched: 2,
    missed: 1,
    falsePositives: 0,
    engine: "client",
    ...overrides,
  };
}

function makeCaseResult(overrides: Partial<LabCaseResult> = {}): LabCaseResult {
  return {
    caseId: "case-1",
    dataset: "positive",
    status: "pass",
    expected: "deny",
    actual: "deny",
    explanationRefIds: ["trace-1"],
    ...overrides,
  };
}

function makeSigmaTrace(overrides: Partial<ExplainabilityTrace & { kind: "sigma_match" }> = {}): ExplainabilityTrace {
  return {
    id: "trace-sigma-1",
    kind: "sigma_match",
    caseId: "case-1",
    matchedSelectors: [{ name: "selection", fields: ["CommandLine"] }],
    matchedFields: [{ path: "CommandLine", value: "whoami" }],
    techniqueHints: ["T1059"],
    sourceLineHints: [5, 8],
    ...overrides,
  } as ExplainabilityTrace;
}

function makeYaraTrace(overrides: Partial<ExplainabilityTrace & { kind: "yara_match" }> = {}): ExplainabilityTrace {
  return {
    id: "trace-yara-1",
    kind: "yara_match",
    caseId: "case-2",
    matchedStrings: [{ name: "$s1", offset: 0, length: 5 }],
    conditionSummary: "any of them",
    sourceLineHints: [10],
    ...overrides,
  } as ExplainabilityTrace;
}

function makeOcsfTrace(overrides: Partial<ExplainabilityTrace & { kind: "ocsf_validation" }> = {}): ExplainabilityTrace {
  return {
    id: "trace-ocsf-1",
    kind: "ocsf_validation",
    caseId: "case-3",
    classUid: 1001,
    missingFields: ["process.name"],
    invalidFields: [],
    sourceLineHints: [3],
    ...overrides,
  } as ExplainabilityTrace;
}

function makePolicyTrace(overrides: Partial<ExplainabilityTrace & { kind: "policy_evaluation" }> = {}): ExplainabilityTrace {
  return {
    id: "trace-policy-1",
    kind: "policy_evaluation",
    caseId: "case-4",
    guardResults: [
      {
        guardId: "forbidden_path",
        guardName: "Forbidden Path",
        verdict: "deny",
        message: "blocked",
      },
    ],
    evaluationPath: [],
    ...overrides,
  } as ExplainabilityTrace;
}

// ---- Tests ----

describe("extractTraces", () => {
  it("returns enriched traces with correct outcomes", () => {
    const run = makeLabRun({
      results: [
        makeCaseResult({ caseId: "case-1", dataset: "positive", status: "pass" }),
        makeCaseResult({ caseId: "case-4", dataset: "positive", status: "fail" }),
      ],
      explainability: [
        makeSigmaTrace({ caseId: "case-1" }),
        makePolicyTrace({ caseId: "case-4" }),
      ],
    });

    const traces = extractTraces(run);
    expect(traces).toHaveLength(2);

    // Sigma match with positive/pass -> expected_match
    expect(traces[0].outcome).toBe("expected_match");
    expect(traces[0].dataset).toBe("positive");
    expect(traces[0].caseResult).not.toBeNull();

    // Policy evaluation with positive/fail -> fail
    expect(traces[1].outcome).toBe("fail");
  });

  it("handles empty runs gracefully", () => {
    const run = makeLabRun();
    const traces = extractTraces(run);
    expect(traces).toHaveLength(0);
  });

  it("handles runs with no explainability traces", () => {
    const run = makeLabRun({
      results: [makeCaseResult()],
      explainability: [],
    });
    const traces = extractTraces(run);
    expect(traces).toHaveLength(0);
  });

  it("assigns unknown dataset when case result not found", () => {
    const run = makeLabRun({
      results: [],
      explainability: [makeSigmaTrace({ caseId: "orphan" })],
    });

    const traces = extractTraces(run);
    expect(traces).toHaveLength(1);
    expect(traces[0].dataset).toBe("unknown");
    expect(traces[0].caseResult).toBeNull();
  });

  it("detects missed outcomes for sigma traces in positive dataset with fail status", () => {
    const run = makeLabRun({
      results: [
        makeCaseResult({ caseId: "case-1", dataset: "positive", status: "fail" }),
      ],
      explainability: [
        makeSigmaTrace({ caseId: "case-1" }),
      ],
    });

    const traces = extractTraces(run);
    expect(traces[0].outcome).toBe("missed");
  });

  it("detects unexpected_match for sigma traces in negative dataset with fail status", () => {
    const run = makeLabRun({
      results: [
        makeCaseResult({ caseId: "case-1", dataset: "negative", status: "fail" }),
      ],
      explainability: [
        makeSigmaTrace({ caseId: "case-1" }),
      ],
    });

    const traces = extractTraces(run);
    expect(traces[0].outcome).toBe("unexpected_match");
  });
});

describe("compareRuns", () => {
  it("detects flipped cases", () => {
    const baseline = makeLabRun({
      id: "run-baseline",
      summary: makeSummary({ passed: 2, failed: 1 }),
      results: [
        makeCaseResult({ caseId: "c1", status: "pass", actual: "allow" }),
        makeCaseResult({ caseId: "c2", status: "fail", actual: "allow" }),
      ],
      explainability: [],
    });

    const current = makeLabRun({
      id: "run-current",
      summary: makeSummary({ passed: 1, failed: 2 }),
      results: [
        makeCaseResult({ caseId: "c1", status: "fail", actual: "deny" }),
        makeCaseResult({ caseId: "c2", status: "pass", actual: "deny" }),
      ],
      explainability: [],
    });

    const delta = compareRuns(current, baseline);
    expect(delta.casesFlipped).toHaveLength(2);

    const c1flip = delta.casesFlipped.find((c) => c.caseId === "c1");
    expect(c1flip?.previousStatus).toBe("pass");
    expect(c1flip?.currentStatus).toBe("fail");

    const c2flip = delta.casesFlipped.find((c) => c.caseId === "c2");
    expect(c2flip?.previousStatus).toBe("fail");
    expect(c2flip?.currentStatus).toBe("pass");
  });

  it("detects technique delta from coverageDelta", () => {
    const baseline = makeLabRun({
      summary: makeSummary(),
      explainability: [],
    });

    const current = makeLabRun({
      summary: makeSummary(),
      explainability: [],
      coverageDelta: {
        techniquesAdded: ["T1059.001"],
        techniquesLost: ["T1003"],
      },
    });

    const delta = compareRuns(current, baseline);
    expect(delta.techniquesAdded).toEqual(["T1059.001"]);
    expect(delta.techniquesLost).toEqual(["T1003"]);
  });

  it("computes summary delta correctly", () => {
    const baseline = makeLabRun({
      summary: makeSummary({ passed: 5, failed: 2, matched: 3, missed: 1, falsePositives: 1 }),
      explainability: [],
    });

    const current = makeLabRun({
      summary: makeSummary({ passed: 6, failed: 1, matched: 4, missed: 0, falsePositives: 0 }),
      explainability: [],
    });

    const delta = compareRuns(current, baseline);
    expect(delta.summaryDelta.passedDelta).toBe(1);
    expect(delta.summaryDelta.failedDelta).toBe(-1);
    expect(delta.summaryDelta.matchedDelta).toBe(1);
    expect(delta.summaryDelta.missedDelta).toBe(-1);
    expect(delta.summaryDelta.falsePositivesDelta).toBe(-1);
  });

  it("handles empty runs", () => {
    const baseline = makeLabRun();
    const current = makeLabRun();

    const delta = compareRuns(current, baseline);
    expect(delta.casesFlipped).toHaveLength(0);
    expect(delta.newMatches).toHaveLength(0);
    expect(delta.newFalsePositives).toHaveLength(0);
    expect(delta.techniquesAdded).toHaveLength(0);
    expect(delta.techniquesLost).toHaveLength(0);
  });
});

describe("groupTracesByOutcome", () => {
  it("groups correctly", () => {
    const run = makeLabRun({
      results: [
        makeCaseResult({ caseId: "c1", dataset: "positive", status: "pass" }),
        makeCaseResult({ caseId: "c2", dataset: "positive", status: "fail" }),
        makeCaseResult({ caseId: "c3", dataset: "negative", status: "fail" }),
        makeCaseResult({ caseId: "c4", dataset: "positive", status: "fail" }),
      ],
      explainability: [
        makeSigmaTrace({ id: "t1", caseId: "c1" }),  // expected_match (positive, pass)
        makeSigmaTrace({ id: "t2", caseId: "c2" }),  // missed (positive, fail)
        makeSigmaTrace({ id: "t3", caseId: "c3" }),  // unexpected_match (negative, fail)
        makePolicyTrace({ id: "t4", caseId: "c4" }), // fail (positive, fail)
      ],
    });

    const traces = extractTraces(run);
    const groups = groupTracesByOutcome(traces);

    expect(groups.matches).toHaveLength(1);
    expect(groups.misses).toHaveLength(1);
    expect(groups.falsePositives).toHaveLength(1);
    expect(groups.failures).toHaveLength(1);
    expect(groups.passes).toHaveLength(0);
  });

  it("handles empty trace list", () => {
    const groups = groupTracesByOutcome([]);
    expect(groups.matches).toHaveLength(0);
    expect(groups.misses).toHaveLength(0);
    expect(groups.falsePositives).toHaveLength(0);
    expect(groups.passes).toHaveLength(0);
    expect(groups.failures).toHaveLength(0);
  });
});

describe("getSourceLineRange", () => {
  it("extracts line range from sigma trace", () => {
    const trace = makeSigmaTrace({ sourceLineHints: [5, 8, 12] });
    const range = getSourceLineRange(trace);
    expect(range).toEqual({ start: 5, end: 12 });
  });

  it("extracts single line from yara trace", () => {
    const trace = makeYaraTrace({ sourceLineHints: [10] });
    const range = getSourceLineRange(trace);
    expect(range).toEqual({ start: 10, end: 10 });
  });

  it("extracts line from ocsf trace", () => {
    const trace = makeOcsfTrace({ sourceLineHints: [3, 7] });
    const range = getSourceLineRange(trace);
    expect(range).toEqual({ start: 3, end: 7 });
  });

  it("returns null for policy evaluation traces", () => {
    const trace = makePolicyTrace();
    const range = getSourceLineRange(trace);
    expect(range).toBeNull();
  });

  it("returns null for empty source line hints", () => {
    const trace = makeSigmaTrace({ sourceLineHints: [] });
    const range = getSourceLineRange(trace);
    expect(range).toBeNull();
  });
});
