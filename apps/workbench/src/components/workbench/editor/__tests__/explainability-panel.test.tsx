import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ExplainabilityPanel } from "../explainability-panel";
import type {
  LabRun,
  LabCaseResult,
  ExplainabilityTrace,
  LabRunSummary,
} from "@/lib/workbench/detection-workflow/shared-types";

// ---- Factories ----

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

function makeLabRun(overrides: Partial<LabRun> = {}): LabRun {
  return {
    id: "run-1",
    documentId: "doc-1",
    evidencePackId: "pack-1",
    fileType: "clawdstrike_policy",
    startedAt: "2026-03-15T00:00:00Z",
    completedAt: "2026-03-15T00:00:01Z",
    summary: makeSummary(),
    results: [],
    explainability: [],
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

function makeSigmaTrace(overrides: Record<string, unknown> = {}): ExplainabilityTrace {
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

function makePolicyTrace(overrides: Record<string, unknown> = {}): ExplainabilityTrace {
  return {
    id: "trace-policy-1",
    kind: "policy_evaluation",
    caseId: "case-2",
    guardResults: [
      {
        guardId: "forbidden_path",
        guardName: "Forbidden Path",
        verdict: "deny",
        message: "blocked /etc/shadow",
      },
    ],
    evaluationPath: [],
    ...overrides,
  } as ExplainabilityTrace;
}

// ---- Tests ----

describe("ExplainabilityPanel", () => {
  it("renders empty state when no run exists", () => {
    render(
      <ExplainabilityPanel
        documentId="doc-1"
        lastRun={null}
      />,
    );

    expect(screen.getByText("No lab run yet")).toBeInTheDocument();
    expect(
      screen.getByText(/Execute a lab run to see/),
    ).toBeInTheDocument();
  });

  it("renders empty state when no documentId", () => {
    render(
      <ExplainabilityPanel
        documentId={undefined}
        lastRun={null}
      />,
    );

    expect(
      screen.getByText("Open a document to view explainability traces"),
    ).toBeInTheDocument();
  });

  it("renders no-traces state when run has no explainability", () => {
    const run = makeLabRun({
      results: [makeCaseResult()],
      explainability: [],
    });

    render(
      <ExplainabilityPanel
        documentId="doc-1"
        lastRun={run}
      />,
    );

    expect(screen.getByText("No traces in this run")).toBeInTheDocument();
  });

  it("shows summary bar with correct counts", () => {
    const run = makeLabRun({
      results: [
        makeCaseResult({ caseId: "case-1", dataset: "positive", status: "pass" }),
        makeCaseResult({ caseId: "case-2", dataset: "positive", status: "fail" }),
      ],
      explainability: [
        makeSigmaTrace({ id: "t1", caseId: "case-1" }),
        makePolicyTrace({ id: "t2", caseId: "case-2" }),
      ],
    });

    render(
      <ExplainabilityPanel
        documentId="doc-1"
        lastRun={run}
      />,
    );

    // Header should show the Explain heading
    expect(screen.getByText("Explain")).toBeInTheDocument();

    // Total traces count in header
    expect(screen.getByText("2 traces")).toBeInTheDocument();

    // Summary bar labels — use getAllByText since section headers also contain "Matches"
    expect(screen.getByText("Total")).toBeInTheDocument();
    expect(screen.getAllByText("Matches").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("Misses")).toBeInTheDocument();
    expect(screen.getByText("FP")).toBeInTheDocument();
  });

  it("renders sigma_match traces", () => {
    const run = makeLabRun({
      results: [
        makeCaseResult({ caseId: "case-1", dataset: "positive", status: "pass" }),
      ],
      explainability: [
        makeSigmaTrace({ caseId: "case-1" }),
      ],
    });

    render(
      <ExplainabilityPanel
        documentId="doc-1"
        lastRun={run}
      />,
    );

    // Sigma trace content
    expect(screen.getByText("Sigma Match")).toBeInTheDocument();
    expect(screen.getByText("selection")).toBeInTheDocument();
    expect(screen.getByText("T1059")).toBeInTheDocument();
  });

  it("renders policy_evaluation traces", async () => {
    const user = userEvent.setup();
    const run = makeLabRun({
      results: [
        makeCaseResult({ caseId: "case-2", dataset: "positive", status: "fail" }),
      ],
      explainability: [
        makePolicyTrace({ caseId: "case-2" }),
      ],
    });

    render(
      <ExplainabilityPanel
        documentId="doc-1"
        lastRun={run}
      />,
    );

    // The trace is in the "Failures" section which is collapsed by default.
    // Click to expand it.
    const failuresButton = screen.getByText("Failures");
    await user.click(failuresButton);

    expect(screen.getByText("Policy Evaluation")).toBeInTheDocument();
    expect(screen.getByText("Forbidden Path")).toBeInTheDocument();
  });

  it("shows comparison delta when baseline provided", () => {
    const baseline = makeLabRun({
      id: "run-baseline",
      summary: makeSummary({ passed: 1, failed: 1, matched: 1, missed: 1 }),
      results: [
        makeCaseResult({ caseId: "c1", status: "pass" }),
        makeCaseResult({ caseId: "c2", status: "fail" }),
      ],
      explainability: [
        makeSigmaTrace({ id: "t1", caseId: "c1" }),
        makePolicyTrace({ id: "t2", caseId: "c2" }),
      ],
    });

    const current = makeLabRun({
      id: "run-current",
      summary: makeSummary({ passed: 2, failed: 0, matched: 2, missed: 0 }),
      results: [
        makeCaseResult({ caseId: "c1", status: "pass" }),
        makeCaseResult({ caseId: "c2", status: "pass" }),
      ],
      explainability: [
        makeSigmaTrace({ id: "t1", caseId: "c1" }),
        makePolicyTrace({ id: "t2", caseId: "c2" }),
      ],
    });

    render(
      <ExplainabilityPanel
        documentId="doc-1"
        lastRun={current}
        baselineRun={baseline}
      />,
    );

    expect(screen.getByText("Comparison Delta")).toBeInTheDocument();
    expect(screen.getByText("Passed")).toBeInTheDocument();
    expect(screen.getByText("Failed")).toBeInTheDocument();
  });

  it("onJumpToLine callback fires on click", async () => {
    const user = userEvent.setup();
    const onJumpToLine = vi.fn();

    const run = makeLabRun({
      results: [
        makeCaseResult({ caseId: "case-1", dataset: "positive", status: "pass" }),
      ],
      explainability: [
        makeSigmaTrace({ caseId: "case-1", sourceLineHints: [5, 8] }),
      ],
    });

    render(
      <ExplainabilityPanel
        documentId="doc-1"
        lastRun={run}
        onJumpToLine={onJumpToLine}
      />,
    );

    // Find and click the source line link
    const lineLink = screen.getByTitle("Jump to line 5");
    await user.click(lineLink);

    expect(onJumpToLine).toHaveBeenCalledWith(5);
  });
});
