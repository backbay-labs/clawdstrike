import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  applyPolicyDelta,
  createDetectionCandidate,
  createPolicyDelta,
  createStagedDetection,
  type DetectionCandidateResponse,
  dryRunPolicyDeltaApply,
  type PolicyDeltaApplyResponse,
  type PolicyDeltaResponse,
  type StageDetectionResponse,
} from "../api/client";
import { exportAsJSON } from "../utils/exportData";
import { RuleImpact } from "./RuleImpact";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    createDetectionCandidate: vi.fn(),
    createPolicyDelta: vi.fn(),
    createStagedDetection: vi.fn(),
    dryRunPolicyDeltaApply: vi.fn(),
    applyPolicyDelta: vi.fn(),
  };
});

vi.mock("../utils/exportData", () => ({
  exportAsJSON: vi.fn(),
}));

const CROSS_WINDOW_IMPACT_HASH =
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CROSS_WINDOW_RECOMMENDATION_HASH =
  "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const simulation = {
  simulationId: "simulation-1",
  ruleId: "endpoint.generated.block.process.npm",
  action: "block" as const,
  rootNodeId: "process:proc-impact-1",
  graphSliceId: "graph-slice-impact-1",
  wouldBlock: true,
  createdAt: "2026-05-16T12:00:00Z",
  affectedNodeCount: 3,
  affectedEdgeCount: 2,
  affectedProcessCount: 1,
  affectedFileCount: 0,
  affectedNetworkCount: 1,
  affectedCredentialCount: 1,
  affectedToolCount: 0,
  developerBreakageScore: 74,
  impactLevel: "high" as const,
  summary: "Generated block rule would stop npm credential access.",
  affectedNodes: [
    {
      nodeId: "credential:npm-token",
      kind: "credential",
      label: "/Users/alice/.npmrc",
      breakageScore: 91,
      reason: "credential read would be blocked",
    },
  ],
  affectedIdentities: [
    {
      identityKind: "user",
      value: "alice",
      sourceNodeId: "process:proc-impact-1",
      sourceNodeKind: "process",
    },
    {
      identityKind: "session",
      value: "session-impact-1",
      sourceNodeId: "process:proc-impact-1",
      sourceNodeKind: "process",
    },
  ],
  affectedTools: [
    {
      toolName: "mcp.shell",
      toolCallId: "tool-call-impact-1",
      sourceNodeId: "tool:mcp.shell",
    },
  ],
};

const candidatePayload: DetectionCandidateResponse = {
  candidate: {
    ruleId: "endpoint.generated.block.process.npm",
    action: "block",
    description: "Block npm credential access",
    rootNodeId: "process:proc-impact-1",
    rootLabel: "/usr/local/bin/npm",
    rootKind: "process",
    graphSliceId: "graph-slice-impact-1",
  },
  recommendedStage: "audit",
  stagePlan: [
    { stage: "observe", action: "observe", promotionGate: "watch only", recommended: false },
    {
      stage: "audit",
      action: "alert",
      promotionGate: "audit before enforcement",
      recommended: true,
    },
    {
      stage: "limited_block",
      action: "restrict_egress",
      promotionGate: "limit egress only",
      recommended: false,
    },
  ],
  simulation,
  graph: {
    nodes: {
      "process:proc-impact-1": { kind: "process", label: "/usr/local/bin/npm" },
      "credential:npm-token": { kind: "credential", label: "/Users/alice/.npmrc" },
    },
    edges: [{ from: "process:proc-impact-1", to: "credential:npm-token", kind: "read" }],
  },
  receipt: {
    receipt: {
      metadata: {
        endpointDecision: {
          receiptFamily: "simulation",
          graph: { graphSliceId: "graph-slice-impact-1" },
        },
      },
    },
  },
};

const stagedPayload: StageDetectionResponse = {
  path: "/tmp/staged-detections.jsonl",
  record: {
    stagedDetectionId: "staged-impact-1",
    stagedAt: "2026-05-16T12:01:00Z",
    stagedBy: "operator:alice",
    stage: "audit",
    note: "stage generated npm guard",
    policy: {
      policyVersion: "test-edr",
      policyHash: "sha256:base",
      policyEpoch: 77,
    },
    candidate: candidatePayload.candidate,
    recommendedStage: "audit",
    stagePlan: candidatePayload.stagePlan,
    simulation,
    simulationReceipt: candidatePayload.receipt,
    crossWindowImpactHash: CROSS_WINDOW_IMPACT_HASH,
    crossWindowRecommendationHash: CROSS_WINDOW_RECOMMENDATION_HASH,
  },
  graph: candidatePayload.graph,
};

const deltaPayload: PolicyDeltaResponse = {
  path: "/tmp/policy-deltas",
  record: {
    policyDeltaId: "policy-delta-impact-1",
    generatedAt: "2026-05-16T12:02:00Z",
    generatedBy: "operator:alice",
    ruleId: "endpoint.generated.block.process.npm",
    stage: "audit",
    action: "alert",
    artifactHash: "0xabc",
    artifactPath: "/tmp/policy-delta-impact-1.json",
    artifact: {
      schemaVersion: "clawdstrike.endpoint_policy_delta.v1",
      policyDeltaId: "policy-delta-impact-1",
      generatedAt: "2026-05-16T12:02:00Z",
      generatedBy: "operator:alice",
      stagedDetectionId: "staged-impact-1",
      sourceSimulationId: "simulation-1",
      sourceSimulationReceiptId: "receipt-1",
      sourceAffectedIdentities: [
        {
          identityKind: "agent",
          value: "agent-delta-1",
          sourceNodeId: "agent:delta",
          sourceNodeKind: "agent",
        },
      ],
      sourceAffectedTools: [
        {
          toolName: "mcp.shell",
          toolCallId: "tool-call-delta-1",
          sourceNodeId: "tool:mcp.shell",
        },
      ],
      candidate: candidatePayload.candidate,
      targetPolicy: {
        basePolicyVersion: "test-edr",
        basePolicyHash: "sha256:base",
        basePolicyEpoch: 77,
        targetPolicyEpoch: 78,
      },
      rollout: {
        stage: "audit",
        action: "alert",
        recommendedStage: "audit",
        promotionGate: "audit before enforcement",
        developerBreakageScore: 74,
        impactLevel: "high",
        wouldBlock: true,
        crossWindowImpactHash: CROSS_WINDOW_IMPACT_HASH,
        crossWindowRecommendationHash: CROSS_WINDOW_RECOMMENDATION_HASH,
      },
      policyPatch: { guards: {} },
    },
    receipt: {
      receipt: { metadata: { endpointDecision: { receiptFamily: "policy_delta" } } },
    },
  },
};

const applyPayload: PolicyDeltaApplyResponse = {
  record: {
    policyDeltaId: "policy-delta-impact-1",
    appliedAt: "2026-05-16T12:03:00Z",
    appliedBy: "operator:alice",
    note: "dry-run staged policy delta",
    dryRun: true,
    applied: false,
    allowBasePolicyDrift: false,
    policyPath: "/tmp/policy.yml",
    backupPath: null,
    expectedBasePolicyHash: "sha256:base",
    previousPolicyHash: "sha256:base",
    newPolicyHash: "sha256:new",
    previousPolicyEpoch: 77,
    newPolicyEpoch: 78,
    crossWindowImpactHash: CROSS_WINDOW_IMPACT_HASH,
    crossWindowRecommendationHash: CROSS_WINDOW_RECOMMENDATION_HASH,
  },
  policyDelta: deltaPayload.record,
  receipt: null,
  postApplyEnforcement: null,
};

const liveApplyPayload: PolicyDeltaApplyResponse = {
  ...applyPayload,
  record: {
    ...applyPayload.record,
    appliedAt: "2026-05-16T12:04:00Z",
    dryRun: false,
    applied: true,
    backupPath: "/tmp/policy.yml.20260516120400.bak",
  },
  receipt: {
    receipt: { metadata: { endpointDecision: { receiptFamily: "policy_delta" } } },
  },
  postApplyEnforcement: {
    policySyncedToDisk: true,
    crossWindowImpactHash: CROSS_WINDOW_IMPACT_HASH,
    crossWindowRecommendationHash: CROSS_WINDOW_RECOMMENDATION_HASH,
    receipt: {
      receipt: { metadata: { endpointDecision: { receiptFamily: "sensor_state" } } },
    },
    providerAcknowledgementPoll: { requested: true, satisfied: true, attempts: 1 },
    providerPolicyAcknowledgements: [
      {
        providerId: "macos.network_extension",
        acknowledged: true,
        observedPolicyEpoch: 78,
        policySynced: true,
        enforcementReady: true,
      },
    ],
  },
};

describe("RuleImpact", () => {
  beforeEach(() => {
    vi.mocked(createDetectionCandidate).mockReset();
    vi.mocked(createStagedDetection).mockReset();
    vi.mocked(createPolicyDelta).mockReset();
    vi.mocked(applyPolicyDelta).mockReset();
    vi.mocked(dryRunPolicyDeltaApply).mockReset();
    vi.mocked(exportAsJSON).mockReset();
  });

  it("generates, stages, promotes, dry-runs, and applies a rule-impact policy delta", async () => {
    vi.mocked(createDetectionCandidate).mockResolvedValue(candidatePayload);
    vi.mocked(createStagedDetection).mockResolvedValue(stagedPayload);
    vi.mocked(createPolicyDelta).mockResolvedValue(deltaPayload);
    vi.mocked(dryRunPolicyDeltaApply).mockResolvedValue(applyPayload);
    vi.mocked(applyPolicyDelta).mockResolvedValue(liveApplyPayload);

    render(<RuleImpact />);

    fireEvent.change(screen.getByLabelText("Process GUID"), {
      target: { value: "proc-impact-1" },
    });
    fireEvent.change(screen.getByLabelText("Operator"), {
      target: { value: "operator:alice" },
    });
    fireEvent.change(screen.getByLabelText("Approval ID"), {
      target: { value: "approval-delta-apply-1" },
    });
    fireEvent.change(screen.getByLabelText("Note"), {
      target: { value: "stage generated npm guard" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Generate Candidate" }));

    await waitFor(() => {
      expect(createDetectionCandidate).toHaveBeenCalledWith({
        process: { processGuid: "proc-impact-1" },
        action: "block",
        maxDepth: 64,
      });
    });
    expect(await screen.findByText("endpoint.generated.block.process.npm")).toBeTruthy();
    expect(screen.getByText("/usr/local/bin/npm")).toBeTruthy();
    expect(screen.getByText("Recommended: audit")).toBeTruthy();
    expect(screen.getByText("audit before enforcement")).toBeTruthy();
    expect(screen.getByText("/Users/alice/.npmrc")).toBeTruthy();
    expect(screen.getByText("session-impact-1")).toBeTruthy();
    expect(screen.getByText("mcp.shell")).toBeTruthy();
    expect(screen.getByText("tool:mcp.shell / tool-call-impact-1")).toBeTruthy();
    expect(screen.getByText("simulation")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Stage Detection" }));
    await waitFor(() => {
      expect(createStagedDetection).toHaveBeenCalledWith({
        process: { processGuid: "proc-impact-1" },
        action: "block",
        maxDepth: 64,
        selectedStage: "audit",
        stagedBy: "operator:alice",
        note: "stage generated npm guard",
      });
    });
    expect(await screen.findByText("staged-impact-1")).toBeTruthy();
    expect(screen.getByText("Epoch 77")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Generate Delta" }));
    await waitFor(() => {
      expect(createPolicyDelta).toHaveBeenCalledWith({
        stagedDetectionId: "staged-impact-1",
        generatedBy: "operator:alice",
        note: "stage generated npm guard",
      });
    });
    expect(await screen.findByText("policy-delta-impact-1")).toBeTruthy();
    expect(screen.getByText("policy_delta")).toBeTruthy();
    expect(screen.getByText("0xabc")).toBeTruthy();
    expect(screen.getByText("agent-delta-1")).toBeTruthy();
    expect(screen.getByText("tool:mcp.shell / tool-call-delta-1")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Dry-run Apply" }));
    await waitFor(() => {
      expect(dryRunPolicyDeltaApply).toHaveBeenCalledWith("policy-delta-impact-1", {
        appliedBy: "operator:alice",
        note: "stage generated npm guard",
      });
    });
    expect(await screen.findByText("Dry run: true")).toBeTruthy();
    expect(screen.getByText("Applied: false")).toBeTruthy();
    expect(screen.getByText("78")).toBeTruthy();
    expect(screen.getByText(CROSS_WINDOW_IMPACT_HASH)).toBeTruthy();
    expect(screen.getByText(CROSS_WINDOW_RECOMMENDATION_HASH)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Apply Delta" }));
    await waitFor(() => {
      expect(applyPolicyDelta).toHaveBeenCalledWith("policy-delta-impact-1", {
        dryRun: false,
        appliedBy: "operator:alice",
        note: "stage generated npm guard",
        verifyProtectionState: true,
        actor: { userId: "operator:alice", approvalId: "approval-delta-apply-1" },
      });
    });
    expect(await screen.findByText("Dry run: false")).toBeTruthy();
    expect(screen.getByText("Applied: true")).toBeTruthy();
    expect(screen.getByText("sensor_state")).toBeTruthy();
    expect(screen.getByText("Synced: true")).toBeTruthy();
    expect(screen.getByText("Provider ACK: true")).toBeTruthy();
    expect(screen.getByText("ACK Attempts: 1")).toBeTruthy();
    expect(screen.getByText("macos.network_extension: acknowledged")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Export JSON" }));
    expect(exportAsJSON).toHaveBeenCalledWith(
      [candidatePayload, stagedPayload, deltaPayload, liveApplyPayload],
      "rule-impact-policy-delta-impact-1",
    );
  });
});
