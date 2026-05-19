import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createPolicyReplay, type PolicyReplayResponse } from "../api/client";
import { exportAsJSON } from "../utils/exportData";
import { PolicyReplay } from "./PolicyReplay";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    createPolicyReplay: vi.fn(),
  };
});

vi.mock("../utils/exportData", () => ({
  exportAsJSON: vi.fn(),
}));

const replayPayload: PolicyReplayResponse = {
  replay: {
    replayId: "policy-replay-1",
    replayedAt: "2026-05-16T12:00:00Z",
    mode: "current_policy_graph_replay",
    policy: {
      policyVersion: "test-edr-replay",
      policyHash: "sha256:policy",
      policyEpoch: 77,
    },
    rootNodeId: "process:proc-replay-1",
    rootLabel: "/usr/local/bin/npm",
    rootKind: "process",
    action: "block",
    graphSliceId: "graph-slice-replay-1",
    observationCount: 2,
    nodeCount: 3,
    edgeCount: 2,
    flightRecorderObservationCount: 5,
    wouldEnforce: true,
    developerBreakageScore: 72,
    impactLevel: "high",
    summary:
      "Replayed graph slice graph-slice-replay-1 under current endpoint policy test-edr-replay epoch 77.",
  },
  simulation: {
    simulationId: "simulation-1",
    ruleId: "endpoint.current_policy_replay.epoch_77.block.process.npm",
    action: "block",
    rootNodeId: "process:proc-replay-1",
    graphSliceId: "graph-slice-replay-1",
    wouldBlock: true,
    createdAt: "2026-05-16T12:00:00Z",
    affectedNodeCount: 3,
    affectedEdgeCount: 2,
    affectedProcessCount: 1,
    affectedFileCount: 0,
    affectedNetworkCount: 1,
    affectedCredentialCount: 1,
    affectedToolCount: 0,
    developerBreakageScore: 72,
    impactLevel: "high",
    summary: "Would block captured graph.",
    affectedNodes: [
      {
        nodeId: "credential:npm-token",
        kind: "credential",
        label: "/Users/alice/.npmrc",
        breakageScore: 90,
        reason: "credential access would be blocked",
      },
      {
        nodeId: "network:registry.npmjs.org:443",
        kind: "network",
        label: "registry.npmjs.org:443",
        breakageScore: 50,
        reason: "network effect would be interrupted",
      },
    ],
    affectedIdentities: [
      {
        identityKind: "user",
        value: "alice",
        sourceNodeId: "process:proc-replay-1",
        sourceNodeKind: "process",
      },
      {
        identityKind: "session",
        value: "session-replay-1",
        sourceNodeId: "process:proc-replay-1",
        sourceNodeKind: "process",
      },
    ],
    affectedTools: [
      {
        toolName: "mcp.shell",
        toolCallId: "tool-call-replay-1",
        sourceNodeId: "tool:mcp.shell",
      },
    ],
  },
  graph: {
    nodes: {
      "process:proc-replay-1": { kind: "process", label: "/usr/local/bin/npm" },
      "credential:npm-token": { kind: "credential", label: "/Users/alice/.npmrc" },
      "network:registry.npmjs.org:443": { kind: "network", label: "registry.npmjs.org:443" },
    },
    edges: [
      { from: "process:proc-replay-1", to: "credential:npm-token", kind: "read" },
      { from: "process:proc-replay-1", to: "network:registry.npmjs.org:443", kind: "opened" },
    ],
  },
  receipt: {
    receipt: {
      metadata: {
        endpointDecision: {
          receiptFamily: "simulation",
          policy: { policyEpoch: 77 },
          graph: { graphSliceId: "graph-slice-replay-1" },
        },
      },
    },
  },
};

describe("PolicyReplay", () => {
  beforeEach(() => {
    vi.mocked(createPolicyReplay).mockReset();
    vi.mocked(exportAsJSON).mockReset();
  });

  it("replays a captured process graph under the current local policy", async () => {
    vi.mocked(createPolicyReplay).mockResolvedValue(replayPayload);

    render(<PolicyReplay />);

    fireEvent.change(screen.getByLabelText("Process GUID"), {
      target: { value: "proc-replay-1" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Replay Policy" }));

    await waitFor(() => {
      expect(createPolicyReplay).toHaveBeenCalledWith({
        process: { processGuid: "proc-replay-1" },
        action: "block",
        maxDepth: 8,
      });
    });
    expect(await screen.findByText("test-edr-replay")).toBeTruthy();
    expect(screen.getByText("Epoch 77")).toBeTruthy();
    expect(screen.getByText("current_policy_graph_replay")).toBeTruthy();
    expect(screen.getByText("Would enforce: yes")).toBeTruthy();
    expect(screen.getByText("72/100")).toBeTruthy();
    expect(screen.getAllByText("high").length).toBeGreaterThan(0);
    expect(screen.getByText("/usr/local/bin/npm")).toBeTruthy();
    expect(
      screen.getByText("endpoint.current_policy_replay.epoch_77.block.process.npm"),
    ).toBeTruthy();
    expect(screen.getByText("/Users/alice/.npmrc")).toBeTruthy();
    expect(screen.getByText("session-replay-1")).toBeTruthy();
    expect(screen.getByText("mcp.shell")).toBeTruthy();
    expect(screen.getByText("tool:mcp.shell / tool-call-replay-1")).toBeTruthy();
    expect(screen.getByText("simulation")).toBeTruthy();
    expect(screen.getByText("graph-slice-replay-1")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Export JSON" }));
    expect(exportAsJSON).toHaveBeenCalledWith([replayPayload], "policy-replay-policy-replay-1");
  });
});
