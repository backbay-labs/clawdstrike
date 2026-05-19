import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  createResponseAction,
  fetchNetworkExtensionEgressPolicyProof,
  fetchResponseExecutions,
  type NetworkExtensionEgressPolicyProofResponse,
  type ResponseActionResponse,
  type ResponseExecutionRollbackResponse,
  type ResponseExecutionsResponse,
  rollbackResponseExecution,
} from "../api/client";
import { exportAsJSON } from "../utils/exportData";
import { LocalContainment } from "./LocalContainment";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    createResponseAction: vi.fn(),
    fetchNetworkExtensionEgressPolicyProof: vi.fn(),
    fetchResponseExecutions: vi.fn(),
    rollbackResponseExecution: vi.fn(),
  };
});

vi.mock("../utils/exportData", () => ({
  exportAsJSON: vi.fn(),
}));

const executionsPayload: ResponseExecutionsResponse = {
  path: "/tmp/response-executions.jsonl",
  execution_count: 1,
  executions: [
    {
      execution: {
        executionId: "exec-contain-1",
        actionId: "response-action-1",
        action: "suspend_process_tree",
        status: "succeeded",
        rootNodeId: "process:proc-contain-1",
        graphSliceId: "graph-slice-contain-1",
        ttlSeconds: 600,
        rollbackRef: "rollback:response-action-1",
        reason: "contain process tree for 10 minutes",
        completedAt: "2026-05-16T12:00:00Z",
        effects: [
          {
            effectId: "effect-1",
            effectType: "suspend_process_tree",
            target: "pid:4242",
          },
        ],
        evidenceBundle: {
          bundleId: "bundle-contain-1",
          graphSliceId: "graph-slice-contain-1",
          contentHash: "0xabc",
          nodeCount: 3,
          edgeCount: 2,
        },
      },
      expiresAt: "2026-05-16T12:10:00Z",
      expired: false,
      rollbackRef: "rollback:response-action-1",
      affectedIdentityCount: 2,
      affectedToolCount: 1,
      affectedIdentities: {
        hosts: [{ nodeId: "process:proc-contain-1", label: "host-exec-1", id: "host-exec-1" }],
        users: [{ nodeId: "process:proc-contain-1", label: "bob", id: "bob" }],
        sessions: [],
        agents: [],
        workloads: [],
        approvals: [],
      },
      affectedTools: [{ nodeId: "tool:mcp.exec", label: "mcp.exec", toolName: "mcp.exec" }],
    },
  ],
};

const actionPayload: ResponseActionResponse = {
  plan: {
    actionId: "response-action-1",
    action: "suspend_process_tree",
    dryRun: true,
    rootNodeId: "process:proc-contain-1",
    graphSliceId: "graph-slice-contain-1",
    ttlSeconds: 600,
    rollbackRef: "rollback:response-action-1",
    reason: "contain process tree for 10 minutes",
    createdAt: "2026-05-16T12:00:00Z",
    expiresAt: "2026-05-16T12:10:00Z",
    nodeCount: 3,
    edgeCount: 2,
  },
  graph: {
    nodes: {
      "process:proc-contain-1": { kind: "process", label: "/usr/bin/python3" },
      "network:exfil.example.invalid:443": {
        kind: "network",
        label: "exfil.example.invalid:443",
      },
    },
    edges: [
      {
        from: "process:proc-contain-1",
        to: "network:exfil.example.invalid:443",
        kind: "opened",
      },
    ],
  },
  affectedIdentityCount: 6,
  affectedToolCount: 1,
  affectedIdentities: {
    hosts: [{ nodeId: "process:proc-contain-1", label: "host-contain-1", id: "host-contain-1" }],
    users: [{ nodeId: "process:proc-contain-1", label: "alice", id: "alice" }],
    sessions: [
      {
        nodeId: "process:proc-contain-1",
        label: "session-contain-1",
        id: "session-contain-1",
      },
    ],
    agents: [
      {
        nodeId: "process:proc-contain-1",
        label: "agent-contain-1",
        id: "agent-contain-1",
      },
    ],
    workloads: [
      {
        nodeId: "process:proc-contain-1",
        label: "workload-contain-1",
        id: "workload-contain-1",
      },
    ],
    approvals: [
      {
        nodeId: "process:proc-contain-1",
        label: "approval-contain-1",
        id: "approval-contain-1",
      },
    ],
  },
  affectedTools: [{ nodeId: "tool:mcp.shell", label: "mcp.shell", toolName: "mcp.shell" }],
  receipt: {
    receipt: {
      metadata: {
        endpointDecision: {
          receiptFamily: "response_request",
          graph: { graphSliceId: "graph-slice-contain-1" },
        },
      },
    },
  },
};

const liveRestrictPayload: ResponseActionResponse = {
  plan: {
    actionId: "response-action-egress-1",
    action: "restrict_egress",
    dryRun: false,
    rootNodeId: "process:proc-contain-1",
    graphSliceId: "graph-slice-contain-1",
    ttlSeconds: 600,
    rollbackRef: "rollback:response-action-egress-1",
    reason: "contain egress for 10 minutes",
    createdAt: "2026-05-16T12:00:00Z",
    expiresAt: "2026-05-16T12:10:00Z",
    nodeCount: 3,
    edgeCount: 2,
  },
  graph: actionPayload.graph,
  receipt: actionPayload.receipt,
  execution: {
    executionId: "exec-egress-1",
    actionId: "response-action-egress-1",
    action: "restrict_egress",
    status: "succeeded",
    rootNodeId: "process:proc-contain-1",
    graphSliceId: "graph-slice-contain-1",
    ttlSeconds: 600,
    rollbackRef: "rollback:response-action-egress-1",
    reason: "contain egress for 10 minutes",
    completedAt: "2026-05-16T12:00:00Z",
    effects: [
      {
        effectId: "effect-egress-1",
        effectType: "restrict_egress",
        target: "egress:exfil.example.invalid:443",
      },
    ],
  },
  executionReceipt: {
    receipt: {
      metadata: {
        endpointDecision: {
          receiptFamily: "response_execution",
          evidence: [
            { key: "networkExtensionReloadRequested", valueHash: "0xreload-requested" },
            { key: "networkExtensionReloadSaved", valueHash: "0xreload-saved" },
            { key: "networkExtensionReloadRequestId", valueHash: "0xreload-request-id" },
            { key: "networkExtensionReloadGeneration", valueHash: "0xreload-generation" },
          ],
        },
      },
    },
  },
};

const rollbackPayload: ResponseExecutionRollbackResponse = {
  path: "/tmp/response-executions.jsonl",
  execution: executionsPayload.executions[0],
  rollback: {
    rollbackId: "rollback-contain-1",
    executionId: "exec-contain-1",
    action: "suspend_process_tree",
    status: "succeeded",
    rootNodeId: "process:proc-contain-1",
    graphSliceId: "graph-slice-contain-1",
    ttlSeconds: 600,
    rollbackRef: "rollback:response-action-1",
    reason: "operator rollback",
    completedAt: "2026-05-16T12:04:00Z",
    effects: [
      {
        effectId: "rollback-effect-1",
        effectType: "resume_process_tree",
        target: "pid:4242",
      },
    ],
    summary: "Resumed suspended process tree execution exec-contain-1.",
  },
  receipt: {
    receipt: {
      metadata: {
        endpointDecision: {
          receiptFamily: "response_rollback",
        },
      },
    },
  },
};

const egressProofPayload: NetworkExtensionEgressPolicyProofResponse = {
  providerPolicyPath: "/tmp/clawdstrike-network-egress-policy.json",
  snapshotPresent: true,
  snapshotDecodable: true,
  snapshotHash: "0xegress-proof",
  generatedAt: "2026-05-16T12:05:00Z",
  restrictionCount: 1,
  activeRestrictionCount: 1,
  expiredRestrictionCount: 0,
  enforcementReady: true,
  flowCounterObserved: true,
  observedFlowCount: 11,
  blockedFlowCount: 3,
  remediationRequestCount: 1,
  droppedVerdictCount: 0,
  providerReloadObserved: true,
  providerReloadRequestId: "provider-reload-observed-1",
  providerReloadGeneration: 5150,
  providerReloadPolicySnapshotPath: "/tmp/clawdstrike-network-egress-policy.json",
  providerReloadReloaded: true,
  providerReloadDelivery: {
    executionId: "exec-contain-1",
    observed: true,
    matched: true,
    requestIdMatches: true,
    generationMatches: true,
    policySnapshotPathMatches: true,
    providerReloaded: true,
  },
  providerStatusRefresh: { requested: true, refreshed: true },
  networkExtensionProvider: {
    runtime: "active",
    policy_synced: true,
    last_reload_observation: {
      request_id: "provider-reload-observed-1",
      policy_snapshot_path: "/tmp/clawdstrike-network-egress-policy.json",
      generation: 5150,
      reloaded: true,
    },
  },
  sensorState: {
    providers: [
      {
        providerId: "macos.network_extension",
        healthy: true,
        policySynced: true,
      },
    ],
  },
  receipt: {
    receipt: {
      metadata: {
        endpointDecision: {
          receiptFamily: "sensor_state",
        },
      },
    },
  },
  degradedProviderReceipts: [],
};

describe("LocalContainment", () => {
  beforeEach(() => {
    vi.mocked(createResponseAction).mockReset();
    vi.mocked(fetchNetworkExtensionEgressPolicyProof).mockReset();
    vi.mocked(fetchResponseExecutions).mockReset();
    vi.mocked(rollbackResponseExecution).mockReset();
    vi.mocked(exportAsJSON).mockReset();
  });

  it("dry-runs containment, displays TTL/rollback state, and rolls back a selected execution", async () => {
    vi.mocked(fetchResponseExecutions).mockResolvedValue(executionsPayload);
    vi.mocked(createResponseAction).mockResolvedValue(actionPayload);
    vi.mocked(rollbackResponseExecution).mockResolvedValue(rollbackPayload);

    render(<LocalContainment />);

    await waitFor(() => {
      expect(fetchResponseExecutions).toHaveBeenCalledWith({ limit: 25 });
    });
    expect((await screen.findAllByText("exec-contain-1")).length).toBeGreaterThan(0);
    expect(screen.getByText("Host: host-exec-1")).toBeTruthy();
    expect(screen.getByText("mcp.exec")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Process GUID"), {
      target: { value: "proc-contain-1" },
    });
    fireEvent.change(screen.getByLabelText("TTL Seconds"), {
      target: { value: "600" },
    });
    fireEvent.change(screen.getByLabelText("Reason"), {
      target: { value: "contain process tree for 10 minutes" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Dry-run Plan" }));

    await waitFor(() => {
      expect(createResponseAction).toHaveBeenCalledWith({
        process: { processGuid: "proc-contain-1" },
        action: "suspend_process_tree",
        ttlSeconds: 600,
        dryRun: true,
        reason: "contain process tree for 10 minutes",
      });
    });
    expect((await screen.findAllByText("TTL 600s")).length).toBeGreaterThan(0);
    expect(screen.getByText("rollback:response-action-1")).toBeTruthy();
    expect(screen.getByText("graph-slice-contain-1")).toBeTruthy();
    expect(screen.getByText("response_request")).toBeTruthy();
    expect(screen.getByText("exfil.example.invalid:443")).toBeTruthy();
    expect(screen.getByText("Host: host-contain-1")).toBeTruthy();
    expect(screen.getByText("User: alice")).toBeTruthy();
    expect(screen.getByText("Session: session-contain-1")).toBeTruthy();
    expect(screen.getByText("mcp.shell")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Rollback Selected" }));
    await waitFor(() => {
      expect(rollbackResponseExecution).toHaveBeenCalledWith("exec-contain-1", {
        reason: "contain process tree for 10 minutes",
      });
    });
    expect(await screen.findByText("response_rollback")).toBeTruthy();
    expect(screen.getByText("resume_process_tree")).toBeTruthy();
    expect(screen.getByText("rollback-contain-1")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Export JSON" }));
    expect(exportAsJSON).toHaveBeenCalledWith(
      [actionPayload, executionsPayload, rollbackPayload],
      "local-containment-exec-contain-1",
    );
  });

  it("fetches NetworkExtension egress-policy proof counters and exports the evidence", async () => {
    vi.mocked(fetchResponseExecutions).mockResolvedValue(executionsPayload);
    vi.mocked(fetchNetworkExtensionEgressPolicyProof).mockResolvedValue(egressProofPayload);

    render(<LocalContainment />);

    await waitFor(() => {
      expect(fetchResponseExecutions).toHaveBeenCalledWith({ limit: 25 });
    });

    fireEvent.click(screen.getByRole("button", { name: "Fetch Egress Proof" }));

    await waitFor(() => {
      expect(fetchNetworkExtensionEgressPolicyProof).toHaveBeenCalledWith({
        refreshProviders: true,
        executionId: "exec-contain-1",
      });
    });

    expect(await screen.findByText("0xegress-proof")).toBeTruthy();
    expect(screen.getByText("sensor_state")).toBeTruthy();
    expect(screen.getByText("11")).toBeTruthy();
    expect(screen.getByText("3")).toBeTruthy();
    expect(screen.getByText("provider-reload-observed-1")).toBeTruthy();
    expect(screen.getByText("5150")).toBeTruthy();
    expect(screen.getAllByText("exec-contain-1").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("Delivery Matched")).toBeTruthy();
    expect(screen.getByText("macos.network_extension")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Export JSON" }));
    expect(exportAsJSON).toHaveBeenCalledWith(
      [executionsPayload, egressProofPayload],
      "local-containment-exec-contain-1",
    );
  });

  it("surfaces signed NetworkExtension reload evidence after live egress containment", async () => {
    vi.mocked(fetchResponseExecutions).mockResolvedValue(executionsPayload);
    vi.mocked(createResponseAction).mockResolvedValue(liveRestrictPayload);

    render(<LocalContainment />);

    await waitFor(() => {
      expect(fetchResponseExecutions).toHaveBeenCalledWith({ limit: 25 });
    });

    fireEvent.change(screen.getByLabelText("Process GUID"), {
      target: { value: "proc-contain-1" },
    });
    fireEvent.change(screen.getByLabelText("Action"), {
      target: { value: "restrict_egress" },
    });
    fireEvent.change(screen.getByLabelText("Reason"), {
      target: { value: "contain egress for 10 minutes" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Execute Live" }));

    await waitFor(() => {
      expect(createResponseAction).toHaveBeenCalledWith({
        process: { processGuid: "proc-contain-1" },
        action: "restrict_egress",
        ttlSeconds: 600,
        dryRun: false,
        reason: "contain egress for 10 minutes",
        actor: { userId: "local-operator" },
      });
    });

    expect(await screen.findByText("response_execution")).toBeTruthy();
    expect(screen.getByText("0xreload-requested")).toBeTruthy();
    expect(screen.getByText("0xreload-saved")).toBeTruthy();
    expect(screen.getByText("0xreload-request-id")).toBeTruthy();
    expect(screen.getByText("0xreload-generation")).toBeTruthy();
  });
});
