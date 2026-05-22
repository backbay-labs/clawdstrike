import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { type FindingGroupsResponse, fetchFindingGroups } from "../api/client";
import { exportAsJSON } from "../utils/exportData";
import { CausalGroups } from "./CausalGroups";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    fetchFindingGroups: vi.fn(),
  };
});

vi.mock("../utils/exportData", () => ({
  exportAsJSON: vi.fn(),
}));

const groupsPayload: FindingGroupsResponse = {
  groupCount: 1,
  findingCount: 2,
  groups: [
    {
      groupId: "group-1",
      rootNodeId: "process:proc-1",
      rootLabel: "/usr/local/bin/npm",
      findingCount: 2,
      nodeCount: 3,
      edgeCount: 2,
      ruleIds: ["supply_chain.developer_secret_access", "supply_chain.install_script.risky"],
      findingIds: ["finding-1", "finding-2"],
      affectedIdentityCount: 2,
      affectedToolCount: 1,
      affectedIdentities: {
        hosts: [],
        users: [{ nodeId: "user:alice", label: "alice", id: "alice" }],
        sessions: [
          {
            nodeId: "session:finding-group-session-1",
            label: "finding-group-session-1",
            id: "finding-group-session-1",
          },
        ],
        agents: [],
        workloads: [],
        approvals: [],
      },
      affectedTools: [
        {
          nodeId: "tool:mcp.shell",
          label: "mcp.shell",
          toolName: "mcp.shell",
        },
      ],
      findings: [
        {
          findingId: "finding-1",
          ruleId: "supply_chain.install_script.risky",
          title: "Risky package install script",
          severity: "high",
        },
        {
          findingId: "finding-2",
          ruleId: "supply_chain.developer_secret_access",
          title: "Developer secret access",
          severity: "high",
        },
      ],
      graph: {
        nodes: {
          "process:proc-1": { kind: "process", label: "/usr/local/bin/npm" },
          "package_script:postinstall": { kind: "package_script", label: "postinstall" },
          "credential:aws": { kind: "credential", label: "aws-credentials" },
        },
        edges: [{ from: "process:proc-1", to: "credential:aws", kind: "read" }],
      },
      receipt: {
        receipt: {
          metadata: {
            endpointDecision: {
              receiptFamily: "graph_slice",
              decision: { findingId: "group-1" },
            },
          },
        },
      },
    },
  ],
};

describe("CausalGroups", () => {
  beforeEach(() => {
    vi.mocked(fetchFindingGroups).mockReset();
    vi.mocked(exportAsJSON).mockReset();
  });

  it("renders causal finding groups with graph and receipt evidence", async () => {
    vi.mocked(fetchFindingGroups).mockResolvedValue(groupsPayload);

    render(<CausalGroups />);

    await waitFor(() => {
      expect(fetchFindingGroups).toHaveBeenCalledWith({ limit: 25, maxDepth: 3 });
    });
    expect(await screen.findByText("/usr/local/bin/npm")).toBeTruthy();
    expect(screen.getByText("Groups: 1")).toBeTruthy();
    expect(screen.getByText("Findings: 2")).toBeTruthy();
    expect(screen.getByText("supply_chain.install_script.risky")).toBeTruthy();
    expect(screen.getByText("supply_chain.developer_secret_access")).toBeTruthy();
    expect(screen.getByText("finding-1")).toBeTruthy();
    expect(screen.getByText("process")).toBeTruthy();
    expect(screen.getByText("package_script")).toBeTruthy();
    expect(screen.getByText("credential")).toBeTruthy();
    expect(screen.getByText("user:alice")).toBeTruthy();
    expect(screen.getByText("session:finding-group-session-1")).toBeTruthy();
    expect(screen.getByText("mcp.shell")).toBeTruthy();
    expect(screen.getByText("graph_slice")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Export Group" }));
    expect(exportAsJSON).toHaveBeenCalledWith([groupsPayload.groups[0]], "causal-group-group-1");
  });
});
