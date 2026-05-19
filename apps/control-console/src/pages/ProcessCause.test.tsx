import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  type CausalContextResponse,
  type CausalSubgraphResponse,
  createCausalContext,
  createCausalSubgraph,
  exportGraphSlice,
  type GraphSliceExportResponse,
} from "../api/client";
import { exportAsJSON } from "../utils/exportData";
import { ProcessCause } from "./ProcessCause";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    createCausalContext: vi.fn(),
    createCausalSubgraph: vi.fn(),
    exportGraphSlice: vi.fn(),
  };
});

vi.mock("../utils/exportData", () => ({
  exportAsJSON: vi.fn(),
}));

const subgraphPayload: CausalSubgraphResponse = {
  root_node_id: "process:proc-1",
  max_depth: 3,
  node_count: 5,
  edge_count: 4,
  affected_identity_count: 2,
  affected_tool_count: 1,
  affected_identities: {
    hosts: [],
    users: [{ nodeId: "user:alice", label: "alice", id: "alice" }],
    sessions: [{ nodeId: "session:dev-session-1", label: "dev-session-1", id: "dev-session-1" }],
    agents: [],
    workloads: [],
    approvals: [],
  },
  affected_tools: [{ nodeId: "tool:mcp.shell", label: "mcp.shell", toolName: "mcp.shell" }],
  graph: {
    nodes: {
      "process:proc-1": { kind: "process", label: "/usr/bin/python3" },
      "session:dev-session-1": { kind: "session", label: "dev-session-1" },
      "tool:mcp.shell": { kind: "tool", label: "mcp.shell" },
      "network:api.example.invalid:443": { kind: "network", label: "api.example.invalid:443" },
      "user:alice": { kind: "user", label: "alice" },
    },
    edges: [
      { from: "user:alice", to: "process:proc-1", kind: "ran_as" },
      { from: "session:dev-session-1", to: "process:proc-1", kind: "in_session" },
      { from: "process:proc-1", to: "tool:mcp.shell", kind: "related" },
      { from: "process:proc-1", to: "network:api.example.invalid:443", kind: "opened" },
    ],
  },
  receipt: {
    receipt: {
      metadata: {
        endpointDecision: {
          receiptFamily: "graph_slice",
          graph: { graphSliceId: "graph-slice-1" },
        },
      },
    },
  },
};

const contextPayload: CausalContextResponse = {
  root_node_id: "network:api.example.invalid:443",
  upstream_depth: 2,
  downstream_depth: 1,
  node_count: 5,
  edge_count: 4,
  affected_identity_count: 1,
  affected_tool_count: 1,
  affected_identities: {
    hosts: [],
    users: [],
    sessions: [
      { nodeId: "session:context-session-1", label: "context-session-1", id: "context-session-1" },
    ],
    agents: [],
    workloads: [],
    approvals: [],
  },
  affected_tools: [{ nodeId: "tool:mcp.browser", label: "mcp.browser", toolName: "mcp.browser" }],
  graph: {
    nodes: {
      "process:proc-1": { kind: "process", label: "/usr/bin/python3" },
      "session:context-session-1": { kind: "session", label: "context-session-1" },
      "tool:mcp.browser": { kind: "tool", label: "mcp.browser" },
      "credential:npm-token": { kind: "credential", label: "/Users/alice/.npmrc" },
      "network:api.example.invalid:443": { kind: "network", label: "api.example.invalid:443" },
    },
    edges: [
      { from: "session:context-session-1", to: "process:proc-1", kind: "in_session" },
      { from: "process:proc-1", to: "tool:mcp.browser", kind: "related" },
      { from: "credential:npm-token", to: "process:proc-1", kind: "read_by" },
      { from: "process:proc-1", to: "network:api.example.invalid:443", kind: "opened" },
    ],
  },
  receipt: {
    receipt: {
      metadata: {
        endpointDecision: {
          receiptFamily: "graph_slice",
          graph: { graphSliceId: "graph-slice-context-1" },
        },
      },
    },
  },
};

const exportPayload: GraphSliceExportResponse = {
  rootNodeId: "process:proc-1",
  sliceKind: "causal_subgraph",
  nodeCount: 2,
  edgeCount: 1,
  affectedIdentityCount: 1,
  affectedToolCount: 1,
  affectedIdentities: {
    hosts: [],
    users: [{ nodeId: "user:exporter", label: "exporter", id: "exporter" }],
    sessions: [],
    agents: [],
    workloads: [],
    approvals: [],
  },
  affectedTools: [{ nodeId: "tool:mcp.export", label: "mcp.export", toolName: "mcp.export" }],
  graph: subgraphPayload.graph,
  bundle: {
    bundleId: "bundle-1",
    graphSliceId: "graph-slice-1",
    contentHash: "0xabc",
    nodeCount: 2,
    edgeCount: 1,
  },
  artifact: {
    bundleId: "bundle-1",
    path: "/tmp/bundle-1.json",
    byteCount: 512,
    contentHash: "0xabc",
  },
  receipt: {
    receipt: {
      metadata: {
        endpointDecision: {
          receiptFamily: "graph_slice",
        },
      },
    },
  },
};

describe("ProcessCause", () => {
  beforeEach(() => {
    vi.mocked(createCausalSubgraph).mockReset();
    vi.mocked(createCausalContext).mockReset();
    vi.mocked(exportGraphSlice).mockReset();
    vi.mocked(exportAsJSON).mockReset();
  });

  it("renders a process-cause subgraph and exports a persisted graph slice", async () => {
    vi.mocked(createCausalSubgraph).mockResolvedValue(subgraphPayload);
    vi.mocked(exportGraphSlice).mockResolvedValue(exportPayload);

    render(<ProcessCause />);

    fireEvent.change(screen.getByLabelText("Process GUID"), { target: { value: "proc-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Show Effects" }));

    await waitFor(() => {
      expect(createCausalSubgraph).toHaveBeenCalledWith({
        process: { processGuid: "proc-1" },
        maxDepth: 3,
      });
    });
    expect(await screen.findByText("/usr/bin/python3")).toBeTruthy();
    expect(screen.getByText("api.example.invalid:443")).toBeTruthy();
    expect(screen.getByText("graph_slice")).toBeTruthy();
    expect(screen.getAllByText("user:alice").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("session:dev-session-1").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("mcp.shell").length).toBeGreaterThanOrEqual(1);

    fireEvent.click(screen.getByRole("button", { name: "Export Slice" }));
    await waitFor(() => {
      expect(exportGraphSlice).toHaveBeenCalledWith({
        rootNodeId: "process:proc-1",
        sliceKind: "causal_subgraph",
        maxDepth: 3,
        reason: "operator graph-slice export",
      });
    });
    expect(await screen.findByText("bundle-1")).toBeTruthy();
    expect(screen.getByText("graph-slice-1")).toBeTruthy();
    expect(screen.getByText("user:exporter")).toBeTruthy();
    expect(screen.getByText("mcp.export")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Export JSON" }));
    expect(exportAsJSON).toHaveBeenCalledWith([exportPayload], "graph-slice-bundle-1");
  });

  it("renders upstream and downstream causal context for a root node", async () => {
    vi.mocked(createCausalContext).mockResolvedValue(contextPayload);

    render(<ProcessCause />);

    fireEvent.change(screen.getByLabelText("Root Node ID"), {
      target: { value: "network:api.example.invalid:443" },
    });
    fireEvent.change(screen.getByLabelText("Upstream Depth"), { target: { value: "2" } });
    fireEvent.change(screen.getByLabelText("Downstream Depth"), { target: { value: "1" } });
    fireEvent.click(screen.getByRole("button", { name: "Show Context" }));

    await waitFor(() => {
      expect(createCausalContext).toHaveBeenCalledWith({
        rootNodeId: "network:api.example.invalid:443",
        upstreamDepth: 2,
        downstreamDepth: 1,
      });
    });
    expect(await screen.findByText("/Users/alice/.npmrc")).toBeTruthy();
    expect(screen.getByText("Context: causal_context")).toBeTruthy();
    expect(screen.getByText("graph-slice-context-1")).toBeTruthy();
    expect(screen.getAllByText("session:context-session-1").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("mcp.browser").length).toBeGreaterThanOrEqual(1);
  });
});
