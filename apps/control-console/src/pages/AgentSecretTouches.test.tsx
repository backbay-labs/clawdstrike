import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  type AgentSecretTouchesFleetPublishResponse,
  type AgentSecretTouchesResponse,
  fetchAgentSecretTouches,
  publishAgentSecretTouchesToFleet,
} from "../api/client";
import { exportAsJSON } from "../utils/exportData";
import { AgentSecretTouches } from "./AgentSecretTouches";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    fetchAgentSecretTouches: vi.fn(),
    publishAgentSecretTouchesToFleet: vi.fn(),
  };
});

vi.mock("../utils/exportData", () => ({
  exportAsJSON: vi.fn(),
}));

const touchesPayload: AgentSecretTouchesResponse = {
  touchCount: 1,
  touches: [
    {
      credentialNodeId: "credential:aws",
      credentialLabel: "/Users/alice/.aws/credentials",
      credentialKind: "cloud_credential",
      path: "/Users/alice/.aws/credentials",
      name: "aws-credentials",
      agentNodeIds: ["agent:codex"],
      agentLabels: ["agent:codex", "mcp__filesystem__read_file"],
      processNodeIds: ["process:python"],
      graph: {
        nodes: {
          "credential:aws": { kind: "credential", label: "/Users/alice/.aws/credentials" },
          "agent:codex": { kind: "agent", label: "agent:codex" },
          "process:python": { kind: "process", label: "/usr/bin/python3" },
        },
        edges: [
          {
            from: "agent:codex",
            to: "credential:aws",
            kind: "read",
          },
        ],
      },
      receipt: {
        receipt: {
          metadata: {
            endpointDecision: {
              receiptFamily: "graph_slice",
              graph: { processNodeId: "credential:aws" },
            },
          },
        },
      },
    },
  ],
};

const publishPayload: AgentSecretTouchesFleetPublishResponse = {
  touchCount: 1,
  publishedCount: 1,
  events: [
    {
      eventId: "hunt-event-1",
      rawRef: "nats://hunt.raw/hunt-event-1",
      credentialNodeId: "credential:aws",
    },
  ],
};

describe("AgentSecretTouches", () => {
  beforeEach(() => {
    vi.mocked(fetchAgentSecretTouches).mockReset();
    vi.mocked(publishAgentSecretTouchesToFleet).mockReset();
    vi.mocked(exportAsJSON).mockReset();
  });

  it("queries credential touch graph slices, publishes them to fleet, and exports evidence", async () => {
    vi.mocked(fetchAgentSecretTouches).mockResolvedValue(touchesPayload);
    vi.mocked(publishAgentSecretTouchesToFleet).mockResolvedValue(publishPayload);

    render(<AgentSecretTouches />);

    fireEvent.change(screen.getByLabelText("Session ID"), {
      target: { value: "agent-secret-session-1" },
    });
    fireEvent.change(screen.getByLabelText("Credential Kind"), {
      target: { value: "cloud_credential" },
    });
    fireEvent.change(screen.getByLabelText("Limit"), {
      target: { value: "10" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Query Touches" }));

    await waitFor(() => {
      expect(fetchAgentSecretTouches).toHaveBeenCalledWith({
        sessionId: "agent-secret-session-1",
        credentialKind: "cloud_credential",
        requireAgentContext: true,
        upstreamDepth: 3,
        downstreamDepth: 1,
        limit: 10,
      });
    });
    expect(await screen.findByText("/Users/alice/.aws/credentials")).toBeTruthy();
    expect(screen.getByText("mcp__filesystem__read_file")).toBeTruthy();
    expect((await screen.findAllByText("graph_slice")).length).toBeGreaterThan(0);
    expect(screen.getByText("process:python")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Publish to Fleet" }));
    await waitFor(() => {
      expect(publishAgentSecretTouchesToFleet).toHaveBeenCalledWith({
        sessionId: "agent-secret-session-1",
        credentialKind: "cloud_credential",
        requireAgentContext: true,
        upstreamDepth: 3,
        downstreamDepth: 1,
        limit: 10,
      });
    });
    expect(await screen.findByText("hunt-event-1")).toBeTruthy();
    expect(screen.getByText("nats://hunt.raw/hunt-event-1")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Export JSON" }));
    expect(exportAsJSON).toHaveBeenCalledWith(
      [touchesPayload, publishPayload],
      "agent-secret-touches-agent-secret-session-1",
    );
  });
});
