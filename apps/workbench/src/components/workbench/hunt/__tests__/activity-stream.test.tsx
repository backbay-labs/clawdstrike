import { useState } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ActivityStream } from "../activity-stream";
import type { AgentEvent, StreamFilters, StreamStats } from "@/lib/workbench/hunt-types";

function makeEvent(overrides: Partial<AgentEvent>): AgentEvent {
  return {
    id: overrides.id ?? crypto.randomUUID(),
    timestamp: overrides.timestamp ?? "2026-03-12T12:00:00.000Z",
    agentId: overrides.agentId ?? "agent-1",
    agentName: overrides.agentName ?? "agent-one",
    sessionId: overrides.sessionId ?? "session-1",
    actionType: overrides.actionType ?? "file_access",
    target: overrides.target ?? "/tmp/file.txt",
    verdict: overrides.verdict ?? "allow",
    guardResults: overrides.guardResults ?? [],
    policyVersion: overrides.policyVersion ?? "1.0.0",
    flags: overrides.flags ?? [],
    teamId: overrides.teamId,
    content: overrides.content,
    receiptId: overrides.receiptId,
    anomalyScore: overrides.anomalyScore,
    trustprintScore: overrides.trustprintScore,
  };
}

const stats: StreamStats = {
  total: 2,
  allowed: 2,
  denied: 0,
  warned: 0,
  anomalies: 0,
  byActionType: {},
};

function ActivityStreamHarness({ events }: { events: AgentEvent[] }) {
  const [filters, setFilters] = useState<StreamFilters>({ timeRange: "24h" });

  return (
    <ActivityStream
      events={events}
      onEscalate={vi.fn()}
      onFilterChange={setFilters}
      filters={filters}
      stats={stats}
      live={false}
      onToggleLive={vi.fn()}
    />
  );
}

describe("ActivityStream", () => {
  it("stores the selected agent filter by agent id while showing the agent name", async () => {
    const user = userEvent.setup();
    const events = [
      makeEvent({ id: "evt-1", agentId: "unknown", agentName: "unknown-agent" }),
      makeEvent({
        id: "evt-2",
        agentId: "agent-2",
        agentName: "named-agent",
        target: "/tmp/other.txt",
        sessionId: "session-2",
      }),
    ];

    render(<ActivityStreamHarness events={events} />);

    expect(screen.getByText("unknown-agent")).toBeInTheDocument();
    expect(screen.getByText("named-agent")).toBeInTheDocument();

    await user.click(screen.getByTestId("activity-stream-agent-filter"));
    await user.click(await screen.findByRole("option", { name: "unknown-agent" }));

    await waitFor(() => {
      expect(screen.getByTestId("activity-stream-visible-count")).toHaveTextContent("1");
    });
  });
});
