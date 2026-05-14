import { act, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ObservatoryTelemetryBridge } from "@/features/observatory/components/ObservatoryTelemetryBridge";
import { useHuntStore } from "@/features/hunt/stores/hunt-store";
import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";
import type { AgentEvent } from "@/lib/workbench/hunt-types";

function makeEvent(
  id: string,
  overrides: Partial<AgentEvent> = {},
): AgentEvent {
  return {
    id,
    timestamp: "2026-03-19T16:00:00.000Z",
    agentId: `agent-${id}`,
    agentName: `Agent ${id}`,
    sessionId: `session-${id}`,
    actionType: "shell_command",
    target: "/tmp/test",
    verdict: "allow",
    guardResults: [],
    policyVersion: "1.4.0",
    flags: [],
    ...overrides,
  };
}

const initialHuntState = useHuntStore.getState();
const initialObservatoryState = useObservatoryStore.getState();

describe("ObservatoryTelemetryBridge", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-19T16:00:00.000Z"));
    useHuntStore.setState({
      ...initialHuntState,
      baselines: [],
      connected: false,
      events: [],
      investigations: [],
      patterns: [],
      stats: initialHuntState.stats,
      actions: initialHuntState.actions,
    });
    useObservatoryStore.setState({
      ...initialObservatoryState,
      mission: null,
      selectedStationId: null,
      stations: initialObservatoryState.stations.map((station) => ({
        ...station,
        artifactCount: 0,
      })),
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("projects hunt telemetry into observatory station state", () => {
    render(<ObservatoryTelemetryBridge />);

    act(() => {
      useHuntStore.setState((state) => ({
        ...state,
        connected: true,
        events: [
          makeEvent("receipt-1", { actionType: "file_access", receiptId: "receipt-1" }),
          makeEvent("receipt-2", { actionType: "file_write", receiptId: "receipt-2" }),
        ],
        investigations: [
          {
            id: "inv-1",
            title: "Receipt surge",
            status: "open",
            severity: "high",
            createdAt: "2026-03-19T16:00:00.000Z",
            updatedAt: "2026-03-19T16:00:00.000Z",
            createdBy: "operator",
            agentIds: ["agent-receipt-1"],
            sessionIds: ["session-receipt-1"],
            timeRange: {
              start: "2026-03-19T15:00:00.000Z",
              end: "2026-03-19T16:00:00.000Z",
            },
            eventIds: ["receipt-1"],
            annotations: [],
          },
        ],
      }));
    });

    const receipts = useObservatoryStore.getState().stations.find((station) => station.id === "receipts");
    expect(useObservatoryStore.getState().connected).toBe(true);
    expect(useObservatoryStore.getState().roomReceiveState).toBe("receiving");
    expect(useObservatoryStore.getState().likelyStationId).toBe("receipts");
    expect(useObservatoryStore.getState().pressureLanes[0]?.stationId).toBe("receipts");
    expect(receipts).toMatchObject({
      artifactCount: 2,
      explanation: {
        primaryLaneId: "receipts",
      },
      route: "/receipt-preview",
      status: "receiving",
    });
  });

  it("falls back to blocked stations when the hunt feed disconnects", () => {
    render(<ObservatoryTelemetryBridge />);

    const statuses = useObservatoryStore.getState().stations.map((station) => station.status);
    expect(statuses.every((status) => status === "blocked")).toBe(true);
    expect(useObservatoryStore.getState().connected).toBe(false);
    expect(useObservatoryStore.getState().pressureLanes.length).toBe(6);
  });
});
