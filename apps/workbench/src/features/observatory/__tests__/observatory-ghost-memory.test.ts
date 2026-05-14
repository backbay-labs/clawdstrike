import { describe, expect, it } from "vitest";
import type { AgentEvent, Investigation } from "@/lib/workbench/hunt-types";
import type { ObservatoryStation } from "@/features/observatory/types";
import { createInitialObservatoryProbeState, dispatchObservatoryProbe } from "@/features/observatory/world/probeRuntime";
import {
  deriveObservatoryGhostMemories,
  resolveObservatoryGhostPresentation,
} from "@/features/observatory/world/observatory-ghost-memory";

function makeStation(
  id: ObservatoryStation["id"],
  overrides: Partial<ObservatoryStation> = {},
): ObservatoryStation {
  return {
    artifactCount: 0,
    affinity: 0.4,
    emphasis: 0.3,
    id,
    kind: "observatory",
    label: id.toUpperCase(),
    route: `/${id}`,
    routeLabel: id.toUpperCase(),
    status: "warming",
    ...overrides,
  };
}

function makeInvestigation(overrides: Partial<Investigation> = {}): Investigation {
  return {
    agentIds: ["agent-1"],
    actions: [],
    annotations: [
      {
        createdAt: "2026-03-19T10:00:00.000Z",
        createdBy: "operator",
        id: "ann-1",
        text: "Receipt pressure is clustering around denied evidence.",
      },
    ],
    createdAt: "2026-03-19T09:00:00.000Z",
    createdBy: "operator",
    eventIds: ["evt-1"],
    id: "inv-1",
    severity: "high",
    sessionIds: ["session-1"],
    status: "in-progress",
    title: "Denied receipts cluster",
    timeRange: { start: "2026-03-19T09:00:00.000Z", end: "2026-03-19T10:00:00.000Z" },
    updatedAt: "2026-03-19T10:05:00.000Z",
    verdict: "policy-gap",
    ...overrides,
  };
}

function makeReceiptEvent(overrides: Partial<AgentEvent> = {}): AgentEvent {
  return {
    actionType: "shell_command",
    agentId: "agent-1",
    agentName: "Agent One",
    content: "Denied receipt trace",
    flags: [],
    guardResults: [],
    id: "evt-1",
    policyVersion: "1.0.0",
    receiptId: "receipt-1",
    sessionId: "session-1",
    target: "/tmp/input",
    timestamp: "2026-03-19T11:00:00.000Z",
    verdict: "deny",
    ...overrides,
  };
}

describe("deriveObservatoryGhostMemories", () => {
  it("produces ranked finding ghosts for the matching district", () => {
    const traces = deriveObservatoryGhostMemories({
      activeStationId: "receipts",
      ghostMode: "auto",
      investigations: [makeInvestigation()],
      nowMs: Date.parse("2026-03-20T00:00:00.000Z"),
      selectedStationId: "receipts",
      stations: [
        makeStation("receipts", { emphasis: 0.82, status: "active" }),
        makeStation("watch", { emphasis: 0.24, status: "idle" }),
      ],
    });

    expect(traces[0].stationId).toBe("receipts");
    expect(traces[0].sourceKind).toBe("finding");
    expect(traces[0].headline).toContain("Denied receipts cluster");
  });

  it("turns denied or receipt-bearing events into receipt-history ghosts when no finding exists", () => {
    const traces = deriveObservatoryGhostMemories({
      events: [makeReceiptEvent()],
      ghostMode: "auto",
      nowMs: Date.parse("2026-03-20T00:00:00.000Z"),
      stations: [
        makeStation("receipts", { emphasis: 0.7, status: "receiving" }),
        makeStation("watch", { emphasis: 0.2, status: "idle" }),
      ],
    });

    expect(traces[0].sourceKind).toBe("receipt");
    expect(traces[0].detail).toContain("denied");
  });

  it("caps traces per district and keeps findings ahead of receipt noise", () => {
    const traces = deriveObservatoryGhostMemories({
      events: [
        makeReceiptEvent({ id: "evt-2", receiptId: "receipt-2" }),
        makeReceiptEvent({ id: "evt-3", receiptId: "receipt-3" }),
      ],
      investigations: [
        makeInvestigation({ id: "inv-2", title: "Receipt pressure hardening", updatedAt: "2026-03-19T11:10:00.000Z" }),
        makeInvestigation({ id: "inv-3", title: "Receipt pressure spillover", updatedAt: "2026-03-19T11:20:00.000Z" }),
      ],
      ghostMode: "auto",
      nowMs: Date.parse("2026-03-20T00:00:00.000Z"),
      stations: [makeStation("receipts", { emphasis: 0.86, status: "active" })],
    });

    const receiptTraces = traces.filter((trace) => trace.stationId === "receipts");
    expect(receiptTraces.length).toBeLessThanOrEqual(2);
    expect(receiptTraces[0].sourceKind).toBe("finding");
  });

  it("resolves presentation to focused or off when replay or probe pressure makes clutter risky", () => {
    const probeState = dispatchObservatoryProbe(createInitialObservatoryProbeState(), "watch", 0);

    expect(resolveObservatoryGhostPresentation({ ghostMode: "off" })).toBe("off");
    expect(resolveObservatoryGhostPresentation({ ghostMode: "auto", mode: "flow" })).toBe("focused");
    expect(resolveObservatoryGhostPresentation({ ghostMode: "auto", probeState })).toBe("focused");
    expect(resolveObservatoryGhostPresentation({ ghostMode: "auto", replayEnabled: true })).toBe("focused");
    expect(resolveObservatoryGhostPresentation({ ghostMode: "full" })).toBe("full");
  });
});
