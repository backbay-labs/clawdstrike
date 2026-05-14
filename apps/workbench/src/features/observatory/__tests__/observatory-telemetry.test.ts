import { describe, expect, it } from "vitest";
import type { AgentEvent, Investigation, HuntPattern } from "@/lib/workbench/hunt-types";
import {
  buildObservatoryReplayFrames,
  deriveObservatoryTelemetry,
  resolveObservatoryStationRoute,
} from "@/features/observatory/world/observatory-telemetry";

const NOW_MS = Date.parse("2026-03-19T16:00:00.000Z");

function makeEvent(
  id: string,
  overrides: Partial<AgentEvent> = {},
): AgentEvent {
  return {
    id,
    timestamp: new Date(NOW_MS - 5 * 60 * 1000).toISOString(),
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

describe("observatory telemetry", () => {
  it("maps live hunt pressure into station status, routing, and receive state", () => {
    const investigations: Investigation[] = [
      {
        id: "inv-1",
        title: "Receipt drift",
        status: "open",
        severity: "high",
        createdAt: new Date(NOW_MS - 30 * 60 * 1000).toISOString(),
        updatedAt: new Date(NOW_MS - 5 * 60 * 1000).toISOString(),
        createdBy: "operator",
        agentIds: ["agent-receipts"],
        sessionIds: ["session-receipts"],
        timeRange: {
          start: new Date(NOW_MS - 60 * 60 * 1000).toISOString(),
          end: new Date(NOW_MS).toISOString(),
        },
        eventIds: ["receipts-1"],
        annotations: [],
        verdict: "policy-gap",
      },
    ];
    const patterns: HuntPattern[] = [
      {
        id: "pattern-1",
        name: "Escalated receipt chain",
        description: "Receipt pressure remains elevated",
        discoveredAt: new Date(NOW_MS - 45 * 60 * 1000).toISOString(),
        status: "confirmed",
        sequence: [],
        matchCount: 3,
        exampleSessionIds: ["session-receipts"],
        agentIds: ["agent-receipts"],
      },
    ];

    const telemetry = deriveObservatoryTelemetry({
      connected: true,
      nowMs: NOW_MS,
      investigations,
      patterns,
      events: [
        makeEvent("receipts-1", {
          agentId: "agent-receipts",
          sessionId: "session-receipts",
          actionType: "file_access",
          verdict: "allow",
          receiptId: "receipt-1",
          anomalyScore: 0.24,
        }),
        makeEvent("receipts-2", {
          agentId: "agent-receipts",
          sessionId: "session-receipts",
          actionType: "file_write",
          verdict: "allow",
          receiptId: "receipt-2",
          anomalyScore: 0.22,
        }),
        makeEvent("run-1", {
          agentId: "agent-run",
          sessionId: "session-run",
          actionType: "shell_command",
        }),
      ],
    });

    const receipts = telemetry.stations.find((station) => station.id === "receipts");
    const watch = telemetry.stations.find((station) => station.id === "watch");

    expect(telemetry.likelyStationId).toBe("receipts");
    expect(telemetry.pressureLanes.slice(0, 2).map((lane) => lane.stationId)).toEqual([
      "receipts",
      "case-notes",
    ]);
    expect(telemetry.roomReceiveState).toBe("receiving");
    expect(receipts).toMatchObject({
      explanation: {
        primaryLaneId: "receipts",
      },
      route: "/receipt-preview",
      routeLabel: "Receipt Preview",
      status: "receiving",
    });
    expect(receipts?.explanation?.causes[0]).toMatchObject({
      route: "/receipt-preview",
      routeLabel: "Receipt Preview",
    });
    expect(watch?.route).toBe("/nexus");
    expect(telemetry.telemetrySnapshotMs).toBe(NOW_MS);
    expect(telemetry.confidence).toBeGreaterThan(0.3);
  });

  it("builds replay frames over the last 24 hours and appends the live frame", () => {
    const frames = buildObservatoryReplayFrames(
      [
        makeEvent("early", {
          timestamp: new Date(NOW_MS - 2 * 60 * 60 * 1000).toISOString(),
        }),
      ],
      NOW_MS,
    );

    expect(frames.length).toBeGreaterThan(1);
    expect(frames[frames.length - 1]).toMatchObject({
      eventCount: 1,
      timestampMs: NOW_MS,
    });
  });

  it("resolves direct workbench routes for every station surface", () => {
    expect(resolveObservatoryStationRoute("targets")).toEqual({
      kind: "hunt",
      label: "Pattern Mining",
      route: "/hunt?tab=patterns",
    });
    expect(resolveObservatoryStationRoute("watch").route).toBe("/nexus");
  });

  it("uses hysteresis to preserve the previous leader during a near tie", () => {
    const previousTelemetry = deriveObservatoryTelemetry({
      connected: true,
      nowMs: NOW_MS,
      events: [
        makeEvent("receipt-1", {
          actionType: "file_access",
          receiptId: "receipt-1",
        }),
        makeEvent("receipt-2", {
          actionType: "file_write",
          receiptId: "receipt-2",
        }),
      ],
      investigations: [
        {
          id: "inv-near-tie",
          title: "Evidence review",
          status: "open",
          severity: "medium",
          createdAt: new Date(NOW_MS - 30 * 60 * 1000).toISOString(),
          updatedAt: new Date(NOW_MS - 5 * 60 * 1000).toISOString(),
          createdBy: "operator",
          agentIds: ["agent-receipt-1"],
          sessionIds: ["session-receipt-1"],
          timeRange: {
            start: new Date(NOW_MS - 60 * 60 * 1000).toISOString(),
            end: new Date(NOW_MS).toISOString(),
          },
          eventIds: ["receipt-1"],
          annotations: [],
        },
      ],
    });

    const telemetry = deriveObservatoryTelemetry({
      connected: true,
      nowMs: NOW_MS + 5 * 60 * 1000,
      previousTelemetry,
      events: [
        makeEvent("watch-3", {
          timestamp: new Date(NOW_MS + 5 * 60 * 1000).toISOString(),
          actionType: "shell_command",
          anomalyScore: 0.2,
          verdict: "deny",
        }),
        makeEvent("receipt-3", {
          timestamp: new Date(NOW_MS + 5 * 60 * 1000).toISOString(),
          actionType: "file_access",
          receiptId: "receipt-3",
        }),
      ],
    });

    expect(previousTelemetry.likelyStationId).toBe("receipts");
    expect(telemetry.likelyStationId).toBe("receipts");
    expect(telemetry.pressureLanes.some((lane) => lane.stationId === "watch")).toBe(true);
  });
});
