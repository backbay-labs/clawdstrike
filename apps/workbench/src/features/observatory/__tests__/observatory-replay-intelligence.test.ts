import { describe, expect, it } from "vitest";
import type {
  AgentEvent,
  Investigation,
} from "@/lib/workbench/hunt-types";
import {
  buildObservatoryReplaySnapshot,
  buildObservatoryReplayTimeline,
  detectObservatoryReplaySpikes,
  deriveObservatoryTelemetry,
  findObservatoryReplaySpikeFrameIndex,
} from "@/features/observatory/world/observatory-telemetry";

const NOW_MS = Date.parse("2026-03-19T16:00:00.000Z");

function makeEvent(
  id: string,
  timestampMs: number,
  overrides: Partial<AgentEvent> = {},
): AgentEvent {
  return {
    id,
    timestamp: new Date(timestampMs).toISOString(),
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

function makeReceiptInvestigation(timestampMs: number): Investigation {
  return {
    id: `inv-${timestampMs}`,
    title: "Receipt surge",
    status: "open",
    severity: "high",
    createdAt: new Date(timestampMs - 15 * 60 * 1000).toISOString(),
    updatedAt: new Date(timestampMs).toISOString(),
    createdBy: "operator",
    agentIds: ["agent-receipt-1"],
    sessionIds: ["session-receipt-1"],
    timeRange: {
      start: new Date(timestampMs - 30 * 60 * 1000).toISOString(),
      end: new Date(timestampMs).toISOString(),
    },
    eventIds: ["receipt-1"],
    annotations: [],
    verdict: "policy-gap",
  };
}

describe("observatory replay intelligence", () => {
  it("builds normalized snapshots for each replay frame and preserves district reads", () => {
    const firstReceipt = NOW_MS - 50 * 60 * 1000;
    const timeline = buildObservatoryReplayTimeline({
      connected: true,
      events: [
        makeEvent("receipt-1", firstReceipt, {
          actionType: "file_access",
          receiptId: "receipt-1",
        }),
        makeEvent("receipt-2", NOW_MS - 25 * 60 * 1000, {
          actionType: "file_write",
          receiptId: "receipt-2",
        }),
        makeEvent("receipt-3", NOW_MS - 20 * 60 * 1000, {
          actionType: "file_write",
          receiptId: "receipt-3",
        }),
        makeEvent("receipt-4", NOW_MS - 15 * 60 * 1000, {
          actionType: "file_write",
          receiptId: "receipt-4",
        }),
        makeEvent("receipt-5", NOW_MS - 10 * 60 * 1000, {
          actionType: "file_write",
          receiptId: "receipt-5",
        }),
      ],
      investigations: [makeReceiptInvestigation(NOW_MS - 10 * 60 * 1000)],
      nowMs: NOW_MS,
    });

    expect(timeline.snapshots).toHaveLength(timeline.frames.length);
    expect(timeline.snapshots[0]).toMatchObject({
      label: timeline.frames[0].label,
      timestampMs: timeline.frames[0].timestampMs,
    });
    const lastSnapshot = timeline.snapshots[timeline.snapshots.length - 1]!;
    const lastFrame = timeline.frames[timeline.frames.length - 1]!;

    expect(lastSnapshot).toMatchObject({
      label: lastFrame.label,
      timestampMs: NOW_MS,
    });

    const receipts = lastSnapshot?.districts.find(
      (district: (typeof lastSnapshot)["districts"][number]) => district.districtId === "receipts",
    );
    expect(receipts).toMatchObject({
      explanation: {
        primaryLaneId: "receipts",
      },
      route: "/receipt-preview",
      routeLabel: "Receipt Preview",
      status: "receiving",
    });
  });

  it("flags quiet snapshots and detects real spike transitions from derived telemetry", () => {
    const lowTelemetry = deriveObservatoryTelemetry({
      connected: true,
      events: [
        makeEvent("receipt-1", NOW_MS - 40 * 60 * 1000, {
          actionType: "file_access",
          receiptId: "receipt-1",
        }),
      ],
      nowMs: NOW_MS,
    });
    const highTelemetry = deriveObservatoryTelemetry({
      connected: true,
      events: [
        makeEvent("receipt-1", NOW_MS - 40 * 60 * 1000, {
          actionType: "file_access",
          receiptId: "receipt-1",
        }),
        makeEvent("receipt-2", NOW_MS - 15 * 60 * 1000, {
          actionType: "file_write",
          receiptId: "receipt-2",
        }),
        makeEvent("receipt-3", NOW_MS - 10 * 60 * 1000, {
          actionType: "file_write",
          receiptId: "receipt-3",
        }),
        makeEvent("receipt-4", NOW_MS - 5 * 60 * 1000, {
          actionType: "file_write",
          receiptId: "receipt-4",
        }),
        makeEvent("receipt-5", NOW_MS - 1 * 60 * 1000, {
          actionType: "file_write",
          receiptId: "receipt-5",
        }),
      ],
      investigations: [makeReceiptInvestigation(NOW_MS - 15 * 60 * 1000)],
      nowMs: NOW_MS,
    });

    const quietSnapshots = [
      buildObservatoryReplaySnapshot({
        frame: {
          eventCount: 1,
          label: "15:00",
          timestampMs: NOW_MS - 30 * 60 * 1000,
        },
        frameIndex: 0,
        telemetry: lowTelemetry,
      }),
      buildObservatoryReplaySnapshot({
        frame: {
          eventCount: 1,
          label: "15:30",
          timestampMs: NOW_MS,
        },
        frameIndex: 1,
        telemetry: lowTelemetry,
      }),
    ];

    expect(detectObservatoryReplaySpikes(quietSnapshots)).toEqual([]);

    const spikeSnapshots = [
      buildObservatoryReplaySnapshot({
        frame: {
          eventCount: 1,
          label: "15:00",
          timestampMs: NOW_MS - 30 * 60 * 1000,
        },
        frameIndex: 0,
        telemetry: lowTelemetry,
      }),
      buildObservatoryReplaySnapshot({
        frame: {
          eventCount: 5,
          label: "15:30",
          timestampMs: NOW_MS,
        },
        frameIndex: 1,
        telemetry: highTelemetry,
      }),
    ];

    const spikes = detectObservatoryReplaySpikes(spikeSnapshots);
    const receiptSpike = spikes.find((spike) => spike.districtId === "receipts");
    expect(receiptSpike).toMatchObject({
      districtId: "receipts",
      frameIndex: 1,
      severity: "high",
      statusAfter: "receiving",
    });
    expect(receiptSpike?.summary).toContain("Evidence shifted from active to receiving");
    expect(receiptSpike?.summary).toContain("evidence receipts are accumulating faster");
  });

  it("finds the nearest spike frame in either direction without wrapping", () => {
    const spikes = [
      {
        artifactDelta: 4,
        districtId: "receipts" as const,
        districtLabel: "Receipts",
        emphasisDelta: 0.22,
        frameIndex: 2,
        reason: "Receipts are hot.",
        severity: "high" as const,
        statusAfter: "receiving" as const,
        statusBefore: "warming" as const,
        summary: "Receipts shifted.",
        timestampMs: NOW_MS - 20 * 60 * 1000,
      },
      {
        artifactDelta: 3,
        districtId: "watch" as const,
        districtLabel: "Watchfield",
        emphasisDelta: 0.19,
        frameIndex: 5,
        reason: "Watchfield is active.",
        severity: "medium" as const,
        statusAfter: "active" as const,
        statusBefore: "idle" as const,
        summary: "Watchfield shifted.",
        timestampMs: NOW_MS - 10 * 60 * 1000,
      },
      {
        artifactDelta: 6,
        districtId: "signal" as const,
        districtLabel: "Signal",
        emphasisDelta: 0.31,
        frameIndex: 8,
        reason: "Signal is spiking.",
        severity: "high" as const,
        statusAfter: "active" as const,
        statusBefore: "warming" as const,
        summary: "Signal shifted.",
        timestampMs: NOW_MS - 5 * 60 * 1000,
      },
    ];

    expect(findObservatoryReplaySpikeFrameIndex(spikes, 5, "prev")).toBe(2);
    expect(findObservatoryReplaySpikeFrameIndex(spikes, 5, "next")).toBe(8);
    expect(findObservatoryReplaySpikeFrameIndex(spikes, 1, "prev")).toBeNull();
    expect(findObservatoryReplaySpikeFrameIndex(spikes, 8, "next")).toBeNull();
  });
});
