import { describe, expect, it } from "vitest";
import type { AgentEvent, Investigation } from "@/lib/workbench/hunt-types";
import {
  buildObservatoryReplayMarkers,
  mergeObservatoryReplayMarkers,
} from "@/features/observatory/world/observatory-replay-markers";

const frames = [
  { eventCount: 1, label: "9:00 AM", timestampMs: Date.parse("2026-03-19T09:00:00.000Z") },
  { eventCount: 4, label: "10:00 AM", timestampMs: Date.parse("2026-03-19T10:00:00.000Z") },
  { eventCount: 8, label: "11:00 AM", timestampMs: Date.parse("2026-03-19T11:00:00.000Z") },
];

function makeEvent(overrides: Partial<AgentEvent> = {}): AgentEvent {
  return {
    actionType: "file_access",
    agentId: "agent-1",
    agentName: "Agent 1",
    flags: [],
    guardResults: [],
    id: "evt-1",
    policyVersion: "1.4.0",
    sessionId: "session-1",
    target: "/tmp/test",
    timestamp: "2026-03-19T10:18:00.000Z",
    verdict: "deny",
    ...overrides,
  };
}

function makeInvestigation(overrides: Partial<Investigation> = {}): Investigation {
  return {
    actions: [],
    agentIds: ["agent-1"],
    annotations: [
      {
        createdAt: "2026-03-19T10:05:00.000Z",
        createdBy: "operator",
        id: "ann-1",
        text: "Receipt evidence is hardening around denied flows.",
      },
    ],
    createdAt: "2026-03-19T09:30:00.000Z",
    createdBy: "operator",
    eventIds: ["evt-1"],
    id: "inv-1",
    severity: "high",
    sessionIds: ["session-1"],
    status: "open",
    title: "Receipt denial cluster",
    timeRange: { start: "2026-03-19T09:00:00.000Z", end: "2026-03-19T10:20:00.000Z" },
    updatedAt: "2026-03-19T10:20:00.000Z",
    verdict: "policy-gap",
    ...overrides,
  };
}

describe("observatory replay markers", () => {
  it("maps investigations, bookmarks, and annotations into the shared marker envelope", () => {
    const markers = buildObservatoryReplayMarkers({
      annotations: [
        {
          authorLabel: "Operator",
          body: "Keep this frame.",
          districtId: "receipts",
          frameIndex: 1,
          id: "annotation-1",
          sourceType: "manual",
          timestampMs: frames[1].timestampMs,
        },
      ],
      bookmarks: [
        {
          districtId: "watch",
          frameIndex: 0,
          id: "bookmark-1",
          label: "Watch spike",
          timestampMs: frames[0].timestampMs,
        },
      ],
      frames,
      investigations: [makeInvestigation()],
    });

    expect(markers.map((marker) => marker.sourceType)).toEqual([
      "bookmark",
      "analyst",
      "investigation",
    ]);
    expect(markers[2]).toMatchObject({
      districtId: "receipts",
      frameIndex: 1,
      sourceType: "investigation",
    });
  });

  it("merges authored and derived markers without duplicating source identity", () => {
    const authored = buildObservatoryReplayMarkers({
      annotations: [],
      bookmarks: [
        {
          districtId: "receipts",
          frameIndex: 1,
          id: "bookmark-1",
          label: "Receipt spike",
          timestampMs: frames[1].timestampMs,
        },
      ],
      frames,
      investigations: [],
    });
    const derived = buildObservatoryReplayMarkers({
      annotations: [],
      bookmarks: [],
      frames,
      investigations: [makeInvestigation({ id: "bookmark-1", title: "Receipt spike" })],
    });

    const merged = mergeObservatoryReplayMarkers(authored, derived);

    expect(merged).toHaveLength(2);
    expect(merged[0].timestampMs).toBeLessThanOrEqual(merged[1].timestampMs);
  });

  it("prefers linked investigation events over ambiguous text when resolving marker districts", () => {
    const markers = buildObservatoryReplayMarkers({
      annotations: [],
      bookmarks: [],
      events: [
        makeEvent({
          receiptId: "receipt-7",
          sessionId: "session-ambiguous",
          verdict: "deny",
        }),
      ],
      frames,
      investigations: [
        makeInvestigation({
          annotations: [
            {
              createdAt: "2026-03-19T10:05:00.000Z",
              createdBy: "operator",
              id: "ann-ambiguous",
              text: "Cluster expanded without a clear label.",
            },
          ],
          eventIds: ["evt-1"],
          sessionIds: ["session-ambiguous"],
          title: "Escalation cluster",
          verdict: "inconclusive",
        }),
      ],
    });

    expect(markers[0]).toMatchObject({
      districtId: "receipts",
      sourceType: "investigation",
    });
  });
});
