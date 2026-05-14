import { describe, expect, it } from "vitest";
import { compareObservatoryReplaySnapshots } from "@/features/observatory/world/observatory-replay-diff";
import type { ObservatoryReplaySnapshot } from "@/features/observatory/world/observatory-telemetry";

function makeSnapshot(
  frameIndex: number,
  timestampMs: number,
  districts: ObservatoryReplaySnapshot["districts"],
): ObservatoryReplaySnapshot {
  return {
    confidence: 0.8,
    districts,
    eventCount: 4,
    frameIndex,
    label: `Frame ${frameIndex}`,
    likelyStationId: districts[0]?.districtId ?? null,
    roomReceiveState: "receiving",
    timestampMs,
  };
}

describe("observatory replay diff", () => {
  it("reports emphasis and artifact deltas with readable status transitions", () => {
    const replaySnapshot = makeSnapshot(2, 1000, [
      {
        affinity: 0.6,
        artifactCount: 2,
        districtId: "receipts",
        emphasis: 0.64,
        explanation: null,
        label: "Receipts",
        reason: "Evidence receipts are still settling.",
        route: "/receipt-preview",
        routeLabel: "Receipt Preview",
        status: "warming",
      },
      {
        affinity: 0.4,
        artifactCount: 1,
        districtId: "watch",
        emphasis: 0.33,
        explanation: null,
        label: "Watchfield",
        reason: "Watchfield is calm.",
        route: "/nexus",
        routeLabel: "Nexus",
        status: "idle",
      },
      {
        affinity: 0.2,
        artifactCount: 0,
        districtId: "signal",
        emphasis: 0.18,
        explanation: null,
        label: "Signal",
        reason: "Signal is quiet.",
        route: "/hunt",
        routeLabel: "Hunt Stream",
        status: "idle",
      },
    ]);
    const liveSnapshot = makeSnapshot(3, 2000, [
      {
        affinity: 0.78,
        artifactCount: 6,
        districtId: "receipts",
        emphasis: 0.86,
        explanation: null,
        label: "Receipts",
        reason: "Evidence receipts are accumulating faster than the archive can settle them.",
        route: "/receipt-preview",
        routeLabel: "Receipt Preview",
        status: "receiving",
      },
      {
        affinity: 0.4,
        artifactCount: 1,
        districtId: "watch",
        emphasis: 0.34,
        explanation: null,
        label: "Watchfield",
        reason: "Watchfield is calm.",
        route: "/nexus",
        routeLabel: "Nexus",
        status: "idle",
      },
      {
        affinity: 0.22,
        artifactCount: 0,
        districtId: "signal",
        emphasis: 0.19,
        explanation: null,
        label: "Signal",
        reason: "Signal is quiet.",
        route: "/hunt",
        routeLabel: "Hunt Stream",
        status: "idle",
      },
    ]);

    const diffs = compareObservatoryReplaySnapshots(liveSnapshot, replaySnapshot);

    expect(diffs[0]).toMatchObject({
      artifactDelta: 4,
      districtId: "receipts",
      quiet: false,
      statusAfter: "receiving",
      statusBefore: "warming",
    });
    expect(diffs[0].emphasisDelta).toBeCloseTo(0.22, 2);
    expect(diffs[0].summary).toContain("Receipts hardened from warming to receiving");
    expect(diffs[0].summary).toContain("+4 artifacts");
    expect(diffs[0].summary).toContain("+0.22 emphasis");
  });

  it("keeps quiet districts in order so the UI can de-emphasize them without losing rows", () => {
    const replaySnapshot = makeSnapshot(0, 1000, [
      {
        affinity: 0.3,
        artifactCount: 0,
        districtId: "signal",
        emphasis: 0.18,
        explanation: null,
        label: "Signal",
        reason: "Signal is quiet.",
        route: "/hunt",
        routeLabel: "Hunt Stream",
        status: "idle",
      },
      {
        affinity: 0.5,
        artifactCount: 2,
        districtId: "receipts",
        emphasis: 0.56,
        explanation: null,
        label: "Receipts",
        reason: "Evidence receipts are still settling.",
        route: "/receipt-preview",
        routeLabel: "Receipt Preview",
        status: "warming",
      },
    ]);
    const liveSnapshot = makeSnapshot(1, 2000, [
      {
        affinity: 0.31,
        artifactCount: 0,
        districtId: "signal",
        emphasis: 0.2,
        explanation: null,
        label: "Signal",
        reason: "Signal is quiet.",
        route: "/hunt",
        routeLabel: "Hunt Stream",
        status: "idle",
      },
      {
        affinity: 0.62,
        artifactCount: 2,
        districtId: "receipts",
        emphasis: 0.7,
        explanation: null,
        label: "Receipts",
        reason: "Evidence receipts are still settling.",
        route: "/receipt-preview",
        routeLabel: "Receipt Preview",
        status: "warming",
      },
    ]);

    const diffs = compareObservatoryReplaySnapshots(liveSnapshot, replaySnapshot);

    expect(diffs).toHaveLength(2);
    expect(diffs[0].districtId).toBe("receipts");
    expect(diffs[1]).toMatchObject({
      districtId: "signal",
      quiet: true,
    });
    expect(diffs[1].summary).toContain("stayed quiet");
  });
});
