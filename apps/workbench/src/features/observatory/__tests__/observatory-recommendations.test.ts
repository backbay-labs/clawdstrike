import { describe, expect, it } from "vitest";
import type {
  ObservatoryPressureLane,
  ObservatoryStation,
} from "@/features/observatory/types";
import type { DerivedObservatoryTelemetry } from "@/features/observatory/world/observatory-telemetry";
import { buildObservatoryProbeGuidance } from "@/features/observatory/world/observatory-recommendations";
import type { HuntStationId } from "@/features/observatory/world/types";

function makeLane(
  stationId: HuntStationId,
  overrides: Partial<ObservatoryPressureLane> = {},
): ObservatoryPressureLane {
  return {
    affinity: 0.52,
    emphasis: 0.48,
    isPrimary: false,
    label: stationId,
    rank: 2,
    rawPressure: 2,
    route: `/${stationId}`,
    routeLabel: stationId.toUpperCase(),
    score: 0.46,
    stationId,
    status: "warming",
    ...overrides,
  };
}

function makeStation(
  stationId: HuntStationId,
  overrides: Partial<ObservatoryStation> = {},
): ObservatoryStation {
  return {
    artifactCount: 1,
    id: stationId,
    kind: "observatory",
    label: stationId.toUpperCase(),
    route: `/${stationId}`,
    status: "warming",
    ...overrides,
  };
}

function makeTelemetry(input: {
  stations: ObservatoryStation[];
  pressureLanes: ObservatoryPressureLane[];
  likelyStationId?: HuntStationId | null;
}): DerivedObservatoryTelemetry {
  return {
    confidence: 0.68,
    likelyStationId: input.likelyStationId ?? input.pressureLanes[0]?.stationId ?? null,
    pressureLanes: input.pressureLanes,
    roomReceiveState: "idle",
    stations: input.stations,
    telemetrySnapshotMs: Date.parse("2026-03-20T00:00:00.000Z"),
  };
}

describe("buildObservatoryProbeGuidance", () => {
  it("returns null while the probe is ready", () => {
    const telemetry = makeTelemetry({
      pressureLanes: [makeLane("signal")],
      stations: [makeStation("signal")],
    });

    expect(
      buildObservatoryProbeGuidance({
        currentTelemetry: telemetry,
        probeState: {
          activeUntilMs: null,
          cooldownUntilMs: null,
          status: "ready",
          targetStationId: null,
        },
      }),
    ).toBeNull();
  });

  it("surfaces lane-up guidance and aligns the recommendation to the mission objective", () => {
    const previousTelemetry = makeTelemetry({
      pressureLanes: [
        makeLane("watch", { isPrimary: true, rank: 1, score: 0.72 }),
        makeLane("receipts", { rank: 2, score: 0.43 }),
      ],
      stations: [
        makeStation("watch"),
        makeStation("receipts", {
          explanation: {
            causes: [
              {
                count: 2,
                id: "receipts-arrivals",
                kind: "receipt",
                label: "Receipt arrivals",
                route: "/receipt-preview",
                routeLabel: "Receipt Preview",
                summary: "Receipts are starting to accumulate.",
                weight: 0.62,
              },
            ],
            generatedAtMs: 1,
            primaryLaneId: "receipts",
            stationId: "receipts",
            summary: "Receipts are starting to accumulate.",
          },
          label: "Receipts",
          route: "/receipt-preview",
          routeLabel: "Receipt Preview",
        }),
      ],
      likelyStationId: "watch",
    });
    const currentTelemetry = makeTelemetry({
      pressureLanes: [
        makeLane("receipts", {
          isPrimary: true,
          rank: 1,
          route: "/receipt-preview",
          routeLabel: "Receipt Preview",
          score: 0.81,
          status: "receiving",
        }),
        makeLane("watch", { rank: 2, score: 0.58 }),
      ],
      stations: [
        makeStation("receipts", {
          explanation: {
            causes: [
              {
                count: 4,
                id: "receipts-investigations",
                kind: "investigation",
                label: "Open investigations",
                route: "/receipt-preview",
                routeLabel: "Receipt Preview",
                summary: "Investigations are pinning the lane open.",
                weight: 0.84,
              },
            ],
            generatedAtMs: 2,
            primaryLaneId: "receipts",
            stationId: "receipts",
            summary: "Investigations are pinning the lane open.",
          },
          label: "Receipts",
          route: "/receipt-preview",
          routeLabel: "Receipt Preview",
        }),
        makeStation("watch"),
      ],
      likelyStationId: "receipts",
    });

    const guidance = buildObservatoryProbeGuidance({
      currentTelemetry,
      missionObjective: {
        stationId: "receipts",
        title: "Review denied receipts",
      },
      previousTelemetry,
      probeState: {
        activeUntilMs: 1000,
        cooldownUntilMs: 2000,
        status: "active",
        targetStationId: "receipts",
      },
    });

    expect(guidance?.delta.kind).toBe("lane-up");
    expect(guidance?.delta.summary).toContain("rose from rank 2 to rank 1");
    expect(guidance?.whyItMatters).toContain("Review denied receipts");
    expect(guidance?.recommendation?.title).toContain("Review denied receipts");
    expect(guidance?.recommendation?.route).toBe("/receipt-preview");
  });

  it("detects cause shifts and folds mission support stations into the recommendation", () => {
    const previousTelemetry = makeTelemetry({
      pressureLanes: [
        makeLane("signal", { isPrimary: true, rank: 1, score: 0.6 }),
        makeLane("watch", { rank: 2, score: 0.38 }),
      ],
      stations: [
        makeStation("signal", {
          explanation: {
            causes: [
              {
                count: 2,
                id: "signal-ingress",
                kind: "traffic",
                label: "Ingress lanes",
                route: "/hunt",
                routeLabel: "Hunt Stream",
                summary: "Traffic is leading the read.",
                weight: 0.61,
              },
            ],
            generatedAtMs: 1,
            primaryLaneId: "signal",
            stationId: "signal",
            summary: "Traffic is leading the read.",
          },
          label: "Signal",
          route: "/hunt",
          routeLabel: "Hunt Stream",
        }),
        makeStation("watch"),
      ],
      likelyStationId: "signal",
    });
    const currentTelemetry = makeTelemetry({
      pressureLanes: [
        makeLane("signal", {
          isPrimary: true,
          rank: 1,
          route: "/hunt",
          routeLabel: "Hunt Stream",
          score: 0.67,
          status: "active",
        }),
        makeLane("watch", { rank: 2, score: 0.49 }),
        makeLane("receipts", { rank: 3, score: 0.41 }),
      ],
      stations: [
        makeStation("signal", {
          explanation: {
            causes: [
              {
                count: 3,
                id: "signal-sessions",
                kind: "traffic",
                label: "Active ingress sessions",
                route: "/hunt",
                routeLabel: "Hunt Stream",
                summary: "Sessions have become the leading cause.",
                weight: 0.79,
              },
            ],
            generatedAtMs: 2,
            primaryLaneId: "signal",
            stationId: "signal",
            summary: "Sessions have become the leading cause.",
          },
          label: "Signal",
          route: "/hunt",
          routeLabel: "Hunt Stream",
        }),
        makeStation("watch"),
        makeStation("receipts"),
      ],
      likelyStationId: "signal",
    });

    const guidance = buildObservatoryProbeGuidance({
      currentTelemetry,
      missionObjective: {
        stationId: "watch",
        title: "Open watchfield review",
      },
      previousTelemetry,
      probeState: {
        activeUntilMs: null,
        cooldownUntilMs: 1000,
        status: "cooldown",
        targetStationId: "signal",
      },
    });

    expect(guidance?.delta.kind).toBe("cause-shift");
    expect(guidance?.delta.summary).toContain("new leading cause");
    expect(guidance?.supportingStationIds).toContain("watch");
    expect(guidance?.recommendation?.supportingStationIds).toContain("watch");
  });
});
