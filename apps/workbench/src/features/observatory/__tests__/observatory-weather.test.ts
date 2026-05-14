import { describe, expect, it } from "vitest";
import type { ObservatoryStation } from "@/features/observatory/types";
import {
  deriveObservatoryWeatherState,
  resolveObservatoryWeatherBudget,
} from "@/features/observatory/world/observatory-weather";

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
    status: "warming",
    ...overrides,
  };
}

describe("observatory weather", () => {
  it("keeps calm scenes crisp and low noise", () => {
    const weather = deriveObservatoryWeatherState({
      confidence: 0.96,
      connected: true,
      likelyStationId: "signal",
      mode: "atlas",
      missionTargetStationId: "signal",
      nowMs: Date.parse("2026-03-20T00:00:00.000Z"),
      roomReceiveState: "idle",
      stations: [makeStation("signal", { emphasis: 0.12, artifactCount: 0, status: "idle" })],
    });

    expect(weather.style).toBe("signal-haze");
    expect(weather.density).toBeLessThanOrEqual(0.12);
    expect(weather.labelOcclusionOpacity).toBeLessThanOrEqual(0.18);
    expect(weather.missionClearRadius).toBeGreaterThanOrEqual(3.5);
  });

  it("biases evidence-heavy and watch-heavy scenes toward the correct atmospheric style", () => {
    const receiptWeather = deriveObservatoryWeatherState({
      confidence: 0.52,
      connected: true,
      likelyStationId: "receipts",
      mode: "flow",
      missionTargetStationId: "receipts",
      nowMs: Date.parse("2026-03-20T00:00:00.000Z"),
      roomReceiveState: "receiving",
      stations: [
        makeStation("receipts", { artifactCount: 6, emphasis: 0.9, status: "receiving" }),
        makeStation("watch", { artifactCount: 1, emphasis: 0.4, status: "idle" }),
      ],
    });
    const watchWeather = deriveObservatoryWeatherState({
      confidence: 0.56,
      connected: true,
      likelyStationId: "watch",
      mode: "flow",
      missionTargetStationId: "watch",
      nowMs: Date.parse("2026-03-20T00:30:00.000Z"),
      roomReceiveState: "receiving",
      stations: [
        makeStation("watch", { artifactCount: 4, emphasis: 0.83, status: "active" }),
        makeStation("receipts", { artifactCount: 2, emphasis: 0.5, status: "warming" }),
      ],
    });

    expect(receiptWeather.style).toBe("receipt-drizzle");
    expect(watchWeather.style).toBe("perimeter-gusts");
    expect(receiptWeather.density).toBeLessThanOrEqual(0.12);
    expect(watchWeather.density).toBeLessThanOrEqual(0.12);
  });

  it("clamps disconnected or low-quality scenes instead of making random storms", () => {
    const weather = deriveObservatoryWeatherState({
      confidence: 0.14,
      connected: false,
      likelyStationId: "receipts",
      mode: "atlas",
      missionTargetStationId: "receipts",
      nowMs: Date.parse("2026-03-20T00:00:00.000Z"),
      reducedMotion: true,
      roomReceiveState: "idle",
      saveData: true,
      stations: [makeStation("receipts", { artifactCount: 20, emphasis: 1, status: "active" })],
    });

    expect(resolveObservatoryWeatherBudget({ connected: false })).toBe("off");
    expect(weather.budget).toBe("off");
    expect(weather.density).toBe(0);
    expect(weather.labelOcclusionOpacity).toBe(0);
  });

  it("stays deterministic for replay snapshots and does not depend on Math.random", () => {
    const input = {
      confidence: 0.61,
      connected: true,
      likelyStationId: "case-notes" as const,
      mode: "flow" as const,
      missionTargetStationId: "case-notes" as const,
      nowMs: Date.parse("2026-03-20T01:00:00.000Z"),
      roomReceiveState: "aftermath" as const,
      stations: [makeStation("case-notes", { artifactCount: 3, emphasis: 0.72, status: "receiving" })],
    };

    expect(deriveObservatoryWeatherState(input)).toEqual(deriveObservatoryWeatherState(input));
  });
});
