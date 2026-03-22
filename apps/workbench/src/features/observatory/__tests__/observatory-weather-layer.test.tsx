import type { ReactNode } from "react";
import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ObservatoryWeatherLayer } from "@/features/observatory/components/world-canvas/ObservatoryWeatherLayer";
import type { ObservatoryWeatherState } from "@/features/observatory/world/observatory-weather";

vi.mock("@react-three/fiber", () => ({
  useThree: vi.fn(() => ({
    scene: {
      fog: { density: 0.0008 },
    },
  })),
  useFrame: vi.fn(),
}));

vi.mock("@react-three/drei", () => ({
  Sparkles: (props: Record<string, unknown>) => (
    <div data-testid="sparkles" data-count={String(props.count)} />
  ),
}));

vi.mock("three", async () => {
  const actual = await vi.importActual<typeof import("three")>("three");
  return {
    ...actual,
    FogExp2: class FogExp2 {
      density = 0.0008;
      constructor(_color: unknown, _density: number) {
        this.density = _density;
      }
    },
  };
});

function makeWeatherState(overrides: Partial<ObservatoryWeatherState> = {}): ObservatoryWeatherState {
  return {
    budget: "full",
    density: 0.08,
    dominantStationId: "signal",
    labelOcclusionOpacity: 0.11,
    missionClearRadius: 4.0,
    phaseOffset: 0.25,
    style: "signal-haze",
    tint: "#7ad7d0",
    ...overrides,
  };
}

describe("ObservatoryWeatherLayer", () => {
  it("renders without crashing when given a full-budget weatherState", () => {
    const weatherState = makeWeatherState({
      density: 0.08,
      style: "signal-haze",
      tint: "#7ad7d0",
      budget: "full",
    });
    const { container } = render(
      <ObservatoryWeatherLayer weatherState={weatherState} />,
    );
    expect(container).toBeDefined();
  });

  it("renders without crashing when given a reduced-budget weatherState", () => {
    const weatherState = makeWeatherState({
      density: 0.05,
      budget: "reduced",
    });
    const { container } = render(
      <ObservatoryWeatherLayer weatherState={weatherState} />,
    );
    expect(container).toBeDefined();
  });

  it("accepts zero-density state without error", () => {
    const weatherState = makeWeatherState({
      density: 0,
      style: "clear",
      budget: "full",
    });
    const { container } = render(
      <ObservatoryWeatherLayer weatherState={weatherState} />,
    );
    expect(container).toBeDefined();
  });
});
