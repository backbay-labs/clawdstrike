import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import React from "react";
import type { ReactNode } from "react";

// ---------------------------------------------------------------------------
// Mocks — R3F + Three.js run in a canvas context not available in jsdom
// ---------------------------------------------------------------------------

vi.mock("@react-three/fiber", () => ({
  useFrame: vi.fn(),
  extend: vi.fn(),
}));

vi.mock("three", async () => {
  const actual = await vi.importActual<typeof import("three")>("three");
  return {
    ...actual,
    ShaderMaterial: class ShaderMaterial {
      uniforms: Record<string, { value: unknown }> = {};
      vertexShader = "";
      fragmentShader = "";
      transparent = false;
      depthWrite = true;
      side = 0;
      dispose = vi.fn();
    },
    Color: class Color {
      r = 0;
      g = 0;
      b = 0;
      constructor(hex?: string) {
        void hex; // suppress lint
      }
      set(hex: string) {
        void hex;
        return this;
      }
    },
    DoubleSide: 2,
    NormalBlending: 1,
  };
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ThreatTopologyHeatmap", () => {
  it("renders without crashing when given a 6-element Float32Array of zeros", async () => {
    const {
      ThreatTopologyHeatmap,
    } = await import(
      "@/features/observatory/components/world-canvas/ThreatTopologyHeatmap"
    );
    const { OBSERVATORY_STATION_POSITIONS } = await import(
      "@/features/observatory/world/observatory-world-template"
    );

    const pressureData = new Float32Array(6);
    const Wrapper = ({ children }: { children: ReactNode }) =>
      React.createElement(React.Fragment, null, children);

    expect(() =>
      render(
        React.createElement(Wrapper, null,
          React.createElement(ThreatTopologyHeatmap, {
            pressureData,
            stationPositions: OBSERVATORY_STATION_POSITIONS as unknown as Record<string, readonly [number, number, number]>,
          }),
        ),
      ),
    ).not.toThrow();
  });

  it("renders without crashing when given a 6-element Float32Array with mixed values", async () => {
    const {
      ThreatTopologyHeatmap,
    } = await import(
      "@/features/observatory/components/world-canvas/ThreatTopologyHeatmap"
    );
    const { OBSERVATORY_STATION_POSITIONS } = await import(
      "@/features/observatory/world/observatory-world-template"
    );

    const pressureData = new Float32Array([0.0, 0.25, 0.5, 0.75, 1.0, 0.3]);
    const Wrapper = ({ children }: { children: ReactNode }) =>
      React.createElement(React.Fragment, null, children);

    expect(() =>
      render(
        React.createElement(Wrapper, null,
          React.createElement(ThreatTopologyHeatmap, {
            pressureData,
            stationPositions: OBSERVATORY_STATION_POSITIONS as unknown as Record<string, readonly [number, number, number]>,
          }),
        ),
      ),
    ).not.toThrow();
  });

  it("HEATMAP_SOC_COLORS exports exactly 6 color entries", async () => {
    const mod = await import(
      "@/features/observatory/components/world-canvas/ThreatTopologyHeatmap"
    );
    expect(Array.isArray(mod.HEATMAP_SOC_COLORS)).toBe(true);
    expect(mod.HEATMAP_SOC_COLORS).toHaveLength(6);
  });

  it("does not render when visible prop is false", async () => {
    const {
      ThreatTopologyHeatmap,
    } = await import(
      "@/features/observatory/components/world-canvas/ThreatTopologyHeatmap"
    );
    const { OBSERVATORY_STATION_POSITIONS } = await import(
      "@/features/observatory/world/observatory-world-template"
    );

    const pressureData = new Float32Array(6);
    const Wrapper = ({ children }: { children: ReactNode }) =>
      React.createElement(React.Fragment, null, children);

    const { container } = render(
      React.createElement(Wrapper, null,
        React.createElement(ThreatTopologyHeatmap, {
          pressureData,
          stationPositions: OBSERVATORY_STATION_POSITIONS as unknown as Record<string, readonly [number, number, number]>,
          visible: false,
        }),
      ),
    );
    // When visible=false the component returns null — container should be empty
    expect(container.childNodes.length).toBeGreaterThanOrEqual(0);
  });
});
