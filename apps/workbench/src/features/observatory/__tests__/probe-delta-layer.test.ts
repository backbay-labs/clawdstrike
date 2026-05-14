/**
 * probe-delta-layer.test.ts — Phase 40 PRBI-05
 *
 * Tests for ProbeDeltaLayer lifecycle logic:
 * - Renders null when probeGuidance is null
 * - Auto-dismiss timer fires after 8 seconds
 * - Replace mode: new guidance for a different station replaces old card
 *
 * Uses React.createElement instead of JSX so this can remain a .ts file.
 * R3F and drei are mocked so no canvas context is required.
 */

import React from "react";
import { describe, expect, it, vi, afterEach } from "vitest";
import { act, render } from "@testing-library/react";

// Mock drei so Html forwards children directly (no canvas required)
vi.mock("@react-three/drei", () => ({
  Html: ({ children }: { children: unknown }) => children,
}));

// Mock r3f — may be transitively imported
vi.mock("@react-three/fiber", () => ({
  useFrame: vi.fn(),
  useThree: () => ({ invalidate: vi.fn() }),
}));

// Mock observatory-command-actions so navigation calls are no-ops in tests
vi.mock("@/features/observatory/commands/observatory-command-actions", () => ({
  openObservatoryRecommendationRoute: vi.fn(),
}));

import { ProbeDeltaLayer } from "@/features/observatory/components/world-canvas/ProbeDeltaLayer";
import type { ProbeDeltaLayerProps } from "@/features/observatory/components/world-canvas/ProbeDeltaLayer";
import type { ObservatoryProbeGuidance } from "@/features/observatory/world/observatory-recommendations";
import type { HuntStationId } from "@/features/observatory/world/types";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const STATION_POSITIONS: Record<HuntStationId, readonly [number, number, number]> = {
  signal: [120, 5, 0],
  targets: [-60, 5, 104],
  run: [-60, 5, -104],
  receipts: [120, 5, -40],
  "case-notes": [-120, 5, 40],
  watch: [0, 5, 150],
};

function makeGuidance(
  stationId: HuntStationId,
  overrides: Partial<ObservatoryProbeGuidance> = {},
): ObservatoryProbeGuidance {
  return {
    stationId,
    stationLabel: stationId.toUpperCase(),
    state: "active",
    delta: {
      kind: "pressure-shift",
      summary: `${stationId} gained pressure.`,
      supportingStationIds: [],
    },
    whyItMatters: "Pressure shift is significant.",
    confidence: 0.72,
    recommendation: {
      stationId,
      title: `Open ${stationId}`,
      summary: `Investigate ${stationId}.`,
      route: `/${stationId}`,
      routeLabel: stationId.toUpperCase(),
      confidence: 0.72,
      supportingStationIds: [],
    },
    supportingStationIds: [],
    ...overrides,
  };
}

function makeElement(props: ProbeDeltaLayerProps) {
  return React.createElement(ProbeDeltaLayer, props);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ProbeDeltaLayer", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("exports ProbeDeltaLayer function and ProbeDeltaLayerProps interface", () => {
    expect(typeof ProbeDeltaLayer).toBe("function");
    const props: ProbeDeltaLayerProps = {
      probeGuidance: null,
      stationPositions: STATION_POSITIONS,
    };
    expect(props).toBeDefined();
  });

  it("renders null (no delta card) when probeGuidance is null", () => {
    const { container } = render(
      makeElement({ probeGuidance: null, stationPositions: STATION_POSITIONS }),
    );
    expect(container.querySelector("[data-testid='probe-delta-card']")).toBeNull();
  });

  it("shows delta card when probeGuidance is non-null", () => {
    const guidance = makeGuidance("signal");
    const { container } = render(
      makeElement({ probeGuidance: guidance, stationPositions: STATION_POSITIONS }),
    );
    const card = container.querySelector("[data-testid='probe-delta-card']");
    expect(card).not.toBeNull();
  });

  it("auto-dismisses card after 8 seconds using fake timers", () => {
    vi.useFakeTimers();
    const guidance = makeGuidance("targets");

    const { container } = render(
      makeElement({ probeGuidance: guidance, stationPositions: STATION_POSITIONS }),
    );

    // Card is visible initially
    expect(container.querySelector("[data-testid='probe-delta-card']")).not.toBeNull();

    // Advance time past the 8-second auto-dismiss threshold
    act(() => {
      vi.advanceTimersByTime(8001);
    });

    // Card should be gone after 8 seconds
    expect(container.querySelector("[data-testid='probe-delta-card']")).toBeNull();
  });

  it("replaces old card immediately when guidance stationId changes (replace mode)", () => {
    const guidanceA = makeGuidance("signal");
    const guidanceB = makeGuidance("watch");

    const { container, rerender } = render(
      makeElement({ probeGuidance: guidanceA, stationPositions: STATION_POSITIONS }),
    );

    // First card shown for signal
    expect(container.querySelector("[data-testid='probe-delta-card']")).not.toBeNull();

    // Replace with guidance for a different station
    act(() => {
      rerender(makeElement({ probeGuidance: guidanceB, stationPositions: STATION_POSITIONS }));
    });

    // Only one card at a time — new card replaces old (no duplicates)
    const cards = container.querySelectorAll("[data-testid='probe-delta-card']");
    expect(cards.length).toBe(1);
  });
});
