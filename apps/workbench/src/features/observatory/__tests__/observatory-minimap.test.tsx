// Observatory minimap panel tests — star chart (MAP-01, MAP-04)
// Tests: worldToChart coordinate mapping, SVG rendering, lane connections,
//        station colors, station click routing, status icon rendering.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render } from "@testing-library/react";
import type { DockingState } from "../character/ship/docking-types";

// ---------------------------------------------------------------------------
// Mock observatory-world-template (OBSERVATORY_STATION_POSITIONS)
// ---------------------------------------------------------------------------

vi.mock(
  "@/features/observatory/world/observatory-world-template",
  () => ({
    OBSERVATORY_STATION_POSITIONS: {
      signal:       [-201.73, 35,  -223.7] as readonly [number, number, number],
      targets:      [-176.34, 10,  -242.53] as readonly [number, number, number],
      run:          [299.45, -5,   31.41] as readonly [number, number, number],
      receipts:     [121.69, -15,  273.73] as readonly [number, number, number],
      "case-notes": [-242.71, 20,  196.47] as readonly [number, number, number],
      watch:        [-378.0, 40,   0.0] as readonly [number, number, number],
    },
  }),
);

// ---------------------------------------------------------------------------
// Mock observatory store
// ---------------------------------------------------------------------------

const observatoryState = vi.hoisted(() => ({
  stations: [] as Array<{
    id: string;
    kind: string;
    label: string;
    route: string;
    artifactCount: number;
    status?: string;
  }>,
  seamSummary: { stationCount: 0, artifactCount: 0, activeProbes: 0 },
  connected: false,
  likelyStationId: null as string | null,
  selectedStationId: null as string | null,
  mission: null as null | {
    objectives: Array<{ id: string; stationId: string }>;
    completedObjectiveIds: string[];
  },
  dockingState: {
    stationId: null,
    zone: null,
    dockLockStartMs: null,
    undockGracePeriodActive: false,
  } as DockingState,
  flightState: {
    velocity: [0, 0, 0] as [number, number, number],
    quaternion: [0, 0, 0, 1] as [number, number, number, number],
    position: [0, 80, 200] as [number, number, number],
    speedTier: "cruise" as const,
    boostActivatedAtMs: null,
    boostOnCooldown: false,
    pointerLocked: false,
    currentSpeed: 0,
    nearestStationId: null as string | null,
    autopilotTargetStationId: null as string | null,
  },
  // Phase 26: all stations discovered by default in tests (full render for assertions)
  discoveredStations: new Set(["signal", "targets", "run", "receipts", "case-notes", "watch"]),
}));

const openObservatoryStationRouteMock = vi.hoisted(() => vi.fn());

const setAutopilotTargetMock = vi.hoisted(() => vi.fn());

vi.mock("@/features/observatory/stores/observatory-store", () => ({
  useObservatoryStore: Object.assign(
    vi.fn(
      (selector?: (state: typeof observatoryState) => unknown) =>
        selector ? selector(observatoryState) : observatoryState,
    ),
    {
      use: {
        stations: vi.fn(() => observatoryState.stations),
        seamSummary: vi.fn(() => observatoryState.seamSummary),
        connected: vi.fn(() => observatoryState.connected),
        likelyStationId: vi.fn(() => observatoryState.likelyStationId),
        selectedStationId: vi.fn(() => observatoryState.selectedStationId),
      },
      getState: vi.fn(() => ({
        flightState: observatoryState.flightState,
        dockingState: observatoryState.dockingState,
        autopilotTargetStationId: null,
        actions: {
          setAutopilotTarget: setAutopilotTargetMock,
        },
      })),
    },
  ),
}));

vi.mock("@/features/observatory/commands/observatory-command-actions", () => ({
  openObservatoryStationRoute: openObservatoryStationRouteMock,
}));

import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";
import {
  ObservatoryMinimapPanel,
  worldToChart,
} from "@/features/observatory/panels/observatory-minimap-panel";
import { STATION_COLORS_HEX } from "@/features/observatory/components/hud/hud-constants";

const mockStations = useObservatoryStore.use.stations as ReturnType<typeof vi.fn>;
const mockConnected = useObservatoryStore.use.connected as ReturnType<typeof vi.fn>;
const mockSelectedStationId = useObservatoryStore.use.selectedStationId as ReturnType<typeof vi.fn>;

// ---------------------------------------------------------------------------
// Unit tests: worldToChart coordinate mapping
// ---------------------------------------------------------------------------

describe("worldToChart — coordinate mapping", () => {
  it("worldToChart(0, 0) returns chart center (100, 100)", () => {
    const { x, y } = worldToChart(0, 0);
    expect(x).toBeCloseTo(100, 1);
    expect(y).toBeCloseTo(100, 1);
  });

  it("worldToChart with positive X maps to right of center", () => {
    const { x } = worldToChart(100, 0);
    expect(x).toBeGreaterThan(100);
  });

  it("worldToChart with negative X maps to left of center", () => {
    const { x } = worldToChart(-100, 0);
    expect(x).toBeLessThan(100);
  });

  it("worldToChart with positive Z maps to above center (SVG Y-axis inverted)", () => {
    const { y } = worldToChart(0, 100);
    // Positive world Z → smaller SVG Y (above center, since SVG Y is inverted)
    expect(y).toBeLessThan(100);
  });

  it("worldToChart with negative Z maps to below center", () => {
    const { y } = worldToChart(0, -100);
    expect(y).toBeGreaterThan(100);
  });

  it("stations at opposite XZ positions map to opposite chart positions", () => {
    const pos1 = worldToChart(200, 0);
    const pos2 = worldToChart(-200, 0);
    // Both should be equidistant from center but on opposite sides
    const d1 = Math.abs(pos1.x - 100);
    const d2 = Math.abs(pos2.x - 100);
    expect(d1).toBeCloseTo(d2, 1);
    expect(pos1.x).toBeGreaterThan(100);
    expect(pos2.x).toBeLessThan(100);
  });

  it("worldToChart results stay within 200x200 viewBox for station positions", async () => {
    // All station world positions should map within [0, 200] x [0, 200]
    const { OBSERVATORY_STATION_POSITIONS } = await import(
      "@/features/observatory/world/observatory-world-template"
    );
    for (const [, pos] of Object.entries(OBSERVATORY_STATION_POSITIONS)) {
      const { x, y } = worldToChart(
        (pos as readonly [number, number, number])[0],
        (pos as readonly [number, number, number])[2],
      );
      expect(x).toBeGreaterThanOrEqual(0);
      expect(x).toBeLessThanOrEqual(200);
      expect(y).toBeGreaterThanOrEqual(0);
      expect(y).toBeLessThanOrEqual(200);
    }
  });
});

// ---------------------------------------------------------------------------
// Rendering tests
// ---------------------------------------------------------------------------

describe("ObservatoryMinimapPanel rendering — star chart", () => {
  beforeEach(() => {
    observatoryState.stations = [];
    observatoryState.seamSummary = { stationCount: 0, artifactCount: 0, activeProbes: 0 };
    observatoryState.connected = false;
    observatoryState.likelyStationId = null;
    observatoryState.selectedStationId = null;
    observatoryState.mission = null;
    observatoryState.dockingState = {
      stationId: null,
      zone: null,
      dockLockStartMs: null,
      undockGracePeriodActive: false,
    };
    observatoryState.flightState = {
      velocity: [0, 0, 0],
      quaternion: [0, 0, 0, 1],
      position: [0, 80, 200],
      speedTier: "cruise",
      boostActivatedAtMs: null,
      boostOnCooldown: false,
      pointerLocked: false,
      currentSpeed: 0,
      nearestStationId: null,
      autopilotTargetStationId: null,
    };
    // Reset all stations to discovered for rendering assertions
    observatoryState.discoveredStations = new Set(["signal", "targets", "run", "receipts", "case-notes", "watch"]);
    openObservatoryStationRouteMock.mockReset();
    setAutopilotTargetMock.mockReset();
    mockStations.mockReturnValue(observatoryState.stations);
    mockConnected.mockReturnValue(observatoryState.connected);
    mockSelectedStationId.mockReturnValue(observatoryState.selectedStationId);
  });

  it("renders without crash when stations array is empty", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    expect(container.firstChild).not.toBeNull();
  });

  it("renders an SVG with viewBox='0 0 200 200'", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    const svg = container.querySelector("svg[aria-label='Observatory station map']");
    expect(svg).not.toBeNull();
    expect(svg?.getAttribute("viewBox")).toBe("0 0 200 200");
  });

  it("renders center core circles", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    const svg = container.querySelector("svg");
    // Should have grid circles + center core circles
    const circles = svg?.querySelectorAll("circle");
    expect((circles?.length ?? 0)).toBeGreaterThanOrEqual(2);
  });

  it("renders 6 station dots for all 6 HUNT_STATION_ORDER entries", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    const svg = container.querySelector("svg");
    // 6 station groups rendered
    const groups = svg?.querySelectorAll("g[key], g");
    // At minimum we should have 6 station groups plus the player arrow group
    const stationDots = svg?.querySelectorAll("[data-station-id]");
    expect((stationDots?.length ?? 0)).toBe(6);
  });

  it("renders station dots with correct fill colors from STATION_COLORS_HEX", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    const svg = container.querySelector("svg");
    // Check the signal station dot has the correct color
    const signalDot = svg?.querySelector("[data-station-id='signal']");
    expect(signalDot).not.toBeNull();
    expect(signalDot?.getAttribute("fill")).toBe(STATION_COLORS_HEX.signal);
  });

  it("renders lane connection SVG lines (at least 4 for the 4 LANE_PAIRS)", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    const svg = container.querySelector("svg");
    // Lane lines have data-testid="lane-*"
    const laneLines = svg?.querySelectorAll("[data-testid^='lane-']");
    expect((laneLines?.length ?? 0)).toBeGreaterThanOrEqual(4);
  });

  it("renders lane line between signal and targets", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    const svg = container.querySelector("svg");
    const signalTargetsLane = svg?.querySelector("[data-testid='lane-signal-targets']");
    expect(signalTargetsLane).not.toBeNull();
  });

  it("renders lane line between receipts and case-notes", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    const svg = container.querySelector("svg");
    const lane = svg?.querySelector("[data-testid='lane-receipts-case-notes']");
    expect(lane).not.toBeNull();
  });

  it("renders seam summary footer with artifact count", () => {
    observatoryState.seamSummary = { stationCount: 2, artifactCount: 7, activeProbes: 0 };
    const { container } = render(<ObservatoryMinimapPanel />);
    expect(container.textContent).toContain("7 artifacts");
  });

  it("renders 'probe active' when activeProbes > 0", () => {
    observatoryState.seamSummary = { stationCount: 1, artifactCount: 2, activeProbes: 1 };
    const { container } = render(<ObservatoryMinimapPanel />);
    expect(container.textContent).toContain("probe active");
  });

  it("does NOT render 'probe active' when activeProbes = 0", () => {
    observatoryState.seamSummary = { stationCount: 0, artifactCount: 0, activeProbes: 0 };
    const { container } = render(<ObservatoryMinimapPanel />);
    expect(container.textContent).not.toContain("probe active");
  });

  it("opens the mapped station route when a station dot is clicked", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    const signalDot = container.querySelector("[data-station-id='signal']");
    expect(signalDot).not.toBeNull();
    fireEvent.click(signalDot as SVGCircleElement);
    expect(openObservatoryStationRouteMock).toHaveBeenCalledWith("signal");
  });

  it("calls setAutopilotTarget with station id when a station dot is clicked", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    const signalDot = container.querySelector("[data-station-id='signal']");
    expect(signalDot).not.toBeNull();
    fireEvent.click(signalDot as SVGCircleElement);
    expect(setAutopilotTargetMock).toHaveBeenCalledWith("signal");
  });

  it("calls setAutopilotTarget with the correct station id for each station", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    const runDot = container.querySelector("[data-station-id='run']");
    expect(runDot).not.toBeNull();
    fireEvent.click(runDot as SVGCircleElement);
    expect(setAutopilotTargetMock).toHaveBeenCalledWith("run");
  });

  it("renders diamond status icon when dockingState.zone==='dock' for a station", () => {
    observatoryState.dockingState = {
      stationId: "signal",
      zone: "dock",
      dockLockStartMs: null,
      undockGracePeriodActive: false,
    };
    const { container } = render(<ObservatoryMinimapPanel />);
    const svg = container.querySelector("svg");
    const dockedIcon = svg?.querySelector("[data-status='docked']");
    expect(dockedIcon).not.toBeNull();
  });

  it("renders mission target icon (*) when station has active mission objective", () => {
    observatoryState.mission = {
      objectives: [{ id: "acknowledge-horizon-ingress", stationId: "signal" }],
      completedObjectiveIds: [],
    };
    const { container } = render(<ObservatoryMinimapPanel />);
    const svg = container.querySelector("svg");
    const missionIcon = svg?.querySelector("[data-status='mission']");
    expect(missionIcon).not.toBeNull();
    expect(missionIcon?.textContent).toBe("*");
  });

  it("does NOT render mission target icon for completed objectives", () => {
    observatoryState.mission = {
      objectives: [{ id: "acknowledge-horizon-ingress", stationId: "signal" }],
      completedObjectiveIds: ["acknowledge-horizon-ingress"],
    };
    const { container } = render(<ObservatoryMinimapPanel />);
    const svg = container.querySelector("svg");
    // Signal station should not have mission icon since it's completed
    const missionIcons = svg?.querySelectorAll("[data-status='mission']");
    expect((missionIcons?.length ?? 0)).toBe(0);
  });

  it("reads summary fields through narrow selectors (seamSummary use.* not called)", () => {
    render(<ObservatoryMinimapPanel />);
    const seamSummarySelector = useObservatoryStore.use.seamSummary as ReturnType<typeof vi.fn>;
    expect(seamSummarySelector).not.toHaveBeenCalled();
  });
});
