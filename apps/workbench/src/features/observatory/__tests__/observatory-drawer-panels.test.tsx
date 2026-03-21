/**
 * observatory-drawer-panels.test.tsx
 *
 * Unit tests for all 4 analyst drawer panel components:
 *   - ExplainabilityDrawerPanel
 *   - MissionDrawerPanel
 *   - ReplayDrawerPanel
 *   - GhostMemoryDrawerPanel
 *
 * Pattern: reset store in beforeEach, render, assert via data-testid selectors.
 */

import { describe, expect, it, beforeEach } from "vitest";
import { render } from "@testing-library/react";
import { ExplainabilityDrawerPanel } from "../components/hud/panels/ExplainabilityDrawerPanel";
import { MissionDrawerPanel } from "../components/hud/panels/MissionDrawerPanel";
import { ReplayDrawerPanel } from "../components/hud/panels/ReplayDrawerPanel";
import { GhostMemoryDrawerPanel } from "../components/hud/panels/GhostMemoryDrawerPanel";
import { useObservatoryStore } from "../stores/observatory-store";
import { createObservatoryMissionLoopState } from "../world/missionLoop";

const initialState = useObservatoryStore.getState();

// ---------------------------------------------------------------------------
// ExplainabilityDrawerPanel
// ---------------------------------------------------------------------------

describe("ExplainabilityDrawerPanel", () => {
  beforeEach(() => {
    useObservatoryStore.setState({ ...initialState, selectedStationId: null });
  });

  it("a. renders empty state when selectedStationId is null", () => {
    const { container } = render(<ExplainabilityDrawerPanel />);
    const emptyState = container.querySelector("[data-testid='explainability-empty-state']");
    expect(emptyState).not.toBeNull();
  });

  it("b. renders station name when selectedStationId is set", () => {
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      selectedStationId: "signal",
    });
    const { container } = render(<ExplainabilityDrawerPanel />);
    // HUNT_STATION_LABELS.signal === "Horizon"
    expect(container.textContent).toContain("Horizon");
  });

  it("c. renders probe button with PROBE STATION text", () => {
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      selectedStationId: "signal",
    });
    const { container } = render(<ExplainabilityDrawerPanel />);
    const btn = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.includes("PROBE STATION"),
    );
    expect(btn).not.toBeUndefined();
  });

  it("d. renders panel root container when station is selected", () => {
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      selectedStationId: "targets",
    });
    const { container } = render(<ExplainabilityDrawerPanel />);
    const panel = container.querySelector("[data-testid='explainability-drawer-panel']");
    expect(panel).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// MissionDrawerPanel
// ---------------------------------------------------------------------------

describe("MissionDrawerPanel", () => {
  beforeEach(() => {
    useObservatoryStore.setState({ ...initialState, mission: null });
  });

  it("a. renders empty state when mission is null", () => {
    const { container } = render(<MissionDrawerPanel />);
    const emptyState = container.querySelector("[data-testid='mission-empty-state']");
    expect(emptyState).not.toBeNull();
  });

  it("b. renders mission briefing when mission is set", () => {
    const mission = createObservatoryMissionLoopState("test", 0);
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      mission,
    });
    const { container } = render(<MissionDrawerPanel />);
    // briefing text should be present
    expect(container.textContent).toContain(mission.briefing);
  });

  it("c. renders objective list with correct count", () => {
    const mission = createObservatoryMissionLoopState("test", 0);
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      mission,
    });
    const { container } = render(<MissionDrawerPanel />);
    // Each objective has a circle or check indicator (\u25CB or \u2713)
    const indicators = Array.from(container.querySelectorAll("span")).filter(
      (s) => s.textContent === "\u25CB" || s.textContent === "\u2713",
    );
    expect(indicators.length).toBe(mission.objectives.length);
  });

  it("d. renders mission panel container", () => {
    const mission = createObservatoryMissionLoopState("test", 0);
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      mission,
    });
    const { container } = render(<MissionDrawerPanel />);
    const panel = container.querySelector("[data-testid='mission-drawer-panel']");
    expect(panel).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// ReplayDrawerPanel
// ---------------------------------------------------------------------------

describe("ReplayDrawerPanel", () => {
  beforeEach(() => {
    useObservatoryStore.setState({
      ...initialState,
      replay: {
        enabled: false,
        frameIndex: 0,
        frameMs: null,
        selectedSpikeTimestampMs: null,
        selectedDistrictId: null,
        bookmarks: [],
        annotations: [],
        markers: [],
      },
    });
  });

  it("a. renders timeline scrubber (range input)", () => {
    const { container } = render(<ReplayDrawerPanel />);
    const rangeInput = container.querySelector("input[type='range']");
    expect(rangeInput).not.toBeNull();
  });

  it("b. renders compare toggle button", () => {
    const { container } = render(<ReplayDrawerPanel />);
    const toggle = container.querySelector("[data-testid='replay-compare-toggle']");
    expect(toggle).not.toBeNull();
  });

  it("c. shows 'No bookmarks yet' when bookmarks is empty", () => {
    const { container } = render(<ReplayDrawerPanel />);
    expect(container.textContent).toContain("No bookmarks yet");
  });

  it("d. renders panel root container", () => {
    const { container } = render(<ReplayDrawerPanel />);
    const panel = container.querySelector("[data-testid='replay-drawer-panel']");
    expect(panel).not.toBeNull();
  });

  it("e. shows JUMP TO SPIKE button when spike is selected", () => {
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      replay: {
        ...useObservatoryStore.getState().replay,
        selectedSpikeTimestampMs: 1234567890,
      },
    });
    const { container } = render(<ReplayDrawerPanel />);
    const btn = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.includes("JUMP TO SPIKE"),
    );
    expect(btn).not.toBeUndefined();
  });

  it("f. compare toggle shows ON/OFF state", () => {
    const { container } = render(<ReplayDrawerPanel />);
    const toggle = container.querySelector("[data-testid='replay-compare-toggle']");
    // replay.enabled defaults to false
    expect(toggle?.textContent).toBe("OFF");
  });
});

// ---------------------------------------------------------------------------
// GhostMemoryDrawerPanel
// ---------------------------------------------------------------------------

describe("GhostMemoryDrawerPanel", () => {
  beforeEach(() => {
    useObservatoryStore.setState({
      ...initialState,
      selectedStationId: null,
    });
  });

  it("a. renders empty state when no traces derive", () => {
    // Default store has no events/investigations, so traces will be empty
    const { container } = render(<GhostMemoryDrawerPanel />);
    const emptyState = container.querySelector("[data-testid='ghost-memory-empty-state']");
    expect(emptyState).not.toBeNull();
  });

  it("b. renders panel root container", () => {
    const { container } = render(<GhostMemoryDrawerPanel />);
    const panel = container.querySelector("[data-testid='ghost-memory-drawer-panel']");
    expect(panel).not.toBeNull();
  });

  it("c. renders heading text 'GHOST MEMORY'", () => {
    const { container } = render(<GhostMemoryDrawerPanel />);
    // CSS textTransform: uppercase only applies visually; check via case-insensitive textContent
    expect(container.textContent?.toUpperCase()).toContain("GHOST MEMORY");
  });

  it("d. renders trace count readout", () => {
    const { container } = render(<GhostMemoryDrawerPanel />);
    // 0 traces from default store
    expect(container.textContent).toContain("0 trace");
  });
});
