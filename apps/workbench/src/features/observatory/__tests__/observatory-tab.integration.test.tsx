import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { OBSERVATORY_PROBE_ACTIVE_MS, OBSERVATORY_PROBE_COOLDOWN_MS } from "@/features/observatory/world/probeRuntime";

const worldCanvasMock = vi.hoisted(() => ({
  state: {
    lastProps: null as Record<string, unknown> | null,
  },
  preloadObservatoryAssets: vi.fn(),
}));

const observatoryCommandActionsMock = vi.hoisted(() => ({
  openObservatoryStationRoute: vi.fn(),
}));

vi.mock("@/features/observatory/components/ObservatoryWorldCanvas", () => ({
  ObservatoryWorldCanvas: (props: Record<string, unknown>) => {
    worldCanvasMock.state.lastProps = props;
    return (
      <div data-testid="observatory-world-canvas">
        <button
          data-testid="complete-objective"
          onClick={() =>
            (props.onMissionObjectiveComplete as
              | ((assetId: "signal-dish-tower", nowMs: number) => void)
              | undefined)?.("signal-dish-tower", 1000)
          }
        >
          complete objective
        </button>
        <button
          data-testid="select-station"
          onClick={() =>
            (props.onSelectStation as ((stationId: "receipts") => void) | undefined)?.("receipts")
          }
        >
          select station
        </button>
      </div>
    );
  },
}));

vi.mock("@/features/observatory/commands/observatory-command-actions", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/features/observatory/commands/observatory-command-actions")>();
  return {
    ...actual,
    openObservatoryStationRoute: observatoryCommandActionsMock.openObservatoryStationRoute,
  };
});

vi.mock("@/features/observatory/utils/observatory-performance", async () => {
  const actual = await vi.importActual<typeof import("@/features/observatory/utils/observatory-performance")>(
    "@/features/observatory/utils/observatory-performance",
  );
  return {
    ...actual,
    preloadObservatoryAssets: worldCanvasMock.preloadObservatoryAssets,
  };
});

import { ObservatoryTab } from "@/features/observatory/components/ObservatoryTab";
import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";
import { useAchievementStore } from "@/features/observatory/stores/achievement-store";
import { usePaneStore } from "@/features/panes/pane-store";
import { useSpiritStore } from "@/features/spirit/stores/spirit-store";

const initialObservatoryState = useObservatoryStore.getState();
const initialPaneState = usePaneStore.getState();
const achievementActions = useAchievementStore.getState().actions;

describe("ObservatoryTab integration", () => {
  beforeEach(() => {
    worldCanvasMock.state.lastProps = null;
    worldCanvasMock.preloadObservatoryAssets.mockReset();
    observatoryCommandActionsMock.openObservatoryStationRoute.mockReset();
    useObservatoryStore.setState({
      ...initialObservatoryState,
      stations: initialObservatoryState.stations.map((station) => ({
        ...station,
        artifactCount: 0,
      })),
      seamSummary: {
        ...initialObservatoryState.seamSummary,
        artifactCount: 0,
        activeProbes: 0,
      },
      mission: null,
    });
    useAchievementStore.setState({
      queue: [],
      actions: achievementActions,
    });
    usePaneStore.setState({
      ...initialPaneState,
      root: initialPaneState.root,
      activePaneId: initialPaneState.activePaneId,
    });
    usePaneStore.getState()._reset();
    usePaneStore.getState().syncRoute("/observatory");
    useSpiritStore.getState().actions.unbindSpirit();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("gates player input behind the active-pane flow easter egg and keeps the world on an always-on loop", () => {
    const { container, getByText } = render(<ObservatoryTab />);

    expect(worldCanvasMock.preloadObservatoryAssets).toHaveBeenCalledTimes(1);
    expect(worldCanvasMock.state.lastProps?.playerInputEnabled).toBe(false);
    expect(worldCanvasMock.state.lastProps?.frameloop).toBe("always");

    fireEvent.click(getByText("ATLAS"));
    fireEvent.doubleClick(container.firstChild as HTMLElement);

    expect(
      container.querySelector("[data-observatory-character-controller]")?.getAttribute(
        "data-observatory-character-controller",
      ),
    ).toBe("on");
    expect(worldCanvasMock.state.lastProps?.playerInputEnabled).toBe(true);
  });

  it("keeps mission progress in the observatory store and the canvas props in sync", () => {
    render(<ObservatoryTab />);

    act(() => {
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
      window.dispatchEvent(new CustomEvent("observatory:mission:start"));
    });

    expect(useObservatoryStore.getState().mission?.completedObjectiveIds).toEqual([]);
    expect(worldCanvasMock.state.lastProps?.mission).not.toBeNull();

    fireEvent.click(screen.getByTestId("complete-objective"));

    expect(useObservatoryStore.getState().mission?.completedObjectiveIds).toEqual([
      "acknowledge-horizon-ingress",
    ]);
    expect(
      (worldCanvasMock.state.lastProps?.mission as { completedObjectiveIds: string[] })
        .completedObjectiveIds,
    ).toEqual(["acknowledge-horizon-ingress"]);
    expect(useAchievementStore.getState().queue).toHaveLength(1);
  });

  it("syncs probe activity into seamSummary as the probe lifecycle advances", () => {
    vi.useFakeTimers();
    let nowMs = 0;
    vi.spyOn(performance, "now").mockImplementation(() => nowMs);

    render(<ObservatoryTab />);

    act(() => {
      window.dispatchEvent(new CustomEvent("observatory:probe"));
    });

    expect(useObservatoryStore.getState().seamSummary.activeProbes).toBe(1);
    expect(
      (worldCanvasMock.state.lastProps?.probeState as { status: string }).status,
    ).toBe("active");

    nowMs = OBSERVATORY_PROBE_ACTIVE_MS + OBSERVATORY_PROBE_COOLDOWN_MS + 200;
    act(() => {
      vi.advanceTimersByTime(180);
    });

    expect(useObservatoryStore.getState().seamSummary.activeProbes).toBe(0);
    expect(
      (worldCanvasMock.state.lastProps?.probeState as { status: string }).status,
    ).toBe("ready");
  });

  it("opens the mapped workbench route when the selected station is clicked again", () => {
    const realDateNow = Date.now;
    let clock = realDateNow();
    Date.now = () => clock;

    render(<ObservatoryTab />);

    fireEvent.click(screen.getByTestId("select-station"));
    // Advance past the 400ms double-click window so the second click
    // is treated as a repeat-select (opens the route) rather than a
    // double-click (enters interior mode).
    clock += 500;
    fireEvent.click(screen.getByTestId("select-station"));

    expect(observatoryCommandActionsMock.openObservatoryStationRoute).toHaveBeenCalledWith(
      "receipts",
    );

    Date.now = realDateNow;
  });
});
