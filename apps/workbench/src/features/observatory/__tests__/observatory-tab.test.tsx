import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { useAchievementStore } from "@/features/observatory/stores/achievement-store";
import { ObservatoryTab } from "@/features/observatory/components/ObservatoryTab";
import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";
import {
  OBSERVATORY_PROBE_ACTIVE_MS,
  advanceObservatoryProbeState,
  createInitialObservatoryProbeState,
  dispatchObservatoryProbe,
} from "@/features/observatory/world/probeRuntime";
import { getActivePaneRoute, usePaneStore } from "@/features/panes/pane-store";
import { useSpiritStore } from "@/features/spirit/stores/spirit-store";
import { useHuntStore } from "@/features/hunt/stores/hunt-store";
import type { AgentEvent } from "@/lib/workbench/hunt-types";
import { OBSERVATORY_REPLAY_PERSISTENCE_KEY } from "@/features/observatory/utils/observatory-replay-persistence";

function makeEvent(
  id: string,
  overrides: Partial<AgentEvent> = {},
): AgentEvent {
  return {
    id,
    timestamp: "2026-03-19T16:00:00.000Z",
    agentId: `agent-${id}`,
    agentName: `Agent ${id}`,
    sessionId: `session-${id}`,
    actionType: "shell_command",
    target: "/tmp/test",
    verdict: "allow",
    guardResults: [],
    policyVersion: "1.4.0",
    flags: [],
    ...overrides,
  };
}

const tabTestState = vi.hoisted(() => ({
  lastWorldProps: null as Record<string, unknown> | null,
  preloadObservatoryAssets: vi.fn(),
}));

vi.mock("motion/react", () => ({
  AnimatePresence: ({ children }: { children: ReactNode }) => <>{children}</>,
  motion: {
    div: ({ children, ...props }: { children?: ReactNode }) => <div {...props}>{children}</div>,
  },
}));

vi.mock("@/features/observatory/components/ObservatoryWorldCanvas", () => ({
  ObservatoryWorldCanvas: (props: Record<string, unknown>) => {
    tabTestState.lastWorldProps = props;
    return <div data-testid="r3f-canvas" />;
  },
}));

vi.mock("@/features/observatory/utils/observatory-performance", async () => {
  const actual = await vi.importActual<typeof import("@/features/observatory/utils/observatory-performance")>(
    "@/features/observatory/utils/observatory-performance",
  );
  return {
    ...actual,
    preloadObservatoryAssets: tabTestState.preloadObservatoryAssets,
  };
});

const initialObservatoryState = useObservatoryStore.getState();
const initialPaneState = usePaneStore.getState();
const initialHuntState = useHuntStore.getState();
const achievementActions = useAchievementStore.getState().actions;

describe("ObservatoryTab", () => {
  beforeEach(() => {
    tabTestState.lastWorldProps = null;
    tabTestState.preloadObservatoryAssets.mockReset();
    useObservatoryStore.setState({
      ...initialObservatoryState,
      probeState: createInitialObservatoryProbeState(),
      mission: null,
      replay: {
        enabled: false,
        frameIndex: 0,
        frameMs: null,
      },
      selectedStationId: null,
      seamSummary: {
        ...initialObservatoryState.seamSummary,
        activeProbes: 0,
        artifactCount: 0,
      },
      stations: initialObservatoryState.stations.map((station) => ({
        ...station,
        artifactCount: 0,
      })),
    });
    useHuntStore.setState({
      ...initialHuntState,
      baselines: [],
      connected: false,
      events: [],
      investigations: [],
      patterns: [],
      stats: initialHuntState.stats,
      actions: initialHuntState.actions,
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
    window.localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("renders and preloads the observatory shell", () => {
    const { container } = render(<ObservatoryTab />);
    expect(container.firstChild).not.toBeNull();
    expect(screen.getByTestId("r3f-canvas")).toBeDefined();
    expect(tabTestState.preloadObservatoryAssets).toHaveBeenCalledTimes(1);
  });

  it("defaults to atlas mode and shows the opening fly-by bars", () => {
    const { container } = render(<ObservatoryTab />);
    expect(container.querySelector("[data-observatory-mode]")?.getAttribute("data-observatory-mode")).toBe("atlas");
    expect(tabTestState.lastWorldProps?.mode).toBe("atlas");
    expect(container.querySelectorAll(".h-12").length).toBeGreaterThanOrEqual(1);
  });

  it("collapses the fly-by letterbox after Escape skips the intro", () => {
    const { container } = render(<ObservatoryTab />);

    act(() => {
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    });

    expect(container.querySelectorAll(".h-0").length).toBeGreaterThanOrEqual(1);
  });

  it("registers and cleans up observatory lifecycle listeners", () => {
    const addEventSpy = vi.spyOn(window, "addEventListener");
    const removeEventSpy = vi.spyOn(window, "removeEventListener");
    const { unmount } = render(<ObservatoryTab />);

    expect(addEventSpy.mock.calls.some(([type]) => type === "keydown")).toBe(true);
    expect(addEventSpy.mock.calls.some(([type]) => type === "observatory:probe")).toBe(true);
    expect(addEventSpy.mock.calls.some(([type]) => type === "observatory:mission:start")).toBe(true);
    expect(addEventSpy.mock.calls.some(([type]) => type === "observatory:mission:reset")).toBe(true);

    unmount();

    expect(removeEventSpy.mock.calls.some(([type]) => type === "keydown")).toBe(true);
    expect(removeEventSpy.mock.calls.some(([type]) => type === "observatory:probe")).toBe(true);
    expect(removeEventSpy.mock.calls.some(([type]) => type === "observatory:mission:start")).toBe(true);
    expect(removeEventSpy.mock.calls.some(([type]) => type === "observatory:mission:reset")).toBe(true);
  });

  it("toggles to flow mode and enables character controls on double-click", () => {
    const { container, getByText } = render(<ObservatoryTab />);

    fireEvent.click(getByText("ATLAS"));
    fireEvent.doubleClick(container.firstChild as HTMLElement);

    expect(container.querySelector("[data-observatory-mode]")?.getAttribute("data-observatory-mode")).toBe("flow");
    expect(
      container.querySelector("[data-observatory-character-controller]")?.getAttribute(
        "data-observatory-character-controller",
      ),
    ).toBe("on");
    expect(tabTestState.lastWorldProps?.playerInputEnabled).toBe(true);
  });

  it("dispatches probes from the observatory event bridge when replay is disabled", () => {
    vi.useFakeTimers();
    let nowMs = 0;
    vi.spyOn(performance, "now").mockImplementation(() => nowMs);

    const { container } = render(<ObservatoryTab />);

    act(() => {
      window.dispatchEvent(new CustomEvent("observatory:probe"));
    });

    expect(useObservatoryStore.getState().probeState.status).toBe("active");
    expect(container.querySelector("[data-observatory-probe-status]")?.getAttribute("data-observatory-probe-status")).toBe("active");
  });

  it("ignores probe dispatch events while replay mode is active", () => {
    useObservatoryStore.getState().actions.setReplayState({
      enabled: true,
      frameIndex: 0,
      frameMs: 123,
    });
    const { container } = render(<ObservatoryTab />);

    act(() => {
      window.dispatchEvent(new CustomEvent("observatory:probe"));
    });

    expect(useObservatoryStore.getState().probeState.status).toBe("ready");
    expect(container.querySelector("[data-observatory-replay]")?.getAttribute("data-observatory-replay")).toBe("on");
  });

  it("starts a mission from the observatory event bridge and returns replay to live", () => {
    useObservatoryStore.getState().actions.setReplayState({
      enabled: true,
      frameIndex: 2,
      frameMs: 999,
    });
    render(<ObservatoryTab />);

    act(() => {
      window.dispatchEvent(new CustomEvent("observatory:mission:start"));
    });

    expect(useObservatoryStore.getState().mission).not.toBeNull();
    expect(useObservatoryStore.getState().replay.enabled).toBe(false);
  });

  it("renders the explainability panel and opens direct cause routes", () => {
    useObservatoryStore.setState((state) => ({
      ...state,
      likelyStationId: "receipts",
      pressureLanes: [
        {
          affinity: 0.84,
          emphasis: 0.88,
          isPrimary: true,
          label: "Evidence",
          rank: 1,
          rawPressure: 4,
          route: "/receipt-preview",
          routeLabel: "Receipt Preview",
          score: 0.9,
          stationId: "receipts",
          status: "receiving",
        },
        {
          affinity: 0.71,
          emphasis: 0.74,
          isPrimary: false,
          label: "Watchfield",
          rank: 2,
          rawPressure: 3,
          route: "/nexus",
          routeLabel: "Nexus",
          score: 0.72,
          stationId: "watch",
          status: "active",
        },
      ],
      stations: state.stations.map((station) =>
        station.id === "receipts"
          ? {
              ...station,
              artifactCount: 2,
              explanation: {
                causes: [
                  {
                    count: 1,
                    id: "receipts-investigations",
                    kind: "investigation",
                    label: "Open investigations",
                    route: "/hunt",
                    routeLabel: "Hunt Stream",
                    summary: "Investigations are pinning new evidence arrivals to active analyst work.",
                    weight: 0.65,
                  },
                ],
                generatedAtMs: 123,
                primaryLaneId: "receipts",
                stationId: "receipts",
                summary: "Evidence is elevated because investigations are pinning new evidence arrivals to active analyst work.",
              },
              label: "Evidence",
              route: "/receipt-preview",
              routeLabel: "Receipt Preview",
              status: "receiving",
            }
          : station,
      ),
    }));

    render(<ObservatoryTab />);

    act(() => {
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    });

    expect(screen.getByTestId("observatory-explainability-panel")).toBeDefined();
    expect(screen.getAllByText("Evidence").length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: "Hunt Stream" }));

    expect(
      getActivePaneRoute(usePaneStore.getState().root, usePaneStore.getState().activePaneId),
    ).toBe("/hunt");
  });

  it("surfaces a cinematic cue for a live spike and hands off to the recommended route", () => {
    render(<ObservatoryTab />);

    act(() => {
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    });

    act(() => {
      useObservatoryStore.setState((state) => ({
        ...state,
        likelyStationId: "receipts",
        pressureLanes: [
          {
            affinity: 0.84,
            emphasis: 0.88,
            isPrimary: true,
            label: "Evidence",
            rank: 1,
            rawPressure: 4,
            route: "/receipt-preview",
            routeLabel: "Receipt Preview",
            score: 0.9,
            stationId: "receipts",
            status: "receiving",
          },
        ],
        stations: state.stations.map((station) =>
          station.id === "receipts"
            ? {
                ...station,
                artifactCount: 4,
                emphasis: 0.88,
                label: "Receipts",
                reason: "Investigations are pinning new evidence arrivals to active analyst work.",
                route: "/receipt-preview",
                routeLabel: "Receipt Preview",
                status: "receiving",
              }
            : station,
        ),
      }));
    });

    expect(screen.getByTestId("observatory-cinematic-overlay")).toBeDefined();
    fireEvent.click(screen.getByRole("button", { name: "Open Receipt Preview" }));

    expect(
      getActivePaneRoute(usePaneStore.getState().root, usePaneStore.getState().activePaneId),
    ).toBe("/receipt-preview");
  });

  it("enters replay mode, mounts the compare panel, and stores bookmarks", () => {
    useHuntStore.setState((state) => ({
      ...state,
      connected: true,
      events: [
        makeEvent("receipt-1", { actionType: "file_access", receiptId: "receipt-1" }),
        makeEvent("receipt-2", {
          actionType: "file_write",
          receiptId: "receipt-2",
          timestamp: "2026-03-19T16:30:00.000Z",
          verdict: "deny",
        }),
      ],
      investigations: [],
      patterns: [],
      baselines: [],
      stats: state.stats,
      actions: state.actions,
    }));

    render(<ObservatoryTab />);

    act(() => {
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    });

    fireEvent.click(screen.getByRole("button", { name: "Replay 24h" }));

    expect(screen.getByTestId("observatory-replay-compare-panel")).toBeDefined();

    fireEvent.click(screen.getByRole("button", { name: "Bookmark" }));

    expect(useObservatoryStore.getState().replay.enabled).toBe(true);
    expect(useObservatoryStore.getState().replay.bookmarks?.length).toBe(1);
  });

  it("hydrates persisted replay artifacts without wiping them on first mount", async () => {
    window.localStorage.setItem(
      OBSERVATORY_REPLAY_PERSISTENCE_KEY,
      JSON.stringify({
        annotations: [
          {
            authorLabel: "Operator",
            body: "Persisted annotation",
            districtId: "receipts",
            frameIndex: 1,
            id: "annotation-1",
            sourceType: "manual",
            timestampMs: Date.parse("2026-03-19T16:30:00.000Z"),
          },
        ],
        bookmarks: [
          {
            districtId: "watch",
            frameIndex: 0,
            id: "bookmark-1",
            label: "Persisted watch spike",
            timestampMs: Date.parse("2026-03-19T16:00:00.000Z"),
          },
        ],
      }),
    );

    render(<ObservatoryTab />);

    await waitFor(() => {
      expect(useObservatoryStore.getState().replay.bookmarks).toHaveLength(1);
      expect(useObservatoryStore.getState().replay.annotations).toHaveLength(1);
    });

    expect(JSON.parse(window.localStorage.getItem(OBSERVATORY_REPLAY_PERSISTENCE_KEY) ?? "{}")).toMatchObject({
      annotations: [{ id: "annotation-1" }],
      bookmarks: [{ id: "bookmark-1" }],
    });
  });
});
