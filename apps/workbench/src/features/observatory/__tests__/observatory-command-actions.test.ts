import { beforeEach, describe, expect, it } from "vitest";
import {
  dispatchObservatoryProbeCommand,
  openObservatoryRecommendationRoute,
  openObservatoryStationRoute,
  resetObservatoryMission,
  setObservatoryAnalystPreset,
  startObservatoryMission,
} from "@/features/observatory/commands/observatory-command-actions";
import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";
import { usePaneStore, getActivePaneRoute } from "@/features/panes/pane-store";
import { useSpiritStore } from "@/features/spirit/stores/spirit-store";
import { useHuntStore } from "@/features/hunt/stores/hunt-store";
import type { AgentEvent } from "@/lib/workbench/hunt-types";
import { dispatchObservatoryProbe } from "@/features/observatory/world/probeRuntime";
import type { ObservatoryRecommendation } from "@/features/observatory/world/observatory-recommendations";

const NOW_ISO = "2026-03-19T16:00:00.000Z";

function makeEvent(
  id: string,
  overrides: Partial<AgentEvent> = {},
): AgentEvent {
  return {
    id,
    timestamp: NOW_ISO,
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

const initialObservatoryState = useObservatoryStore.getState();
const initialPaneState = usePaneStore.getState();
const initialHuntState = useHuntStore.getState();

describe("observatory command actions", () => {
  beforeEach(() => {
    useObservatoryStore.setState({
      ...initialObservatoryState,
      mission: null,
      probeState: initialObservatoryState.probeState,
      selectedStationId: null,
      replay: { enabled: false, frameIndex: 0, frameMs: null },
      stations: initialObservatoryState.stations.map((station) => ({
        ...station,
        artifactCount: 0,
      })),
      seamSummary: {
        ...initialObservatoryState.seamSummary,
        artifactCount: 0,
        activeProbes: 0,
      },
    });
    usePaneStore.setState({
      ...initialPaneState,
      root: initialPaneState.root,
      activePaneId: initialPaneState.activePaneId,
    });
    usePaneStore.getState()._reset();
    usePaneStore.getState().syncRoute("/home");
    useHuntStore.setState({
      ...initialHuntState,
      baselines: [],
      connected: true,
      events: [],
      investigations: [],
      patterns: [],
      stats: initialHuntState.stats,
      actions: initialHuntState.actions,
    });
    useSpiritStore.getState().actions.unbindSpirit();
  });

  it("opens the mapped pane route and selects the station", () => {
    openObservatoryStationRoute("watch");

    expect(useObservatoryStore.getState().selectedStationId).toBe("watch");
    expect(
      getActivePaneRoute(usePaneStore.getState().root, usePaneStore.getState().activePaneId),
    ).toBe("/nexus");
  });

  it("dispatches a probe against the selected station and ignores re-dispatch while busy", () => {
    useObservatoryStore.getState().actions.setSelectedStation("watch");

    dispatchObservatoryProbeCommand();

    expect(useObservatoryStore.getState().probeState.status).toBe("active");
    expect(useObservatoryStore.getState().probeState.targetStationId).toBe("watch");

    const activeState = useObservatoryStore.getState().probeState;
    dispatchObservatoryProbeCommand();

    expect(useObservatoryStore.getState().probeState).toEqual(activeState);
  });

  it("starts a mission, resets probe state, and focuses the observatory pane", () => {
    useObservatoryStore.getState().actions.setProbeState(
      dispatchObservatoryProbe(initialObservatoryState.probeState, "signal", 10),
    );
    useHuntStore.setState((state) => ({
      ...state,
      events: [
        makeEvent("receipt-1", { actionType: "file_access", receiptId: "receipt-1" }),
        makeEvent("receipt-2", { actionType: "file_write", receiptId: "receipt-2" }),
      ],
      investigations: [
        {
          id: "inv-1",
          title: "Receipt pressure",
          status: "open",
          severity: "high",
          createdAt: NOW_ISO,
          updatedAt: NOW_ISO,
          createdBy: "operator",
          agentIds: ["agent-receipt-1"],
          sessionIds: ["session-receipt-1"],
          timeRange: { start: NOW_ISO, end: NOW_ISO },
          eventIds: ["receipt-1"],
          annotations: [],
        },
      ],
    }));

    startObservatoryMission();

    expect(useObservatoryStore.getState().mission).not.toBeNull();
    expect(useObservatoryStore.getState().probeState.status).toBe("ready");
    expect(
      getActivePaneRoute(usePaneStore.getState().root, usePaneStore.getState().activePaneId),
    ).toBe("/observatory");
  });

  it("resets mission and probe state together", () => {
    startObservatoryMission();
    useObservatoryStore.getState().actions.setProbeState(
      dispatchObservatoryProbe(initialObservatoryState.probeState, "run", 10),
    );

    resetObservatoryMission();

    expect(useObservatoryStore.getState().mission).toBeNull();
    expect(useObservatoryStore.getState().probeState).toEqual(initialObservatoryState.probeState);
  });

  it("selects the mapped focus station when an analyst preset is applied", () => {
    setObservatoryAnalystPreset("receipts");

    expect(useObservatoryStore.getState().analystPresetId).toBe("receipts");
    expect(useObservatoryStore.getState().selectedStationId).toBe("receipts");
  });

  it("opens the recommendation route and updates station focus", () => {
    const recommendation: ObservatoryRecommendation = {
      confidence: 0.84,
      route: "/receipt-preview",
      routeLabel: "Receipt Preview",
      stationId: "receipts",
      summary: "Open the receipts surface for the current probe result.",
      supportingStationIds: ["watch"],
      title: "Open Receipt Preview",
    };

    openObservatoryRecommendationRoute(recommendation);

    expect(useObservatoryStore.getState().selectedStationId).toBe("receipts");
    expect(
      getActivePaneRoute(usePaneStore.getState().root, usePaneStore.getState().activePaneId),
    ).toBe("/receipt-preview");
  });
});
