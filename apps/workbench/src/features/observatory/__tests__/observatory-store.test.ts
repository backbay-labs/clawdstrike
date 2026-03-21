import { beforeEach, describe, expect, it } from "vitest";
import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";
import type { HudPanelId } from "@/features/observatory/types";

const initialState = useObservatoryStore.getState();

describe("observatory-store", () => {
  beforeEach(() => {
    useObservatoryStore.setState({
      ...initialState,
      stations: initialState.stations.map((station) => ({ ...station, artifactCount: 0 })),
      seamSummary: { ...initialState.seamSummary, artifactCount: 0, activeProbes: 0 },
      mission: null,
      activePanel: null,
    });
  });

  it("boots with the six canonical observatory stations", () => {
    const { pressureLanes, seamSummary, stations, telemetrySnapshotMs } = useObservatoryStore.getState();

    expect(stations.map((station) => station.id)).toEqual([
      "signal",
      "targets",
      "run",
      "receipts",
      "case-notes",
      "watch",
    ]);
    expect(pressureLanes).toEqual([]);
    expect(seamSummary.stationCount).toBe(6);
    expect(telemetrySnapshotMs).toBeNull();
  });

  it("tracks active probe count through the dedicated action", () => {
    useObservatoryStore.getState().actions.setActiveProbes(3);
    expect(useObservatoryStore.getState().seamSummary.activeProbes).toBe(3);

    useObservatoryStore.getState().actions.setActiveProbes(-2);
    expect(useObservatoryStore.getState().seamSummary.activeProbes).toBe(0);
  });

  it("returns the updated mission when completing an objective", () => {
    const started = useObservatoryStore.getState().actions.startMission("workbench", 10);
    const completed = useObservatoryStore.getState().actions.completeObjective(
      "signal-dish-tower",
      20,
      { branchHint: "operations-first" },
    );

    expect(started.completedObjectiveIds).toHaveLength(0);
    expect(completed?.completedObjectiveIds).toEqual(["acknowledge-horizon-ingress"]);
    expect(useObservatoryStore.getState().mission?.completedObjectiveIds).toEqual([
      "acknowledge-horizon-ingress",
    ]);
  });

  it("persists ranked lanes and snapshot timing in scene telemetry", () => {
    useObservatoryStore.getState().actions.setSceneTelemetry({
      confidence: 0.73,
      likelyStationId: "receipts",
      pressureLanes: [
        {
          affinity: 0.8,
          emphasis: 0.82,
          isPrimary: true,
          label: "Evidence",
          rank: 1,
          rawPressure: 4,
          route: "/receipt-preview",
          routeLabel: "Receipt Preview",
          score: 0.84,
          stationId: "receipts",
          status: "receiving",
        },
      ],
      roomReceiveState: "receiving",
      telemetrySnapshotMs: 321,
    });

    expect(useObservatoryStore.getState().pressureLanes[0]?.stationId).toBe("receipts");
    expect(useObservatoryStore.getState().telemetrySnapshotMs).toBe(321);
  });

  describe("panel registry", () => {
    it("boots with activePanel as null", () => {
      expect(useObservatoryStore.getState().activePanel).toBeNull();
    });

    it("openPanel sets activePanel to the given id", () => {
      useObservatoryStore.getState().actions.openPanel("mission" as HudPanelId);
      expect(useObservatoryStore.getState().activePanel).toBe("mission");
    });

    it("openPanel replaces the current active panel — mutual exclusion by single field", () => {
      useObservatoryStore.getState().actions.openPanel("mission" as HudPanelId);
      useObservatoryStore.getState().actions.openPanel("replay" as HudPanelId);
      expect(useObservatoryStore.getState().activePanel).toBe("replay");
    });

    it("closePanel resets activePanel to null", () => {
      useObservatoryStore.getState().actions.openPanel("explainability" as HudPanelId);
      useObservatoryStore.getState().actions.closePanel();
      expect(useObservatoryStore.getState().activePanel).toBeNull();
    });

    it("togglePanel opens a panel when activePanel is null", () => {
      useObservatoryStore.getState().actions.togglePanel("mission" as HudPanelId);
      expect(useObservatoryStore.getState().activePanel).toBe("mission");
    });

    it("togglePanel closes the panel when the same id is already active", () => {
      useObservatoryStore.getState().actions.openPanel("mission" as HudPanelId);
      useObservatoryStore.getState().actions.togglePanel("mission" as HudPanelId);
      expect(useObservatoryStore.getState().activePanel).toBeNull();
    });

    it("togglePanel switches to the new panel when a different id is already active", () => {
      useObservatoryStore.getState().actions.openPanel("mission" as HudPanelId);
      useObservatoryStore.getState().actions.togglePanel("replay" as HudPanelId);
      expect(useObservatoryStore.getState().activePanel).toBe("replay");
    });
  });
});
