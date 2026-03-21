import type { ObservatoryAnalystPresetId } from "../types";
import { usePaneStore } from "@/features/panes/pane-store";
import { useSpiritStore } from "@/features/spirit/stores/spirit-store";
import { useObservatoryStore } from "../stores/observatory-store";
import { deriveObservatoryTelemetry, resolveObservatoryStationRoute } from "../world/observatory-telemetry";
import { buildObservatorySceneState } from "../world/observatory-scene-bridge";
import {
  advanceObservatoryProbeState,
  dispatchObservatoryProbe,
} from "../world/probeRuntime";
import {
  createObservatoryMissionPlan,
  deriveObservatoryMissionBranch,
} from "../world/missionLoop";
import { getObservatoryNowMs } from "../utils/observatory-time";
import { useHuntStore } from "@/features/hunt/stores/hunt-store";
import type { ObservatoryRecommendation } from "../world/observatory-recommendations";

const SPIRIT_KIND_WEIGHT = 0.5;
const PRESET_FOCUS_STATION: Record<ObservatoryAnalystPresetId, Parameters<typeof openObservatoryStationRoute>[0]> = {
  threat: "watch",
  evidence: "case-notes",
  receipts: "receipts",
  ghost: "watch",
};

function buildCurrentSceneState(mode: "atlas" | "flow" = "atlas") {
  const observatory = useObservatoryStore.getState();
  const telemetry = deriveObservatoryTelemetry({
    baselines: useHuntStore.getState().baselines,
    connected: useHuntStore.getState().connected,
    events: useHuntStore.getState().events,
    investigations: useHuntStore.getState().investigations,
    patterns: useHuntStore.getState().patterns,
  });
  const spiritKind = useSpiritStore.getState().kind;
  return buildObservatorySceneState({
    analystPresetId: observatory.analystPresetId,
    confidence: telemetry.confidence || observatory.confidence,
    likelyStationId: telemetry.likelyStationId ?? observatory.likelyStationId,
    mode,
    roomReceiveState: telemetry.roomReceiveState,
    spiritFieldBias: spiritKind ? SPIRIT_KIND_WEIGHT : 0,
    stations: telemetry.stations,
  });
}

export function startObservatoryMission(): void {
  const sceneState = buildCurrentSceneState("atlas");
  const nowMs = getObservatoryNowMs();
  const actions = useObservatoryStore.getState().actions;
  actions.startMission("workbench", nowMs, {
    branchHint: deriveObservatoryMissionBranch(sceneState),
    plan: createObservatoryMissionPlan({
      investigations: useHuntStore.getState().investigations,
      patterns: useHuntStore.getState().patterns,
      sceneState,
    }),
  });
  actions.resetProbe();
  usePaneStore.getState().openApp("/observatory", "Observatory");
}

export function resetObservatoryMission(): void {
  const actions = useObservatoryStore.getState().actions;
  actions.resetMission();
  actions.resetProbe();
}

export function dispatchObservatoryProbeCommand(): void {
  const observatory = useObservatoryStore.getState();
  const nowMs = getObservatoryNowMs();
  const nextState = advanceObservatoryProbeState(observatory.probeState, nowMs);
  if (nextState.status !== "ready") {
    return;
  }

  const targetStationId =
    observatory.selectedStationId
    ?? observatory.likelyStationId
    ?? "signal";
  observatory.actions.setProbeState(
    dispatchObservatoryProbe(nextState, targetStationId, nowMs),
  );
}

export function openObservatoryStationRoute(stationId: Parameters<typeof resolveObservatoryStationRoute>[0]): void {
  const route = resolveObservatoryStationRoute(stationId);
  useObservatoryStore.getState().actions.setSelectedStation(stationId);
  usePaneStore.getState().openApp(route.route, route.label);
}

export function setObservatoryAnalystPreset(
  presetId: ObservatoryAnalystPresetId | null,
): void {
  useObservatoryStore.getState().actions.setAnalystPreset(presetId);
  if (presetId) {
    useObservatoryStore.getState().actions.setSelectedStation(PRESET_FOCUS_STATION[presetId]);
  }
}

export function openObservatoryRecommendationRoute(
  recommendation: ObservatoryRecommendation | null,
): void {
  if (!recommendation) {
    return;
  }
  useObservatoryStore.getState().actions.setSelectedStation(recommendation.stationId);
  usePaneStore.getState().openApp(recommendation.route, recommendation.routeLabel);
}
