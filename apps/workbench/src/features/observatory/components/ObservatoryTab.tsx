// ObservatoryTab — store bridge wrapper that reads workbench stores and passes
// pre-built HuntObservatorySceneState to ObservatoryWorldCanvas.
// Pattern 1 from Phase 03 RESEARCH.md: ObservatoryTab as Store Bridge.
//
// This component intentionally props the canvas with a pre-built sceneState —
// it is the ONLY place that reads workbench stores and converts to huntronomer types.
//
// Plan 03-02 additions:
// - probeState: ObservatoryProbeState in local useState
// - window event "observatory:probe" → dispatchProbe callback
// - mode toggle button (ATLAS/FLOW) in top-right corner of tab

import {
  useState,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  Component,
  type ReactNode,
} from "react";
import { AnimatePresence, motion } from "motion/react";
import { useAchievementStore } from "../stores/achievement-store";
import type { Achievement } from "../stores/achievement-store";
import type { HuntStationId } from "../world/types";
import type { ObservatoryReplayAnnotation } from "../types";
import { useObservatoryStore } from "../stores/observatory-store";
import { useHuntStore } from "@/features/hunt/stores/hunt-store";
import { useSpiritStore } from "@/features/spirit/stores/spirit-store";
import { usePaneStore, getActivePaneRoute } from "@/features/panes/pane-store";
import { ObservatoryWorldCanvas } from "./ObservatoryWorldCanvas";
import type { SpiritKind } from "@/features/spirit/types";
import {
  advanceObservatoryProbeState,
  createInitialObservatoryProbeState,
  dispatchObservatoryProbe,
} from "../world/probeRuntime";
import { SpaceFlightHud } from "./hud/SpaceFlightHud";
import { ObservatoryStatusStrip } from "./hud/ObservatoryStatusStrip";
import { ObservatoryLeftDrawer } from "./hud/ObservatoryLeftDrawer";
import { useObservatoryHotkeys } from "./hud/useObservatoryHotkeys";
import {
  createObservatoryMissionPlan,
  deriveObservatoryMissionBranch,
  getCurrentObservatoryMissionObjective,
} from "../world/missionLoop";
import type { ObservatoryHeroPropAssetId } from "../world/propAssets";
import { OBSERVATORY_STATION_POSITIONS } from "../world/observatory-world-template";
import { HUNT_STATION_ORDER } from "../world/stations";
import { preloadObservatoryAssets } from "../utils/observatory-performance";
import { buildObservatorySceneState } from "../world/observatory-scene-bridge";
import { getObservatoryNowMs, useObservatoryNow } from "../utils/observatory-time";
import {
  buildObservatoryReplayFrames,
  buildObservatoryReplaySnapshot,
  buildObservatoryReplayTimeline,
  deriveObservatoryTelemetry,
  type DerivedObservatoryTelemetry,
  findObservatoryReplaySpikeFrameIndex,
} from "../world/observatory-telemetry";
import {
  buildObservatoryReplayMarkers,
  mergeObservatoryReplayMarkers,
} from "../world/observatory-replay-markers";
import {
  openObservatoryRecommendationRoute,
  openObservatoryStationRoute,
  setObservatoryAnalystPreset,
} from "../commands/observatory-command-actions";
import {
  buildObservatoryProbeGuidance,
  type ObservatoryProbeGuidance,
} from "../world/observatory-recommendations";
import {
  buildObservatorySpikeCueKey,
  deriveObservatorySpikeCue,
  type ObservatorySpikeCue,
} from "../world/observatory-presence";
import {
  deriveObservatoryGhostMemories,
  resolveObservatoryGhostPresentation,
} from "../world/observatory-ghost-memory";
import { deriveObservatoryWeatherState } from "../world/observatory-weather";
import {
  loadPersistedObservatoryReplayArtifacts,
  savePersistedObservatoryReplayArtifacts,
} from "../utils/observatory-replay-persistence";

// Maps workbench SpiritKind to ObservatorySpiritVisual.kind
const SPIRIT_KIND_MAP: Record<SpiritKind, "tracker" | "lantern" | "ledger" | "forge"> = {
  sentinel: "tracker",
  oracle: "lantern",
  witness: "ledger",
  specter: "forge",
};

function cn(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(" ");
}

// Temporary error boundary to surface R3F errors that Suspense swallows
class CanvasErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  render() {
    if (this.state.error) {
      return (
        <div className="absolute inset-0 flex items-center justify-center bg-[#05060a] text-red-400 text-xs font-mono p-4">
          <div>
            <p className="text-sm font-bold mb-2">Observatory Error</p>
            <pre className="whitespace-pre-wrap max-w-[600px] overflow-auto">{this.state.error.message}</pre>
            <pre className="whitespace-pre-wrap max-w-[600px] overflow-auto text-[#6f7f9a] mt-2">{this.state.error.stack?.split('\n').slice(0, 5).join('\n')}</pre>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

// UIP-04: Achievement popup toast — spring slide-in from right, auto-dismiss at 3.2s.
function AchievementToast({ achievement, onDone }: { achievement: Achievement; onDone: () => void }) {
  useEffect(() => {
    const timer = setTimeout(onDone, 3200);
    return () => clearTimeout(timer);
  }, [onDone]);

  return (
    <motion.div
      initial={{ opacity: 0, x: 60 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 60 }}
      transition={{ type: 'spring', stiffness: 380, damping: 28 }}
      className="bg-[#0a0d14]/90 border border-yellow-500/30 rounded-lg px-4 py-2 text-sm backdrop-blur-sm"
    >
      <div className="text-yellow-400 font-bold font-mono text-[11px] tracking-widest">{achievement.title}</div>
      <div className="text-yellow-200/60 text-[10px] font-mono mt-0.5">{achievement.description}</div>
    </motion.div>
  );
}

// UIP-04: Achievement overlay layer — renders outside Canvas using Framer Motion AnimatePresence.
function AchievementLayer() {
  const queue = useAchievementStore.use.queue();
  const popAchievement = useAchievementStore.use.actions().popAchievement;

  return (
    <div className="absolute bottom-6 right-4 z-30 flex flex-col gap-2 pointer-events-none">
      <AnimatePresence mode="popLayout">
        {queue.map((achievement: Achievement) => (
          <AchievementToast
            key={achievement.id}
            achievement={achievement}
            onDone={() => popAchievement(achievement.id)}
          />
        ))}
      </AnimatePresence>
    </div>
  );
}

export function ObservatoryTab() {
  const [mode, setMode] = useState<"atlas" | "flow">("atlas");
  const [characterControllerEnabled, setCharacterControllerEnabled] = useState(false);
  const [ghostMode, setGhostMode] = useState<"off" | "auto" | "full">("auto");
  const [cameraResetToken, setCameraResetToken] = useState(0);
  const [replayArtifactsHydrated, setReplayArtifactsHydrated] = useState(false);
  // Inline transient notification for Easter-egg (avoids ToastProvider context requirement in tests).
  // Message auto-clears after 3 seconds.
  const [easterEggMsg, setEasterEggMsg] = useState<string | null>(null);
  const easterEggTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showEasterEggNotification = useCallback((msg: string) => {
    if (easterEggTimerRef.current) clearTimeout(easterEggTimerRef.current);
    setEasterEggMsg(msg);
    easterEggTimerRef.current = setTimeout(() => setEasterEggMsg(null), 3000);
  }, []);

  // Cleanup timer on unmount
  useEffect(() => {
    return () => {
      if (easterEggTimerRef.current) clearTimeout(easterEggTimerRef.current);
    };
  }, []);

  useEffect(() => {
    preloadObservatoryAssets();
  }, []);

  // paneIsActive: true when the active pane is showing the /observatory route.
  // Prevents WASD from consuming keyboard events when another pane is focused.
  const paneIsActive = usePaneStore((state) =>
    getActivePaneRoute(state.root, state.activePaneId) === "/observatory",
  );

  // Phase 30 HUD-14/HUD-15: Panel hotkeys (E/R/M/G/Escape) — only active when this tab is focused
  useObservatoryHotkeys(paneIsActive);

  // CAM-01: Fly-by state — true until the opening sweep finishes for the first time this session
  const [flyByActive, setFlyByActive] = useState(true);
  // flyByDoneRef stays true once the fly-by completes; prevents replay on re-mount
  const flyByDoneRef = useRef(false);

  // CAM-01: Called when WorldCameraRig finishes all waypoints or user skips
  const handleFlyByComplete = useCallback(() => {
    flyByDoneRef.current = true;
    setFlyByActive(false);
  }, []);

  // CAM-01: Skip fly-by on click or Escape
  const handleSkipFlyBy = useCallback(() => {
    if (!flyByActive) return;
    handleFlyByComplete();
  }, [flyByActive, handleFlyByComplete]);

  // CAM-01: Escape key skips fly-by
  useEffect(() => {
    if (!flyByActive) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") handleSkipFlyBy();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [flyByActive, handleSkipFlyBy]);

  const stations = useObservatoryStore.use.stations();
  const confidence = useObservatoryStore.use.confidence();
  const likelyStationId = useObservatoryStore.use.likelyStationId();
  const pressureLanes = useObservatoryStore.use.pressureLanes();
  const analystPresetId = useObservatoryStore.use.analystPresetId();
  const mission = useObservatoryStore.use.mission();
  const probeState = useObservatoryStore.use.probeState();
  const replay = useObservatoryStore.use.replay();
  const roomReceiveState = useObservatoryStore.use.roomReceiveState();
  const selectedStationId = useObservatoryStore.use.selectedStationId();
  const observatoryActions = useObservatoryStore.use.actions();
  const connected = useObservatoryStore.use.connected();
  const huntEvents = useHuntStore.use.events();
  const huntBaselines = useHuntStore.use.baselines();
  const huntInvestigations = useHuntStore.use.investigations();
  const huntPatterns = useHuntStore.use.patterns();
  const kind = useSpiritStore.use.kind();
  const accentColor = useSpiritStore.use.accentColor();
  const openApp = usePaneStore((state) => state.openApp);
  const probeNowMs = useObservatoryNow(probeState.status !== "ready");
  const runtimeEnvironment = useMemo(() => {
    const navigatorConnection =
      typeof navigator !== "undefined" && "connection" in navigator
        ? (navigator as Navigator & { connection?: { saveData?: boolean } }).connection
        : undefined;
    const reducedMotion =
      typeof window !== "undefined"
      && typeof window.matchMedia === "function"
      && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    return {
      reducedMotion,
      saveData: navigatorConnection?.saveData === true,
    };
  }, []);
  const probeTelemetryBaselineRef = useRef<DerivedObservatoryTelemetry | null>(null);
  const previousStationEmphasisRef = useRef<Partial<Record<HuntStationId, number>>>({});
  const previousLikelyStationIdRef = useRef<HuntStationId | null>(null);
  const previousProbeStatusRef = useRef<typeof probeState.status | null>(probeState.status);
  const dismissedCueKeyRef = useRef<string | null>(null);
  const [activeSpikeCue, setActiveSpikeCue] = useState<ObservatorySpikeCue | null>(null);

  // TRN-03: Station arrival name card — triggered once per station per session within 180 units
  const arrivedStationsRef = useRef(new Set<HuntStationId>());
  const [arrivalStation, setArrivalStation] = useState<HuntStationId | null>(null);

  useEffect(() => {
    observatoryActions.setProbeState((current) => advanceObservatoryProbeState(current, probeNowMs));
  }, [observatoryActions, probeNowMs]);

  useEffect(() => {
    observatoryActions.setActiveProbes(probeState.status === "active" ? 1 : 0);
    return () => {
      observatoryActions.setActiveProbes(0);
    };
  }, [observatoryActions, probeState.status]);

  // UIP-04: Push achievement when a new mission objective is completed.
  // Tracks length delta to detect newly added completed objective IDs.
  const pushAchievement = useAchievementStore.use.actions().pushAchievement;
  const prevCompletedCountRef = useRef(0);
  useEffect(() => {
    if (!mission) { prevCompletedCountRef.current = 0; return; }
    const count = mission.completedObjectiveIds.length;
    if (count > prevCompletedCountRef.current) {
      const newId = mission.completedObjectiveIds[count - 1];
      pushAchievement({
        id: `obj-${newId ?? 'unknown'}-${Math.round(getObservatoryNowMs())}`,
        title: "OBJECTIVE COMPLETE",
        description: (newId ?? '').replace(/-/g, ' '),
      });
    }
    prevCompletedCountRef.current = count;
  }, [mission?.completedObjectiveIds?.length, pushAchievement]);

  const fallbackLiveTelemetry = useMemo(
    () =>
      deriveObservatoryTelemetry({
        baselines: huntBaselines,
        connected,
        events: huntEvents,
        investigations: huntInvestigations,
        patterns: huntPatterns,
      }),
    [connected, huntBaselines, huntEvents, huntInvestigations, huntPatterns],
  );
  const liveTelemetry = useMemo<DerivedObservatoryTelemetry>(
    () => ({
      confidence: pressureLanes.length > 0 ? confidence : fallbackLiveTelemetry.confidence,
      likelyStationId: likelyStationId ?? fallbackLiveTelemetry.likelyStationId,
      pressureLanes: pressureLanes.length > 0 ? pressureLanes : fallbackLiveTelemetry.pressureLanes,
      roomReceiveState,
      stations:
        pressureLanes.length > 0
          ? stations
          : fallbackLiveTelemetry.stations,
      telemetrySnapshotMs: fallbackLiveTelemetry.telemetrySnapshotMs,
    }),
    [
      confidence,
      fallbackLiveTelemetry,
      likelyStationId,
      pressureLanes,
      roomReceiveState,
      stations,
    ],
  );
  const sceneState = useMemo(
    () => buildObservatorySceneState({
      analystPresetId,
      confidence: liveTelemetry.confidence,
      likelyStationId: liveTelemetry.likelyStationId,
      mode,
      roomReceiveState: liveTelemetry.roomReceiveState,
      spiritFieldBias: kind ? 0.5 : 0,
      stations: liveTelemetry.stations,
    }),
    [analystPresetId, kind, liveTelemetry, mode],
  );
  const replayFrames = useMemo(
    () => buildObservatoryReplayFrames(huntEvents),
    [huntEvents],
  );
  const replayTimeline = useMemo(
    () =>
      buildObservatoryReplayTimeline({
        baselines: huntBaselines,
        connected,
        events: huntEvents,
        investigations: huntInvestigations,
        nowMs: liveTelemetry.telemetrySnapshotMs,
        patterns: huntPatterns,
      }),
    [
      connected,
      huntBaselines,
      huntEvents,
      huntInvestigations,
      huntPatterns,
      liveTelemetry.telemetrySnapshotMs,
    ],
  );
  const replaySpikes = replayTimeline.spikes;
  const replayBookmarks = replay.bookmarks ?? [];
  const replayAnnotations = replay.annotations ?? [];
  const replayFrame = replay.enabled
    ? (replayFrames[Math.min(replay.frameIndex, Math.max(0, replayFrames.length - 1))]
      ?? replayFrames[replayFrames.length - 1]
      ?? null)
    : null;
  const replayTelemetry = useMemo(
    () => {
      if (!replay.enabled || !replayFrame) {
        return null;
      }
      const maxFrameIndex = Math.min(replay.frameIndex, Math.max(0, replayFrames.length - 1));
      let previousTelemetry: DerivedObservatoryTelemetry | null = null;
      for (let frameIndex = 0; frameIndex <= maxFrameIndex; frameIndex += 1) {
        previousTelemetry = deriveObservatoryTelemetry({
          baselines: huntBaselines,
          connected,
          events: huntEvents,
          investigations: huntInvestigations,
          patterns: huntPatterns,
          previousTelemetry,
          snapshotMs: replayFrames[frameIndex]?.timestampMs ?? null,
        });
      }
      return previousTelemetry;
    },
    [connected, huntBaselines, huntEvents, huntInvestigations, huntPatterns, replay.enabled, replay.frameIndex, replayFrame, replayFrames],
  );
  const effectiveTelemetry = replay.enabled && replayTelemetry ? replayTelemetry : liveTelemetry;
  const effectiveSceneState = useMemo(
    () => buildObservatorySceneState({
      analystPresetId,
      confidence: effectiveTelemetry.confidence,
      likelyStationId: effectiveTelemetry.likelyStationId,
      mode,
      roomReceiveState: effectiveTelemetry.roomReceiveState,
      spiritFieldBias: kind ? 0.5 : 0,
      stations: effectiveTelemetry.stations,
    }),
    [analystPresetId, effectiveTelemetry, kind, mode],
  );
  const effectiveMission = replay.enabled ? null : mission;
  const effectiveProbeState = replay.enabled ? createInitialObservatoryProbeState() : probeState;
  const currentMissionObjective = getCurrentObservatoryMissionObjective(effectiveMission);
  const probeGuidance = useMemo<ObservatoryProbeGuidance | null>(
    () =>
      buildObservatoryProbeGuidance({
        currentTelemetry: effectiveTelemetry,
        missionObjective: currentMissionObjective
          ? {
              stationId: currentMissionObjective.stationId,
              title: currentMissionObjective.title,
            }
          : null,
        previousTelemetry: probeTelemetryBaselineRef.current,
        probeState: effectiveProbeState,
      }),
    [currentMissionObjective, effectiveProbeState, effectiveTelemetry],
  );
  const panelStationId =
    selectedStationId
    ?? effectiveTelemetry.pressureLanes[0]?.stationId
    ?? effectiveTelemetry.likelyStationId
    ?? null;
  const panelStation = panelStationId
    ? effectiveTelemetry.stations.find((station) => station.id === panelStationId) ?? null
    : null;
  // CAM-04: Derive active mission objective station for camera focus flight
  const missionObjectiveStationId: HuntStationId | null = effectiveMission
    ? (getCurrentObservatoryMissionObjective(effectiveMission)?.stationId ?? null)
    : null;

  const spirit = useMemo(
    () => (kind && accentColor ? { kind: SPIRIT_KIND_MAP[kind], accentColor } : null),
    [accentColor, kind],
  );
  const liveSnapshot = useMemo(
    () =>
      buildObservatoryReplaySnapshot({
        frame: {
          eventCount: huntEvents.length,
          label: "Live scene",
          timestampMs: liveTelemetry.telemetrySnapshotMs,
        },
        frameIndex: replayFrames.length,
        telemetry: liveTelemetry,
      }),
    [huntEvents.length, liveTelemetry, replayFrames.length],
  );
  const replaySnapshot = useMemo(
    () =>
      replay.enabled && replayFrame
        ? buildObservatoryReplaySnapshot({
            frame: replayFrame,
            frameIndex: Math.min(replay.frameIndex, Math.max(0, replayFrames.length - 1)),
            telemetry: effectiveTelemetry,
          })
        : null,
    [effectiveTelemetry, replay.enabled, replay.frameIndex, replayFrame, replayFrames.length],
  );
  const liveSpikeCue = useMemo(
    () =>
      deriveObservatorySpikeCue({
        flyByActive,
        likelyStationId: liveTelemetry.likelyStationId,
        missionTargetStationId: currentMissionObjective?.stationId ?? null,
        mode,
        nowMs: liveTelemetry.telemetrySnapshotMs,
        previousCueKey: dismissedCueKeyRef.current,
        previousLikelyStationId: previousLikelyStationIdRef.current,
        previousProbeStatus: previousProbeStatusRef.current,
        previousStationEmphasis: previousStationEmphasisRef.current,
        probeState,
        replayEnabled: replay.enabled,
        selectedStationId,
        stations: liveTelemetry.stations,
      }),
    [
      currentMissionObjective?.stationId,
      flyByActive,
      liveTelemetry.likelyStationId,
      liveTelemetry.stations,
      liveTelemetry.telemetrySnapshotMs,
      mode,
      probeState,
      replay.enabled,
      selectedStationId,
    ],
  );
  const ghostTraces = useMemo(
    () =>
      deriveObservatoryGhostMemories({
        activeStationId: selectedStationId ?? missionObjectiveStationId,
        events: huntEvents,
        ghostMode,
        investigations: huntInvestigations,
        likelyStationId: effectiveTelemetry.likelyStationId,
        missionTargetStationId: missionObjectiveStationId,
        mode,
        nowMs: effectiveTelemetry.telemetrySnapshotMs,
        probeState: effectiveProbeState,
        replayEnabled: replay.enabled,
        selectedStationId,
        stations: effectiveTelemetry.stations,
      }),
    [
      effectiveProbeState,
      effectiveTelemetry.likelyStationId,
      effectiveTelemetry.stations,
      effectiveTelemetry.telemetrySnapshotMs,
      ghostMode,
      huntEvents,
      huntInvestigations,
      missionObjectiveStationId,
      mode,
      replay.enabled,
      selectedStationId,
    ],
  );
  const ghostPresentation = useMemo(
    () =>
      resolveObservatoryGhostPresentation({
        activeStationId: selectedStationId ?? missionObjectiveStationId,
        ghostMode,
        mode,
        probeState: effectiveProbeState,
        replayEnabled: replay.enabled,
        selectedStationId,
        traceCount: ghostTraces.length,
      }),
    [
      effectiveProbeState,
      ghostMode,
      ghostTraces.length,
      missionObjectiveStationId,
      mode,
      replay.enabled,
      selectedStationId,
    ],
  );
  const weatherState = useMemo(
    () =>
      deriveObservatoryWeatherState({
        confidence: effectiveTelemetry.confidence,
        connected,
        likelyStationId: effectiveTelemetry.likelyStationId,
        mode,
        missionTargetStationId: missionObjectiveStationId,
        nowMs: effectiveTelemetry.telemetrySnapshotMs,
        replayEnabled: replay.enabled,
        reducedMotion: runtimeEnvironment.reducedMotion,
        roomReceiveState: effectiveTelemetry.roomReceiveState,
        saveData: runtimeEnvironment.saveData,
        stations: effectiveTelemetry.stations,
      }),
    [
      connected,
      effectiveTelemetry.confidence,
      effectiveTelemetry.likelyStationId,
      effectiveTelemetry.roomReceiveState,
      effectiveTelemetry.stations,
      effectiveTelemetry.telemetrySnapshotMs,
      missionObjectiveStationId,
      mode,
      replay.enabled,
      runtimeEnvironment.reducedMotion,
      runtimeEnvironment.saveData,
    ],
  );
  const replayMarkers = useMemo(() => {
    const authoredMarkers = buildObservatoryReplayMarkers({
      annotations: replayAnnotations,
      bookmarks: replayBookmarks,
      events: huntEvents,
      frames: replayFrames,
      investigations: [],
    });
    const investigationMarkers = buildObservatoryReplayMarkers({
      annotations: [],
      bookmarks: [],
      events: huntEvents,
      frames: replayFrames,
      investigations: huntInvestigations,
    });
    return mergeObservatoryReplayMarkers(authoredMarkers, investigationMarkers);
  }, [huntEvents, huntInvestigations, replayAnnotations, replayBookmarks, replayFrames]);

  const handleMissionObjectiveComplete = useCallback(
    (assetId: ObservatoryHeroPropAssetId, nowMs: number) =>
      observatoryActions.completeObjective(assetId, nowMs, {
        branchHint: deriveObservatoryMissionBranch(sceneState),
      }),
    [observatoryActions, sceneState],
  );

  const handleDispatchProbe = useCallback(() => {
    if (replay.enabled) {
      return;
    }
    const nowMs = getObservatoryNowMs();
    const targetStationId = selectedStationId ?? missionObjectiveStationId ?? likelyStationId ?? "signal";
    probeTelemetryBaselineRef.current = effectiveTelemetry;
    observatoryActions.setProbeState((current) =>
      dispatchObservatoryProbe(advanceObservatoryProbeState(current, nowMs), targetStationId, nowMs),
    );
  }, [effectiveTelemetry, likelyStationId, missionObjectiveStationId, observatoryActions, replay.enabled, selectedStationId]);

  const handleSelectStation = useCallback(
    (stationId: HuntStationId) => {
      if (selectedStationId === stationId) {
        openObservatoryStationRoute(stationId);
        return;
      }
      observatoryActions.setSelectedStation(stationId);
      // Phase 30 HUD-16: clicking a station opens the Explainability panel
      observatoryActions.openPanel("explainability");
      setCameraResetToken((prev) => prev + 1);
    },
    [observatoryActions, selectedStationId],
  );
  const handleStartMission = useCallback(() => {
    observatoryActions.startMission("workbench", probeNowMs, {
      branchHint: deriveObservatoryMissionBranch(effectiveSceneState),
      plan: createObservatoryMissionPlan({
        investigations: huntInvestigations,
        patterns: huntPatterns,
        sceneState: effectiveSceneState,
      }),
    });
    probeTelemetryBaselineRef.current = null;
    observatoryActions.resetProbe();
    observatoryActions.setReplayState({ enabled: false, frameIndex: 0, frameMs: null });
    setCameraResetToken((prev) => prev + 1);
  }, [effectiveSceneState, huntInvestigations, huntPatterns, observatoryActions, probeNowMs]);
  const handleReplayToggle = useCallback(() => {
    observatoryActions.setReplayState({
      enabled: !replay.enabled,
      frameIndex: replay.enabled ? 0 : Math.max(0, replayFrames.length - 1),
      frameMs: replay.enabled
        ? null
        : replayFrames[Math.max(0, replayFrames.length - 1)]?.timestampMs ?? null,
      selectedDistrictId: replay.enabled ? null : selectedStationId ?? null,
      selectedSpikeTimestampMs: null,
    });
  }, [observatoryActions, replay.enabled, replayFrames, selectedStationId]);
  const handleReplayJumpSpike = useCallback(
    (direction: "prev" | "next") => {
      const currentFrameIndex = Math.min(replay.frameIndex, Math.max(0, replayFrames.length - 1));
      const targetFrameIndex = findObservatoryReplaySpikeFrameIndex(
        replaySpikes,
        currentFrameIndex,
        direction,
      );
      if (targetFrameIndex == null) {
        return;
      }
      const targetFrame = replayFrames[targetFrameIndex] ?? null;
      const targetSpike = replaySpikes.find((spike) => spike.frameIndex === targetFrameIndex) ?? null;
      observatoryActions.setReplayState({
        enabled: true,
        frameIndex: targetFrameIndex,
        frameMs: targetFrame?.timestampMs ?? null,
        selectedDistrictId: targetSpike?.districtId ?? null,
        selectedSpikeTimestampMs: targetSpike?.timestampMs ?? targetFrame?.timestampMs ?? null,
      });
      if (targetSpike?.districtId) {
        observatoryActions.setSelectedStation(targetSpike.districtId);
      }
    },
    [observatoryActions, replay.frameIndex, replayFrames, replaySpikes],
  );
  const handleAddReplayBookmark = useCallback(
    (frame: (typeof replayFrames)[number]) => {
      const districtId =
        replaySnapshot?.likelyStationId
        ?? replay.selectedDistrictId
        ?? selectedStationId
        ?? effectiveTelemetry.likelyStationId
        ?? "signal";
      const districtLabel =
        replaySnapshot?.districts.find((district) => district.districtId === districtId)?.label
        ?? panelStation?.label
        ?? frame.label;
      observatoryActions.addReplayBookmark({
        districtId,
        frameIndex: Math.min(replay.frameIndex, Math.max(0, replayFrames.length - 1)),
        id: `bookmark:${frame.timestampMs}:${replayBookmarks.length}`,
        label: `${districtLabel} · ${frame.label}`,
        timestampMs: frame.timestampMs,
      });
    },
    [
      effectiveTelemetry.likelyStationId,
      observatoryActions,
      panelStation?.label,
      replay.frameIndex,
      replay.selectedDistrictId,
      replayBookmarks.length,
      replayFrames.length,
      replaySnapshot,
      selectedStationId,
    ],
  );
  const handleReplaySelectDistrict = useCallback(
    (districtId: HuntStationId) => {
      observatoryActions.setReplayState({
        selectedDistrictId: districtId,
      });
      observatoryActions.setSelectedStation(districtId);
    },
    [observatoryActions],
  );
  const handleReplayCreateAnnotation = useCallback(
    (annotation: ObservatoryReplayAnnotation) => {
      observatoryActions.upsertReplayAnnotation(annotation);
      observatoryActions.setReplayState({
        selectedDistrictId: annotation.districtId,
      });
    },
    [observatoryActions],
  );
  const handleDismissSpikeCue = useCallback(() => {
    if (activeSpikeCue) {
      dismissedCueKeyRef.current = buildObservatorySpikeCueKey(activeSpikeCue);
    }
    setActiveSpikeCue(null);
  }, [activeSpikeCue]);
  const handleOpenSpikeCueRoute = useCallback(
    (stationId: HuntStationId) => {
      if (activeSpikeCue) {
        dismissedCueKeyRef.current = buildObservatorySpikeCueKey(activeSpikeCue);
      }
      openObservatoryStationRoute(stationId);
      setActiveSpikeCue(null);
    },
    [activeSpikeCue],
  );
  const cycleGhostMode = useCallback(() => {
    setGhostMode((current) =>
      current === "off" ? "auto" : current === "auto" ? "full" : "off",
    );
  }, []);
  const handleReplayJumpMarker = useCallback(
    (markerId: string) => {
      const marker = replayMarkers.find((entry) => entry.id === markerId);
      if (!marker) {
        return;
      }
      observatoryActions.setReplayState({
        enabled: true,
        frameIndex: marker.frameIndex,
        frameMs: marker.timestampMs,
        selectedDistrictId: marker.districtId,
        selectedSpikeTimestampMs: null,
      });
      if (marker.districtId) {
        observatoryActions.setSelectedStation(marker.districtId);
      }
    },
    [observatoryActions, replayMarkers],
  );

  useEffect(() => {
    const handleProbe = () => {
      handleDispatchProbe();
    };
    const handleMissionStart = () => {
      handleStartMission();
    };
    const handleMissionReset = () => {
      observatoryActions.resetMission();
      observatoryActions.resetProbe();
      observatoryActions.setReplayState({ enabled: false, frameIndex: 0, frameMs: null });
    };
    window.addEventListener("observatory:probe", handleProbe);
    window.addEventListener("observatory:mission:start", handleMissionStart);
    window.addEventListener("observatory:mission:reset", handleMissionReset);
    return () => {
      window.removeEventListener("observatory:probe", handleProbe);
      window.removeEventListener("observatory:mission:start", handleMissionStart);
      window.removeEventListener("observatory:mission:reset", handleMissionReset);
    };
  }, [handleDispatchProbe, handleStartMission, observatoryActions]);
  useEffect(() => {
    if (liveSpikeCue == null) {
      return;
    }
    setActiveSpikeCue((current) =>
      current?.cueKey === liveSpikeCue.cueKey ? current : liveSpikeCue,
    );
  }, [liveSpikeCue]);
  useEffect(() => {
    if (flyByActive || replay.enabled) {
      setActiveSpikeCue(null);
    }
  }, [flyByActive, replay.enabled]);

  // TRN-03: Proximity detection for station arrival name card
  // Subscribe to flightState store changes (rare event — not per-frame)
  useEffect(() => {
    if (flyByActive || replay.enabled || !characterControllerEnabled) return;

    const unsubscribe = useObservatoryStore.subscribe((state) => {
      const position = state.flightState.position;
      if (!position) return;
      const [px, py, pz] = position;
      for (const stationId of HUNT_STATION_ORDER) {
        if (arrivedStationsRef.current.has(stationId)) continue;
        const stationPos = OBSERVATORY_STATION_POSITIONS[stationId];
        const dx = px - stationPos[0];
        const dy = py - stationPos[1];
        const dz = pz - stationPos[2];
        const distance = Math.sqrt(dx * dx + dy * dy + dz * dz);
        if (distance < 180) {
          arrivedStationsRef.current.add(stationId);
          setArrivalStation((current) => current === null ? stationId : current);
          break;
        }
      }
    });

    return unsubscribe;
  }, [flyByActive, replay.enabled, characterControllerEnabled]);
  useEffect(() => {
    previousStationEmphasisRef.current = Object.fromEntries(
      liveTelemetry.stations.map((station) => [station.id, station.emphasis ?? 0]),
    ) as Partial<Record<HuntStationId, number>>;
    previousLikelyStationIdRef.current = liveTelemetry.likelyStationId;
    previousProbeStatusRef.current = probeState.status;
  }, [liveTelemetry.likelyStationId, liveTelemetry.stations, probeState.status]);
  useEffect(() => {
    observatoryActions.setReplayMarkers(replayMarkers);
  }, [observatoryActions, replayMarkers]);
  useEffect(() => {
    const persisted = loadPersistedObservatoryReplayArtifacts();
    observatoryActions.hydrateReplayArtifacts(persisted);
    setReplayArtifactsHydrated(true);
  }, [observatoryActions]);
  useEffect(() => {
    if (!replayArtifactsHydrated) {
      return;
    }
    savePersistedObservatoryReplayArtifacts({
      annotations: replayAnnotations,
      bookmarks: replayBookmarks,
    });
  }, [replayAnnotations, replayArtifactsHydrated, replayBookmarks]);

  const handleDoubleClick = useCallback(() => {
    if (mode !== "flow") return;
    setCharacterControllerEnabled((prev) => {
      const next = !prev;
      showEasterEggNotification(next ? "Flight controls activated" : "Flight controls deactivated");
      return next;
    });
  }, [mode, showEasterEggNotification]);

  return (
    <div
      className="relative h-full flex-1 overflow-hidden"
      onDoubleClick={handleDoubleClick}
      onClick={flyByActive ? handleSkipFlyBy : undefined}
    >
      <div className="absolute inset-0">
        <CanvasErrorBoundary>
        <ObservatoryWorldCanvas
          mode={mode}
          sceneState={effectiveSceneState}
          mission={effectiveMission}
          probeState={effectiveProbeState}
          ghostPresentation={ghostPresentation}
          ghostTraces={ghostTraces}
          activeStationId={flyByActive ? null : selectedStationId ?? missionObjectiveStationId}
          spirit={spirit}
          weatherState={weatherState}
          cameraResetToken={cameraResetToken}
          onSelectStation={handleSelectStation}
          onProbeStateChange={observatoryActions.setProbeState}
          onMissionObjectiveComplete={handleMissionObjectiveComplete}
          className="absolute inset-0"
          flyByActive={flyByActive}
          frameloop={flyByActive || effectiveProbeState.status !== "ready" ? "always" : "demand"}
          playerInputEnabled={!replay.enabled && paneIsActive && characterControllerEnabled && mode === "flow"}
          replayFrameIndex={replay.enabled ? replay.frameIndex : null}
          onFlyByComplete={handleFlyByComplete}
        />
        </CanvasErrorBoundary>
      </div>

      {/* Phase 24 HUD: SpaceFlightHud overlay — visible only during flight mode */}
      <SpaceFlightHud
        visible={!flyByActive && !replay.enabled && characterControllerEnabled && mode === "flow"}
      />

      {/* Phase 30 HUD: ObservatoryLeftDrawer — slides in from left when a panel is active */}
      <ObservatoryLeftDrawer />

      {/* Phase 29 HUD: ObservatoryStatusStrip — persistent cockpit footer, always visible */}
      <ObservatoryStatusStrip />

      {/* CAM-01: Letterbox top bar — h-12 during fly-by, h-0 after */}
      <div
        className={cn(
          "absolute top-0 left-0 right-0 z-20 pointer-events-none bg-black transition-all duration-500",
          flyByActive ? "h-12" : "h-0",
        )}
      />

      {/* CAM-01: Letterbox bottom bar — h-12 during fly-by, h-0 after; shows skip hint */}
      <div
        className={cn(
          "absolute bottom-0 left-0 right-0 z-20 pointer-events-none transition-all duration-500 flex items-center justify-center bg-black",
          flyByActive ? "h-12" : "h-0 overflow-hidden",
        )}
      >
        {flyByActive && (
          <span className="text-[10px] font-mono text-white/40 tracking-widest select-none">
            CLAWDSTRIKE WORKBENCH — SECURITY OBSERVATORY &nbsp;&middot;&nbsp; ESC to skip
          </span>
        )}
      </div>

      {/* OBS-05: Mode toggle button (ATLAS/FLOW) — absolute top-right, z-10 */}
      <button
        type="button"
        className={cn(
          "absolute top-2 right-2 z-10 rounded-md px-2 py-1 text-[10px] font-mono transition-colors",
          mode === "flow"
            ? "bg-[#131721] text-[#3dbf84] border border-[#3dbf84]/40"
            : "bg-[#0a0d14]/80 text-[#6f7f9a] border border-[#202531]",
        )}
        onClick={() => setMode(mode === "atlas" ? "flow" : "atlas")}
      >
        {mode === "flow" ? "FLOW" : "ATLAS"}
      </button>


      {/* OBS-06: Easter-egg activation toast — inline notification, no ToastProvider required */}
      {easterEggMsg && (
        <div
          className="absolute bottom-8 left-1/2 -translate-x-1/2 z-20 px-4 py-2 rounded-md bg-[#0b0d13] border border-[#3dbf84]/40 text-[#3dbf84] text-xs font-mono pointer-events-none select-none"
          data-testid="easter-egg-toast"
        >
          {easterEggMsg}
        </div>
      )}

      {/* Probe status indicator and mode state attrs for tests */}
      <div
        className="sr-only"
        data-observatory-mode={mode}
        data-observatory-character-controller={characterControllerEnabled ? "on" : "off"}
        data-observatory-probe-status={probeState.status}
        data-observatory-replay={replay.enabled ? "on" : "off"}
      />

      {/* UIP-04: Achievement popups — outside Canvas, Framer Motion AnimatePresence */}
      <AchievementLayer />
    </div>
  );
}
