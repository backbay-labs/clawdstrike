// ObservatoryTab — store bridge wrapper that reads workbench stores and passes
// pre-built HuntObservatorySceneState to ObservatoryWorldCanvas.
// Pattern 1 from Phase 03 RESEARCH.md: ObservatoryTab as Store Bridge.
//
// This component intentionally props the canvas with a pre-built sceneState —
// it is the ONLY place that reads workbench stores and converts to huntronomer types.
//
// Plan 03-02 additions:
// - probeState: ObservatoryProbeState in local useState
// - frameloop: "demand" | "always" — switches to "always" during active probe, back to "demand" otherwise
// - window event "observatory:probe" → dispatchProbe callback
// - mode toggle button (ATLAS/FLOW) in top-right corner of tab

import { useState, useCallback, useEffect, useRef, Component, type ReactNode } from "react";
import { AnimatePresence, motion } from "motion/react";
import { useAchievementStore } from "../stores/achievement-store";
import type { Achievement } from "../stores/achievement-store";
import type { HuntObservatorySceneState, HuntStationId, HuntStationState } from "../world/types";
import { HUNT_STATION_LABELS, HUNT_STATION_PLACEMENTS } from "../world/stations";
import { useObservatoryStore } from "../stores/observatory-store";
import { useSpiritStore } from "@/features/spirit/stores/spirit-store";
import { usePaneStore, getActivePaneRoute } from "@/features/panes/pane-store";
import { ObservatoryWorldCanvas } from "./ObservatoryWorldCanvas";
import type { SpiritKind } from "@/features/spirit/types";
import type { ObservatoryProbeState } from "../world/probeRuntime";
import {
  createInitialObservatoryProbeState,
  advanceObservatoryProbeState,
  dispatchObservatoryProbe,
} from "../world/probeRuntime";
import { ObservatoryProbeHud } from "./ObservatoryProbeHud";
import { ObservatoryMissionHud } from "./ObservatoryMissionHud";
import { resolveObservatoryMissionProbeTargetStationId, getCurrentObservatoryMissionObjective } from "../world/missionLoop";
import { STATION_AFFINITY_MAP } from "@/features/spirit/scene-math";

// Fixed station IDs that huntronomer recognizes — maps workbench stations to world positions.
const WORKBENCH_STATION_IDS: HuntStationId[] = HUNT_STATION_PLACEMENTS.map((p) => p.id);

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
  const [cameraResetToken, setCameraResetToken] = useState(0);
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

  // paneIsActive: true when the active pane is showing the /observatory route.
  // Prevents WASD from consuming keyboard events when another pane is focused.
  const paneIsActive = usePaneStore((state) =>
    getActivePaneRoute(state.root, state.activePaneId) === "/observatory",
  );

  // OBS-04: Probe state machine (local — purely visual/transient, not in Zustand store)
  const [probeState, setProbeState] = useState<ObservatoryProbeState>(
    () => createInitialObservatoryProbeState(),
  );

  // OBS-04: Frameloop switching — "always" during active probe, "demand" otherwise
  const [frameloop, setFrameloop] = useState<"demand" | "always">("demand");

  // CAM-01: Fly-by state — true until the opening sweep finishes for the first time this session
  const [flyByActive, setFlyByActive] = useState(true);
  // flyByDoneRef stays true once the fly-by completes; prevents replay on re-mount
  const flyByDoneRef = useRef(false);

  // CAM-01: Called when WorldCameraRig finishes all waypoints or user skips
  const handleFlyByComplete = useCallback(() => {
    flyByDoneRef.current = true;
    setFlyByActive(false);
    // Revert frameloop to demand — fly-by was holding it at "always"
    setFrameloop("demand");
  }, []);

  // CAM-01: Skip fly-by on click or Escape
  const handleSkipFlyBy = useCallback(() => {
    if (!flyByActive) return;
    handleFlyByComplete();
  }, [flyByActive, handleFlyByComplete]);

  // CAM-01: Force frameloop=always while fly-by is active
  useEffect(() => {
    if (flyByActive && !flyByDoneRef.current) {
      setFrameloop("always");
    }
  }, [flyByActive]);

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
  const mission = useObservatoryStore.use.mission();
  const kind = useSpiritStore.use.kind();
  const accentColor = useSpiritStore.use.accentColor();

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
        id: `obj-${newId ?? 'unknown'}-${Date.now()}`,
        title: "OBJECTIVE COMPLETE",
        description: (newId ?? '').replace(/-/g, ' '),
      });
    }
    prevCompletedCountRef.current = count;
  }, [mission?.completedObjectiveIds?.length, pushAchievement]);

  // CAM-04: Derive active mission objective station for camera focus flight
  const missionObjectiveStationId: HuntStationId | null = mission
    ? (getCurrentObservatoryMissionObjective(mission)?.stationId ?? null)
    : null;

  // Derive per-station affinity map from the bound spirit kind.
  // undefined when no spirit bound — rings render invisible.
  const stationAffinities: Record<HuntStationId, number> | undefined =
    kind ? STATION_AFFINITY_MAP[kind] : undefined;

  // Build HuntStationState[] — map workbench stations to huntronomer station IDs by index.
  // Workbench station[0] → signal, [1] → targets, [2] → run, [3] → receipts, [4] → case-notes, [5] → watch.
  // If workbench has no stations or fewer than 6, pad remaining with artifactCount 0.
  const stationStates: HuntStationState[] = WORKBENCH_STATION_IDS.map((huntId, index) => {
    const workbenchStation = stations[index] ?? null;
    return {
      id: huntId,
      label: HUNT_STATION_LABELS[huntId],
      status: "idle",
      affinity: 0,
      emphasis: 0,
      artifactCount: workbenchStation?.artifactCount ?? 0,
      hasUnread: (workbenchStation?.artifactCount ?? 0) > 0,
    };
  });

  const sceneState: HuntObservatorySceneState = {
    huntId: "workbench",
    mode,
    stations: stationStates,
    activeSelection: { type: "none" },
    likelyStationId: null,
    roomReceiveState: "idle",
    spiritFieldBias: kind ? 0.5 : 0,
    confidence: 0.5,
    cameraPreset: "overview",
    openedDetailSurface: "none",
  };

  const spirit =
    kind && accentColor
      ? { kind: SPIRIT_KIND_MAP[kind], accentColor }
      : null;

  // OBS-04: Dispatch probe — advances state machine and switches frameloop to "always"
  // OBS-12: probe target follows active mission objective station via resolveObservatoryMissionProbeTargetStationId
  const dispatchProbe = useCallback(() => {
    const now = performance.now();
    setProbeState((prev) => {
      const resolved = advanceObservatoryProbeState(prev, now);
      if (resolved.status !== "ready") return prev;
      // Mission-aware target: follows current mission objective, falls back to first station
      const targetId: HuntStationId =
        resolveObservatoryMissionProbeTargetStationId(mission, {}) ??
        WORKBENCH_STATION_IDS[0] ??
        "signal";
      const next = dispatchObservatoryProbe(resolved, targetId, now);
      setFrameloop("always");
      // CAM-03: probe dispatch shake — fast decay
      window.dispatchEvent(new CustomEvent("observatory:shake", { detail: { intensity: 0.45 } }));
      return next;
    });
  }, [mission]);

  // OBS-04: Listen for "observatory:probe" window CustomEvent from command palette
  useEffect(() => {
    const handler = () => dispatchProbe();
    window.addEventListener("observatory:probe", handler);
    return () => window.removeEventListener("observatory:probe", handler);
  }, [dispatchProbe]);

  // OBS-12: Listen for "observatory:mission:start" to start a mission
  useEffect(() => {
    const handler = () => {
      useObservatoryStore.getState().actions.startMission("workbench", Date.now());
      // CAM-04: force WorldCameraRig goalChanged even if desiredPosition is identical (edge case)
      setCameraResetToken((prev) => prev + 1);
    };
    window.addEventListener("observatory:mission:start", handler);
    return () => window.removeEventListener("observatory:mission:start", handler);
  }, []);

  // OBS-12: Listen for "observatory:mission:reset" to reset the mission
  useEffect(() => {
    const handler = () => {
      useObservatoryStore.getState().actions.resetMission();
    };
    window.addEventListener("observatory:mission:reset", handler);
    return () => window.removeEventListener("observatory:mission:reset", handler);
  }, []);

  // OBS-04: Revert frameloop to "demand" when probe exits active state
  useEffect(() => {
    if (probeState.status !== "active") {
      setFrameloop("demand");
    }
  }, [probeState.status]);

  const handleSelectStation = useCallback(
    (stationId: HuntStationId) => {
      // Station selection — resets camera to focus on selected station.
      // Full routing deferred to later plan.
      setCameraResetToken((prev) => prev + 1);
      // noop for now; onSelectStation prop for future routing
      void stationId;
    },
    [],
  );

  const handleDoubleClick = useCallback(() => {
    if (mode !== "flow") return;
    setCharacterControllerEnabled((prev) => {
      const next = !prev;
      showEasterEggNotification(next ? "WASD controls activated" : "WASD controls deactivated");
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
          sceneState={sceneState}
          activeStationId={flyByActive ? null : missionObjectiveStationId}
          spirit={spirit}
          cameraResetToken={cameraResetToken}
          onSelectStation={handleSelectStation}
          className="absolute inset-0"
          flyByActive={flyByActive}
          frameloop={frameloop}
          onFlyByComplete={handleFlyByComplete}
        />
        </CanvasErrorBoundary>
      </div>

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

      {/* OBS-04: Probe HUD overlay — hidden during fly-by so letterbox bars are unobstructed */}
      {!flyByActive && <ObservatoryProbeHud probeState={probeState} />}

      {/* OBS-11: Mission HUD overlay — hidden during fly-by */}
      {!flyByActive && <ObservatoryMissionHud mission={mission} />}

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
      />

      {/* UIP-04: Achievement popups — outside Canvas, Framer Motion AnimatePresence */}
      <AchievementLayer />
    </div>
  );
}
