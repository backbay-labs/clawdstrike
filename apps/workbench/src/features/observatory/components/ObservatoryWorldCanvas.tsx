import { Billboard, CameraShake, Html, Line, OrbitControls, Sparkles, Stars, Text, useGLTF, type ShakeController } from "@react-three/drei";
import { Canvas, type ThreeEvent, useFrame } from "@react-three/fiber";
import { buildSpiritLut } from "../utils/buildSpiritLut";
import { createNormalizedObservatoryModelInstance } from "../utils/observatory-models";
import type { SpiritKind } from "@/features/spirit/types";
import {
  Suspense,
  lazy,
  memo,
  type RefObject,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import * as THREE from "three";
import type {
  HuntObservatorySceneState,
  HuntStationId,
} from "../world/types";
import type { ObservatoryAnnotationPin } from "../types";
import type {
  ObservatoryGhostPresentation,
  ObservatoryGhostTrace,
} from "../world/observatory-ghost-memory";
import type { ObservatoryWeatherState } from "../world/observatory-weather";

import {
  OBSERVATORY_ASTRONAUT_OPERATOR_ANIMATION_URLS,
  OBSERVATORY_ASTRONAUT_OPERATOR_ASSET_URL,
  OBSERVATORY_ASTRONAUT_OPERATOR_TEXTURE_SOURCE_URL,
} from "../character/avatar/assetManifest";
import { ObservatoryPlayerAvatar } from "../character/avatar/ObservatoryPlayerAvatar";
import {
  deriveObservatoryWorld,
  type DerivedObservatoryWorld,
  type ObservatoryCameraRecipe,
  type ObservatoryDistrictRecipe,
  type ObservatoryGrowthStructureRecipe,
  type ObservatoryHypothesisScaffoldRecipe,
  type ObservatoryDistrictSilhouetteRecipe,
  type ObservatoryHeroPropRecipe,
  type ObservatorySpiritVisual,
  type ObservatoryTransitRouteRecipe,
  type ObservatoryWatchfieldRecipe,
} from "../world/deriveObservatoryWorld";
import {
  getCurrentObservatoryMissionObjective,
  isObservatoryMissionObjectiveProp,
  resolveObservatoryMissionProbeTargetStationId,
  type ObservatoryMissionLoopState,
} from "../world/missionLoop";
import {
  advanceObservatoryProbeState,
  canDispatchObservatoryProbe,
  dispatchObservatoryProbe,
  getObservatoryProbeCharge,
  getObservatoryProbeRemainingMs,
  OBSERVATORY_PROBE_ACTIVE_MS,
  type ObservatoryProbeState,
} from "../world/probeRuntime";
import { applyObservatoryProbeConsequences } from "../world/probeConsequences";
import { ProbeDischargeVFX } from "../vfx/ProbeDischargeVFX";
import { StationNpcCrew } from "../world/npcCrew";
import { SpaceStationMesh } from "../world/districtGeometry";
import { createSpaceStationSeed } from "../world/districtGeometryResources";
import { OBSERVATORY_STATION_POSITIONS } from "../world/observatory-world-template";
import {
  createObservatoryPerformanceProfile,
  type ObservatoryRuntimeQuality,
  shouldRenderObservatoryPostFx,
} from "../utils/observatory-performance";
import { getObservatoryNowMs, useObservatoryNow } from "../utils/observatory-time";
import type {
  MissionInteractionSource,
  ObservatoryPlayerFocusState,
  ObservatoryPlayerWorldState,
} from "./flow-runtime/grounding";
import {
  ObservatoryQualityMonitor,
  ObservatoryRuntimeActivityMonitor,
} from "./ObservatoryRuntimeMonitors";
import { ObservatoryInvalidationController } from "./world-canvas/ObservatoryInvalidationController";
import { HudCameraBridge } from "./hud/camera-bridge";
import { ObservatoryWorldScene as ExtractedObservatoryWorldScene } from "./world-canvas/ObservatoryWorldScene";
import { useObservatoryWorldLifecycle } from "./world-canvas/useObservatoryWorldLifecycle";
import { useObservatoryStore } from "../stores/observatory-store";
import type { FlightState } from "../character/ship/flight-types";
import { WarpSpeedLines } from "../vfx/WarpSpeedLines";
import { MissionWaypointTrail } from "./MissionWaypointTrail";
import { MissionObjectiveBeacons } from "./MissionObjectiveBeacons";
import { ObservatoryWeatherLayer } from "./world-canvas/ObservatoryWeatherLayer";
import { deriveHeatmapDataTexture, type HeatmapStationPressure } from "../utils/observatory-derivations";
import { HUNT_STATION_ORDER } from "../world/stations";
import type { ObservatoryProbeGuidance } from "../world/observatory-recommendations";
import { useSpiritStore } from "@/features/spirit/stores/spirit-store";
import { useSpiritEvolutionStore } from "@/features/spirit/stores/spirit-evolution-store";

const LazyObservatoryPostFX = lazy(() =>
  import("./ObservatoryPostFX").then((module) => ({ default: module.ObservatoryPostFX })),
);
const LazyObservatoryFlowRuntimeScene = lazy(() =>
  import("./ObservatoryFlowRuntimeScene").then((module) => ({ default: module.ObservatoryFlowRuntimeScene })),
);
const LazyObservatoryVFXPools = lazy(() =>
  import("../vfx/ObservatoryVFXPools").then((module) => ({ default: module.ObservatoryVFXPools })),
);

export interface ObservatoryWorldCanvasProps {
  mode: HuntObservatorySceneState["mode"];
  sceneState: HuntObservatorySceneState | null;
  mission: ObservatoryMissionLoopState | null;
  probeState: ObservatoryProbeState;
  activeStationId: HuntStationId | null;
  ghostPresentation?: ObservatoryGhostPresentation;
  ghostTraces?: ObservatoryGhostTrace[];
  spirit?: ObservatorySpiritVisual;
  weatherState?: ObservatoryWeatherState | null;
  cameraResetToken?: number;
  onSelectStation?: (stationId: HuntStationId) => void;
  onProbeStateChange?: (
    next:
      | ObservatoryProbeState
      | ((current: ObservatoryProbeState) => ObservatoryProbeState),
  ) => void;
  onMissionObjectiveComplete?: (
    assetId: ObservatoryHeroPropRecipe["assetId"],
    nowMs: number,
  ) => ObservatoryMissionLoopState | null;
  className?: string;
  /** CAM-01: frameloop for the R3F Canvas — "always" during fly-by, "demand" otherwise */
  frameloop?: "demand" | "always";
  /** Gates keyboard listeners so the active pane owns movement controls. */
  playerInputEnabled?: boolean;
  replayFrameIndex?: number | null;
  /** CAM-01: set flyByActive=true to run the opening camera sweep */
  flyByActive?: boolean;
  /** CAM-01: called when the fly-by sequence finishes all waypoints */
  onFlyByComplete?: () => void;
  probeGuidance?: ObservatoryProbeGuidance | null;
}
// PP-04: Maps ObservatorySpiritVisual.kind back to SpiritKind for LUT lookup.
// ObservatoryTab maps: sentinel→tracker, oracle→lantern, witness→ledger, specter→forge
// "loom" is a valid ObservatorySpiritVisual.kind but not in SpiritKind — returns undefined.
const OBSERVATORY_KIND_TO_SPIRIT_KIND: Record<string, SpiritKind> = {
  tracker: "sentinel",
  lantern: "oracle",
  ledger: "witness",
  forge: "specter",
};

const STATION_HEIGHT = 0.72;
const ERUPTION_DURATION_MS = 2800;

// CAM-01: Fly-by waypoint sequence — 3 legs sweeping the station ring, ~4.8s total.
// Positions arc from south-east low approach -> west elevated arc -> atlas default landing.
// Guard: legs with travel < 0.5 units are skipped automatically.
const FLY_BY_WAYPOINTS: ReadonlyArray<{
  readonly position: readonly [number, number, number];
  readonly target: readonly [number, number, number];
  readonly durationMs: number;
}> = [
  { position: [420, 120, 420],   target: [0, 10, 0],  durationMs: 1800 },
  { position: [-330, 210, 300],  target: [0, 15, 0],  durationMs: 1800 },
  { position: [0, 310, 550],     target: [0, 5, 0],   durationMs: 1800 },
] as const;
const DISTRICT_ARRIVAL_DURATION_MS = 2400;
const HERO_CHOREOGRAPHY_STATIONS = new Set<HuntStationId>(["signal", "run", "receipts", "case-notes"]);
const EVENT_KIND_BY_STATION: Partial<Record<HuntStationId, "signal" | "run" | "evidence" | "judgment" | "watch">> = {
  signal: "signal",
  run: "run",
  receipts: "evidence",
  "case-notes": "judgment",
  watch: "watch",
};

interface WorldEruption {
  key: string;
  stationId: HuntStationId;
  routeStationId?: HuntStationId | null;
  startedAt: number;
  expiresAt: number;
  kind: "signal" | "run" | "evidence" | "judgment" | "watch";
}

interface ActiveHeroInteraction {
  assetId: ObservatoryHeroPropRecipe["assetId"];
  expiresAt: number;
  startedAt: number;
  stationId: HuntStationId | "core";
  targetStationId?: HuntStationId | null;
}

interface DistrictArrivalCue {
  expiresAt: number;
  startedAt: number;
  stationId: HuntStationId;
  token: number;
}

function lerpAlpha(speed: number, delta: number): number {
  return 1 - Math.exp(-speed * delta);
}

// ---------------------------------------------------------------------------
// TRN-05: Station proximity fade
// ---------------------------------------------------------------------------

/**
 * Module-level ref storing per-station distance from the ship (updated once per frame).
 * All station sub-elements that need proximity fade read from this ref.
 */
const stationProximityRef: Record<HuntStationId, number> = {
  signal: Infinity,
  targets: Infinity,
  run: Infinity,
  receipts: Infinity,
  "case-notes": Infinity,
  watch: Infinity,
};

/**
 * Computes NPC crew proximity opacity from distance.
 * NPCs fade in between 180 (invisible) and 120 units (fully visible).
 * Formula: clamp((180 - distance) / 60, 0, 1)
 */
function computeNpcProximityOpacity(distance: number): number {
  return Math.min(1, Math.max(0, (180 - distance) / 60));
}

/**
 * Computes distance-label opacity from distance.
 * Labels fade out as camera approaches — visible at 180, invisible at 60.
 * Formula: clamp((distance - 60) / 120, 0, 1)
 */
function computeDistanceFadeOpacity(distance: number): number {
  return Math.min(1, Math.max(0, (distance - 60) / 120));
}

/**
 * StationNpcCrewFade — wraps StationNpcCrew with per-frame proximity opacity.
 * Updates opacity from the module-level stationProximityRef; avoids React re-renders
 * by using a threshold check (only updates state on meaningful opacity change).
 */
function StationNpcCrewFade({
  stationId,
  stationWorldPos,
  colorHex,
  lodTier,
}: {
  stationId: HuntStationId;
  stationWorldPos: [number, number, number];
  colorHex: string;
  lodTier?: import("../utils/observatory-performance").ObservatoryLodTier;
}) {
  const [proximityOpacity, setProximityOpacity] = useState(1);
  const lastOpacityRef = useRef(1);

  useFrame(() => {
    const distance = stationProximityRef[stationId] ?? Infinity;
    const nextOpacity = computeNpcProximityOpacity(distance);
    // Only trigger a re-render when opacity change is meaningful (>1% threshold)
    if (Math.abs(nextOpacity - lastOpacityRef.current) > 0.01) {
      lastOpacityRef.current = nextOpacity;
      setProximityOpacity(nextOpacity);
    }
  });

  return (
    <StationNpcCrew
      stationWorldPos={stationWorldPos}
      colorHex={colorHex}
      lodTier={lodTier}
      proximityOpacity={proximityOpacity}
    />
  );
}

/**
 * TRN-01: Boost FOV phase constants
 *   ramp-up:   FOV 60 → 90 over 0.3s, ease-in (t*t)
 *   sustain:   hold 90 while boost is active
 *   ramp-down: FOV 90 → 60 over 0.8s, ease-out (1-(1-t)^2)
 */
const BOOST_FOV_RAMP_UP_S = 0.3;
const BOOST_FOV_RAMP_DOWN_S = 0.8;
const BOOST_FOV_BASE = 60;
const BOOST_FOV_PEAK = 90;

export function FovController({
  playerFocusRef,
  probeActive,
  boostActive,
}: {
  playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>;
  probeActive: boolean;
  /** TRN-01: true when flightState.speedTier === "boost" */
  boostActive: boolean;
}) {
  // TRN-01: Boost FOV phase tracking — refs only, no setState in 60fps loop
  const boostFovPhaseRef = useRef<"idle" | "ramp-up" | "sustain" | "ramp-down">("idle");
  const boostFovTimerRef = useRef(0);
  const prevBoostActiveRef = useRef(boostActive);

  useFrame(({ camera }, delta) => {
    const pCam = camera as THREE.PerspectiveCamera;
    const safeDelta = Math.min(delta, 1 / 20);

    // TRN-01: Detect boost transition edges
    const wasBoostActive = prevBoostActiveRef.current;
    prevBoostActiveRef.current = boostActive;

    if (!wasBoostActive && boostActive) {
      // Boost just activated: start ramp-up
      boostFovPhaseRef.current = "ramp-up";
      boostFovTimerRef.current = 0;
    } else if (wasBoostActive && !boostActive && boostFovPhaseRef.current === "sustain") {
      // Boost ended while sustaining: start ramp-down
      boostFovPhaseRef.current = "ramp-down";
      boostFovTimerRef.current = 0;
    }

    // TRN-01: Compute FOV from boost phase
    let boostFov: number | null = null;
    const phase = boostFovPhaseRef.current;
    if (phase === "ramp-up") {
      boostFovTimerRef.current += safeDelta;
      const t = Math.min(boostFovTimerRef.current / BOOST_FOV_RAMP_UP_S, 1);
      const eased = t * t; // ease-in
      boostFov = BOOST_FOV_BASE + (BOOST_FOV_PEAK - BOOST_FOV_BASE) * eased;
      if (boostFovTimerRef.current >= BOOST_FOV_RAMP_UP_S) {
        boostFovPhaseRef.current = "sustain";
      }
    } else if (phase === "sustain") {
      boostFov = BOOST_FOV_PEAK;
    } else if (phase === "ramp-down") {
      boostFovTimerRef.current += safeDelta;
      const t = Math.min(boostFovTimerRef.current / BOOST_FOV_RAMP_DOWN_S, 1);
      const eased = 1 - (1 - t) * (1 - t); // ease-out
      boostFov = BOOST_FOV_PEAK - (BOOST_FOV_PEAK - BOOST_FOV_BASE) * eased;
      if (boostFovTimerRef.current >= BOOST_FOV_RAMP_DOWN_S) {
        boostFovPhaseRef.current = "idle";
      }
    }

    let targetFov: number;
    if (boostFov !== null) {
      targetFov = boostFov;
    } else {
      const sprinting = playerFocusRef.current?.sprinting ?? false;
      targetFov = probeActive ? 35 : sprinting ? 90 : 60;
    }

    pCam.fov += (targetFov - pCam.fov) * lerpAlpha(5.0, safeDelta);
    pCam.updateProjectionMatrix();
  });
  return null;
}

function smoothstep01(value: number): number {
  const clamped = Math.min(1, Math.max(0, value));
  return clamped * clamped * (3 - 2 * clamped);
}

function bezierPointInto(
  out: THREE.Vector3,
  start: THREE.Vector3,
  mid: THREE.Vector3,
  end: THREE.Vector3,
  t: number,
): THREE.Vector3 {
  const inverse = 1 - t;
  return out
    .copy(start)
    .multiplyScalar(inverse * inverse)
    .addScaledVector(mid, 2 * inverse * t)
    .addScaledVector(end, t * t);
}

export function WorldCameraRig({
  camera,
  controlsRef,
  flyByActive,
  onFlyByComplete,
  playerFocusRef,
  resetToken,
}: {
  camera: ObservatoryCameraRecipe;
  controlsRef: RefObject<THREE.EventDispatcher | null>;
  flyByActive: boolean;
  onFlyByComplete: () => void;
  playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>;
  resetToken: number;
}) {
  const initializedRef = useRef(false);
  const previousGoalRef = useRef<{
    initialized: boolean;
    position: THREE.Vector3;
    target: THREE.Vector3;
    resetToken: number;
  }>({
    initialized: false,
    position: new THREE.Vector3(),
    target: new THREE.Vector3(),
    resetToken: 0,
  });
  const flightRef = useRef<{
    active: boolean;
    startTime: number;
    duration: number;
    fromPosition: THREE.Vector3;
    viaPosition: THREE.Vector3;
    toPosition: THREE.Vector3;
    fromTarget: THREE.Vector3;
    viaTarget: THREE.Vector3;
    toTarget: THREE.Vector3;
  }>({
    active: false,
    startTime: 0,
    duration: 0,
    fromPosition: new THREE.Vector3(),
    viaPosition: new THREE.Vector3(),
    toPosition: new THREE.Vector3(),
    fromTarget: new THREE.Vector3(),
    viaTarget: new THREE.Vector3(),
    toTarget: new THREE.Vector3(),
  });
  // CAM-01: fly-by refs — track which waypoint we're on and whether we already called complete
  const waypointIndexRef = useRef(0);
  const flyByCompleteCalledRef = useRef(false);
  // CAM-04: mission focus dwell — holds camera on objective station after flight completes
  const dwellRef = useRef<{ expiresAt: number } | null>(null);
  const chaseTargetRef = useRef(new THREE.Vector3());
  const chasePositionRef = useRef(new THREE.Vector3());
  const followedTargetRef = useRef(new THREE.Vector3());
  const followedPositionRef = useRef(new THREE.Vector3());
  const axisRef = useRef(new THREE.Vector3());
  const lateralRef = useRef(new THREE.Vector3());
  const travelPositionRef = useRef(new THREE.Vector3());
  const travelTargetRef = useRef(new THREE.Vector3());
  const desiredPosition = useMemo(
    () => new THREE.Vector3(...camera.desiredPosition),
    [camera.desiredPosition],
  );
  const desiredTarget = useMemo(
    () => new THREE.Vector3(...camera.desiredTarget),
    [camera.desiredTarget],
  );
  const initialPosition = useMemo(
    () => new THREE.Vector3(...camera.initialPosition),
    [camera.initialPosition],
  );

  useFrame(({ clock }, delta) => {
    const controls = controlsRef.current as unknown as {
      object?: THREE.Camera;
      target?: THREE.Vector3;
      update?: () => void;
    } | null;
    if (!controls?.object || !controls.target || !controls.update) return;

    // CAM-01: fly-by sequencing — runs before normal tracking when flyByActive=true
    if (flyByActive && !flyByCompleteCalledRef.current) {
      // First frame of fly-by: place camera at waypoint 0 and mark initialized
      if (!initializedRef.current) {
        const wp = FLY_BY_WAYPOINTS[0];
        controls.object.position.set(wp.position[0], wp.position[1], wp.position[2]);
        controls.target.set(wp.target[0], wp.target[1], wp.target[2]);
        controls.update();
        initializedRef.current = true;
        waypointIndexRef.current = 0;
        return;
      }
      // Launch flight to next waypoint if none in progress
      if (!flightRef.current.active) {
        const idx = waypointIndexRef.current;
        if (idx >= FLY_BY_WAYPOINTS.length) {
          // All waypoints done — hand off
          flyByCompleteCalledRef.current = true;
          onFlyByComplete();
          return;
        }
        const wp = FLY_BY_WAYPOINTS[idx];
        const flight = flightRef.current;
        flight.fromPosition.copy(controls.object.position);
        flight.toPosition.set(wp.position[0], wp.position[1], wp.position[2]);
        flight.toTarget.set(wp.target[0], wp.target[1], wp.target[2]);
        flight.fromTarget.copy(controls.target);
        const axis = axisRef.current.copy(flight.toPosition).sub(flight.fromPosition);
        const travelDist = axis.length();
        // Guard: skip near-zero travel legs
        if (travelDist < 0.5) {
          waypointIndexRef.current = idx + 1;
          return;
        }
        const lateral = lateralRef.current
          .set(-axis.z, 0, axis.x)
          .normalize()
          .multiplyScalar(Math.min(2.4, 0.8 + travelDist * 0.04));
        flight.viaPosition
          .copy(flight.fromPosition)
          .lerp(flight.toPosition, 0.5)
          .add(lateral)
          .setY(Math.max(flight.fromPosition.y, flight.toPosition.y) + camera.arrivalLift + 1.2);
        flight.viaTarget
          .copy(flight.fromTarget)
          .lerp(flight.toTarget, 0.5)
          .setY(Math.max(flight.fromTarget.y, flight.toTarget.y) + camera.arrivalLift * 0.32);
        flight.startTime = clock.elapsedTime;
        flight.duration = wp.durationMs / 1000;
        flight.active = true;
      }
      // Run the active fly-by flight
      if (flightRef.current.active) {
        const progress =
          (clock.elapsedTime - flightRef.current.startTime) / flightRef.current.duration;
        if (progress >= 1) {
          controls.object.position.copy(flightRef.current.toPosition);
          controls.target.copy(flightRef.current.toTarget);
          controls.update();
          flightRef.current.active = false;
          waypointIndexRef.current += 1;
          return;
        }
        const eased = smoothstep01(progress);
        const travelPos = bezierPointInto(
          travelPositionRef.current,
          flightRef.current.fromPosition,
          flightRef.current.viaPosition,
          flightRef.current.toPosition,
          eased,
        );
        const travelTgt = bezierPointInto(
          travelTargetRef.current,
          flightRef.current.fromTarget,
          flightRef.current.viaTarget,
          flightRef.current.toTarget,
          eased,
        );
        controls.object.position.copy(travelPos);
        controls.target.copy(travelTgt);
        controls.update();
        return;
      }
      return;
    }

    if (!initializedRef.current) {
      controls.object.position.copy(initialPosition);
      controls.target.copy(desiredTarget);
      controls.update();
      initializedRef.current = true;
      previousGoalRef.current.initialized = true;
      previousGoalRef.current.position.copy(desiredPosition);
      previousGoalRef.current.target.copy(desiredTarget);
      previousGoalRef.current.resetToken = resetToken;
      return;
    }
    const previousGoal = previousGoalRef.current;
    const goalChanged =
      !previousGoal.initialized ||
      previousGoal.position.distanceToSquared(desiredPosition) > 0.25 ||
      previousGoal.target.distanceToSquared(desiredTarget) > 0.12 ||
      previousGoal.resetToken !== resetToken;

    const playerFocus = playerFocusRef.current;
    const followStrength = playerFocus
      ? playerFocus.airborne
        ? 0.88
        : playerFocus.moving
          ? 0.82
          : 0.28
      : 0;
    const chaseHeading = playerFocus
      ? playerFocus.moving
        ? Math.atan2(playerFocus.moveVector[0], playerFocus.moveVector[1])
        : playerFocus.facingRadians
      : 0;
    const chaseTarget = playerFocus
      ? chaseTargetRef.current.set(
          playerFocus.position[0],
          1.62 + (playerFocus.airborne ? 0.5 : playerFocus.moving ? 0.18 : 0),
          playerFocus.position[2],
        )
      : null;
    const chasePosition = playerFocus
      ? chasePositionRef.current.set(
          playerFocus.position[0] - Math.sin(chaseHeading) * (playerFocus.sprinting ? 5.8 : 4.8),
          3.7 + (playerFocus.airborne ? 1.2 : playerFocus.moving ? 0.56 : 0.2),
          playerFocus.position[2] - Math.cos(chaseHeading) * (playerFocus.sprinting ? 5.8 : 4.8),
        )
      : null;
    const followedTarget = followedTargetRef.current.copy(desiredTarget);
    if (chaseTarget) {
      followedTarget.lerp(chaseTarget, followStrength);
    }
    const followedPosition = followedPositionRef.current.copy(desiredPosition);
    if (chasePosition) {
      followedPosition.lerp(chasePosition, followStrength);
    }

    // CAM-04: suppress goal change while dwell is active (hold on objective station)
    const isDwelling = dwellRef.current !== null && clock.elapsedTime < dwellRef.current.expiresAt;
    if (isDwelling) {
      // Camera is holding — do NOT launch a new flight. Soft lerp toward current target.
      // When dwell expires, goalChanged will naturally take effect on the next frame.
      const alpha = lerpAlpha(camera.lerpSpeed * 0.4, delta);
      controls.object.position.lerp(followedPosition, alpha);
      controls.target.lerp(followedTarget, alpha);
      controls.update();
      return;
    }
    // Dwell expired — clear it so next goalChanged triggers normally
    if (dwellRef.current && clock.elapsedTime >= dwellRef.current.expiresAt) {
      dwellRef.current = null;
    }

    if (goalChanged) {
      const flight = flightRef.current;
      flight.fromPosition.copy(controls.object.position);
      flight.fromTarget.copy(controls.target);
      const axis = axisRef.current.copy(followedPosition).sub(flight.fromPosition);
      const travelDistance = axis.length();
      const lateral = lateralRef.current
        .set(-axis.z, 0, axis.x)
        .normalize()
        .multiplyScalar(Math.min(1.8, 0.6 + travelDistance * 0.03));
      flight.viaPosition
        .copy(flight.fromPosition)
        .lerp(followedPosition, 0.5)
        .add(lateral)
        .setY(Math.max(flight.fromPosition.y, followedPosition.y) + camera.arrivalLift + travelDistance * 0.05);
      flight.viaTarget
        .copy(flight.fromTarget)
        .lerp(followedTarget, 0.5)
        .setY(Math.max(flight.fromTarget.y, followedTarget.y) + camera.arrivalLift * 0.32);
      flight.startTime = clock.elapsedTime;
      flight.duration = camera.arrivalDurationMs / 1000;
      flight.toPosition.copy(followedPosition);
      flight.toTarget.copy(followedTarget);
      flight.active = true;
      previousGoal.initialized = true;
      previousGoal.position.copy(followedPosition);
      previousGoal.target.copy(followedTarget);
      previousGoal.resetToken = resetToken;
    }

    if (flightRef.current.active) {
      const progress = (clock.elapsedTime - flightRef.current.startTime) / flightRef.current.duration;
      if (progress >= 1) {
        controls.object.position.copy(flightRef.current.toPosition);
        controls.target.copy(flightRef.current.toTarget);
        flightRef.current.active = false;
        controls.update();
        // CAM-04: Set dwell period if camera.missionFocusDwellMs > 0
        if (camera.missionFocusDwellMs > 0) {
          dwellRef.current = { expiresAt: clock.elapsedTime + camera.missionFocusDwellMs / 1000 };
        }
        return;
      }
      const eased = smoothstep01(progress);
      const travelPosition = bezierPointInto(
        travelPositionRef.current,
        flightRef.current.fromPosition,
        flightRef.current.viaPosition,
        flightRef.current.toPosition,
        eased,
      );
      const travelTarget = bezierPointInto(
        travelTargetRef.current,
        flightRef.current.fromTarget,
        flightRef.current.viaTarget,
        flightRef.current.toTarget,
        eased,
      );
      const settle = Math.max(0, (eased - 0.74) / 0.26);
      if (settle > 0) {
        const orbitAngle = settle * Math.PI * 0.9;
        const orbitRadius = camera.settleRadius * (1 - settle);
        travelPosition.x += Math.cos(orbitAngle) * orbitRadius;
        travelPosition.z += Math.sin(orbitAngle) * orbitRadius;
      }
      controls.object.position.copy(travelPosition);
      controls.target.copy(travelTarget);
      controls.update();
      return;
    }

    const alpha = lerpAlpha(camera.lerpSpeed, delta);
    controls.object.position.lerp(followedPosition, alpha);
    controls.target.lerp(followedTarget, alpha);
    controls.update();
  });

  return null;
}

function ReadyObservatoryHeroPropModel({
  prop,
}: {
  prop: ObservatoryHeroPropRecipe;
}) {
  const loaded = useGLTF(prop.assetUrl);
  const root = useMemo(() => {
    return createNormalizedObservatoryModelInstance(prop.assetUrl, loaded.scene);
  }, [loaded.scene, prop.assetUrl]);

  useEffect(() => {
    root.traverse((child) => {
      const mesh = child as THREE.Mesh;
      if ("isMesh" in mesh && mesh.isMesh) {
        mesh.castShadow = true;
        mesh.receiveShadow = true;
      }
    });
  }, [root]);

  return <primitive object={root} />;
}

function ObservatoryHeroPropFallbackModel({
  prop,
}: {
  prop: ObservatoryHeroPropRecipe;
}) {
  const color = useMemo(() => new THREE.Color(prop.glowColor), [prop.glowColor]);
  switch (prop.fallbackKind) {
    case "tower-dish":
      return (
        <group>
          <mesh position={[0, 0.72, 0]}>
            <cylinderGeometry args={[0.12, 0.16, 1.2, 10]} />
            <meshStandardMaterial color="#121a27" emissive={color} emissiveIntensity={0.28} />
          </mesh>
          <mesh position={[0, 1.58, 0]} rotation={[-0.5, 0.22, 0]}>
            <coneGeometry args={[0.54, 0.42, 7, 1, true]} />
            <meshStandardMaterial color="#182335" emissive={color} emissiveIntensity={0.48} wireframe />
          </mesh>
        </group>
      );
    case "lattice-anchor":
      return (
        <group>
          <mesh position={[0, 0.8, 0]} rotation={[0, Math.PI / 4, 0]}>
            <octahedronGeometry args={[0.72, 0]} />
            <meshStandardMaterial color="#142334" emissive={color} emissiveIntensity={0.42} transparent opacity={0.86} />
          </mesh>
          <mesh rotation={[Math.PI / 2, 0, 0]}>
            <torusGeometry args={[0.96, 0.04, 10, 48]} />
            <meshBasicMaterial color={color} transparent opacity={0.46} />
          </mesh>
        </group>
      );
    case "scan-rig":
      return (
        <group>
          <mesh position={[0, 0.38, 0]}>
            <boxGeometry args={[0.96, 0.26, 0.72]} />
            <meshStandardMaterial color="#121926" emissive={color} emissiveIntensity={0.24} />
          </mesh>
          <mesh position={[0.34, 0.84, -0.08]}>
            <boxGeometry args={[0.18, 0.92, 0.18]} />
            <meshStandardMaterial color="#182131" emissive={color} emissiveIntensity={0.32} />
          </mesh>
          <mesh position={[0.34, 1.18, -0.08]} rotation={[0.18, 0.22, 0]}>
            <boxGeometry args={[0.22, 0.12, 0.62]} />
            <meshStandardMaterial color="#223048" emissive={color} emissiveIntensity={0.44} />
          </mesh>
        </group>
      );
    case "vault-rack":
      return (
        <group>
          {[-0.34, 0, 0.34].map((x, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              position={[x, 0.62 + index * 0.18, 0]}
            >
              <boxGeometry args={[0.24, 0.94 + index * 0.16, 0.58]} />
              <meshStandardMaterial color="#142130" emissive={color} emissiveIntensity={0.2 + index * 0.08} />
            </mesh>
          ))}
        </group>
      );
    case "judgment-dais":
      return (
        <group>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.08, 0]}>
            <ringGeometry args={[0.92, 1.28, 32]} />
            <meshBasicMaterial color={color} transparent opacity={0.42} />
          </mesh>
          <mesh position={[0, 0.22, 0]}>
            <cylinderGeometry args={[0.92, 1.12, 0.22, 20]} />
            <meshStandardMaterial color="#201710" emissive={color} emissiveIntensity={0.24} />
          </mesh>
          <mesh position={[0, 0.48, 0]}>
            <boxGeometry args={[0.74, 0.18, 0.74]} />
            <meshStandardMaterial color="#2a1d13" emissive={color} emissiveIntensity={0.32} />
          </mesh>
        </group>
      );
    case "sentinel-beacon":
      return (
        <group>
          <mesh position={[0, 0.94, 0]}>
            <cylinderGeometry args={[0.14, 0.18, 1.78, 10]} />
            <meshStandardMaterial color="#181a21" emissive={color} emissiveIntensity={0.36} />
          </mesh>
          <mesh position={[0, 1.98, 0]}>
            <sphereGeometry args={[0.18, 14, 14]} />
            <meshStandardMaterial color="#f3e7a4" emissive={color} emissiveIntensity={0.76} />
          </mesh>
        </group>
      );
    case "operator-drone":
      return (
        <group>
          <mesh>
            <sphereGeometry args={[0.22, 14, 14]} />
            <meshStandardMaterial color="#132033" emissive={color} emissiveIntensity={0.62} />
          </mesh>
          <mesh rotation={[Math.PI / 2, 0, 0]}>
            <torusGeometry args={[0.44, 0.04, 10, 42]} />
            <meshBasicMaterial color={color} transparent opacity={0.58} />
          </mesh>
        </group>
      );
  }
}

// UIP-01: 3D waypoint beacon (Billboard + Text) for active mission objective stations.
// Uses useFrame pulsing opacity on the ring mesh — no Html elements.
export function MissionObjectiveBeacon({ position, label }: { position: [number, number, number]; label: string }) {
  const meshRef = useRef<THREE.Mesh | null>(null);
  useFrame(({ clock }) => {
    if (meshRef.current) {
      const mat = meshRef.current.material as THREE.MeshBasicMaterial;
      mat.opacity = 0.5 + Math.sin(clock.elapsedTime * 2.5) * 0.3;
    }
  });
  const beaconPos: [number, number, number] = [position[0], position[1] + 2.8, position[2]];
  return (
    <Billboard position={beaconPos}>
      <Text
        fontSize={0.20}
        color="#f4d060"
        anchorX="center"
        anchorY="bottom"
        renderOrder={10}
      >
        {`[ ${label} ]`}
      </Text>
      <mesh ref={meshRef} position={[0, -0.05, 0]} renderOrder={9}>
        <ringGeometry args={[0.14, 0.20, 32]} />
        <meshBasicMaterial color="#f4d060" transparent opacity={0.8} depthWrite={false} />
      </mesh>
    </Billboard>
  );
}

function ObservatoryHeroProp({
  prop,
  active,
  presenceScale,
  interactable = false,
  missionTarget = false,
  onTrigger,
}: {
  prop: ObservatoryHeroPropRecipe;
  active: boolean;
  presenceScale: number;
  interactable?: boolean;
  missionTarget?: boolean;
  onTrigger?: (prop: ObservatoryHeroPropRecipe, meta: MissionInteractionSource) => void;
}) {
  const groupRef = useRef<THREE.Group | null>(null);
  const glowColor = useMemo(() => new THREE.Color(prop.glowColor), [prop.glowColor]);
  const dormant = !active && presenceScale < 0.4;

  useFrame(({ clock }) => {
    if (!groupRef.current) {
      return;
    }
    const yaw =
      prop.availability === "slot"
        ? Math.sin(clock.elapsedTime * (prop.bobSpeed + 0.08) + prop.position[2]) * 0.18
        : 0;
    groupRef.current.rotation.y = prop.rotation[1] + yaw;
    groupRef.current.position.y =
      prop.position[1] + Math.sin(clock.elapsedTime * prop.bobSpeed + prop.position[0]) * prop.bobAmplitude;
  });

  return (
    <group
      ref={groupRef}
      position={prop.position}
      rotation={prop.rotation}
      scale={prop.scale * presenceScale}
    >
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.02, 0]}>
        <ringGeometry args={[0.38, 0.58, 28]} />
        <meshBasicMaterial
          color={prop.glowColor}
          transparent
          opacity={
            ((prop.availability === "ready" ? 0.26 : 0.42)
              + (active ? 0.16 : 0)
              + (missionTarget ? 0.18 : 0)
              + (interactable ? 0.14 : 0))
            * (0.42 + presenceScale * 0.58)
          }
        />
      </mesh>
      <mesh position={[0, 0.05, 0]}>
        <cylinderGeometry args={[0.32, 0.4, 0.08, 18]} />
        <meshStandardMaterial
          color="#0a1018"
          emissive={glowColor}
          emissiveIntensity={
            ((active ? 1.8 : 0.08) + (missionTarget ? 0.5 : 0) + (interactable ? 0.3 : 0))
            * (0.56 + presenceScale * 0.44)
          }
          toneMapped={false}
        />
      </mesh>
      <mesh
        onClick={(event: ThreeEvent<MouseEvent>) => {
          event.stopPropagation();
          onTrigger?.(prop, { source: "click" });
        }}
        position={[0, 0.42, 0]}
        visible={false}
      >
        <cylinderGeometry args={[0.88, 0.88, 2.6, 18]} />
        <meshBasicMaterial transparent opacity={0} />
      </mesh>
      {dormant ? (
        <>
          <mesh position={[0, 0.22, 0]}>
            <sphereGeometry args={[0.12, 12, 12]} />
            <meshBasicMaterial color={prop.glowColor} transparent opacity={0.18 + presenceScale * 0.26} />
          </mesh>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.1, 0]}>
            <ringGeometry args={[0.22, 0.34, 20]} />
            <meshBasicMaterial color={prop.glowColor} transparent opacity={0.12 + presenceScale * 0.2} />
          </mesh>
        </>
      ) : prop.availability === "ready" ? (
        <ReadyObservatoryHeroPropModel prop={prop} />
      ) : (
        <group position={[0, 0.06, 0]}>
          <ObservatoryHeroPropFallbackModel prop={prop} />
        </group>
      )}
      {active ? <HeroPropInteractionEffect prop={prop} /> : null}
      {missionTarget || interactable ? (
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.18, 0]}>
          <ringGeometry args={[0.72, 0.86, 32]} />
          <meshBasicMaterial
            color={missionTarget ? "#fff1c6" : prop.glowColor}
            transparent
            opacity={missionTarget ? 0.3 : 0.18}
          />
        </mesh>
      ) : null}
      {/* PFX-03: Station ambient motes — frustum-culled via parent group bounding sphere */}
      {!dormant ? (
        <Sparkles
          count={30}
          scale={2.5}
          size={0.6}
          speed={0.3}
          opacity={0.35}
          color={prop.glowColor}
          noise={0.8}
        />
      ) : null}
      {/* UIP-03: Html occlude tooltip — shown only for the interactable (nearest) prop */}
      {interactable && (
        <Html
          position={[0, 1.2, 0]}
          distanceFactor={8}
          occlude
          style={{ pointerEvents: 'none' }}
        >
          <div style={{
            background: 'rgba(4,8,14,0.88)',
            border: '1px solid rgba(244,208,96,0.3)',
            borderRadius: 6,
            padding: '4px 8px',
            fontSize: 11,
            color: '#f4d060',
            fontFamily: 'monospace',
            whiteSpace: 'nowrap',
          }}>
            {prop.assetId.replace(/-/g, ' ').toUpperCase()}
          </div>
        </Html>
      )}
    </group>
  );
}

function HeroPropInteractionEffect({
  prop,
}: {
  prop: ObservatoryHeroPropRecipe;
}) {
  switch (prop.assetId) {
    case "signal-dish-tower":
      return (
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.18, 0]}>
          <ringGeometry args={[0.88, 1.32, 28, 1, 0, Math.PI / 2]} />
          <meshBasicMaterial color={prop.glowColor} transparent opacity={0.28} side={THREE.DoubleSide} />
        </mesh>
      );
    case "operations-scan-rig":
      return (
        <group>
          <mesh position={[0, 0.92, 0]}>
            <cylinderGeometry args={[0.14, 0.34, 1.6, 14]} />
            <meshBasicMaterial color={prop.glowColor} transparent opacity={0.16} />
          </mesh>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.08, 0]}>
            <ringGeometry args={[0.66, 0.92, 28]} />
            <meshBasicMaterial color={prop.glowColor} transparent opacity={0.26} />
          </mesh>
        </group>
      );
    case "evidence-vault-rack":
      return (
        <group>
          {[-0.28, 0, 0.28].map((x, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              position={[x, 0.64 + index * 0.08, 0.36]}
              rotation={[0.14, index * 0.12, 0]}
            >
              <boxGeometry args={[0.34, 0.02, 0.48]} />
              <meshBasicMaterial color={prop.glowColor} transparent opacity={0.22 - index * 0.03} />
            </mesh>
          ))}
        </group>
      );
    case "judgment-dais":
      return (
        <>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.12, 0]}>
            <ringGeometry args={[0.74, 0.94, 28]} />
            <meshBasicMaterial color={prop.glowColor} transparent opacity={0.28} />
          </mesh>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.18, 0]}>
            <ringGeometry args={[1.08, 1.22, 28]} />
            <meshBasicMaterial color={prop.glowColor} transparent opacity={0.18} />
          </mesh>
        </>
      );
    case "watchfield-sentinel-beacon":
      return (
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.1, 0]}>
          <ringGeometry args={[0.82, 1.06, 28]} />
          <meshBasicMaterial color={prop.glowColor} transparent opacity={0.28} />
        </mesh>
      );
    case "operator-drone":
      return (
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.06, 0]}>
          <ringGeometry args={[0.54, 0.72, 28]} />
          <meshBasicMaterial color={prop.glowColor} transparent opacity={0.24} />
        </mesh>
      );
  }
}

function buildOverlayArc(
  start: [number, number, number],
  end: [number, number, number],
  lift: number,
): [number, number, number][] {
  const startVector = new THREE.Vector3(...start);
  const endVector = new THREE.Vector3(...end);
  const middle = startVector.clone().lerp(endVector, 0.5);
  middle.y += lift;
  return new THREE.CatmullRomCurve3([startVector, middle, endVector]).getPoints(24).map((point) => [
    point.x,
    point.y,
    point.z,
  ]);
}

function HiddenSignalPathReveal({
  interaction,
  world,
  persistent = false,
}: {
  interaction: ActiveHeroInteraction | null;
  world: DerivedObservatoryWorld;
  persistent?: boolean;
}) {
  const strength = persistent ? 0.76 : readInteractionStrength(interaction, "signal-dish-tower");
  if (strength <= 0.04) return null;
  const signalProp = world.heroProps.find((prop) => prop.assetId === "signal-dish-tower");
  const start = signalProp?.position ?? world.districts.find((district) => district.id === "signal")?.position ?? [0, 0, 0];
  const targets = ["targets", "run", "watch"] as const;
  return (
    <group>
      {targets.map((stationId) => {
        const end =
          stationId === "watch"
            ? world.watchfield.position
            : world.districts.find((district) => district.id === stationId)?.position ?? [0, 0, 0];
        const arc = buildOverlayArc(
          [start[0], start[1] + 1.4, start[2]],
          [end[0], end[1] + (stationId === "watch" ? 1.1 : 1.4), end[2]],
          2.4 + strength * 1.1,
        );
        return (
          <group key={stationId}>
            <Line
              points={arc}
              color="#c8f4ff"
              transparent
              opacity={0.16 + strength * 0.24}
              lineWidth={1.6}
            />
            {arc.filter((_, index) => index > 0 && index < arc.length - 1 && index % 8 === 0).map((point, index) => (
              <mesh
                // eslint-disable-next-line react/no-array-index-key
                key={index}
                position={point}
              >
                <sphereGeometry args={[0.08 + strength * 0.04, 12, 12]} />
                <meshBasicMaterial color="#dff9ff" transparent opacity={0.22 + strength * 0.18} />
              </mesh>
            ))}
          </group>
        );
      })}
    </group>
  );
}

function SubjectsClusterReveal({
  interaction,
  world,
  persistent = false,
}: {
  interaction: ActiveHeroInteraction | null;
  world: DerivedObservatoryWorld;
  persistent?: boolean;
}) {
  const strength = persistent ? 0.72 : readInteractionStrength(interaction, "subjects-lattice-anchor");
  if (strength <= 0.04) return null;
  const subjectsProp = world.heroProps.find((prop) => prop.assetId === "subjects-lattice-anchor");
  const start = subjectsProp?.position ?? world.districts.find((district) => district.id === "targets")?.position ?? [0, 0, 0];
  const targetRoutes = world.transitLinks.filter((route) => route.fromStationId === "targets");
  return (
    <group>
      {targetRoutes.map((route) => (
        <group key={route.key}>
          <Line
            points={route.points}
            color="#cde9ff"
            transparent
            opacity={0.12 + strength * 0.2}
            lineWidth={1.4}
          />
          {route.waypointPositions.map((point, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              position={[point[0], point[1] + 0.12, point[2]]}
            >
              <sphereGeometry args={[0.07 + strength * 0.03, 10, 10]} />
              <meshBasicMaterial color="#ecf6ff" transparent opacity={0.22 + strength * 0.18} />
            </mesh>
          ))}
        </group>
      ))}
      {[-0.6, 0, 0.6].map((offset, index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          position={[start[0] + offset, start[1] + 1.1 + index * 0.14, start[2] - offset * 0.22]}
        >
          <sphereGeometry args={[0.18 + index * 0.03, 14, 14]} />
          <meshBasicMaterial color="#d8f2ff" transparent opacity={0.18 + strength * 0.14} />
        </mesh>
      ))}
    </group>
  );
}

function RunBootConsequence({
  interaction,
  world,
  persistent = false,
}: {
  interaction: ActiveHeroInteraction | null;
  world: DerivedObservatoryWorld;
  persistent?: boolean;
}) {
  const strength = persistent ? 0.74 : readInteractionStrength(interaction, "operations-scan-rig");
  if (strength <= 0.04) return null;
  const runProp = world.heroProps.find((prop) => prop.assetId === "operations-scan-rig");
  const route = world.transitLinks.find((entry) => entry.fromStationId === "run" && entry.stationId === "receipts");
  return (
    <group>
      {runProp ? (
        <>
          {[-0.9, -0.3, 0.3, 0.9].map((x, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              position={[runProp.position[0] + x, runProp.position[1] + 0.9 + index * 0.14, runProp.position[2]]}
              scale={[0.08, 1.1 + strength * 0.8, 0.08]}
            >
              <boxGeometry args={[1, 1, 1]} />
              <meshBasicMaterial color="#fff1be" transparent opacity={0.12 + strength * 0.16} />
            </mesh>
          ))}
        </>
      ) : null}
      {route ? (
        <>
          <Line points={route.points} color="#fff0bf" transparent opacity={0.16 + strength * 0.26} lineWidth={2} />
          {route.waypointPositions.map((point, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              position={point}
            >
              <sphereGeometry args={[0.1 + strength * 0.04, 12, 12]} />
              <meshBasicMaterial color="#fff4d4" transparent opacity={0.24 + strength * 0.18} />
            </mesh>
          ))}
        </>
      ) : null}
    </group>
  );
}

function EvidenceArrivalReveal({
  interaction,
  world,
  persistent = false,
}: {
  interaction: ActiveHeroInteraction | null;
  world: DerivedObservatoryWorld;
  persistent?: boolean;
}) {
  const strength = persistent ? 0.72 : readInteractionStrength(interaction, "evidence-vault-rack");
  if (strength <= 0.04) return null;
  const rack = world.heroProps.find((prop) => prop.assetId === "evidence-vault-rack");
  if (!rack) return null;
  return (
    <group position={rack.position}>
      {[-0.48, -0.18, 0.14, 0.46].map((x, index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          position={[x, 0.92 + index * 0.18, 0.48 - index * 0.06]}
          rotation={[0.18 - index * 0.04, index * 0.18, 0]}
        >
          <boxGeometry args={[0.52, 0.04, 0.72]} />
          <meshBasicMaterial color={index % 2 === 0 ? "#dffcff" : "#8fefff"} transparent opacity={0.2 + strength * (0.16 - index * 0.02)} />
        </mesh>
      ))}
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.18, 0]}>
        <ringGeometry args={[1.04, 1.26, 30]} />
        <meshBasicMaterial color="#cfffff" transparent opacity={0.12 + strength * 0.16} />
      </mesh>
    </group>
  );
}

function JudgmentSealConsequence({
  interaction,
  scaffolds,
  persistent = false,
}: {
  interaction: ActiveHeroInteraction | null;
  scaffolds: ObservatoryHypothesisScaffoldRecipe[];
  persistent?: boolean;
}) {
  const strength = persistent ? 0.82 : readInteractionStrength(interaction, "judgment-dais");
  if (strength <= 0.04) return null;
  return (
    <group>
      {scaffolds
        .filter((scaffold) => scaffold.primaryStationId === "case-notes")
        .flatMap((scaffold) => scaffold.lockPositions.concat(scaffold.nodes.map((node) => node.position)))
        .map((position, index) => (
          <group
            // eslint-disable-next-line react/no-array-index-key
            key={index}
            position={position}
          >
            <mesh rotation={[-Math.PI / 2, 0, 0]}>
              <ringGeometry args={[0.24 + strength * 0.14, 0.36 + strength * 0.14, 24]} />
              <meshBasicMaterial color="#ffe8bc" transparent opacity={0.16 + strength * 0.18} />
            </mesh>
            <mesh position={[0, 0.48 + strength * 0.42, 0]} scale={[0.05, 0.92 + strength * 0.8, 0.05]}>
              <boxGeometry args={[1, 1, 1]} />
              <meshBasicMaterial color="#ffe8bc" transparent opacity={0.12 + strength * 0.16} />
            </mesh>
          </group>
        ))}
    </group>
  );
}

export function HeroConsequenceLayer({
  interaction,
  world,
  mission,
}: {
  interaction: ActiveHeroInteraction | null;
  world: DerivedObservatoryWorld;
  mission: ObservatoryMissionLoopState | null;
}) {
  if (!interaction && !mission) return null;
  return (
    <>
      <HiddenSignalPathReveal
        interaction={interaction}
        persistent={mission?.progress.acknowledgedIngress ?? false}
        world={world}
      />
      <SubjectsClusterReveal
        interaction={interaction}
        persistent={mission?.progress.subjectsResolved ?? false}
        world={world}
      />
      <RunBootConsequence
        interaction={interaction}
        persistent={mission?.progress.runArmed ?? false}
        world={world}
      />
      <EvidenceArrivalReveal
        interaction={interaction}
        persistent={mission?.progress.evidenceInspected ?? false}
        world={world}
      />
      <JudgmentSealConsequence
        interaction={interaction}
        persistent={mission?.progress.findingSealed ?? false}
        scaffolds={world.hypothesisScaffolds}
      />
    </>
  );
}

function readArrivalProgress(cue: DistrictArrivalCue | null): { decay: number; progress: number } {
  if (!cue) {
    return { decay: 0, progress: 1 };
  }
  const duration = Math.max(1, cue.expiresAt - cue.startedAt);
  const progress = Math.min(1, Math.max(0, (getObservatoryNowMs() - cue.startedAt) / duration));
  return {
    decay: 1 - smoothstep01(progress),
    progress,
  };
}

function readInteractionStrength(
  interaction: ActiveHeroInteraction | null,
  assetId?: ObservatoryHeroPropRecipe["assetId"],
): number {
  if (!interaction) return 0;
  if (assetId && interaction.assetId !== assetId) return 0;
  const duration = Math.max(1, interaction.expiresAt - interaction.startedAt);
  const progress = Math.min(1, Math.max(0, (getObservatoryNowMs() - interaction.startedAt) / duration));
  return Math.sin(progress * Math.PI);
}

function sampleCrewLoop(
  waypoints: ObservatoryDistrictRecipe["crew"][number]["waypoints"],
  phase: number,
): { facing: number; position: [number, number, number] } {
  if (waypoints.length === 0) {
    return { facing: 0, position: [0, 0, 0] };
  }
  if (waypoints.length === 1) {
    return { facing: 0, position: waypoints[0] };
  }
  const wrapped = phase % 1;
  const scaled = wrapped * waypoints.length;
  const currentIndex = Math.floor(scaled) % waypoints.length;
  const nextIndex = (currentIndex + 1) % waypoints.length;
  const alpha = scaled - Math.floor(scaled);
  const current = new THREE.Vector3(...waypoints[currentIndex]);
  const next = new THREE.Vector3(...waypoints[nextIndex]);
  const position = current.clone().lerp(next, alpha);
  const facing = Math.atan2(next.x - current.x, next.z - current.z);
  return { facing, position: [position.x, position.y, position.z] };
}

function buildCrewResponseWaypoints(
  crew: ObservatoryDistrictRecipe["crew"][number],
): ObservatoryDistrictRecipe["crew"][number]["waypoints"] {
  const focusTarget = crew.response?.focusTarget;
  if (!focusTarget || crew.waypoints.length < 2) {
    return crew.waypoints;
  }
  const focusAlreadyPresent = crew.waypoints.some(
    (waypoint) =>
      Math.abs(waypoint[0] - focusTarget[0]) < 0.02
      && Math.abs(waypoint[1] - focusTarget[1]) < 0.02
      && Math.abs(waypoint[2] - focusTarget[2]) < 0.02,
  );
  if (focusAlreadyPresent) {
    return crew.waypoints;
  }
  return [
    crew.waypoints[0],
    focusTarget,
    ...crew.waypoints.slice(1),
    focusTarget,
  ];
}

function HorizonArrivalBeat({
  cue,
  district,
  heroProp,
}: {
  cue: DistrictArrivalCue;
  district: ObservatoryDistrictRecipe;
  heroProp: ObservatoryHeroPropRecipe | null;
}) {
  const sweepRef = useRef<THREE.Group | null>(null);
  const ringRefs = useRef<Array<THREE.Mesh | null>>([]);
  const beamRef = useRef<THREE.Mesh | null>(null);
  const origin = heroProp?.position ?? district.position;

  useFrame(({ clock }) => {
    const { decay, progress } = readArrivalProgress(cue);
    if (sweepRef.current) {
      sweepRef.current.rotation.y = clock.elapsedTime * 0.9 + progress * Math.PI * 1.35;
      sweepRef.current.position.y = origin[1] + 0.45 + progress * 0.18;
    }
    if (beamRef.current) {
      beamRef.current.scale.setScalar(0.85 + progress * 0.3);
      const material = beamRef.current.material;
      if (material instanceof THREE.MeshBasicMaterial) {
        material.opacity = 0.08 + decay * 0.22;
      }
    }
    ringRefs.current.forEach((mesh, index) => {
      if (!mesh) return;
      const localProgress = Math.max(0, progress - index * 0.12) / Math.max(0.0001, 1 - index * 0.12);
      const scale = 1 + localProgress * (1.8 + index * 0.42);
      mesh.scale.setScalar(scale);
      const material = mesh.material;
      if (material instanceof THREE.MeshBasicMaterial) {
        material.opacity = Math.max(0, (0.26 - index * 0.06) * (1 - localProgress) * (0.4 + decay * 0.9));
      }
    });
  });

  return (
    <group position={origin}>
      <group ref={sweepRef}>
        <mesh ref={beamRef} rotation={[-Math.PI / 2, 0, 0]}>
          <ringGeometry args={[1.3, 3.9, 36, 1, 0, Math.PI / 1.8]} />
          <meshBasicMaterial color="#9ce5ff" transparent opacity={0.2} side={THREE.DoubleSide} />
        </mesh>
      </group>
      {[0, 1, 2].map((index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          ref={(mesh) => {
            ringRefs.current[index] = mesh;
          }}
          rotation={[-Math.PI / 2, 0, 0]}
          position={[0, 0.06 + index * 0.05, 0]}
        >
          <ringGeometry args={[0.72 + index * 0.2, 0.9 + index * 0.2, 28]} />
          <meshBasicMaterial color="#dff8ff" transparent opacity={0.16} />
        </mesh>
      ))}
    </group>
  );
}

function OperationsArrivalBeat({
  cue,
  district,
  heroProp,
}: {
  cue: DistrictArrivalCue;
  district: ObservatoryDistrictRecipe;
  heroProp: ObservatoryHeroPropRecipe | null;
}) {
  const columnRefs = useRef<Array<THREE.Mesh | null>>([]);
  const barRefs = useRef<Array<THREE.Mesh | null>>([]);
  const origin = heroProp?.position ?? district.position;

  useFrame(({ clock }) => {
    const { decay, progress } = readArrivalProgress(cue);
    columnRefs.current.forEach((mesh, index) => {
      if (!mesh) return;
      mesh.position.y = origin[1] + 0.6 + Math.sin(clock.elapsedTime * 3.2 + index) * 0.1 * decay;
      mesh.scale.y = 1 + decay * (1.4 - index * 0.22);
      const material = mesh.material;
      if (material instanceof THREE.MeshBasicMaterial) {
        material.opacity = 0.08 + decay * (0.24 - index * 0.04);
      }
    });
    barRefs.current.forEach((mesh, index) => {
      if (!mesh) return;
      mesh.position.y = origin[1] + 0.22 + ((progress + index * 0.18) % 1) * 1.6;
      const material = mesh.material;
      if (material instanceof THREE.MeshBasicMaterial) {
        material.opacity = 0.1 + decay * 0.18;
      }
    });
  });

  return (
    <group position={[origin[0], 0, origin[2]]}>
      {[-0.54, 0, 0.54].map((x, index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={`col-${index}`}
          ref={(mesh) => {
            columnRefs.current[index] = mesh;
          }}
          position={[x, origin[1] + 0.6, 0.68]}
        >
          <cylinderGeometry args={[0.1, 0.18, 1.8, 16]} />
          <meshBasicMaterial color="#ffe29d" transparent opacity={0.16} />
        </mesh>
      ))}
      {[-0.42, 0.42].map((x, index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={`bar-${index}`}
          ref={(mesh) => {
            barRefs.current[index] = mesh;
          }}
          position={[x, origin[1] + 0.4, 0.18]}
          rotation={[0, 0.18 * (index === 0 ? -1 : 1), 0]}
        >
          <boxGeometry args={[0.12, 0.92, 1.5]} />
          <meshBasicMaterial color="#fff3c8" transparent opacity={0.18} />
        </mesh>
      ))}
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, origin[1] + 0.05, 0]}>
        <ringGeometry args={[0.92, 1.26, 30]} />
        <meshBasicMaterial color="#ffd77d" transparent opacity={0.24} />
      </mesh>
    </group>
  );
}

function EvidenceArrivalBeat({
  cue,
  district,
  heroProp,
}: {
  cue: DistrictArrivalCue;
  district: ObservatoryDistrictRecipe;
  heroProp: ObservatoryHeroPropRecipe | null;
}) {
  const cardRefs = useRef<Array<THREE.Mesh | null>>([]);
  const pathRefs = useRef<Array<THREE.Mesh | null>>([]);
  const origin = heroProp?.position ?? district.position;

  useFrame(({ clock }) => {
    const { decay, progress } = readArrivalProgress(cue);
    cardRefs.current.forEach((mesh, index) => {
      if (!mesh) return;
      const fan = (-0.34 + index * 0.24) * (0.35 + decay * 0.9);
      mesh.rotation.set(-0.14 + progress * 0.08, fan, 0);
      mesh.position.set(
        origin[0] - 0.34 + index * 0.34,
        origin[1] + 0.6 + Math.sin(clock.elapsedTime * 1.6 + index) * 0.08 * decay,
        origin[2] + 0.52 - index * 0.06,
      );
      const material = mesh.material;
      if (material instanceof THREE.MeshBasicMaterial) {
        material.opacity = 0.08 + decay * (0.16 - index * 0.02);
      }
    });
    pathRefs.current.forEach((mesh, index) => {
      if (!mesh) return;
      const material = mesh.material;
      if (material instanceof THREE.MeshBasicMaterial) {
        material.opacity = 0.05 + decay * (0.14 - index * 0.03);
      }
      mesh.position.x = origin[0] + 1.2 - progress * (1.5 + index * 0.32);
    });
  });

  return (
    <group>
      {[0, 1, 2].map((index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={`card-${index}`}
          ref={(mesh) => {
            cardRefs.current[index] = mesh;
          }}
          position={[origin[0], origin[1] + 0.6, origin[2] + 0.5]}
        >
          <planeGeometry args={[0.42, 0.72]} />
          <meshBasicMaterial color={index === 1 ? "#eaffff" : "#8ceaff"} transparent opacity={0.16} side={THREE.DoubleSide} />
        </mesh>
      ))}
      {[0, 1].map((index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={`path-${index}`}
          ref={(mesh) => {
            pathRefs.current[index] = mesh;
          }}
          position={[origin[0] + 1.2, origin[1] + 0.22 + index * 0.1, origin[2] - 0.42]}
          rotation={[0, 0.18, 0]}
        >
          <boxGeometry args={[0.94, 0.04, 0.14]} />
          <meshBasicMaterial color="#d7ffff" transparent opacity={0.14} />
        </mesh>
      ))}
    </group>
  );
}

function JudgmentArrivalBeat({
  cue,
  district,
  heroProp,
}: {
  cue: DistrictArrivalCue;
  district: ObservatoryDistrictRecipe;
  heroProp: ObservatoryHeroPropRecipe | null;
}) {
  const ringRefs = useRef<Array<THREE.Mesh | null>>([]);
  const beamRefs = useRef<Array<THREE.Mesh | null>>([]);
  const origin = heroProp?.position ?? district.position;

  useFrame(() => {
    const { decay, progress } = readArrivalProgress(cue);
    ringRefs.current.forEach((mesh, index) => {
      if (!mesh) return;
      mesh.position.y = origin[1] + 0.16 + index * 0.14 + progress * 0.22;
      mesh.scale.setScalar(1 + progress * (0.54 + index * 0.16));
      const material = mesh.material;
      if (material instanceof THREE.MeshBasicMaterial) {
        material.opacity = Math.max(0, (0.18 - index * 0.04) * decay + 0.04);
      }
    });
    beamRefs.current.forEach((mesh, index) => {
      if (!mesh) return;
      mesh.scale.y = 0.7 + decay * (1.1 - index * 0.18);
      mesh.position.y = origin[1] + 0.5 + mesh.scale.y * 0.46;
      const material = mesh.material;
      if (material instanceof THREE.MeshBasicMaterial) {
        material.opacity = 0.04 + decay * (0.14 - index * 0.03);
      }
    });
  });

  return (
    <group position={[origin[0], 0, origin[2]]}>
      {[0, 1, 2].map((index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={`ring-${index}`}
          ref={(mesh) => {
            ringRefs.current[index] = mesh;
          }}
          rotation={[-Math.PI / 2, 0, 0]}
          position={[0, origin[1] + 0.18 + index * 0.14, 0]}
        >
          <ringGeometry args={[0.76 + index * 0.34, 0.92 + index * 0.34, 34]} />
          <meshBasicMaterial color={index === 0 ? "#ffe3ba" : "#f4ba7b"} transparent opacity={0.14} />
        </mesh>
      ))}
      {[-0.42, 0.42].map((x, index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={`beam-${index}`}
          ref={(mesh) => {
            beamRefs.current[index] = mesh;
          }}
          position={[x, origin[1] + 0.9, -0.08]}
        >
          <boxGeometry args={[0.1, 1.1, 0.1]} />
          <meshBasicMaterial color="#fff0d7" transparent opacity={0.12} />
        </mesh>
      ))}
    </group>
  );
}

function DistrictHeroChoreography({
  cue,
  district,
  heroProp,
}: {
  cue: DistrictArrivalCue | null;
  district: ObservatoryDistrictRecipe;
  heroProp: ObservatoryHeroPropRecipe | null;
}) {
  if (!cue || cue.stationId !== district.id) {
    return null;
  }
  switch (district.id) {
    case "signal":
      return <HorizonArrivalBeat cue={cue} district={district} heroProp={heroProp} />;
    case "run":
      return <OperationsArrivalBeat cue={cue} district={district} heroProp={heroProp} />;
    case "receipts":
      return <EvidenceArrivalBeat cue={cue} district={district} heroProp={heroProp} />;
    case "case-notes":
      return <JudgmentArrivalBeat cue={cue} district={district} heroProp={heroProp} />;
    default:
      return null;
  }
}

export function PlayerAccentLights({
  playerFocusRef,
}: {
  playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>;
}) {
  const keyLightRef = useRef<THREE.PointLight | null>(null);
  const rimLightRef = useRef<THREE.PointLight | null>(null);
  const playerPositionRef = useRef(new THREE.Vector3());
  const keyTargetRef = useRef(new THREE.Vector3());
  const keyOffsetRef = useRef(new THREE.Vector3());
  const rimTargetRef = useRef(new THREE.Vector3());
  const rimOffsetRef = useRef(new THREE.Vector3());

  useFrame((_, delta) => {
    const keyLight = keyLightRef.current;
    const rimLight = rimLightRef.current;
    if (!keyLight || !rimLight) {
      return;
    }

    const focus = playerFocusRef.current;
    const keyAlpha = lerpAlpha(7.5, delta);
    const fadeAlpha = lerpAlpha(4.5, delta);

    if (!focus) {
      keyLight.intensity = THREE.MathUtils.lerp(keyLight.intensity, 0, fadeAlpha);
      rimLight.intensity = THREE.MathUtils.lerp(rimLight.intensity, 0, fadeAlpha);
      return;
    }

    const playerPosition = playerPositionRef.current.set(...focus.position);
    const airborneLift = focus.airborne ? 1 : 0.35;
    const keyOffset = keyOffsetRef.current.set(1.8, 3.4 + airborneLift, 2.1);
    const rimOffset = rimOffsetRef.current.set(-2.4, 1.9 + airborneLift * 0.6, -2.8);
    const keyTarget = keyTargetRef.current
      .copy(playerPosition)
      .add(keyOffset);
    const rimTarget = rimTargetRef.current
      .copy(playerPosition)
      .add(rimOffset);

    keyLight.position.lerp(keyTarget, keyAlpha);
    rimLight.position.lerp(rimTarget, keyAlpha);
    keyLight.intensity = THREE.MathUtils.lerp(
      keyLight.intensity,
      focus.moving || focus.airborne ? 1.05 : 0.82,
      keyAlpha,
    );
    rimLight.intensity = THREE.MathUtils.lerp(
      rimLight.intensity,
      focus.airborne ? 0.92 : 0.68,
      keyAlpha,
    );
  });

  return (
    <>
      <pointLight
        ref={keyLightRef}
        color="#eef6ff"
        decay={2}
        distance={15}
        intensity={0}
      />
      <pointLight
        ref={rimLightRef}
        color="#4db6ff"
        decay={2}
        distance={12}
        intensity={0}
      />
    </>
  );
}

function FlowPulse({
  colorHex,
  points,
  index,
  active,
}: {
  colorHex: string;
  points: [number, number, number][];
  index: number;
  active: boolean;
}) {
  const meshRef = useRef<THREE.Mesh | null>(null);
  const curve = useMemo(
    () => new THREE.CatmullRomCurve3(points.map((point) => new THREE.Vector3(...point))),
    [points],
  );
  const color = useMemo(() => new THREE.Color(colorHex), [colorHex]);

  useFrame(({ clock }) => {
    if (!meshRef.current) return;
    const t = (clock.elapsedTime * (active ? 0.18 : 0.11) + index * 0.22) % 1;
    const point = curve.getPointAt(t);
    meshRef.current.position.copy(point);
    const scale = active ? 0.22 : 0.14;
    meshRef.current.scale.setScalar(scale + Math.sin(clock.elapsedTime * 2 + index) * 0.02);
  });

  return (
    <mesh ref={meshRef}>
      <sphereGeometry args={[1, 16, 16]} />
      <meshBasicMaterial color={color} transparent opacity={active ? 0.86 : 0.52} />
    </mesh>
  );
}

export function TransitConvoy({
  route,
  modeOpacityScale,
}: {
  route: ObservatoryTransitRouteRecipe;
  modeOpacityScale: number;
}) {
  const podRefs = useRef<Array<THREE.Mesh | null>>([]);
  const curve = useMemo(
    () => new THREE.CatmullRomCurve3(route.points.map((point) => new THREE.Vector3(...point))),
    [route.points],
  );
  const color = useMemo(() => new THREE.Color(route.colorHex), [route.colorHex]);

  useFrame(({ clock }) => {
    podRefs.current.forEach((pod, index) => {
      if (!pod) return;
      const t = (clock.elapsedTime * (route.active ? 0.075 : 0.045) + index * 0.11) % 1;
      const point = curve.getPointAt(t);
      const tangent = curve.getTangentAt(t).normalize();
      pod.position.copy(point);
      pod.lookAt(point.clone().add(tangent));
      const scale = 0.16 + route.intensity * 0.14 - index * 0.02;
      pod.scale.set(scale, scale * 0.82, scale);
    });
  });

  return (
    <>
      {Array.from({ length: route.convoyCount }).map((_, index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          ref={(mesh) => {
            podRefs.current[index] = mesh;
          }}
        >
          <capsuleGeometry args={[0.3, 0.66, 5, 10]} />
          <meshStandardMaterial
            color={color}
            emissive={color}
            emissiveIntensity={1.2 + route.intensity * 1.8}
            transparent
            opacity={(0.82 - index * 0.1) * Math.max(0.24, modeOpacityScale)}
            toneMapped={false}
          />
        </mesh>
      ))}
    </>
  );
}

export function TransitCorridor({
  route,
  color,
  modeOpacityScale,
}: {
  route: ObservatoryTransitRouteRecipe;
  color: THREE.Color;
  modeOpacityScale: number;
}) {
  const curve = useMemo(
    () => new THREE.CatmullRomCurve3(route.points.map((point) => new THREE.Vector3(...point))),
    [route.points],
  );

  return (
    <group>
      <mesh>
        <tubeGeometry args={[curve, 90, route.glowRadius, 12, false]} />
        <meshBasicMaterial color={color} transparent opacity={route.corridorOpacity * 0.38 * modeOpacityScale} />
      </mesh>
      <mesh>
        <tubeGeometry args={[curve, 90, route.corridorRadius, 12, false]} />
        <meshBasicMaterial color={color} transparent opacity={route.corridorOpacity * modeOpacityScale} />
      </mesh>
    </group>
  );
}

export function TransitRoute({
  route,
  eruptionStrength,
  modeOpacityScale,
  missionTarget = false,
}: {
  route: ObservatoryTransitRouteRecipe;
  eruptionStrength: number;
  modeOpacityScale: number;
  missionTarget?: boolean;
}) {
  const color = useMemo(() => new THREE.Color(route.colorHex), [route.colorHex]);
  return (
    <group>
      <TransitCorridor route={route} color={color} modeOpacityScale={modeOpacityScale} />
      <Line
        points={route.leftEdgePoints}
        color={route.colorHex}
        transparent
        opacity={(route.opacity * 0.42 + eruptionStrength * 0.08 + (missionTarget ? 0.1 : 0)) * modeOpacityScale}
        lineWidth={1}
      />
      <Line
        points={route.rightEdgePoints}
        color={route.colorHex}
        transparent
        opacity={(route.opacity * 0.42 + eruptionStrength * 0.08 + (missionTarget ? 0.1 : 0)) * modeOpacityScale}
        lineWidth={1}
      />
      <Line
        points={route.points}
        color={route.colorHex}
        transparent
        opacity={(route.opacity + eruptionStrength * 0.18 + (missionTarget ? 0.14 : 0)) * modeOpacityScale}
        lineWidth={1.5}
      />
      {route.waypointPositions.map((point, index) => (
        <group
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          position={point}
        >
          <mesh rotation={[-Math.PI / 2, 0, 0]}>
            <ringGeometry args={[0.14 + index * 0.03, 0.22 + index * 0.03, 20]} />
            <meshBasicMaterial color={route.colorHex} transparent opacity={0.2 + route.intensity * 0.16} />
          </mesh>
          <mesh position={[0, 0.08, 0]}>
            <sphereGeometry args={[0.04 + index * 0.01, 10, 10]} />
            <meshBasicMaterial color={route.colorHex} transparent opacity={0.28 + route.intensity * 0.22} />
          </mesh>
        </group>
      ))}
      <TransitConvoy route={route} modeOpacityScale={modeOpacityScale} />
      {route.showPulse ? (
        <FlowPulse colorHex={route.colorHex} points={route.points} index={1} active={route.active} />
      ) : null}
    </group>
  );
}


function HorizonGlyph({ color, emphasis }: { color: THREE.Color; emphasis: number }) {
  const groupRef = useRef<THREE.Group | null>(null);
  useFrame(({ clock }) => {
    if (!groupRef.current) return;
    groupRef.current.rotation.y = Math.sin(clock.elapsedTime * 0.35) * 0.24;
  });
  return (
    <group ref={groupRef}>
      <mesh position={[0, 0.86, 0]}>
        <coneGeometry args={[0.55, 1.2, 6]} />
        <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.7 + emphasis * 0.4} />
      </mesh>
      <mesh rotation={[Math.PI / 2, 0, 0]} position={[0, 0.18, 0]}>
        <torusGeometry args={[0.92, 0.05, 14, 56]} />
        <meshBasicMaterial color={color} transparent opacity={0.72} />
      </mesh>
    </group>
  );
}

function SubjectsGlyph({ color, emphasis }: { color: THREE.Color; emphasis: number }) {
  const groupRef = useRef<THREE.Group | null>(null);
  useFrame(({ clock }) => {
    if (!groupRef.current) return;
    groupRef.current.rotation.y = clock.elapsedTime * 0.18;
  });
  return (
    <group ref={groupRef}>
      {[
        [-0.44, 0.72, 0.12],
        [0.48, 0.94, -0.18],
        [0.08, 0.42, 0.5],
      ].map((position, index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          position={position as [number, number, number]}
        >
          <sphereGeometry args={[0.22 + index * 0.03, 16, 16]} />
          <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.58 + emphasis * 0.3} />
        </mesh>
      ))}
    </group>
  );
}

function OperationsGlyph({ color, emphasis }: { color: THREE.Color; emphasis: number }) {
  return (
    <group>
      {[
        [-0.42, 0.58, 0.14, 0.44, 0.96, 0.44],
        [0, 0.88, 0, 0.42, 1.54, 0.42],
        [0.42, 0.7, -0.16, 0.36, 1.18, 0.36],
      ].map(([x, y, z, sx, sy, sz], index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          position={[x, y, z]}
          scale={[sx, sy, sz]}
        >
          <boxGeometry args={[1, 1, 1]} />
          <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.52 + emphasis * 0.34} />
        </mesh>
      ))}
    </group>
  );
}

function EvidenceGlyph({ color, emphasis }: { color: THREE.Color; emphasis: number }) {
  return (
    <group>
      <mesh position={[0, 0.56, 0]} rotation={[-0.2, 0.12, -0.18]}>
        <boxGeometry args={[1.3, 0.1, 0.86]} />
        <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.58 + emphasis * 0.34} />
      </mesh>
      <mesh position={[0.28, 0.94, -0.14]} rotation={[0.34, -0.28, 0.18]}>
        <boxGeometry args={[0.24, 1.02, 0.08]} />
        <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.7 + emphasis * 0.28} />
      </mesh>
      <mesh position={[-0.34, 0.78, 0.22]} rotation={[-0.22, 0.18, 0.08]}>
        <boxGeometry args={[0.18, 0.82, 0.08]} />
        <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.62 + emphasis * 0.24} />
      </mesh>
    </group>
  );
}

function JudgmentGlyph({ color, emphasis }: { color: THREE.Color; emphasis: number }) {
  return (
    <group>
      {[
        [0, 0.44, 0, 1.18, 0.16, 0.82],
        [0, 0.72, -0.06, 0.9, 0.16, 0.62],
        [0, 1.0, -0.12, 0.62, 0.16, 0.4],
      ].map(([x, y, z, sx, sy, sz], index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          position={[x, y, z]}
          scale={[sx, sy, sz]}
        >
          <boxGeometry args={[1, 1, 1]} />
          <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.48 + emphasis * 0.28} />
        </mesh>
      ))}
    </group>
  );
}

function StationGlyph({
  stationId,
  color,
  emphasis,
}: {
  stationId: HuntStationId;
  color: THREE.Color;
  emphasis: number;
}) {
  switch (stationId) {
    case "signal":
      return <HorizonGlyph color={color} emphasis={emphasis} />;
    case "targets":
      return <SubjectsGlyph color={color} emphasis={emphasis} />;
    case "run":
      return <OperationsGlyph color={color} emphasis={emphasis} />;
    case "receipts":
      return <EvidenceGlyph color={color} emphasis={emphasis} />;
    case "case-notes":
      return <JudgmentGlyph color={color} emphasis={emphasis} />;
    case "watch":
      return null;
  }
}

function GrowthStructure({
  color,
  structure,
}: {
  color: THREE.Color;
  structure: ObservatoryGrowthStructureRecipe;
}) {
  const opacity = structure.opacity;
  switch (structure.kind) {
    case "halo":
      return (
        <mesh rotation={structure.rotation} scale={structure.scale}>
          <torusGeometry args={[1.1, 0.08, 12, 48]} />
          <meshBasicMaterial color={color} transparent opacity={opacity} />
        </mesh>
      );
    case "dish":
      return (
        <group rotation={structure.rotation}>
          <mesh position={[0, 0.38 + structure.wakeAmount * 0.12, 0]} scale={structure.scale}>
            <coneGeometry args={[0.86, 0.28, 20, 1, true]} />
            <meshStandardMaterial color={color} emissive={color} emissiveIntensity={structure.emissiveIntensity} transparent opacity={opacity} side={THREE.DoubleSide} />
          </mesh>
          <mesh position={[0, 0.08, 0]}>
            <cylinderGeometry args={[0.06, 0.1, 0.44 + structure.wakeAmount * 0.3, 10]} />
            <meshStandardMaterial color={color} emissive={color} emissiveIntensity={structure.emissiveIntensity * 0.72} transparent opacity={opacity * 0.78} />
          </mesh>
        </group>
      );
    case "satellite":
      return (
        <mesh scale={structure.scale} position={[0, 0.24 + structure.wakeAmount * 0.18, 0]} rotation={structure.rotation}>
          <octahedronGeometry args={[1, 0]} />
          <meshStandardMaterial color={color} emissive={color} emissiveIntensity={structure.emissiveIntensity} transparent opacity={opacity} />
        </mesh>
      );
    case "panel":
      return (
        <group rotation={structure.rotation}>
          <mesh position={[0, 0.08 + structure.wakeAmount * 0.05, 0]} scale={structure.scale}>
            <boxGeometry args={[1.2, 1, 1.2]} />
            <meshStandardMaterial color={color} emissive={color} emissiveIntensity={structure.emissiveIntensity * 0.78} transparent opacity={opacity} />
          </mesh>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.04, 0]}>
            <ringGeometry args={[0.36, 0.52, 24]} />
            <meshBasicMaterial color={color} transparent opacity={opacity * 0.44} />
          </mesh>
        </group>
      );
    case "array":
      return (
        <group rotation={structure.rotation}>
          <mesh position={[0, 0.24 + structure.scale[1] * 0.5, 0]} scale={structure.scale}>
            <boxGeometry args={[1.2, 1, 1.2]} />
            <meshStandardMaterial color={color} emissive={color} emissiveIntensity={structure.emissiveIntensity} transparent opacity={opacity} />
          </mesh>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.06, 0]}>
            <ringGeometry args={[0.22, 0.36, 20]} />
            <meshBasicMaterial color={color} transparent opacity={opacity * 0.8} />
          </mesh>
        </group>
      );
    case "spire":
      return (
        <group rotation={structure.rotation}>
          <mesh position={[0, 0.18 + structure.scale[1] * 0.54, 0]} scale={structure.scale}>
            <coneGeometry args={[0.84, 1.2, 8]} />
            <meshStandardMaterial color={color} emissive={color} emissiveIntensity={structure.emissiveIntensity} transparent opacity={opacity} />
          </mesh>
          <mesh position={[0, 0.22 + structure.scale[1] * 1.08, 0]}>
            <sphereGeometry args={[0.09 + structure.wakeAmount * 0.04, 12, 12]} />
            <meshBasicMaterial color={color} transparent opacity={opacity * 0.8} />
          </mesh>
        </group>
      );
    case "pylon":
    default:
      return (
        <group rotation={structure.rotation}>
          <mesh position={[0, 0.2 + structure.scale[1] * 0.5, 0]} scale={structure.scale}>
            <cylinderGeometry args={[0.4, 0.7, 1, 10]} />
            <meshStandardMaterial color={color} emissive={color} emissiveIntensity={structure.emissiveIntensity} transparent opacity={opacity} />
          </mesh>
          <mesh position={[0, 0.3 + structure.scale[1], 0]}>
            <sphereGeometry args={[0.08 + structure.wakeAmount * 0.05, 12, 12]} />
            <meshBasicMaterial color={color} transparent opacity={opacity * 0.9} />
          </mesh>
        </group>
      );
  }
}

function MasterplanFeature({
  color,
  feature,
  modeOpacityScale,
}: {
  color: THREE.Color;
  feature: ObservatoryDistrictRecipe["masterplanFeatures"][number];
  modeOpacityScale: number;
}) {
  const opacity = feature.opacity * modeOpacityScale;
  switch (feature.kind) {
    case "tower":
    case "sensor-mast":
    case "link-pylon":
    case "outer-pylon":
    case "beacon":
      return (
        <group rotation={feature.rotation}>
          <mesh position={[0, feature.scale[1] * 0.5, 0]} scale={feature.scale}>
            <cylinderGeometry args={[0.28, 0.38, 1, 10]} />
            <meshStandardMaterial color="#0f1722" emissive={color} emissiveIntensity={feature.emissiveIntensity} transparent opacity={opacity} />
          </mesh>
          <mesh position={[0, feature.scale[1] + 0.12, 0]}>
            <sphereGeometry args={[0.1, 12, 12]} />
            <meshBasicMaterial color={color} transparent opacity={opacity * 0.86} />
          </mesh>
        </group>
      );
    case "dish":
      return (
        <group rotation={feature.rotation}>
          <mesh position={[0, 0.22, 0]}>
            <cylinderGeometry args={[0.12, 0.18, 0.4, 8]} />
            <meshStandardMaterial color="#111a28" emissive={color} emissiveIntensity={feature.emissiveIntensity * 0.6} transparent opacity={opacity} />
          </mesh>
          <mesh position={[0, 0.58, 0]} rotation={[-0.45, 0.24, 0]} scale={feature.scale}>
            <coneGeometry args={[0.6, 0.18, 10, 1, true]} />
            <meshStandardMaterial color="#162234" emissive={color} emissiveIntensity={feature.emissiveIntensity} transparent opacity={opacity} wireframe />
          </mesh>
        </group>
      );
    case "orbit-platform":
    case "archive-lane":
    case "terrace":
    case "scaffold-court":
      return (
        <group rotation={feature.rotation}>
          <mesh scale={feature.scale}>
            <boxGeometry args={[1, 1, 1]} />
            <meshStandardMaterial color="#0e1620" emissive={color} emissiveIntensity={feature.emissiveIntensity * 0.6} transparent opacity={opacity} />
          </mesh>
          <mesh position={[0, -feature.scale[1] * 0.54, 0]} scale={[feature.scale[0] * 0.82, feature.scale[1] * 0.32, feature.scale[2] * 0.82]}>
            <cylinderGeometry args={[0.78, 0.94, 1, 12]} />
            <meshStandardMaterial color="#0b1119" emissive={color} emissiveIntensity={feature.emissiveIntensity * 0.24} transparent opacity={opacity * 0.58} />
          </mesh>
        </group>
      );
    case "gantry":
      return (
        <group rotation={feature.rotation}>
          <mesh position={[0, 0.06, 0]} scale={feature.scale}>
            <boxGeometry args={[1, 1, 1]} />
            <meshStandardMaterial color="#101923" emissive={color} emissiveIntensity={feature.emissiveIntensity * 0.4} transparent opacity={opacity} />
          </mesh>
          {[-0.42, 0.42].map((x, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              position={[x * feature.scale[0], -feature.scale[1] * 0.42, 0]}
              scale={[0.08, Math.max(0.8, feature.scale[1] * 2.4), 0.08]}
            >
              <boxGeometry args={[1, 1, 1]} />
              <meshStandardMaterial color="#121d2b" emissive={color} emissiveIntensity={feature.emissiveIntensity * 0.36} transparent opacity={opacity * 0.92} />
            </mesh>
          ))}
        </group>
      );
    case "reactor":
      return (
        <group rotation={feature.rotation}>
          <mesh position={[0, feature.scale[1] * 0.48, 0]} scale={feature.scale}>
            <cylinderGeometry args={[0.5, 0.7, 1, 16]} />
            <meshStandardMaterial color="#101521" emissive={color} emissiveIntensity={feature.emissiveIntensity} transparent opacity={opacity} />
          </mesh>
          <mesh position={[0, feature.scale[1], 0]}>
            <sphereGeometry args={[0.18, 14, 14]} />
            <meshBasicMaterial color={color} transparent opacity={opacity * 0.9} />
          </mesh>
        </group>
      );
    case "rig":
    case "vault-stack":
    default:
      return (
        <group rotation={feature.rotation}>
          <mesh position={[0, feature.scale[1] * 0.5, 0]} scale={feature.scale}>
            <boxGeometry args={[1, 1, 1]} />
            <meshStandardMaterial color="#101821" emissive={color} emissiveIntensity={feature.emissiveIntensity * 0.7} transparent opacity={opacity} />
          </mesh>
          <mesh position={[0, feature.scale[1] * 1.08, 0]}>
            <ringGeometry args={[0.12, 0.22, 18]} />
            <meshBasicMaterial color={color} transparent opacity={opacity * 0.52} />
          </mesh>
        </group>
      );
  }
}

function TraversalSurface({
  color,
  surface,
  modeOpacityScale,
}: {
  color: THREE.Color;
  surface: ObservatoryDistrictRecipe["traversalSurfaces"][number];
  modeOpacityScale: number;
}) {
  const opacity = surface.opacity * modeOpacityScale;
  if (surface.kind === "jump-pad") {
    return (
      <group rotation={surface.rotation}>
        <mesh scale={surface.scale}>
          <cylinderGeometry args={[0.5, 0.62, 1, 20]} />
          <meshStandardMaterial color="#0c1420" emissive={color} emissiveIntensity={surface.emissiveIntensity} transparent opacity={opacity} />
        </mesh>
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, surface.scale[1] * 0.52, 0]}>
          <ringGeometry args={[0.24, 0.42, 28]} />
          <meshBasicMaterial color={color} transparent opacity={opacity * 0.94} />
        </mesh>
      </group>
    );
  }

  return (
    <group rotation={surface.rotation}>
      <mesh scale={surface.scale}>
        <boxGeometry args={[1, 1, 1]} />
        <meshStandardMaterial color="#0b1119" emissive={color} emissiveIntensity={surface.emissiveIntensity} transparent opacity={opacity} />
      </mesh>
      {(surface.kind === "platform" || surface.kind === "observation-platform" || surface.kind === "hanging-platform") ? (
        <mesh position={[0, -surface.scale[1] * 0.62, 0]} scale={[surface.scale[0] * 0.82, Math.max(0.18, surface.scale[1] * 0.8), surface.scale[2] * 0.82]}>
          <cylinderGeometry args={[0.72, 0.94, 1, 10]} />
          <meshStandardMaterial color="#0a1118" emissive={color} emissiveIntensity={surface.emissiveIntensity * 0.18} transparent opacity={opacity * 0.34} />
        </mesh>
      ) : null}
      {(surface.kind === "catwalk" || surface.kind === "bridge" || surface.kind === "control-deck") ? (
        <>
          {[-0.46, 0.46].map((x, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              position={[x * surface.scale[0], surface.scale[1] * 0.64, 0]}
              scale={[0.03, 0.4, 0.03]}
            >
              <boxGeometry args={[1, 1, 1]} />
              <meshBasicMaterial color={color} transparent opacity={opacity * 0.72} />
            </mesh>
          ))}
          {[-0.38, 0.38].map((x, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={`support-${index}`}
              position={[x * surface.scale[0], -surface.scale[1] * 0.94, 0]}
              scale={[0.06, 1.24, 0.06]}
            >
              <boxGeometry args={[1, 1, 1]} />
              <meshStandardMaterial color="#0b121b" emissive={color} emissiveIntensity={surface.emissiveIntensity * 0.16} transparent opacity={opacity * 0.46} />
            </mesh>
          ))}
        </>
      ) : null}
      {surface.kind === "ramp" ? (
        <mesh position={[0, -surface.scale[1] * 0.72, 0]} scale={[0.08, 1.16, 0.08]}>
          <boxGeometry args={[1, 1, 1]} />
          <meshStandardMaterial color="#0b121b" emissive={color} emissiveIntensity={surface.emissiveIntensity * 0.16} transparent opacity={opacity * 0.42} />
        </mesh>
      ) : null}
    </group>
  );
}

function DistrictMasterplan({
  district,
  modeOpacityScale,
  focusStrength,
}: {
  district: ObservatoryDistrictRecipe;
  modeOpacityScale: number;
  focusStrength: number;
}) {
  const color = useMemo(() => new THREE.Color(district.colorHex), [district.colorHex]);
  const atlasMode = modeOpacityScale < 0.9;
  return (
    <>
      <DistrictAtmosphere district={district} atlasMode={atlasMode} focusStrength={focusStrength} />
      {district.masterplanFeatures.map((feature) => (
        <group key={feature.key} position={feature.position}>
          <MasterplanFeature color={color} feature={feature} modeOpacityScale={modeOpacityScale} />
        </group>
      ))}
      {district.traversalSurfaces.map((surface) => (
        <group key={surface.key} position={surface.position}>
          <TraversalSurface color={color} surface={surface} modeOpacityScale={modeOpacityScale} />
        </group>
      ))}
    </>
  );
}

function DistrictLifecycleAura({
  district,
  focusStrength,
}: {
  district: ObservatoryDistrictRecipe;
  focusStrength: number;
}) {
  const baseOpacity = 0.06 + district.lifecycleProgress * 0.16;
  switch (district.lifecycleState) {
    case "dormant":
      return (
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.28, 0]}>
          <ringGeometry args={[1.4, 1.82, 32]} />
          <meshBasicMaterial color={district.colorHex} transparent opacity={baseOpacity * 0.42} />
        </mesh>
      );
    case "waking":
      return (
        <>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.12, 0]}>
            <ringGeometry args={[1.6, 2.14, 36]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={baseOpacity * 0.72} />
          </mesh>
          <mesh position={[0, 0.92, 0]} scale={[0.08, 1.2, 0.08]}>
            <boxGeometry args={[1, 1, 1]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={baseOpacity * 0.46} />
          </mesh>
        </>
      );
    case "active":
      return (
        <>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.12, 0]}>
            <ringGeometry args={[1.7, 2.22, 36]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={baseOpacity * 0.88} />
          </mesh>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.18, 0]}>
            <ringGeometry args={[1.18, 1.32, 32]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={baseOpacity * 0.62} />
          </mesh>
        </>
      );
    case "saturated":
      return (
        <>
          {[0.02, 0.42].map((y, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              rotation={[-Math.PI / 2, 0, 0]}
              position={[0, y, 0]}
            >
              <ringGeometry args={[1.42 + index * 0.34, 1.64 + index * 0.36, 40]} />
              <meshBasicMaterial color={district.colorHex} transparent opacity={baseOpacity * (0.94 - index * 0.18)} />
            </mesh>
          ))}
          <mesh position={[0, district.verticalSpan * 0.46, 0]} scale={[0.1, 1.8 + focusStrength * 0.4, 0.1]}>
            <boxGeometry args={[1, 1, 1]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={baseOpacity * 0.42} />
          </mesh>
        </>
      );
    case "critical":
      return (
        <>
          {[0, 0.3, 0.62].map((y, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              rotation={[-Math.PI / 2, 0, 0]}
              position={[0, y, 0]}
            >
              <ringGeometry args={[1.48 + index * 0.38, 1.72 + index * 0.4, 44]} />
              <meshBasicMaterial color="#fff0cb" transparent opacity={baseOpacity * (1.04 - index * 0.16)} />
            </mesh>
          ))}
          <mesh position={[0, district.verticalSpan * 0.52, 0]} scale={[0.14, 2.2 + focusStrength * 0.8, 0.14]}>
            <boxGeometry args={[1, 1, 1]} />
            <meshBasicMaterial color="#fff0cb" transparent opacity={baseOpacity * 0.52} />
          </mesh>
        </>
      );
  }
}

function DistrictProbeReaction({
  district,
}: {
  district: ObservatoryDistrictRecipe;
}) {
  if (!district.probeReaction) {
    return null;
  }
  const color =
    district.probeReaction.state === "surveying" ? "#dff7ff" : "#ffe6b5";
  const intensity = district.probeReaction.intensity;
  const beamOpacity =
    district.probeReaction.state === "surveying"
      ? 0.16 + intensity * 0.12
      : 0.1 + intensity * 0.08;
  return (
    <group>
      {[0.08, 0.34, 0.62].map((y, index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          rotation={[-Math.PI / 2, 0, 0]}
          position={[0, y, 0]}
        >
          <ringGeometry
            args={[
              1.26 + index * 0.34 + intensity * 0.14,
              1.46 + index * 0.38 + intensity * 0.16,
              40,
            ]}
          />
          <meshBasicMaterial
            color={color}
            transparent
            opacity={(0.16 - index * 0.034) * (0.72 + intensity * 0.56)}
          />
        </mesh>
      ))}
      <mesh
        position={[0, district.verticalSpan * 0.52, 0]}
        scale={[0.1 + intensity * 0.06, 1.5 + intensity * 1.2, 0.1 + intensity * 0.06]}
      >
        <boxGeometry args={[1, 1, 1]} />
        <meshBasicMaterial color={color} transparent opacity={beamOpacity} />
      </mesh>
      <mesh position={[0, district.verticalSpan * 1.02, 0]}>
        <sphereGeometry args={[0.18 + intensity * 0.06, 14, 14]} />
        <meshBasicMaterial color={color} transparent opacity={0.24 + intensity * 0.14} />
      </mesh>
    </group>
  );
}

function DistrictCrewPopulation({
  crew,
  modeOpacityScale,
}: {
  crew: ObservatoryDistrictRecipe["crew"][number];
  modeOpacityScale: number;
}) {
  const groupRef = useRef<THREE.Group | null>(null);
  const utilityRef = useRef<THREE.Group | null>(null);
  const controllerStateRef = useRef({
    activeAction: "idle" as string | null,
    facingRadians: 0,
    grounded: true,
    position: [0, 0, 0] as [number, number, number],
    sprinting: false,
    velocity: [0, 0, 0] as [number, number, number],
  });
  const lastPositionRef = useRef<[number, number, number]>(crew.position);
  const responseWaypoints = useMemo(() => buildCrewResponseWaypoints(crew), [crew]);

  useFrame(({ clock }, delta) => {
    if (!groupRef.current) return;
    const responseIntensity = crew.response?.intensity ?? 0;
    const phase = clock.elapsedTime * crew.pace * (crew.response?.paceMultiplier ?? 1);
    const sampled = sampleCrewLoop(responseWaypoints, phase);
    const verticalBob =
      crew.loopKind === "calibrate-horizon"
        ? Math.sin(clock.elapsedTime * 1.4) * 0.04
        : crew.loopKind === "service-operations"
          ? Math.sin(clock.elapsedTime * 2.2) * 0.03
          : crew.loopKind === "tend-evidence"
            ? Math.sin(clock.elapsedTime * 0.9) * 0.02
            : Math.sin(clock.elapsedTime * 1.6) * 0.015;
    const amplifiedBob = verticalBob * (1 + responseIntensity * 0.35);
    groupRef.current.position.set(sampled.position[0], sampled.position[1] + verticalBob, sampled.position[2]);
    groupRef.current.position.y = sampled.position[1] + amplifiedBob;
    groupRef.current.rotation.y = sampled.facing + Math.sin(clock.elapsedTime * 0.55) * (0.04 + responseIntensity * 0.03);
    const previousPosition = lastPositionRef.current;
    const velocity: [number, number, number] = delta > 0
      ? [
          (sampled.position[0] - previousPosition[0]) / delta,
          0,
          (sampled.position[2] - previousPosition[2]) / delta,
        ]
      : [0, 0, 0];
    lastPositionRef.current = sampled.position;
    const horizontalSpeed = Math.hypot(velocity[0], velocity[2]);
    controllerStateRef.current.activeAction =
      horizontalSpeed > 1.8 ? "run" : horizontalSpeed > 0.18 ? "walk" : "idle";
    controllerStateRef.current.position = sampled.position;
    controllerStateRef.current.sprinting = horizontalSpeed > 1.8;
    controllerStateRef.current.velocity = velocity;
    if (utilityRef.current && crew.utilityTarget) {
      utilityRef.current.visible = crew.active || Boolean(crew.response?.utilityVisible);
      utilityRef.current.position.set(...crew.utilityTarget);
      utilityRef.current.rotation.y = clock.elapsedTime * (0.3 + responseIntensity * 0.24);
    }
  });

  return (
    <group>
      {crew.utilityTarget ? (
        <group ref={utilityRef} position={crew.utilityTarget}>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.02, 0]}>
            <ringGeometry args={[0.18, 0.3, 24]} />
            <meshBasicMaterial color={crew.accentColor} transparent opacity={modeOpacityScale > 0.5 ? 0.32 : 0.16} />
          </mesh>
          <mesh position={[0, 0.22, 0]} scale={[0.05, 0.52, 0.05]}>
            <boxGeometry args={[1, 1, 1]} />
            <meshBasicMaterial color={crew.accentColor} transparent opacity={0.14} />
          </mesh>
        </group>
      ) : null}
      <group ref={groupRef} position={crew.position}>
      <ObservatoryPlayerAvatar
        accentColor={crew.accentColor}
        animationAssetUrls={OBSERVATORY_ASTRONAUT_OPERATOR_ANIMATION_URLS}
        assetUrl={OBSERVATORY_ASTRONAUT_OPERATOR_ASSET_URL}
        bodyColor="#111a26"
        controllerState={controllerStateRef.current}
        materialSourceUrl={OBSERVATORY_ASTRONAUT_OPERATOR_TEXTURE_SOURCE_URL}
        positionOffset={[0, -0.78, 0]}
        scale={crew.scale * 1.7}
        trimColor="#d8c895"
        visible={modeOpacityScale > 0.52}
        visorColor="#c8fbff"
      />
      </group>
    </group>
  );
}

function DormantInfrastructure({
  district,
  color,
}: {
  district: ObservatoryDistrictRecipe;
  color: THREE.Color;
}) {
  return (
    <>
      {district.growth.conduitPaths.map((path, index) => (
        <Line
          // eslint-disable-next-line react/no-array-index-key
          key={`conduit-${index}`}
          points={path}
          color={district.colorHex}
          transparent
          opacity={0.06 + district.growth.growthLevel * 0.12}
          lineWidth={1}
        />
      ))}
      {district.growth.structures.map((structure) => (
        <group key={structure.key} position={structure.position}>
          <GrowthStructure color={color} structure={structure} />
        </group>
      ))}
    </>
  );
}

function DistrictTimeStrata({
  district,
}: {
  district: ObservatoryDistrictRecipe;
}) {
  return (
    <>
      {district.timeStrata.map((stratum, index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          rotation={[-Math.PI / 2, 0, 0]}
          position={[0, stratum.yOffset, 0]}
        >
          <ringGeometry args={[stratum.radius, stratum.radius + 0.24, 48]} />
          <meshBasicMaterial color={district.colorHex} transparent opacity={Math.max(0, stratum.opacity)} />
        </mesh>
      ))}
    </>
  );
}

function DistrictOccupancy({
  district,
}: {
  district: ObservatoryDistrictRecipe;
}) {
  return (
    <>
      {district.occupancyNodes.map((node, index) => (
        <group
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          position={node.position}
        >
          <mesh scale={node.scale}>
            <cylinderGeometry args={[1, 1.2, 1, 12]} />
            <meshBasicMaterial
              color={district.colorHex}
              transparent
              opacity={node.opacity}
            />
          </mesh>
          {node.filled ? (
            <mesh position={[0, 0.14, 0]}>
              <sphereGeometry args={[0.06, 10, 10]} />
              <meshBasicMaterial color={district.colorHex} transparent opacity={0.26 + district.occupancyLevel * 0.2} />
            </mesh>
          ) : null}
        </group>
      ))}
    </>
  );
}

function DistrictMicroInteraction({
  district,
  interactionState,
}: {
  district: ObservatoryDistrictRecipe;
  interactionState: "idle" | "hover" | "active";
}) {
  const groupRef = useRef<THREE.Group | null>(null);
  const strength = interactionState === "active" ? 1 : interactionState === "hover" ? 0.65 : 0;

  useFrame(({ clock }) => {
    if (!groupRef.current || strength <= 0) return;
    if (district.microInteraction === "sweep") {
      groupRef.current.rotation.y = clock.elapsedTime * 0.6;
    } else if (district.microInteraction === "expand-cluster") {
      const scale = 1 + Math.sin(clock.elapsedTime * 1.8) * 0.12 * strength;
      groupRef.current.scale.setScalar(scale);
    } else if (district.microInteraction === "engage-machinery") {
      groupRef.current.position.y = Math.sin(clock.elapsedTime * 2.4) * 0.12 * strength;
    } else if (district.microInteraction === "fan-stacks") {
      groupRef.current.rotation.z = Math.sin(clock.elapsedTime * 1.3) * 0.22 * strength;
    } else if (district.microInteraction === "seal-scaffold") {
      groupRef.current.rotation.z = clock.elapsedTime * 0.34;
    } else if (district.microInteraction === "sentry-wake") {
      groupRef.current.scale.setScalar(1 + Math.sin(clock.elapsedTime * 2.6) * 0.08 * strength);
    }
  });

  if (strength <= 0) return null;

  switch (district.microInteraction) {
    case "sweep":
      return (
        <group ref={groupRef}>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.08, 0]}>
            <ringGeometry args={[1.8, 2.9, 28, 1, 0, Math.PI / 2.8]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={0.12 + strength * 0.08} side={THREE.DoubleSide} />
          </mesh>
        </group>
      );
    case "expand-cluster":
      return (
        <group ref={groupRef}>
          {district.silhouette.nodePositions.slice(0, 3).map((position, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              position={position}
            >
              <sphereGeometry args={[0.12 + index * 0.02, 12, 12]} />
              <meshBasicMaterial color={district.colorHex} transparent opacity={0.14 + strength * 0.12} />
            </mesh>
          ))}
        </group>
      );
    case "engage-machinery":
      return (
        <group ref={groupRef}>
          {[-0.6, 0, 0.6].map((x, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              position={[x, 0.44 + index * 0.1, 0.9]}
              scale={[0.14, 0.8 + index * 0.16, 0.14]}
            >
              <boxGeometry args={[1, 1, 1]} />
              <meshBasicMaterial color={district.colorHex} transparent opacity={0.14 + strength * 0.1} />
            </mesh>
          ))}
        </group>
      );
    case "fan-stacks":
      return (
        <group ref={groupRef}>
          {[-0.26, 0, 0.26].map((z, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              position={[0.92, 0.46 + index * 0.08, z]}
              rotation={[0, 0.18 + index * 0.16, 0]}
              scale={[0.84, 0.02, 0.56]}
            >
              <boxGeometry args={[1, 1, 1]} />
              <meshBasicMaterial color={district.colorHex} transparent opacity={0.12 + strength * 0.1} />
            </mesh>
          ))}
        </group>
      );
    case "seal-scaffold":
      return (
        <group ref={groupRef}>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.2, 0]}>
            <ringGeometry args={[1.2, 1.38, 32]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={0.12 + strength * 0.12} />
          </mesh>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.26, 0]}>
            <ringGeometry args={[1.62, 1.74, 32]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={0.08 + strength * 0.08} />
          </mesh>
        </group>
      );
    case "sentry-wake":
      return (
        <group ref={groupRef}>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.16, 0]}>
            <ringGeometry args={[1.5, 1.8, 32]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={0.1 + strength * 0.08} />
          </mesh>
        </group>
      );
  }
}

function DistrictSilhouette({
  silhouette,
  colorHex,
  emphasis,
}: {
  silhouette: ObservatoryDistrictSilhouetteRecipe;
  colorHex: string;
  emphasis: number;
}) {
  return (
    <group>
      {silhouette.frameLoops.map((frame, index) => (
        <Line
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          points={frame}
          color={colorHex}
          transparent
          opacity={0.08 + emphasis * 0.14 - index * 0.02}
          lineWidth={1}
        />
      ))}
      {silhouette.nodePositions.map((position, index) => (
        <group
          // eslint-disable-next-line react/no-array-index-key
          key={`n-${index}`}
          position={position}
        >
          <mesh>
            <sphereGeometry args={[0.08 + index * 0.02, 12, 12]} />
            <meshBasicMaterial color={colorHex} transparent opacity={0.18 + emphasis * 0.2} />
          </mesh>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.12, 0]}>
            <ringGeometry args={[0.16 + index * 0.03, 0.24 + index * 0.03, 18]} />
            <meshBasicMaterial color={colorHex} transparent opacity={0.1 + emphasis * 0.12} />
          </mesh>
        </group>
      ))}
    </group>
  );
}

function DistrictAtmosphere({
  district,
  atlasMode,
  focusStrength,
}: {
  district: ObservatoryDistrictRecipe;
  atlasMode: boolean;
  focusStrength: number;
}) {
  const lifecycleBoost =
    district.lifecycleState === "critical"
      ? 1.28
      : district.lifecycleState === "saturated"
        ? 1.16
        : district.lifecycleState === "active"
          ? 1.02
          : district.lifecycleState === "waking"
            ? 0.88
            : 0.68;
  const opacityScale = (atlasMode ? 0.82 : 1.08) * (0.52 + focusStrength * 0.82) * lifecycleBoost;
  switch (district.id) {
    case "signal":
      return (
        <group>
          <mesh position={[0, district.verticalSpan * 0.42, 0]}>
            <coneGeometry args={[2.2, 6.2, 18, 1, true]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={0.05 * opacityScale} side={THREE.DoubleSide} />
          </mesh>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.22, 0]}>
            <ringGeometry args={[2.2, 3.8, 48]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={0.08 * opacityScale} />
          </mesh>
        </group>
      );
    case "targets":
      return (
        <group>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.18, 0]}>
            <ringGeometry args={[1.4, 2.8, 48]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={0.09 * opacityScale} />
          </mesh>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 1.16, 0]}>
            <ringGeometry args={[0.9, 1.7, 40]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={0.06 * opacityScale} />
          </mesh>
        </group>
      );
    case "run":
      return (
        <group>
          <mesh position={[0, district.verticalSpan * 0.34, 0]}>
            <cylinderGeometry args={[1.4, 2.2, 5.8, 20, 1, true]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={0.045 * opacityScale} side={THREE.DoubleSide} />
          </mesh>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.18, 0]}>
            <ringGeometry args={[2.4, 4.2, 56]} />
            <meshBasicMaterial color={district.colorHex} transparent opacity={0.08 * opacityScale} />
          </mesh>
        </group>
      );
    case "receipts":
      return (
        <group>
          {[-0.8, 0, 0.8].map((x, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              position={[x, 1.2 + index * 0.38, 0]}
              rotation={[0.08, 0.16 * (index - 1), 0]}
            >
              <planeGeometry args={[1.6, 2.8]} />
              <meshBasicMaterial color={district.colorHex} transparent opacity={(0.04 - index * 0.008) * opacityScale} side={THREE.DoubleSide} />
            </mesh>
          ))}
        </group>
      );
    case "case-notes":
      return (
        <group>
          {[0.1, 0.7, 1.35].map((y, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              rotation={[-Math.PI / 2, 0, 0]}
              position={[0.2 * index, y, -0.16 * index]}
            >
              <ringGeometry args={[1.2 + index * 0.4, 2 + index * 0.42, 44]} />
              <meshBasicMaterial color={district.colorHex} transparent opacity={(0.07 - index * 0.014) * opacityScale} />
            </mesh>
          ))}
        </group>
      );
    default:
      return null;
  }
}

function DistrictArrivalBackdrop({
  district,
  focusStrength,
}: {
  district: ObservatoryDistrictRecipe;
  focusStrength: number;
}) {
  if (focusStrength <= 0.2) {
    return null;
  }
  const direction = new THREE.Vector3(district.position[0], 0, district.position[2]).normalize();
  const yaw = Math.atan2(-direction.x, -direction.z);
  const offsetX = -direction.x * 2;
  const offsetZ = -direction.z * 2;
  const baseOpacity = 0.04 + focusStrength * 0.12;
  switch (district.id) {
    case "signal":
      return (
        <group rotation={[0, yaw, 0]} position={[offsetX, district.verticalSpan * 0.62, offsetZ - 0.1]}>
          <mesh position={[0, 0.6, 0]}>
            <coneGeometry args={[4.2, 7.6, 22, 1, true]} />
            <meshBasicMaterial color="#78cfff" transparent opacity={baseOpacity * 0.76} side={THREE.DoubleSide} />
          </mesh>
          <mesh position={[0, 1.4, -0.8]}>
            <planeGeometry args={[5.6, 6.4]} />
            <meshBasicMaterial color="#d7f3ff" transparent opacity={baseOpacity * 0.64} side={THREE.DoubleSide} />
          </mesh>
        </group>
      );
    case "run":
      return (
        <group rotation={[0, yaw, 0]} position={[offsetX, district.verticalSpan * 0.56, offsetZ]}>
          <mesh position={[0, 0.8, 0.1]}>
            <boxGeometry args={[6.2, 5.8, 0.2]} />
            <meshBasicMaterial color="#f4d982" transparent opacity={baseOpacity * 0.38} side={THREE.DoubleSide} />
          </mesh>
          <mesh position={[0, 1.5, -0.2]}>
            <planeGeometry args={[4.8, 4.8]} />
            <meshBasicMaterial color="#fff1bf" transparent opacity={baseOpacity * 0.7} side={THREE.DoubleSide} />
          </mesh>
        </group>
      );
    case "receipts":
      return (
        <group rotation={[0, yaw, 0]} position={[offsetX, district.verticalSpan * 0.56, offsetZ]}>
          {[-1.1, 0, 1.1].map((x, index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              position={[x, 1 + index * 0.3, -0.4 * index]}
              rotation={[0.08, 0.18 * (index - 1), 0]}
            >
              <planeGeometry args={[1.8, 5.6]} />
              <meshBasicMaterial color={index === 1 ? "#dffcff" : "#88eaff"} transparent opacity={baseOpacity * (0.44 - index * 0.08)} side={THREE.DoubleSide} />
            </mesh>
          ))}
        </group>
      );
    case "case-notes":
      return (
        <group rotation={[0, yaw, 0]} position={[offsetX, district.verticalSpan * 0.58, offsetZ]}>
          {[0, 1, 2].map((index) => (
            <mesh
              // eslint-disable-next-line react/no-array-index-key
              key={index}
              rotation={[-Math.PI / 2, 0, 0]}
              position={[0, 0.3 + index * 0.66, -0.2 * index]}
            >
              <ringGeometry args={[1.6 + index * 0.55, 2.5 + index * 0.58, 44]} />
              <meshBasicMaterial color={index === 1 ? "#ffe1b5" : "#f0b87b"} transparent opacity={baseOpacity * (0.62 - index * 0.12)} />
            </mesh>
          ))}
        </group>
      );
    default:
      return (
        <group rotation={[0, yaw, 0]} position={[offsetX, district.verticalSpan * 0.54, offsetZ]}>
          <mesh position={[0, 0.5, 0]}>
            <planeGeometry args={[6.8, 5.8]} />
            <meshBasicMaterial
              color={district.colorHex}
              transparent
              opacity={baseOpacity}
              side={THREE.DoubleSide}
            />
          </mesh>
          <mesh position={[0, 1.2, -0.1]}>
            <planeGeometry args={[4.2, 4.8]} />
            <meshBasicMaterial
              color="#dfeeff"
              transparent
              opacity={0.03 + focusStrength * 0.08}
              side={THREE.DoubleSide}
            />
          </mesh>
        </group>
      );
  }
}

function DistrictArrivalLights({
  district,
  focusStrength,
}: {
  district: ObservatoryDistrictRecipe;
  focusStrength: number;
}) {
  if (focusStrength <= 0.2) {
    return null;
  }
  const accentColor =
    district.id === "signal"
      ? "#82d8ff"
      : district.id === "run"
        ? "#ffd879"
        : district.id === "receipts"
          ? "#9af5ff"
          : district.id === "case-notes"
            ? "#ffc38c"
            : district.colorHex;
  const fillColor =
    district.id === "signal"
      ? "#e4f7ff"
      : district.id === "run"
        ? "#fff3cf"
        : district.id === "receipts"
          ? "#ecffff"
          : district.id === "case-notes"
            ? "#fff0df"
            : "#eef7ff";
  const lifecycleIntensity =
    district.lifecycleState === "critical"
      ? 1.42
      : district.lifecycleState === "saturated"
        ? 1.22
        : district.lifecycleState === "active"
          ? 1.02
          : district.lifecycleState === "waking"
            ? 0.84
            : 0.62;
  const keyHeight =
    district.id === "signal" ? district.verticalSpan * 1.05 : district.id === "run" ? district.verticalSpan * 0.78 : district.verticalSpan * 0.88;
  const fillPosition: [number, number, number] =
    district.id === "signal"
      ? [-2.2, district.verticalSpan * 0.68, 1.8]
      : district.id === "run"
        ? [2.6, district.verticalSpan * 0.58, 1.6]
        : district.id === "receipts"
          ? [-1.2, district.verticalSpan * 0.72, 2.5]
          : district.id === "case-notes"
            ? [1.1, district.verticalSpan * 0.78, 2.1]
            : [1.8, district.verticalSpan * 0.72, 2.4];
  return (
    <>
      <pointLight
        color={accentColor}
        decay={2}
        distance={11 + district.verticalSpan * 0.8}
        intensity={(0.9 + focusStrength * 1.8) * lifecycleIntensity}
        position={[0, keyHeight, 0]}
      />
      <pointLight
        color={fillColor}
        decay={2}
        distance={9 + district.verticalSpan * 0.6}
        intensity={(0.34 + focusStrength * 0.86) * lifecycleIntensity}
        position={fillPosition}
      />
    </>
  );
}

export function StationDistrict({
  district,
  interactionState,
  eruptionStrength,
  modeProfile,
  missionTarget = false,
  onSelect,
  onHover,
}: {
  district: ObservatoryDistrictRecipe;
  interactionState: "idle" | "hover" | "active";
  eruptionStrength: number;
  modeProfile: DerivedObservatoryWorld["modeProfile"];
  missionTarget?: boolean;
  onSelect?: (stationId: HuntStationId) => void;
  onHover?: (stationId: HuntStationId | null) => void;
}) {
  const color = useMemo(() => new THREE.Color(district.colorHex), [district.colorHex]);
  const ringRef = useRef<THREE.Mesh | null>(null);
  const groupRef = useRef<THREE.Group | null>(null);
  const atlasMode = modeProfile.label === "ATLAS";
  const focusStrength =
    district.active
      ? 1
      : district.probeReaction
        ? 0.96
        : missionTarget
          ? 0.9
          : district.likely
            ? 0.82
            : interactionState === "hover"
              ? 0.64
              : 0.16;
  const lifecycleQuietScale =
    district.lifecycleState === "critical"
      ? 1.16
      : district.lifecycleState === "saturated"
        ? 1.04
        : district.lifecycleState === "active"
          ? 0.92
          : district.lifecycleState === "waking"
            ? 0.66
            : 0.42;
  const quietScale =
    district.active || district.likely || district.probeReaction !== null || interactionState === "hover"
      ? 1
      : atlasMode
        ? lifecycleQuietScale * 0.46
        : lifecycleQuietScale * 0.4;
  const showExpandedDistrict =
    district.active
    || district.probeReaction !== null
    || missionTarget
    || district.likely
    || interactionState === "hover"
    || district.lifecycleState === "critical"
    || district.lifecycleState === "saturated"
    || (atlasMode && district.emphasis > 0.58);
  const showOccupancy = !atlasMode && showExpandedDistrict && (district.artifactCount > 0 || district.lifecycleState !== "dormant");
  const showGrowthStructures = showExpandedDistrict || (atlasMode && district.lifecycleProgress > 0.34);
  const showGrowthAnchors = showExpandedDistrict;
  const showTimeStrata = !atlasMode && showExpandedDistrict && (district.artifactCount > 1 || district.lifecycleState === "saturated" || district.lifecycleState === "critical");
  const showSilhouette = atlasMode || showExpandedDistrict || district.lifecycleState === "critical";
  const showCrew = (!atlasMode || district.active || district.likely || district.probeReaction !== null || district.lifecycleState === "saturated") && district.crew.length > 0;

  useFrame(({ clock }) => {
    if (ringRef.current) {
      ringRef.current.rotation.z += district.pulseSpeed;
      const pulse =
        1 +
        Math.sin(clock.elapsedTime * (district.likely ? 2.1 : 1.2)) *
          (district.active ? district.pulseAmplitude : Math.min(0.03, district.pulseAmplitude));
      ringRef.current.scale.set(pulse, pulse, pulse);
    }
    if (groupRef.current) {
      groupRef.current.position.y =
        district.position[1] + Math.sin(clock.elapsedTime * 0.8 + district.position[0]) * district.floatAmplitude;
    }
  });
  return (
    <group
      ref={groupRef}
      position={district.position}
      onClick={(event: ThreeEvent<MouseEvent>) => {
        event.stopPropagation();
        onSelect?.(district.id);
      }}
      onPointerEnter={() => onHover?.(district.id)}
      onPointerLeave={() => onHover?.(null)}
    >
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.54, 0]}>
        <circleGeometry args={[district.baseDiscRadius, 56]} />
        <meshBasicMaterial
          color={color}
          transparent
          opacity={district.baseDiscOpacity * (district.active ? 1.4 : missionTarget ? 1.28 : district.likely ? 1.18 : quietScale)}
        />
      </mesh>
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.56, 0]}>
        <ringGeometry args={[district.outerRingInnerRadius, district.outerRingOuterRadius, 72]} />
        <meshBasicMaterial
          color={color}
          transparent
          opacity={district.outerRingOpacity * (district.active ? 1.5 : missionTarget ? 1.26 : district.likely ? 1.18 : quietScale)}
        />
      </mesh>
      <DistrictArrivalBackdrop district={district} focusStrength={focusStrength} />
      <DistrictArrivalLights district={district} focusStrength={focusStrength} />
      <DistrictLifecycleAura district={district} focusStrength={focusStrength} />
      <DistrictProbeReaction district={district} />
      <DistrictMasterplan
        district={district}
        focusStrength={focusStrength}
        modeOpacityScale={
          modeProfile.layoutOpacityScale *
          (district.active
            ? 1.44
            : district.probeReaction
              ? 1.3
            : district.likely
              ? 1.24
              : interactionState === "hover"
                ? 1.02
                : quietScale)
        }
      />
      <mesh ref={ringRef} rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.48, 0]}>
        <torusGeometry args={[district.torusRadius, district.torusTubeRadius, 18, 64]} />
        <meshBasicMaterial
          color={color}
          transparent
          opacity={district.torusOpacity * (district.active ? 1.3 : district.likely ? 1.12 : quietScale)}
        />
      </mesh>
      {showTimeStrata ? <DistrictTimeStrata district={district} /> : null}
      {showSilhouette ? (
        <DistrictSilhouette
          silhouette={district.silhouette}
          colorHex={district.colorHex}
          emphasis={
            atlasMode
              ? district.emphasis * (district.active ? 1.9 : district.likely ? 1.48 : 0.42)
              : district.emphasis * (district.active ? 1.34 : district.likely ? 1.1 : 0.36)
          }
        />
      ) : null}
      {showOccupancy ? <DistrictOccupancy district={district} /> : null}
      {showGrowthStructures ? <DormantInfrastructure district={district} color={color} /> : null}
      <StationGlyph stationId={district.id} color={color} emphasis={district.emphasis} />
      <DistrictMicroInteraction district={district} interactionState={interactionState} />
      {showGrowthAnchors
        ? district.growthAnchors.map((anchor, index) => (
        <group
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          position={anchor.position}
        >
          <mesh rotation={[-Math.PI / 2, 0, 0]}>
            <ringGeometry args={[anchor.ringInnerRadius, anchor.ringOuterRadius, 32]} />
            <meshBasicMaterial color={color} transparent opacity={anchor.opacity} />
          </mesh>
          <mesh position={[0, 0.12, 0]}>
            <sphereGeometry args={[anchor.nodeRadius, 12, 12]} />
            <meshBasicMaterial color={color} transparent opacity={Math.min(0.62, anchor.opacity + 0.06)} />
          </mesh>
        </group>
          ))
        : null}
      {eruptionStrength > 0 ? (
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.18, 0]}>
          <ringGeometry args={[2.1 + eruptionStrength * 1.1, 2.34 + eruptionStrength * 1.1, 56]} />
          <meshBasicMaterial color={district.colorHex} transparent opacity={0.14 + eruptionStrength * 0.18} />
        </mesh>
      ) : null}
      {showCrew ? district.crew.map((crew) => (
        <DistrictCrewPopulation
          key={crew.key}
          crew={crew}
          modeOpacityScale={
            modeProfile.populationOpacityScale *
            (district.active || district.likely || district.probeReaction !== null
              ? 1.46
              : interactionState === "hover"
                ? 1.08
                : 0.52)
          }
        />
      )) : null}
    </group>
  );
}

export const MemoizedStationDistrict = memo(StationDistrict);

export function HypothesisScaffold({
  scaffold,
}: {
  scaffold: ObservatoryHypothesisScaffoldRecipe;
}) {
  const stageOpacityBias =
    scaffold.stage === "stabilizing"
      ? 0.12
      : scaffold.stage === "branched"
        ? 0.06
        : scaffold.stage === "weakening"
          ? -0.04
          : 0;
  return (
    <group>
      {scaffold.frameLoops.map((frame, index) => (
        <Line
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          points={frame}
          color={scaffold.colorHex}
          transparent
          opacity={0.12 + scaffold.intensity + stageOpacityBias - index * 0.04}
          lineWidth={1}
        />
      ))}
      {scaffold.conduitPaths.map((path, index) => (
        <Line
          // eslint-disable-next-line react/no-array-index-key
          key={`c-${index}`}
          points={path}
          color={scaffold.colorHex}
          transparent
          opacity={0.08 + scaffold.intensity * 0.52}
          lineWidth={1}
        />
      ))}
      {scaffold.branchPaths.map((path, index) => (
        <Line
          // eslint-disable-next-line react/no-array-index-key
          key={`b-${index}`}
          points={path}
          color={scaffold.colorHex}
          transparent
          opacity={0.05 + scaffold.intensity * 0.34}
          lineWidth={1}
        />
      ))}
      {scaffold.nodes.map((node, index) => (
        <group
          // eslint-disable-next-line react/no-array-index-key
          key={`n-${index}`}
          position={node.position}
        >
          <mesh>
            <sphereGeometry args={[node.radius, 14, 14]} />
            <meshBasicMaterial color={scaffold.colorHex} transparent opacity={node.opacity} />
          </mesh>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.18, 0]}>
            <ringGeometry args={[node.radius * 1.25, node.radius * 1.7, 18]} />
            <meshBasicMaterial color={scaffold.colorHex} transparent opacity={node.opacity * 0.52} />
          </mesh>
        </group>
      ))}
      {scaffold.panels.map((panel, index) => (
        <group
          // eslint-disable-next-line react/no-array-index-key
          key={`p-${index}`}
          position={panel.position}
          rotation={panel.rotation}
        >
          <mesh scale={panel.scale}>
            <planeGeometry args={[1.2, 1]} />
            <meshBasicMaterial color={scaffold.colorHex} transparent opacity={panel.opacity} side={THREE.DoubleSide} />
          </mesh>
        </group>
      ))}
      {scaffold.lockPositions.map((position, index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={`l-${index}`}
          rotation={[-Math.PI / 2, 0, 0]}
          position={position}
        >
          <ringGeometry args={[0.28 + index * 0.04, 0.36 + index * 0.04, 22]} />
          <meshBasicMaterial color={scaffold.colorHex} transparent opacity={0.16 + scaffold.intensity * 0.16} />
        </mesh>
      ))}
    </group>
  );
}

export function WatchfieldPerimeter({
  watchfield,
  eruptionStrength,
  raisedPosture,
  onSelect,
  onHover,
}: {
  watchfield: ObservatoryWatchfieldRecipe;
  eruptionStrength: number;
  raisedPosture: boolean;
  onSelect?: (stationId: HuntStationId) => void;
  onHover?: (stationId: HuntStationId | null) => void;
}) {
  const color = useMemo(() => new THREE.Color(watchfield.colorHex), [watchfield.colorHex]);
  const beaconRef = useRef<THREE.Mesh | null>(null);

  useFrame(({ clock }) => {
    if (!beaconRef.current) return;
    const pulse = 1 + Math.sin(clock.elapsedTime * 1.4) * 0.05;
    beaconRef.current.scale.set(pulse, pulse, pulse);
  });

  return (
    <group>
      <Line
        points={watchfield.ringPoints}
        color={watchfield.colorHex}
        transparent
        opacity={0.22 + watchfield.emphasis * 0.22 + eruptionStrength * 0.12 + (raisedPosture ? 0.14 : 0)}
        lineWidth={1}
      />
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.04, 0]}>
        <ringGeometry args={[watchfield.perimeterInnerRadius, watchfield.perimeterOuterRadius, 96]} />
        <meshBasicMaterial color={color} transparent opacity={watchfield.perimeterOpacity} />
      </mesh>
      <group
        position={watchfield.position}
        onClick={(event: ThreeEvent<MouseEvent>) => {
          event.stopPropagation();
          onSelect?.("watch");
        }}
        onPointerEnter={() => onHover?.("watch")}
        onPointerLeave={() => onHover?.(null)}
      >
        <mesh ref={beaconRef}>
          <torusGeometry args={[watchfield.beaconRadius, 0.08, 18, 64]} />
          <meshBasicMaterial color={color} transparent opacity={watchfield.beaconOpacity} />
        </mesh>
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.44, 0]}>
          <ringGeometry args={[watchfield.secondaryRingInnerRadius, watchfield.secondaryRingOuterRadius, 56]} />
          <meshBasicMaterial color={color} transparent opacity={watchfield.secondaryRingOpacity} />
        </mesh>
        {raisedPosture ? (
          <>
            <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.28, 0]}>
              <ringGeometry args={[1.72, 2.04, 56]} />
              <meshBasicMaterial color="#fff0be" transparent opacity={0.28 + eruptionStrength * 0.12} />
            </mesh>
            <mesh position={[0, 1.28, 0]} scale={[0.08, 1.84, 0.08]}>
              <boxGeometry args={[1, 1, 1]} />
              <meshBasicMaterial color="#fff0be" transparent opacity={0.16} />
            </mesh>
          </>
        ) : null}
        {eruptionStrength > 0 ? (
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.36, 0]}>
            <ringGeometry args={[1.5 + eruptionStrength * 0.3, 1.74 + eruptionStrength * 0.3, 40]} />
            <meshBasicMaterial color={color} transparent opacity={0.14 + eruptionStrength * 0.14} />
          </mesh>
        ) : null}
      </group>
    </group>
  );
}

export const MemoizedWatchfieldPerimeter = memo(WatchfieldPerimeter);

function ProbeBreadcrumbPath({
  colorHex,
  points,
}: {
  colorHex: string;
  points: [number, number, number][];
}) {
  const markerRefs = useRef<Array<THREE.Mesh | null>>([]);
  const curve = useMemo(
    () => new THREE.CatmullRomCurve3(points.map((point) => new THREE.Vector3(...point))),
    [points],
  );
  const breadcrumbs = useMemo(
    () =>
      Array.from({ length: 4 }, (_, index) =>
        curve.getPointAt((index + 1) / 5),
      ),
    [curve],
  );

  useFrame(({ clock }) => {
    markerRefs.current.forEach((marker, index) => {
      if (!marker) return;
      const pulse = 0.9 + Math.sin(clock.elapsedTime * 3.2 - index * 0.45) * 0.18;
      marker.scale.set(pulse, pulse, pulse);
      const material = marker.material as THREE.MeshBasicMaterial;
      material.opacity = 0.16 + Math.max(0, Math.sin(clock.elapsedTime * 3.2 - index * 0.45)) * 0.22;
    });
  });

  return (
    <group>
      <Line points={points} color={colorHex} transparent opacity={0.18} lineWidth={1.2} />
      {breadcrumbs.map((point, index) => (
        <group
          // eslint-disable-next-line react/no-array-index-key
          key={`probe-breadcrumb-${index}`}
          position={[point.x, point.y, point.z]}
        >
          <mesh
            ref={(element) => {
              markerRefs.current[index] = element;
            }}
            rotation={[-Math.PI / 2, 0, 0]}
          >
            <ringGeometry args={[0.14, 0.22, 22]} />
            <meshBasicMaterial color={colorHex} transparent opacity={0.2} />
          </mesh>
          <mesh position={[0, 0.08, 0]}>
            <sphereGeometry args={[0.05, 10, 10]} />
            <meshBasicMaterial color={colorHex} transparent opacity={0.32} />
          </mesh>
        </group>
      ))}
    </group>
  );
}

export function OperatorProbe({
  world,
  targetStationId,
  activeRoute,
}: {
  world: DerivedObservatoryWorld;
  targetStationId: HuntStationId | null;
  activeRoute: boolean;
}) {
  const groupRef = useRef<THREE.Group | null>(null);
  const beamRef = useRef<THREE.Mesh | null>(null);
  const anchorRef = useRef<THREE.Group | null>(null);
  const currentTargetRef = useRef(new THREE.Vector3(0, 4.2, 0));
  const hoverTargetRef = useRef(new THREE.Vector3());
  const orbitOffsetRef = useRef(new THREE.Vector3());
  const beamTargetRef = useRef(new THREE.Vector3());
  const beamLookAtRef = useRef(new THREE.Vector3());

  const resolvedTarget = useMemo(() => {
    if (targetStationId === "watch") {
      return {
        base: new THREE.Vector3(...world.watchfield.position),
        anchor: new THREE.Vector3(...world.watchfield.position).setY(1.1),
        color: world.watchfield.colorHex,
        district: null,
        guideRoute: null,
      };
    }
    const district = world.districts.find((entry) => entry.id === targetStationId) ?? null;
    if (!district) return null;
    const anchorOffset = district.growthAnchors[0]?.position ?? [0, 0, 0];
    const guideRoute =
      world.transitLinks.find((entry) => entry.stationId === targetStationId)
      ?? world.coreLinks.find((entry) => entry.stationId === targetStationId)
      ?? null;
    return {
      base: new THREE.Vector3(...district.position),
      anchor: new THREE.Vector3(
        district.position[0] + anchorOffset[0],
        1 + anchorOffset[1],
        district.position[2] + anchorOffset[2],
      ),
      color: district.colorHex,
      district,
      guideRoute,
    };
  }, [targetStationId, world.coreLinks, world.districts, world.transitLinks, world.watchfield]);

  useEffect(() => {
    if (!resolvedTarget) return;
    currentTargetRef.current.copy(resolvedTarget.base);
  }, [resolvedTarget]);

  useFrame(({ clock }, delta) => {
    if (!groupRef.current || !beamRef.current || !anchorRef.current || !resolvedTarget) return;
    const orbitAngle = clock.elapsedTime * 0.7;
    const orbitRadius = 1.1;
    const hoverTarget = hoverTargetRef.current
      .copy(resolvedTarget.base)
      .add(
        orbitOffsetRef.current.set(
          Math.cos(orbitAngle) * orbitRadius,
          3.4 + Math.sin(clock.elapsedTime * 1.4) * 0.18,
          Math.sin(orbitAngle) * orbitRadius,
        ),
      );
    currentTargetRef.current.lerp(hoverTarget, lerpAlpha(4.8, delta));
    groupRef.current.position.copy(currentTargetRef.current);
    groupRef.current.lookAt(resolvedTarget.anchor);
    anchorRef.current.position.copy(resolvedTarget.anchor);

    const beamTarget = beamTargetRef.current
      .copy(resolvedTarget.anchor)
      .sub(groupRef.current.position);
    const beamLength = Math.max(0.8, beamTarget.length());
    beamRef.current.position.set(0, -beamLength * 0.5, 0);
    beamRef.current.scale.set(1, beamLength, 1);
    beamRef.current.lookAt(beamLookAtRef.current.set(0, -beamLength, 0));
  });

  if (!resolvedTarget) return null;

  return (
    <>
      <group ref={anchorRef}>
        <mesh>
          <sphereGeometry args={[0.08, 12, 12]} />
          <meshBasicMaterial color={resolvedTarget.color} transparent opacity={0.44} />
        </mesh>
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.12, 0]}>
          <ringGeometry args={[0.18, 0.28, 24]} />
          <meshBasicMaterial color={resolvedTarget.color} transparent opacity={0.24} />
        </mesh>
      </group>
      <group ref={groupRef}>
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.14, 0]}>
          <ringGeometry args={[0.22, 0.34, 24]} />
          <meshBasicMaterial color={resolvedTarget.color} transparent opacity={0.38} />
        </mesh>
        <mesh>
          <sphereGeometry args={[0.16, 16, 16]} />
          <meshStandardMaterial color="#f3f8ff" emissive={resolvedTarget.color} emissiveIntensity={0.74} />
        </mesh>
        <mesh ref={beamRef}>
          <coneGeometry args={[0.18, 1, 16, 1, true]} />
          <meshBasicMaterial color={resolvedTarget.color} transparent opacity={0.16} side={THREE.DoubleSide} />
        </mesh>
      </group>
      {activeRoute && resolvedTarget.guideRoute ? (
        <ProbeBreadcrumbPath colorHex={resolvedTarget.color} points={resolvedTarget.guideRoute.points} />
      ) : null}
      {resolvedTarget.district ? (
        <group position={resolvedTarget.district.position}>
          {activeRoute ? (
            <Line
              points={buildOverlayArc(
                [0, 1.32, 0],
                [
                  resolvedTarget.anchor.x - resolvedTarget.district.position[0],
                  resolvedTarget.anchor.y - resolvedTarget.district.position[1],
                  resolvedTarget.anchor.z - resolvedTarget.district.position[2],
                ],
                1.8,
              )}
              color={resolvedTarget.color}
              transparent
              opacity={0.28}
              lineWidth={1.4}
            />
          ) : null}
          {resolvedTarget.district.growth.conduitPaths.slice(0, 2).map((path, index) => (
            <Line
              // eslint-disable-next-line react/no-array-index-key
              key={`probe-c-${index}`}
              points={path}
              color={resolvedTarget.color}
              transparent
              opacity={0.16 + resolvedTarget.district.occupancyLevel * 0.12}
              lineWidth={1}
            />
          ))}
          {resolvedTarget.district.growth.structures.slice(0, 1).map((structure) => (
            <group key={`probe-spot-${structure.key}`} position={structure.position}>
              <mesh rotation={[-Math.PI / 2, 0, 0]}>
                <ringGeometry args={[0.34, 0.52, 24]} />
                <meshBasicMaterial color={resolvedTarget.color} transparent opacity={0.28} />
              </mesh>
            </group>
          ))}
        </group>
      ) : null}
    </>
  );
}

export function ThesisCore({
  core,
}: {
  core: DerivedObservatoryWorld["core"];
}) {
  const groupRef = useRef<THREE.Group | null>(null);
  const ringRef = useRef<THREE.Mesh | null>(null);
  const accent = useMemo(() => new THREE.Color(core.accentColor), [core.accentColor]);

  useFrame(({ clock }) => {
    if (groupRef.current) {
      groupRef.current.rotation.y += 0.003;
      groupRef.current.position.y = 1.1 + Math.sin(clock.elapsedTime * 0.6) * 0.08;
    }
    if (ringRef.current) {
      ringRef.current.rotation.z += 0.006;
      const pulse = core.receiveState === "receiving" ? 1.14 : core.receiveState === "aftermath" ? 1.05 : 1;
      ringRef.current.scale.set(pulse, pulse, pulse);
    }
  });

  return (
    <group position={[0, 0.72, 0]}>
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.52, 0]}>
        <circleGeometry args={[core.haloRadius, 72]} />
        <meshBasicMaterial color="#74d8ff" transparent opacity={core.haloOpacity} />
      </mesh>
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.54, 0]}>
        <ringGeometry args={[core.outerRingInnerRadius, core.outerRingOuterRadius, 96]} />
        <meshBasicMaterial color="#efe8d5" transparent opacity={core.outerRingOpacity} />
      </mesh>
      <mesh ref={ringRef} rotation={[Math.PI / 2.1, 0, 0]}>
        <torusGeometry args={[core.torusRadius, core.torusTubeRadius, 18, 88]} />
        <meshStandardMaterial
          color="#efe8d5"
          emissive={accent}
          emissiveIntensity={Math.max(1.8, core.torusEmissiveIntensity * 2.5)}
          transparent
          opacity={0.92}
          toneMapped={false}
        />
      </mesh>
      <group ref={groupRef}>
        <mesh position={[0, 0.52, 0]}>
          <icosahedronGeometry args={[core.shellRadius, 0]} />
          <meshStandardMaterial
            color="#ede6c9"
            emissive={accent}
            emissiveIntensity={2.2}
            roughness={0.36}
            metalness={0.18}
            transparent
            opacity={core.shellOpacity}
            toneMapped={false}
          />
        </mesh>
        <mesh position={[0, -0.72, 0]}>
          <cylinderGeometry args={[core.pedestalTopRadius, core.pedestalBottomRadius, core.pedestalHeight, 12]} />
          <meshStandardMaterial color="#c6d4cf" emissive="#7abdf2" emissiveIntensity={0.12} transparent opacity={0.88} />
        </mesh>
      </group>
    </group>
  );
}

function ObservatoryWorldScene({
  world,
  cameraResetToken,
  flyByActive,
  onFlyByComplete,
  eruptionStrengthByStation,
  eruptionStrengthByRouteStation,
  activeHeroInteraction,
  mission,
  missionTargetStationId,
  missionTargetAssetId,
  playerInteractableAssetId,
  probeLockedTargetStationId,
  probeStatus,
  watchfieldRaised,
  onTriggerHeroProp,
  onSelectStation,
  playerFocusRef,
}: {
  world: DerivedObservatoryWorld;
  cameraResetToken: number;
  flyByActive: boolean;
  onFlyByComplete: () => void;
  eruptionStrengthByStation: Partial<Record<HuntStationId, number>>;
  eruptionStrengthByRouteStation: Partial<Record<HuntStationId, number>>;
  activeHeroInteraction: ActiveHeroInteraction | null;
  mission: ObservatoryMissionLoopState | null;
  missionTargetStationId: HuntStationId | null;
  missionTargetAssetId: ObservatoryHeroPropRecipe["assetId"] | null;
  playerInteractableAssetId: ObservatoryHeroPropRecipe["assetId"] | null;
  probeLockedTargetStationId: HuntStationId | null;
  probeStatus: ObservatoryProbeState["status"];
  watchfieldRaised: boolean;
  onTriggerHeroProp?: (prop: ObservatoryHeroPropRecipe, meta: MissionInteractionSource) => void;
  onSelectStation?: (stationId: HuntStationId) => void;
  playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>;
}) {
  const controlsRef = useRef<THREE.EventDispatcher | null>(null);
  const shakeRef = useRef<ShakeController | null>(null);
  // TRN-01/TRN-02: Read speedTier from store — subscription fires only on boost start/end (~rarely)
  const speedTier = useObservatoryStore((s) => s.flightState.speedTier);
  const boostFov = speedTier === "boost";
  const [arrivalCue, setArrivalCue] = useState<DistrictArrivalCue | null>(null);
  const [hoveredStationId, setHoveredStationId] = useState<HuntStationId | null>(null);
  const previousPrimaryStationIdRef = useRef<HuntStationId | null>(null);
  const interactionStationId =
    activeHeroInteraction?.stationId === "core" ? null : activeHeroInteraction?.stationId ?? null;
  const primaryStationId =
    interactionStationId ??
    world.districts.find((district) => district.active)?.id ??
    world.likelyStationId;
  const heroPropByStation = useMemo(
    () =>
      new Map(
        world.heroProps
          .filter((prop) => prop.stationId !== "core")
          .map((prop) => [prop.stationId, prop] as const),
      ),
    [world.heroProps],
  );

  // PFX-02: Probe discharge position — derive from probeLockedTargetStationId's hero prop
  const probeDischargePosition = useMemo((): [number, number, number] => {
    if (!probeLockedTargetStationId) return [0, 0, 0];
    const prop = heroPropByStation.get(probeLockedTargetStationId);
    return prop?.position ?? [0, 0, 0];
  }, [heroPropByStation, probeLockedTargetStationId]);

  const probeTargetStationId =
    (probeStatus === "active"
      ? probeLockedTargetStationId ?? activeHeroInteraction?.targetStationId ?? missionTargetStationId ?? interactionStationId ?? world.likelyStationId
      : null) ??
    hoveredStationId ??
    missionTargetStationId ??
    world.districts.find((district) => district.active)?.id ??
    (world.watchfield.active ? "watch" : null) ??
    world.likelyStationId;

  // CAM-03: Listen for observatory:shake events dispatched by probe/landing triggers
  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent<{ intensity: number }>).detail;
      shakeRef.current?.setIntensity(detail.intensity ?? 0.4);
    };
    window.addEventListener("observatory:shake", handler);
    return () => window.removeEventListener("observatory:shake", handler);
  }, []);

  useEffect(() => {
    setHoveredStationId(null);
  }, [cameraResetToken, flyByActive, interactionStationId, world.likelyStationId, world.watchfield.active]);

  useEffect(() => {
    if (!primaryStationId || !HERO_CHOREOGRAPHY_STATIONS.has(primaryStationId)) {
      previousPrimaryStationIdRef.current = primaryStationId;
      return;
    }
    if (previousPrimaryStationIdRef.current === primaryStationId) {
      return;
    }
    previousPrimaryStationIdRef.current = primaryStationId;
    const now = getObservatoryNowMs();
    const nextCue: DistrictArrivalCue = {
      expiresAt: now + DISTRICT_ARRIVAL_DURATION_MS,
      startedAt: now,
      stationId: primaryStationId,
      token: now,
    };
    setArrivalCue(nextCue);
    const timer = window.setTimeout(() => {
      setArrivalCue((current) => (current?.token === nextCue.token ? null : current));
    }, DISTRICT_ARRIVAL_DURATION_MS + 40);
    return () => {
      window.clearTimeout(timer);
    };
  }, [primaryStationId]);

  // TRN-05: Update module-level stationProximityRef once per frame from ship position.
  // Reads via getState() — zero React subscriptions, zero re-renders in the 60Hz loop.
  useFrame(() => {
    const pos = useObservatoryStore.getState().flightState.position;
    const [px, py, pz] = pos;
    for (const stationId of Object.keys(stationProximityRef) as HuntStationId[]) {
      const sp = OBSERVATORY_STATION_POSITIONS[stationId];
      const dx = px - sp[0];
      const dy = py - sp[1];
      const dz = pz - sp[2];
      stationProximityRef[stationId] = Math.sqrt(dx * dx + dy * dy + dz * dz);
    }
  });

  return (
    <>
      {/* WLD-01: Dark space background with Stars. HDR skybox available when
          a CC0 .hdr file is placed at public/textures/space-nebula.hdr */}
      <color attach="background" args={["#04080f"]} />
      <Stars
        radius={world.environment.starsRadius}
        depth={world.environment.starsDepth}
        count={world.environment.starsCount}
        factor={world.environment.starsFactor}
        fade
        speed={0.4}
      />
      <fog attach="fog" args={[world.environment.fogColor, world.environment.fogNear, world.environment.fogFar]} />
      <ambientLight intensity={world.environment.ambientIntensity} color={world.environment.ambientColor} />
      <hemisphereLight args={["#b7d4ff", "#02050b", 0.18]} />
      <directionalLight
        position={world.environment.directionalLightPosition}
        intensity={world.environment.directionalLightIntensity}
        color={world.environment.directionalLightColor}
      />
      <directionalLight
        position={[-16, 13, -12]}
        intensity={0.58}
        color="#5ec3ff"
      />
      <pointLight
        position={world.environment.pointLightPosition}
        intensity={world.environment.pointLightIntensity}
        color={world.environment.pointLightColor}
      />
      <PlayerAccentLights playerFocusRef={playerFocusRef} />

      <OrbitControls
        ref={controlsRef as never}
        makeDefault
        enableRotate={false}
        enablePan={false}
        enableZoom
        enableDamping
        dampingFactor={world.camera.dampingFactor}
        minDistance={world.camera.minDistance}
        maxDistance={world.camera.maxDistance}
      />
      <WorldCameraRig
        camera={world.camera}
        controlsRef={controlsRef}
        flyByActive={flyByActive}
        onFlyByComplete={onFlyByComplete}
        playerFocusRef={playerFocusRef}
        resetToken={cameraResetToken}
      />
      <FovController playerFocusRef={playerFocusRef} probeActive={probeStatus === "active"} boostActive={boostFov} />
      <CameraShake
        ref={shakeRef}
        intensity={0}
        decay
        decayRate={0.85}
        maxYaw={0.018}
        maxPitch={0.012}
        maxRoll={0.008}
        yawFrequency={0.6}
        pitchFrequency={0.5}
        rollFrequency={0.4}
      />

      <ThesisCore core={world.core} />
      <OperatorProbe
        activeRoute={probeStatus === "active"}
        world={world}
        targetStationId={probeTargetStationId}
      />
      <HeroConsequenceLayer interaction={activeHeroInteraction} mission={mission} world={world} />

      {world.coreLinks.map((entry) => (
        <Line
          key={entry.key}
          points={entry.points}
          color={entry.colorHex}
          transparent
          opacity={entry.opacity}
          lineWidth={1}
        />
      ))}
      {world.hypothesisScaffolds.map((scaffold) => (
        <HypothesisScaffold key={scaffold.key} scaffold={scaffold} />
      ))}
      {world.transitLinks.map((route) => (
        <TransitRoute
          key={route.key}
          modeOpacityScale={world.modeProfile.routeOpacityScale}
          missionTarget={missionTargetStationId === route.stationId}
          route={route}
          eruptionStrength={(eruptionStrengthByRouteStation[route.stationId] ?? 0) + (interactionStationId === route.stationId ? 0.28 : 0)}
        />
      ))}
      {world.heroProps.map((prop) => (
        <ObservatoryHeroProp
          key={prop.key}
          active={activeHeroInteraction?.assetId === prop.assetId}
          interactable={playerInteractableAssetId === prop.assetId}
          missionTarget={missionTargetAssetId === prop.assetId}
          presenceScale={
            prop.stationId === "core"
              ? primaryStationId
                ? 0.52
                : 1
              : prop.stationId === primaryStationId
                ? 1.34
                : prop.stationId === world.likelyStationId
                  ? 0.58
                  : 0.28
          }
          onTrigger={onTriggerHeroProp}
          prop={prop}
        />
      ))}
      {/* PFX-02: Probe energy discharge shell */}
      <ProbeDischargeVFX
        position={probeDischargePosition}
        probeStatus={probeStatus}
        color={world.core.accentColor}
      />
      {world.districts.map((district) => (
        <DistrictHeroChoreography
          key={`arrival:${district.id}`}
          cue={arrivalCue}
          district={district}
          heroProp={heroPropByStation.get(district.id) ?? null}
        />
      ))}

      {world.districts.map((district) => (
        <MemoizedStationDistrict
          key={district.id}
          district={district}
          interactionState={
            interactionStationId === district.id
              ? "active"
              : hoveredStationId === district.id
              ? "hover"
              : district.active
                ? "active"
                : "idle"
          }
          eruptionStrength={(eruptionStrengthByStation[district.id] ?? 0) + (interactionStationId === district.id ? 0.22 : 0)}
          missionTarget={missionTargetStationId === district.id}
          modeProfile={world.modeProfile}
          onSelect={onSelectStation}
          onHover={setHoveredStationId}
        />
      ))}

      <MemoizedWatchfieldPerimeter
        watchfield={world.watchfield}
        eruptionStrength={eruptionStrengthByStation.watch ?? 0}
        raisedPosture={watchfieldRaised}
        onSelect={onSelectStation}
        onHover={setHoveredStationId}
      />

      {/* UIP-01: 3D waypoint beacons on mission objective stations */}
      {missionTargetStationId && world.districts
        .filter((d) => d.id === missionTargetStationId)
        .map((d) => (
          <MissionObjectiveBeacon
            key={`beacon:${d.id}`}
            position={d.position}
            label={d.label}
          />
        ))}

      {/* NPC-01/02/03: Instanced capsule crew, patrol loops, proximity wave */}
      {/* TRN-05: proximityFade — StationNpcCrewFade wraps StationNpcCrew with per-frame detailFade */}
      {world.districts.map((district) => (
        <StationNpcCrewFade
          key={`npc:${district.id}`}
          stationId={district.id}
          stationWorldPos={district.position as [number, number, number]}
          colorHex={district.colorHex}
        />
      ))}

      {/* STN-01: Floating space station geometry */}
      {world.districts.map((district) => (
        <SpaceStationMesh
          key={`station-mesh:${district.id}`}
          position={district.position as [number, number, number]}
          colorHex={district.colorHex}
          seed={createSpaceStationSeed(district.position[0], district.position[2])}
        />
      ))}

      {/* TRN-02: Warp speed lines — 40 instanced streaks during boost */}
      <WarpSpeedLines active={speedTier === "boost"} />
    </>
  );
}

export function ObservatoryWorldCanvas({
  mode,
  sceneState,
  mission,
  probeState,
  activeStationId,
  ghostPresentation = "off",
  ghostTraces = [],
  spirit = null,
  weatherState = null,
  cameraResetToken = 0,
  onSelectStation,
  onProbeStateChange,
  onMissionObjectiveComplete,
  className,
  frameloop,
  playerInputEnabled = false,
  replayFrameIndex = null,
  flyByActive = false,
  onFlyByComplete,
  probeGuidance = null,
}: ObservatoryWorldCanvasProps) {
  const [eruptions, setEruptions] = useState<WorldEruption[]>([]);
  const [activeHeroInteraction, setActiveHeroInteraction] = useState<ActiveHeroInteraction | null>(null);
  const [watchfieldRaised, setWatchfieldRaised] = useState(false);
  const [playerWorldState, setPlayerWorldState] = useState<ObservatoryPlayerWorldState>({
    interactableAssetId: null,
    stationId: null,
  });
  const [adaptiveQuality, setAdaptiveQuality] = useState<ObservatoryRuntimeQuality>("high");
  const [runtimeActivityHigh, setRuntimeActivityHigh] = useState(false);
  // TRN-04: Bloom spike state — null = default threshold (0.85), number = override during boost
  // Drives a 0.85 → 0.5 → 0.85 luminanceThreshold spike: 0.8s hold at 0.5, then 0.5s ease back.
  const [bloomLuminanceOverride, setBloomLuminanceOverride] = useState<number | null>(null);
  const bloomSpikeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const bloomEaseTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // TRN-01/TRN-04: Subscribe to speedTier in outer component for bloom spike effect.
  // (Inner scene subscribes separately for FOV/WarpSpeedLines.)
  const speedTierOuter = useObservatoryStore((s) => s.flightState.speedTier);
  // GHO-03: Read analyst preset for ghost marker opacity gating
  const analystPresetIdOuter = useObservatoryStore((s) => s.analystPresetId);
  // GHO-03: full opacity when GHOST preset active, 20% when any other preset or none
  const ghostOpacityScale = analystPresetIdOuter === "ghost" ? 1.0 : 0.2;
  const constellations = useObservatoryStore((state) => state.constellations);
  const annotationPins = useObservatoryStore((state) => state.annotationPins);
  const replayState = useObservatoryStore((state) => state.replay);
  const interiorState = useObservatoryStore.use.interiorState();
  const spiritMoodFromStore = useSpiritStore.use.mood();
  const spiritKindFromStore = useSpiritStore.use.kind();
  const spiritLevel = useSpiritEvolutionStore(
    (state) => spiritKindFromStore ? (state.evolution[spiritKindFromStore]?.level ?? 1) : 1,
  );
  const spiritMood = spiritKindFromStore ? spiritMoodFromStore : null;
  const handleAnnotationDrop = useCallback((worldPosition: [number, number, number]) => {
    const state = useObservatoryStore.getState();
    const replay = state.replay;
    const pin: ObservatoryAnnotationPin = {
      id: `anno-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      frameIndex: replay.frameIndex,
      timestampMs: replay.frameMs ?? Date.now(),
      worldPosition,
      note: "",
      districtId: state.likelyStationId ?? ("signal" as HuntStationId),
    };
    state.actions.addAnnotationPin(pin);
  }, []);
  useEffect(() => {
    if (speedTierOuter === "boost") {
      // Boost activated: drop bloom threshold immediately
      setBloomLuminanceOverride(0.5);
      // After 0.8s hold, start easing back — we approximate by discrete steps using rAF budget
      // (single setState is acceptable here — fires only on boost start, ~once per 6s)
      if (bloomSpikeTimerRef.current !== null) {
        clearTimeout(bloomSpikeTimerRef.current);
      }
      if (bloomEaseTimerRef.current !== null) {
        clearTimeout(bloomEaseTimerRef.current);
      }
      bloomSpikeTimerRef.current = setTimeout(() => {
        // Start ease back at 0.8s: ease from 0.5 → 0.85 over 0.5s.
        // We approximate with a mid-point at 0.25s then full restore at 0.5s.
        setBloomLuminanceOverride(0.5 + 0.35 * 0.5); // ~0.675 at midpoint
        bloomEaseTimerRef.current = setTimeout(() => {
          setBloomLuminanceOverride(null); // restore to default 0.85
        }, 250);
      }, 800);
    }
    return () => {
      // Do not clear on boost end — let the ease complete naturally
    };
  }, [speedTierOuter]);
  const now = useObservatoryNow(
    activeHeroInteraction !== null || probeState.status !== "ready" || eruptions.length > 0,
  );
  const playerFocusRef = useRef<ObservatoryPlayerFocusState | null>(null);
  const previousWorldRef = useRef<{
    stationArtifactCounts: Partial<Record<HuntStationId, number>>;
    stationStatus: Partial<Record<HuntStationId, boolean>>;
    scaffoldStages: Record<string, ObservatoryHypothesisScaffoldRecipe["stage"]>;
    receiveState: DerivedObservatoryWorld["receiveState"];
  } | null>(null);
  useEffect(() => {
    if (!activeHeroInteraction || now < activeHeroInteraction.expiresAt) {
      return;
    }
    setActiveHeroInteraction((current) =>
      current?.expiresAt === activeHeroInteraction.expiresAt ? null : current,
    );
  }, [activeHeroInteraction, now]);
  useEffect(() => {
    setActiveHeroInteraction(null);
    setPlayerWorldState({ interactableAssetId: null, stationId: null });
  }, [sceneState?.huntId]);
  useEffect(() => {
    setWatchfieldRaised(mission?.progress.watchfieldRaised ?? false);
  }, [mission?.progress.watchfieldRaised]);
  const world = useMemo(
    () => deriveObservatoryWorld({ mode, sceneState, activeStationId, spirit }),
    [activeStationId, mode, sceneState, spirit],
  );
  const currentMissionObjective = useMemo(
    () => getCurrentObservatoryMissionObjective(mission),
    [mission],
  );
  const missionProbeTargetStationId = useMemo(
    () =>
      resolveObservatoryMissionProbeTargetStationId(mission, {
        activeStationId,
        likelyStationId: world.likelyStationId,
      }),
    [activeStationId, mission, world.likelyStationId],
  );
  const operatorDroneProp = useMemo(
    () => world.heroProps.find((entry) => entry.assetId === "operator-drone") ?? null,
    [world.heroProps],
  );
  // PP-03: Resolve world position of active hero prop for Autofocus DOF
  const activeHeroPropPosition = useMemo((): [number, number, number] | null => {
    if (!activeHeroInteraction) return null;
    const prop = world.heroProps.find((p) => p.assetId === activeHeroInteraction.assetId);
    return prop?.position ?? null;
  }, [activeHeroInteraction, world.heroProps]);
  // PP-04: Build LUT texture for current spirit kind.
  // spirit.kind is the observatory visual kind (tracker/lantern/ledger/forge/loom).
  // Reverse-map to SpiritKind, then build the 3D LUT texture.
  // Returns null when no spirit is bound or kind is unmapped (identity pass-through).
  const spiritLut = useMemo(() => {
    if (!spirit?.kind) return null;
    const spiritKind = OBSERVATORY_KIND_TO_SPIRIT_KIND[spirit.kind];
    if (!spiritKind) return null;
    return buildSpiritLut(spiritKind);
  }, [spirit?.kind]);
  const performanceProfile = useMemo(() => {
    const navigatorConnection =
      typeof navigator !== "undefined" && "connection" in navigator
        ? (navigator as Navigator & { connection?: { saveData?: boolean } }).connection
        : undefined;
    const prefersReducedMotion =
      typeof window !== "undefined" &&
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    return createObservatoryPerformanceProfile({
      mode,
      flyByActive,
      activeHeroInteraction: activeHeroInteraction !== null,
      playerInputEnabled,
      runtimeQuality: runtimeActivityHigh ? "low" : adaptiveQuality,
      hardwareConcurrency:
        typeof navigator !== "undefined" ? navigator.hardwareConcurrency : null,
      prefersReducedMotion,
      saveData: navigatorConnection?.saveData === true,
      spiritBound: spiritLut !== null,
    });
  }, [activeHeroInteraction, adaptiveQuality, flyByActive, mode, playerInputEnabled, runtimeActivityHigh, spiritLut]);
  const effectiveWeatherState = useMemo(() => {
    if (!weatherState || !performanceProfile.enableWeather) {
      return null;
    }
    const budgetRank = { off: 0, reduced: 1, full: 2 } as const;
    const budget =
      budgetRank[performanceProfile.weatherBudget] < budgetRank[weatherState.budget]
        ? performanceProfile.weatherBudget
        : weatherState.budget;
    if (budget === "off") {
      return null;
    }
    if (budget === weatherState.budget) {
      return weatherState;
    }
    return {
      ...weatherState,
      budget,
      density: Math.min(weatherState.density, 0.06),
      labelOcclusionOpacity: Math.min(weatherState.labelOcclusionOpacity, 0.1),
    };
  }, [performanceProfile.enableWeather, performanceProfile.weatherBudget, weatherState]);
  const heatmapPressureData = useMemo(() => {
    const pressures: HeatmapStationPressure[] = world.districts.map((d) => ({
      stationId: d.id,
      pressure: d.emphasis,
    }));
    return deriveHeatmapDataTexture(pressures, HUNT_STATION_ORDER);
  }, [world.districts]);
  const heatmapVisible = performanceProfile.weatherBudget !== "off";
  const heatmapPresetMultiplier = analystPresetIdOuter === "threat" ? 1.5 : 1.0;
  const flowRuntimeEnabled = performanceProfile.mountFlowSystems;
  useEffect(() => {
    if (flowRuntimeEnabled) {
      return;
    }
    setAdaptiveQuality("high");
    setRuntimeActivityHigh(false);
    playerFocusRef.current = null;
    setPlayerWorldState({ interactableAssetId: null, stationId: null });
  }, [flowRuntimeEnabled]);
  useEffect(() => {
    const nowMs = getObservatoryNowMs();
    const previous = previousWorldRef.current;
    const nextEruptions: WorldEruption[] = [];
    if (previous) {
      world.districts.forEach((district) => {
        const previousCount = previous.stationArtifactCounts[district.id] ?? 0;
        const previousActive = previous.stationStatus[district.id] ?? false;
        if (district.artifactCount > previousCount || (district.active && !previousActive)) {
          const kind = EVENT_KIND_BY_STATION[district.id];
          if (kind) {
            nextEruptions.push({
              key: `${district.id}-${nowMs}`,
              stationId: district.id,
              routeStationId: district.id === "signal" ? "targets" : district.id,
              startedAt: nowMs,
              expiresAt: nowMs + ERUPTION_DURATION_MS,
              kind,
            });
          }
        }
      });
      world.hypothesisScaffolds.forEach((scaffold) => {
        const previousStage = previous.scaffoldStages[scaffold.key];
        if (previousStage && previousStage !== scaffold.stage) {
          nextEruptions.push({
            key: `${scaffold.key}-${nowMs}`,
            stationId: scaffold.primaryStationId,
            routeStationId: scaffold.primaryStationId,
            startedAt: nowMs,
            expiresAt: nowMs + ERUPTION_DURATION_MS,
            kind: scaffold.stage === "weakening" ? "evidence" : "judgment",
          });
        }
      });
      if (world.receiveState === "receiving" && previous.receiveState !== "receiving") {
        const stationId =
          world.districts.find((district) => district.active)?.id ?? world.likelyStationId ?? null;
        if (stationId) {
          nextEruptions.push({
            key: `receive-${stationId}-${nowMs}`,
            stationId,
            routeStationId: stationId,
            startedAt: nowMs,
            expiresAt: nowMs + ERUPTION_DURATION_MS,
            kind: EVENT_KIND_BY_STATION[stationId] ?? "signal",
          });
        }
      }
    }
    if (nextEruptions.length > 0) {
      setEruptions((current) =>
        [...current.filter((entry) => entry.expiresAt > nowMs), ...nextEruptions].slice(-8),
      );
    } else {
      setEruptions((current) => current.filter((entry) => entry.expiresAt > nowMs));
    }
    previousWorldRef.current = {
      stationArtifactCounts: Object.fromEntries(
        world.districts.map((district) => [district.id, district.artifactCount]),
      ) as Partial<Record<HuntStationId, number>>,
      stationStatus: Object.fromEntries(
        world.districts.map((district) => [district.id, district.active]),
      ) as Partial<Record<HuntStationId, boolean>>,
      scaffoldStages: Object.fromEntries(
        world.hypothesisScaffolds.map((scaffold) => [scaffold.key, scaffold.stage]),
      ),
      receiveState: world.receiveState,
    };
  }, [world]);
  useEffect(() => {
    setEruptions((current) => {
      if (!current.some((entry) => entry.expiresAt <= now)) {
        return current;
      }
      return current.filter((entry) => entry.expiresAt > now);
    });
  }, [now]);
  const hasActiveEruptions = useMemo(
    () => eruptions.some((entry) => entry.expiresAt > now),
    [eruptions, now],
  );
  const resolvedProbeState = useMemo(
    () => advanceObservatoryProbeState(probeState, now),
    [now, probeState],
  );
  const { effectiveFrameloop, realtimeActivitySources } = useObservatoryWorldLifecycle({
    activeHeroInteraction: activeHeroInteraction !== null,
    cameraResetToken,
    eruptionCount: eruptions.length,
    flyByActive,
    missionTargetStationId: currentMissionObjective?.stationId ?? null,
    playerInputEnabled,
    probeStatus: resolvedProbeState.status,
    replayFrameIndex,
    replayScrubbing: false,
    routeSignature: [
      activeStationId ?? "none",
      cameraResetToken,
      currentMissionObjective?.stationId ?? "none",
      replayFrameIndex ?? "noreplay",
      world.likelyStationId ?? "none",
    ].join("|"),
    selectedStationId: activeStationId ?? null,
    shouldInvalidateOnRouteChange: cameraResetToken > 0,
  });
  const canvasFrameloop = frameloop === "always" ? "always" : effectiveFrameloop;
  const canDispatchProbe = useMemo(
    () => canDispatchObservatoryProbe(resolvedProbeState, now),
    [resolvedProbeState, now],
  );
  const probeCharge = useMemo(
    () => getObservatoryProbeCharge(resolvedProbeState, now),
    [resolvedProbeState, now],
  );
  const probeCountdownMs = useMemo(
    () => getObservatoryProbeRemainingMs(resolvedProbeState, now),
    [resolvedProbeState, now],
  );
  const probeConsequences = useMemo(
    () => applyObservatoryProbeConsequences(world, resolvedProbeState, mission),
    [mission, resolvedProbeState, world],
  );
  const reactiveWorld = probeConsequences.world;
  const probeDirective = probeConsequences.directive;
  const eruptionStrengthByStation = useMemo(() => {
    const entries = eruptions.filter((entry) => entry.expiresAt > now);
    return entries.reduce<Partial<Record<HuntStationId, number>>>((acc, entry) => {
      const progress = 1 - (entry.expiresAt - now) / ERUPTION_DURATION_MS;
      const strength = Math.max(0, Math.sin(progress * Math.PI) * 0.92);
      acc[entry.stationId] = Math.max(acc[entry.stationId] ?? 0, strength);
      return acc;
    }, {});
  }, [eruptions, now]);
  const eruptionStrengthByRouteStation = useMemo(() => {
    const entries = eruptions.filter((entry) => entry.expiresAt > now);
    return entries.reduce<Partial<Record<HuntStationId, number>>>((acc, entry) => {
      if (!entry.routeStationId) return acc;
      const progress = 1 - (entry.expiresAt - now) / ERUPTION_DURATION_MS;
      const strength = Math.max(0, Math.sin(progress * Math.PI) * 0.78);
      acc[entry.routeStationId] = Math.max(acc[entry.routeStationId] ?? 0, strength);
      return acc;
    }, {});
  }, [eruptions, now]);
  const triggerHeroProp = useCallback(
    (
      prop: ObservatoryHeroPropRecipe,
      meta: MissionInteractionSource = { source: "click" },
    ) => {
      const nowMs = getObservatoryNowMs();
      let nextSelectionStationId: HuntStationId | null =
        prop.stationId === "core" ? null : prop.stationId;
      const durations: Partial<Record<ObservatoryHeroPropRecipe["assetId"], number>> = {
        "signal-dish-tower": 5600,
        "subjects-lattice-anchor": 5400,
        "operations-scan-rig": 6000,
        "evidence-vault-rack": 5600,
        "judgment-dais": 6200,
        "watchfield-sentinel-beacon": 6800,
        "operator-drone": OBSERVATORY_PROBE_ACTIVE_MS,
      };
      const targetStationId =
        prop.assetId === "operator-drone"
          ? resolveObservatoryMissionProbeTargetStationId(mission, {
              activeStationId,
              likelyStationId: world.likelyStationId ?? "signal",
            }) ?? "signal"
          : null;
      if (prop.assetId === "operator-drone") {
        if (!canDispatchObservatoryProbe(probeState, nowMs)) {
          return;
        }
        onProbeStateChange?.((current) => dispatchObservatoryProbe(current, targetStationId, nowMs));
      }
      if (prop.assetId === "operator-drone" && targetStationId) {
        nextSelectionStationId = targetStationId;
      }
      setActiveHeroInteraction({
        assetId: prop.assetId,
        expiresAt: nowMs + (durations[prop.assetId] ?? 6200),
        startedAt: nowMs,
        stationId: prop.stationId,
        targetStationId,
      });
      if (meta.source === "player" && mission && isObservatoryMissionObjectiveProp(mission, prop.assetId)) {
        const nextMission = onMissionObjectiveComplete?.(prop.assetId, nowMs) ?? mission;
        const nextObjective = getCurrentObservatoryMissionObjective(nextMission);
        if (nextObjective) {
          nextSelectionStationId = nextObjective.stationId;
        }
      }
      if (prop.assetId === "watchfield-sentinel-beacon") {
        setWatchfieldRaised((current) => !current);
      }
      const heroEvents: WorldEruption[] = (() => {
        switch (prop.assetId) {
          case "signal-dish-tower":
            return [
              {
                key: `hero-signal-${nowMs}`,
                stationId: "signal",
                routeStationId: "targets",
                startedAt: nowMs,
                expiresAt: nowMs + ERUPTION_DURATION_MS,
                kind: "signal",
              },
            ];
          case "subjects-lattice-anchor":
            return [
              {
                key: `hero-subjects-${nowMs}`,
                stationId: "targets",
                routeStationId: "targets",
                startedAt: nowMs,
                expiresAt: nowMs + ERUPTION_DURATION_MS,
                kind: "signal",
              },
              {
                key: `hero-subjects-run-${nowMs}`,
                stationId: "run",
                routeStationId: "run",
                startedAt: nowMs,
                expiresAt: nowMs + ERUPTION_DURATION_MS,
                kind: "run",
              },
            ];
          case "operations-scan-rig":
            return [
              {
                key: `hero-run-${nowMs}`,
                stationId: "run",
                routeStationId: "run",
                startedAt: nowMs,
                expiresAt: nowMs + ERUPTION_DURATION_MS,
                kind: "run",
              },
              {
                key: `hero-run-evidence-${nowMs}`,
                stationId: "receipts",
                routeStationId: "receipts",
                startedAt: nowMs,
                expiresAt: nowMs + ERUPTION_DURATION_MS,
                kind: "run",
              },
            ];
          case "evidence-vault-rack":
            return [
              {
                key: `hero-evidence-${nowMs}`,
                stationId: "receipts",
                routeStationId: "receipts",
                startedAt: nowMs,
                expiresAt: nowMs + ERUPTION_DURATION_MS,
                kind: "evidence",
              },
            ];
          case "judgment-dais":
            return [
              {
                key: `hero-judgment-${nowMs}`,
                stationId: "case-notes",
                routeStationId: "case-notes",
                startedAt: nowMs,
                expiresAt: nowMs + ERUPTION_DURATION_MS,
                kind: "judgment",
              },
            ];
          case "watchfield-sentinel-beacon":
            return [
              {
                key: `hero-watch-${nowMs}`,
                stationId: "watch",
                routeStationId: "watch",
                startedAt: nowMs,
                expiresAt: nowMs + ERUPTION_DURATION_MS,
                kind: "watch",
              },
            ];
          case "operator-drone":
            return targetStationId
              ? [
                  {
                    key: `hero-drone-${nowMs}`,
                    stationId: targetStationId,
                    routeStationId: targetStationId,
                    startedAt: nowMs,
                    expiresAt: nowMs + ERUPTION_DURATION_MS,
                    kind: EVENT_KIND_BY_STATION[targetStationId] ?? "signal",
                  },
                ]
              : [];
          default:
            return [];
        }
      })();
      if (heroEvents.length > 0) {
        setEruptions((current) =>
          [...current.filter((entry) => entry.expiresAt > nowMs), ...heroEvents].slice(-12),
        );
      }
      if (nextSelectionStationId) {
        onSelectStation?.(nextSelectionStationId);
      }
    },
    [
      activeStationId,
      mission,
      onMissionObjectiveComplete,
      onProbeStateChange,
      onSelectStation,
      probeState,
      world.likelyStationId,
    ],
  );
  const focusCurrentObjective = useCallback(() => {
    if (!currentMissionObjective) return false;
    onSelectStation?.(currentMissionObjective.stationId);
    return true;
  }, [currentMissionObjective, onSelectStation]);
  const dispatchCurrentObjectiveProbe = useCallback(() => {
    if (!currentMissionObjective || !operatorDroneProp || !canDispatchProbe) return false;
    triggerHeroProp(operatorDroneProp, { source: "click" });
    onSelectStation?.(currentMissionObjective.stationId);
    return true;
  }, [canDispatchProbe, currentMissionObjective, onSelectStation, operatorDroneProp, triggerHeroProp]);
  useEffect(() => {
    const rootWindow = window as Window & {
      __huntronomerObservatoryMission?: {
        completedObjectiveIds: ObservatoryMissionLoopState["completedObjectiveIds"];
        currentObjectiveId: string | null;
        progress: ObservatoryMissionLoopState["progress"] | null;
        probeActive: boolean;
        probeAffectedStationIds: HuntStationId[];
        probeCharge: number;
        probeCrewDirective: string | null;
        probeCountdownMs: number;
        probeDirectiveRead: string | null;
        probeStatus: ObservatoryProbeState["status"];
        probeTargetStationId: HuntStationId | null;
        status: ObservatoryMissionLoopState["status"] | null;
      };
      __huntronomerObservatoryMissionHarness?: {
        completeCurrentObjective: () => boolean;
        dispatchCurrentObjectiveProbe: () => boolean;
        focusCurrentObjective: () => boolean;
      };
    };
    rootWindow.__huntronomerObservatoryMission = {
      completedObjectiveIds: mission?.completedObjectiveIds ?? [],
      currentObjectiveId: getCurrentObservatoryMissionObjective(mission)?.id ?? null,
      progress: mission?.progress ?? null,
      probeActive: resolvedProbeState.status === "active",
      probeAffectedStationIds: probeDirective?.affectedStationIds ?? [],
      probeCharge,
      probeCrewDirective: probeDirective?.crewDirective ?? null,
      probeCountdownMs,
      probeDirectiveRead: probeDirective?.missionRead ?? null,
      probeStatus: resolvedProbeState.status,
      probeTargetStationId: resolvedProbeState.targetStationId ?? missionProbeTargetStationId,
      status: mission?.status ?? null,
    };
    rootWindow.__huntronomerObservatoryMissionHarness = {
      completeCurrentObjective: () => {
        const objective = getCurrentObservatoryMissionObjective(mission);
        if (!objective) return false;
        const prop = world.heroProps.find((entry) => entry.assetId === objective.assetId);
        if (!prop) return false;
        triggerHeroProp(prop, { source: "player" });
        return true;
      },
      dispatchCurrentObjectiveProbe,
      focusCurrentObjective,
    };
    return () => {
      delete rootWindow.__huntronomerObservatoryMission;
      delete rootWindow.__huntronomerObservatoryMissionHarness;
    };
  }, [
    dispatchCurrentObjectiveProbe,
    focusCurrentObjective,
    mission,
    missionProbeTargetStationId,
    probeCharge,
    probeDirective?.affectedStationIds,
    probeDirective?.crewDirective,
    probeDirective?.missionRead,
    probeCountdownMs,
    resolvedProbeState.status,
    resolvedProbeState.targetStationId,
    triggerHeroProp,
    world.heroProps,
  ]);

  // FlightState store bridge — writes live position/quaternion/speedTier/currentSpeed
  // into the store at ~100ms intervals via the onStateChange prop chain.
  // Uses getState() (imperative write) so this 60fps callback never causes React re-renders.
  const handleFlightStateChange = useCallback((state: FlightState) => {
    useObservatoryStore.getState().actions.setFlightState(state);
  }, []);

  return (
    <div className={className} style={{ background: "#04080f" }}>
      <Canvas
        dpr={performanceProfile.dpr}
        frameloop={canvasFrameloop}
        camera={{ position: world.camera.initialPosition, fov: world.camera.fov }}
        gl={{
          // WebGPU renderer disabled: @react-three/postprocessing (EffectComposer)
          // calls renderer.getContext().getContextAttributes() which is WebGL-only.
          // Re-enable after postprocessing library adds WebGPU support.
          antialias: false,
          alpha: false,
          powerPreference: "high-performance",
          logarithmicDepthBuffer: true,
        }}
        style={{ background: "#04080f" }}
      >
        <Suspense fallback={null}>
          <ObservatoryQualityMonitor
            enabled={flowRuntimeEnabled}
            onQualityChange={(quality) => {
              setAdaptiveQuality((current) => (current === quality ? current : quality));
            }}
          />
          <ObservatoryRuntimeActivityMonitor
            activeHeroInteractionActive={activeHeroInteraction !== null}
            enabled={flowRuntimeEnabled}
            hasActiveEruptions={hasActiveEruptions}
            onHighActivityChange={(next) => {
              setRuntimeActivityHigh((current) => (current === next ? current : next));
            }}
            playerFocusRef={playerFocusRef}
            probeStatus={resolvedProbeState.status}
          />
          {/* Phase 24 HUD-06: Camera bridge — writes camera matrices into hudCameraRef each frame */}
          <HudCameraBridge />
          <ObservatoryInvalidationController sources={realtimeActivitySources} />
          <ExtractedObservatoryWorldScene
            world={reactiveWorld}
            cameraResetToken={cameraResetToken}
            flyByActive={flyByActive}
            onFlyByComplete={onFlyByComplete ?? (() => {})}
            eruptionStrengthByStation={eruptionStrengthByStation}
            eruptionStrengthByRouteStation={eruptionStrengthByRouteStation}
            activeHeroInteraction={activeHeroInteraction}
            mission={mission}
            missionTargetStationId={currentMissionObjective?.stationId ?? null}
            missionTargetAssetId={currentMissionObjective?.assetId ?? null}
            playerInteractableAssetId={
              flowRuntimeEnabled ? playerWorldState.interactableAssetId : null
            }
            probeLockedTargetStationId={resolvedProbeState.targetStationId}
            probeStatus={resolvedProbeState.status}
            watchfieldRaised={watchfieldRaised}
            onTriggerHeroProp={triggerHeroProp}
            onSelectStation={onSelectStation}
            playerFocusRef={playerFocusRef}
            ghostTraces={ghostTraces}
            ghostOpacityScale={ghostOpacityScale}
            analystPresetId={analystPresetIdOuter}
            heatmapPressureData={heatmapPressureData}
            heatmapVisible={heatmapVisible}
            heatmapPresetMultiplier={heatmapPresetMultiplier}
            probeGuidance={probeGuidance}
            constellations={constellations}
            spiritAccentColor={spirit?.accentColor ?? null}
            spiritMood={spiritMood}
            spiritLevel={spiritLevel}
            annotationPins={annotationPins}
            replayEnabled={replayState.enabled}
            replayFrameIndex={replayState.frameIndex}
            replayFrameMs={replayState.frameMs ?? null}
            onAnnotationDrop={handleAnnotationDrop}
            interiorActive={interiorState.active}
            interiorStationId={interiorState.stationId}
            interiorTransitionPhase={interiorState.transitionPhase}
            onInteriorTransitionComplete={(phase) => {
              if (phase === "inside") {
                useObservatoryStore.getState().actions.setInteriorState({ transitionPhase: "inside" });
              } else {
                useObservatoryStore.getState().actions.clearInterior();
              }
            }}
          />
          {/* DSC-03: Mission waypoint trail — glowing green CatmullRom tube to objective station */}
          <MissionWaypointTrail
            mission={mission}
            characterControllerEnabled={playerInputEnabled}
          />
          {/* MSN-01 MSN-02 MSN-03 MSN-04: Emissive beacon columns at mission objective stations */}
          <MissionObjectiveBeacons mission={mission} />
          {/* WTH-01: Weather layer — telemetry-driven fog/particles/ambient tint */}
          {effectiveWeatherState !== null ? (
            <ObservatoryWeatherLayer weatherState={effectiveWeatherState} />
          ) : null}
          {flowRuntimeEnabled ? (
            <Suspense fallback={null}>
              <LazyObservatoryFlowRuntimeScene
                enableCharacterVfx={performanceProfile.enableParticles}
                heroProps={world.heroProps}
                inputEnabled={playerInputEnabled}
                onInteractProp={triggerHeroProp}
                onStateChange={handleFlightStateChange}
                onWorldStateChange={setPlayerWorldState}
                playerFocusRef={playerFocusRef}
                preferredStationId={activeStationId ?? world.likelyStationId}
                world={world}
              />
            </Suspense>
          ) : null}
          {shouldRenderObservatoryPostFx(performanceProfile) ? (
            <Suspense fallback={null}>
              <LazyObservatoryPostFX
                activeHeroPropPosition={activeHeroPropPosition}
                bloomLuminanceOverride={bloomLuminanceOverride}
                profile={performanceProfile}
                spiritLut={spiritLut}
              />
            </Suspense>
          ) : null}
          {performanceProfile.mountVfxPools ? (
            <Suspense fallback={null}>
              <LazyObservatoryVFXPools />
            </Suspense>
          ) : null}
        </Suspense>
      </Canvas>
    </div>
  );
}
