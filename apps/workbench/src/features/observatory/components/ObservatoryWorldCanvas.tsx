// Ported from huntronomer apps/desktop/src/features/hunt-observatory/world/ObservatoryWorldCanvas.tsx
// Removals: mission system (missionLoop), OpenClaw context, NexusAppRail, session routing,
//   useGLTF hero prop loading (all hero props use fallback procedural geometry only).
// Retained: station sphere rendering, WorldCameraRig (bezier flight + smoothstep),
//   drei Text labels, probe ring visuals, OrbitControls, Stars, lighting, flow mode terrain.
// Physics: conditional on mode === "flow" && characterControllerEnabled (never always-on).
// Canvas: frameloop is a prop (defaults "demand"). dpr=[1, 1.8].

import { Text, Stars, OrbitControls } from "@react-three/drei";
import { Canvas, useFrame } from "@react-three/fiber";
import {
  Suspense,
  type RefObject,
  useCallback,
  useMemo,
  useRef,
} from "react";
import * as THREE from "three";
import {
  HUNT_STATION_LABELS,
  HUNT_STATION_PLACEMENTS,
  HUNT_PERIMETER_STATION_ID,
} from "../world/stations";
import type {
  HuntObservatorySceneState,
  HuntStationId,
  ObservatorySpiritVisual as _ObservatorySpiritVisual,
} from "../world/deriveObservatoryWorld";
import type { ObservatorySpiritVisual } from "../world/deriveObservatoryWorld";
import { deriveObservatoryWorld } from "../world/deriveObservatoryWorld";
import type { ObservatoryProbeState } from "../world/probeRuntime";
import { advanceObservatoryProbeState, OBSERVATORY_PROBE_ACTIVE_MS } from "../world/probeRuntime";

export interface ObservatoryWorldCanvasProps {
  mode: "atlas" | "flow";
  sceneState: HuntObservatorySceneState | null;
  activeStationId: HuntStationId | null;
  spirit?: ObservatorySpiritVisual;
  characterControllerEnabled?: boolean;
  frameloop?: "demand" | "always";
  probeState?: ObservatoryProbeState | null;
  cameraResetToken?: number;
  onSelectStation?: (stationId: HuntStationId) => void;
  className?: string;
}

const PRIMARY_RADIUS = 13.8;
const WATCHFIELD_RADIUS = 20.5;
const STATION_HEIGHT = 0.72;

const STATION_COLORS: Record<HuntStationId, string> = {
  signal: "#7cc8ff",
  targets: "#9df2dd",
  run: "#f4d982",
  receipts: "#7ee6f2",
  "case-notes": "#f0b87b",
  watch: "#d3b56e",
};

function stationWorldPosition(stationId: HuntStationId): [number, number, number] {
  const placement = HUNT_STATION_PLACEMENTS.find((entry) => entry.id === stationId);
  if (!placement) return [0, STATION_HEIGHT, 0];
  const radius = placement.id === HUNT_PERIMETER_STATION_ID ? WATCHFIELD_RADIUS : PRIMARY_RADIUS;
  const angle = (placement.angleDeg * Math.PI) / 180;
  const x = Math.cos(angle) * radius;
  const z = Math.sin(angle) * radius * 0.82;
  return [x, STATION_HEIGHT, z];
}

// ─── WorldCameraRig (ported from huntronomer) ────────────────────────────────
// Bezier flight path + smoothstep easing, settle orbit on arrival.
interface CameraRigProps {
  position: [number, number, number];
  target: [number, number, number];
  lerpSpeed: number;
  arrivalDurationMs: number;
  arrivalLift: number;
  settleRadius: number;
  controlsRef: RefObject<THREE.EventDispatcher | null>;
  resetToken: number;
}

function smoothstep01(value: number): number {
  const clamped = Math.min(1, Math.max(0, value));
  return clamped * clamped * (3 - 2 * clamped);
}

function bezierPoint(
  start: THREE.Vector3,
  mid: THREE.Vector3,
  end: THREE.Vector3,
  t: number,
): THREE.Vector3 {
  const inverse = 1 - t;
  return start
    .clone()
    .multiplyScalar(inverse * inverse)
    .add(mid.clone().multiplyScalar(2 * inverse * t))
    .add(end.clone().multiplyScalar(t * t));
}

function lerpAlpha(speed: number, delta: number): number {
  return 1 - Math.exp(-speed * delta);
}

function WorldCameraRig({ position, target, lerpSpeed, arrivalDurationMs, arrivalLift, settleRadius, controlsRef, resetToken }: CameraRigProps) {
  const initializedRef = useRef(false);
  const previousGoalRef = useRef<{
    position: THREE.Vector3;
    target: THREE.Vector3;
    resetToken: number;
  } | null>(null);
  const flightRef = useRef<{
    startTime: number;
    duration: number;
    fromPosition: THREE.Vector3;
    viaPosition: THREE.Vector3;
    toPosition: THREE.Vector3;
    fromTarget: THREE.Vector3;
    viaTarget: THREE.Vector3;
    toTarget: THREE.Vector3;
  } | null>(null);

  const desired = useMemo(
    () => ({
      position: new THREE.Vector3(...position),
      target: new THREE.Vector3(...target),
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [position[0], position[1], position[2], target[0], target[1], target[2]],
  );

  useFrame(({ clock }, delta) => {
    const controls = controlsRef.current as unknown as {
      object?: THREE.Camera;
      target?: THREE.Vector3;
      update?: () => void;
    } | null;
    if (!controls?.object || !controls.target || !controls.update) return;

    if (!initializedRef.current) {
      controls.object.position.copy(desired.position);
      controls.target.copy(desired.target);
      controls.update();
      initializedRef.current = true;
      previousGoalRef.current = {
        position: desired.position.clone(),
        target: desired.target.clone(),
        resetToken,
      };
      return;
    }

    const previousGoal = previousGoalRef.current;
    const goalChanged =
      previousGoal == null ||
      previousGoal.position.distanceToSquared(desired.position) > 0.25 ||
      previousGoal.target.distanceToSquared(desired.target) > 0.12 ||
      previousGoal.resetToken !== resetToken;

    if (goalChanged) {
      const fromPosition = controls.object.position.clone();
      const fromTarget = controls.target.clone();
      const axis = desired.position.clone().sub(fromPosition);
      const travelDistance = axis.length();
      const lateral = new THREE.Vector3(-axis.z, 0, axis.x)
        .normalize()
        .multiplyScalar(Math.min(1.8, 0.6 + travelDistance * 0.03));
      const viaPosition = fromPosition
        .clone()
        .lerp(desired.position, 0.5)
        .add(lateral)
        .setY(Math.max(fromPosition.y, desired.position.y) + arrivalLift + travelDistance * 0.05);
      const viaTarget = fromTarget
        .clone()
        .lerp(desired.target, 0.5)
        .setY(Math.max(fromTarget.y, desired.target.y) + arrivalLift * 0.32);

      flightRef.current = {
        startTime: clock.elapsedTime,
        duration: arrivalDurationMs / 1000,
        fromPosition,
        viaPosition,
        toPosition: desired.position.clone(),
        fromTarget,
        viaTarget,
        toTarget: desired.target.clone(),
      };
      previousGoalRef.current = {
        position: desired.position.clone(),
        target: desired.target.clone(),
        resetToken,
      };
    }

    if (flightRef.current) {
      const flight = flightRef.current;
      const progress = (clock.elapsedTime - flight.startTime) / flight.duration;
      if (progress >= 1) {
        controls.object.position.copy(flight.toPosition);
        controls.target.copy(flight.toTarget);
        flightRef.current = null;
        controls.update();
        return;
      }
      const eased = smoothstep01(progress);
      const travelPosition = bezierPoint(flight.fromPosition, flight.viaPosition, flight.toPosition, eased);
      const travelTarget = bezierPoint(flight.fromTarget, flight.viaTarget, flight.toTarget, eased);
      const settle = Math.max(0, (eased - 0.74) / 0.26);
      if (settle > 0) {
        const orbitAngle = settle * Math.PI * 0.9;
        const orbitRadius = settleRadius * (1 - settle);
        travelPosition.x += Math.cos(orbitAngle) * orbitRadius;
        travelPosition.z += Math.sin(orbitAngle) * orbitRadius;
      }
      controls.object.position.copy(travelPosition);
      controls.target.copy(travelTarget);
      controls.update();
      return;
    }

    const alpha = lerpAlpha(lerpSpeed, delta);
    controls.object.position.lerp(desired.position, alpha);
    controls.target.lerp(desired.target, alpha);
    controls.update();
  });

  return null;
}

// ─── ProbeRingEffect ────────────────────────────────────────────────────────
// Animated ring expanding from active station position.
function ProbeRingEffect({ stationId, probeState }: { stationId: HuntStationId; probeState: ObservatoryProbeState }) {
  const meshRef = useRef<THREE.Mesh | null>(null);
  const position = stationWorldPosition(stationId);
  const color = useMemo(() => new THREE.Color(STATION_COLORS[stationId]), [stationId]);

  useFrame(() => {
    if (!meshRef.current) return;
    const now = performance.now();
    const advanced = advanceObservatoryProbeState(probeState, now);
    if (advanced.status !== "active" || advanced.activeUntilMs == null) {
      meshRef.current.visible = false;
      return;
    }
    const elapsed = now - (advanced.activeUntilMs - OBSERVATORY_PROBE_ACTIVE_MS);
    const progress = Math.min(1, elapsed / OBSERVATORY_PROBE_ACTIVE_MS);
    const scale = 1 + progress * 8;
    meshRef.current.scale.setScalar(scale);
    const mat = meshRef.current.material as THREE.MeshBasicMaterial;
    mat.opacity = 0.6 * (1 - progress);
    meshRef.current.visible = true;
  });

  return (
    <mesh ref={meshRef} position={position} rotation={[-Math.PI / 2, 0, 0]}>
      <ringGeometry args={[0.8, 1.0, 32]} />
      <meshBasicMaterial color={color} transparent opacity={0.6} />
    </mesh>
  );
}

// ─── StationSphere ───────────────────────────────────────────────────────────
function StationSphere({
  stationId,
  artifactCount,
  isActive,
  isLikely,
  onSelect,
}: {
  stationId: HuntStationId;
  artifactCount: number;
  isActive: boolean;
  isLikely: boolean;
  onSelect?: (id: HuntStationId) => void;
}) {
  const pos = stationWorldPosition(stationId);
  const color = STATION_COLORS[stationId];
  const label = HUNT_STATION_LABELS[stationId];
  const emissiveIntensity = isActive ? 0.88 : isLikely ? 0.56 : artifactCount > 0 ? 0.38 : 0.18;
  const radius = stationId === HUNT_PERIMETER_STATION_ID ? 0.9 : 0.72;

  const handleClick = useCallback(() => {
    onSelect?.(stationId);
  }, [stationId, onSelect]);

  return (
    <group position={pos}>
      {/* Station sphere */}
      <mesh onClick={handleClick}>
        <sphereGeometry args={[radius, 20, 20]} />
        <meshStandardMaterial
          color="#0e1621"
          emissive={color}
          emissiveIntensity={emissiveIntensity}
          roughness={0.6}
          metalness={0.3}
        />
      </mesh>
      {/* Outer glow ring */}
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -radius * 0.5, 0]}>
        <ringGeometry args={[radius * 1.1, radius * 1.45, 32]} />
        <meshBasicMaterial color={color} transparent opacity={isActive ? 0.32 : 0.12} />
      </mesh>
      {/* drei Text label above sphere */}
      <Text
        position={[0, radius + 0.7, 0]}
        fontSize={0.44}
        color={color}
        anchorX="center"
        anchorY="middle"
        outlineColor="#030608"
        outlineWidth={0.02}
        maxWidth={3}
      >
        {label}
      </Text>
      {/* Artifact count badge */}
      {artifactCount > 0 && (
        <Text
          position={[radius * 0.8, radius * 0.8, 0]}
          fontSize={0.28}
          color="#ece7dc"
          anchorX="center"
          anchorY="middle"
        >
          {String(artifactCount)}
        </Text>
      )}
    </group>
  );
}

// ─── CoreNode ────────────────────────────────────────────────────────────────
function CoreNode({ accentColor }: { accentColor: string }) {
  const meshRef = useRef<THREE.Mesh | null>(null);

  useFrame(({ clock }) => {
    if (!meshRef.current) return;
    const mat = meshRef.current.material as THREE.MeshStandardMaterial;
    mat.emissiveIntensity = 0.42 + Math.sin(clock.elapsedTime * 0.8) * 0.12;
  });

  return (
    <group position={[0, 1.14, 0]}>
      <mesh ref={meshRef}>
        <sphereGeometry args={[0.48, 20, 20]} />
        <meshStandardMaterial
          color="#030608"
          emissive={accentColor}
          emissiveIntensity={0.42}
          roughness={0.4}
          metalness={0.6}
        />
      </mesh>
      <mesh rotation={[-Math.PI / 2, 0, 0]}>
        <ringGeometry args={[0.68, 0.82, 32]} />
        <meshBasicMaterial color={accentColor} transparent opacity={0.24} />
      </mesh>
      {/* Core label */}
      <Text
        position={[0, 1.1, 0]}
        fontSize={0.32}
        color={accentColor}
        anchorX="center"
        anchorY="middle"
        outlineColor="#030608"
        outlineWidth={0.02}
      >
        CORE
      </Text>
    </group>
  );
}

// ─── Floor / Grid ────────────────────────────────────────────────────────────
function ObservatoryFloor({ mode }: { mode: "atlas" | "flow" }) {
  return (
    <>
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.02, 0]} receiveShadow>
        <circleGeometry args={[46, 48]} />
        <meshStandardMaterial
          color={mode === "flow" ? "#030508" : "#040709"}
          roughness={0.9}
          metalness={0.1}
          transparent
          opacity={mode === "flow" ? 0.9 : 0.84}
        />
      </mesh>
      {/* Grid lines */}
      <gridHelper
        args={[132, 40, "#0c1526", "#0c1526"]}
        position={[0, 0.01, 0]}
      />
    </>
  );
}

// ─── Scene (inside Canvas) ───────────────────────────────────────────────────
function ObservatoryScene({
  mode,
  sceneState,
  activeStationId,
  spirit,
  characterControllerEnabled = false,
  probeState,
  cameraResetToken,
  onSelectStation,
}: {
  mode: "atlas" | "flow";
  sceneState: HuntObservatorySceneState | null;
  activeStationId: HuntStationId | null;
  spirit?: ObservatorySpiritVisual;
  characterControllerEnabled?: boolean;
  probeState: ObservatoryProbeState | null;
  cameraResetToken: number;
  onSelectStation?: (id: HuntStationId) => void;
}) {
  const controlsRef = useRef<THREE.EventDispatcher | null>(null);
  const world = useMemo(
    () => deriveObservatoryWorld({ mode, sceneState, activeStationId, spirit }),
    [mode, sceneState, activeStationId, spirit],
  );

  const accentColor = spirit?.accentColor ?? "#d8c895";

  return (
    <>
      {/* Camera */}
      <WorldCameraRig
        position={world.camera.desiredPosition}
        target={world.camera.desiredTarget}
        lerpSpeed={world.camera.lerpSpeed}
        arrivalDurationMs={world.camera.arrivalDurationMs}
        arrivalLift={world.camera.arrivalLift}
        settleRadius={world.camera.settleRadius}
        controlsRef={controlsRef}
        resetToken={cameraResetToken}
      />
      <OrbitControls
        ref={controlsRef as React.Ref<unknown>}
        enabled={mode === "atlas"}
        minDistance={world.camera.minDistance}
        maxDistance={world.camera.maxDistance}
        dampingFactor={world.camera.dampingFactor}
        enableDamping
        makeDefault
      />

      {/* Lighting */}
      <ambientLight color={world.environment.ambientColor} intensity={world.environment.ambientIntensity} />
      <directionalLight
        position={world.environment.directionalLightPosition}
        color={world.environment.directionalLightColor}
        intensity={world.environment.directionalLightIntensity}
        castShadow
      />
      <pointLight
        position={world.environment.pointLightPosition}
        color={world.environment.pointLightColor}
        intensity={world.environment.pointLightIntensity}
      />

      {/* Background atmosphere */}
      <fog
        attach="fog"
        color={world.environment.fogColor}
        near={world.environment.fogNear}
        far={world.environment.fogFar}
      />
      <color attach="background" args={[world.environment.backgroundColor]} />
      <Stars
        radius={world.environment.starsRadius}
        depth={world.environment.starsDepth}
        count={world.environment.starsCount}
        factor={world.environment.starsFactor}
        fade
        speed={0.4}
      />

      {/* Floor */}
      <ObservatoryFloor mode={mode} />

      {/* Core node */}
      <CoreNode accentColor={accentColor} />

      {/* Station spheres */}
      {HUNT_STATION_PLACEMENTS.map((placement) => {
        const stationState = sceneState?.stations.find((s) => s.id === placement.id);
        return (
          <StationSphere
            key={placement.id}
            stationId={placement.id}
            artifactCount={stationState?.artifactCount ?? 0}
            isActive={activeStationId === placement.id}
            isLikely={sceneState?.likelyStationId === placement.id}
            onSelect={onSelectStation}
          />
        );
      })}

      {/* Probe ring animation (shown when probe is active) */}
      {probeState && probeState.status !== "ready" && probeState.targetStationId && (
        <ProbeRingEffect
          stationId={probeState.targetStationId}
          probeState={probeState}
        />
      )}

      {/* Flow mode atmosphere — only in flow mode (Character controller deferred to FlowModeController) */}
      {mode === "flow" && (
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.1, 0]}>
          <circleGeometry args={[28, 32]} />
          <meshBasicMaterial color="#0a1428" transparent opacity={0.28} />
        </mesh>
      )}
    </>
  );
}

// ─── ObservatoryWorldCanvas ──────────────────────────────────────────────────
export function ObservatoryWorldCanvas({
  mode,
  sceneState,
  activeStationId,
  spirit,
  characterControllerEnabled = false,
  frameloop = "demand",
  probeState = null,
  cameraResetToken = 0,
  onSelectStation,
  className,
}: ObservatoryWorldCanvasProps) {
  return (
    <Canvas
      frameloop={frameloop}
      dpr={[1, 1.8]}
      gl={{ antialias: true, alpha: false, powerPreference: "high-performance" }}
      className={className}
      style={{ width: "100%", height: "100%" }}
      camera={{ fov: 42 }}
    >
      <Suspense fallback={null}>
        <ObservatoryScene
          mode={mode}
          sceneState={sceneState}
          activeStationId={activeStationId}
          spirit={spirit}
          characterControllerEnabled={characterControllerEnabled}
          probeState={probeState}
          cameraResetToken={cameraResetToken}
          onSelectStation={onSelectStation}
        />
      </Suspense>
    </Canvas>
  );
}
