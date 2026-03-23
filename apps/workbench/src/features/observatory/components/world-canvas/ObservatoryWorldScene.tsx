import { CameraShake, OrbitControls } from "@react-three/drei";
import type { ReactNode, RefObject } from "react";
import { useEffect, useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import type {
  ObservatoryHeroPropRecipe,
  DerivedObservatoryWorld,
} from "../../world/deriveObservatoryWorld";
import type { ObservatoryMissionLoopState } from "../../world/missionLoop";
import type { ObservatoryProbeState } from "../../world/probeRuntime";
import type { HuntStationId } from "../../world/types";
import {
  FovController,
  HeroConsequenceLayer,
  OperatorProbe,
  PlayerAccentLights,
  ThesisCore,
  WorldCameraRig,
} from "../../components/ObservatoryWorldCanvas";
import { ProbeDischargeVFX } from "../../vfx/ProbeDischargeVFX";
import { createObservatoryLodPolicy, type ObservatoryLodTier } from "../../utils/observatory-performance";
import type { ObservatoryPlayerFocusState } from "../flow-runtime/grounding";
import { ObservatoryDistrictLayer } from "./ObservatoryDistrictLayer";
import { ObservatoryNebulaClouds } from "./ObservatoryNebulaClouds";
import { ObservatoryStarfield } from "./ObservatoryStarfield";
import { ObservatoryTransitLayer } from "./ObservatoryTransitLayer";
import type { ObservatoryWorldSceneProps } from "./observatory-world-scene-types";
import { GhostTraceLayer } from "../GhostTraceLayer";
import { ThreatPresetOverlay } from "../ThreatPresetOverlay";
import { EvidencePresetOverlay } from "../EvidencePresetOverlay";
import { ReceiptsPresetOverlay } from "../ReceiptsPresetOverlay";
import { GhostPresetOverlay } from "../GhostPresetOverlay";
import { ThreatTopologyHeatmap } from "./ThreatTopologyHeatmap";
import { ProbeDeltaLayer } from "./ProbeDeltaLayer";
import { ConstellationRoutesLayer } from "./ConstellationRoutesLayer";
import { SpiritTrailsLayer } from "./SpiritTrailsLayer";
import { SpiritResonanceConnections } from "./SpiritResonanceConnections";
import { ReplayAnnotationLayer } from "./ReplayAnnotationLayer";
import { OBSERVATORY_STATION_POSITIONS } from "../../world/observatory-world-template";
import { StationInteriorScene } from "./StationInteriorScene";
import { useInteriorCameraTransition } from "./useInteriorCameraTransition";

// ---------------------------------------------------------------------------
// ExteriorDimmer — dims exterior scene layers to 0.2 opacity when interior active
// Stays mounted for smooth reverse transition; interior lerps material opacity
// ---------------------------------------------------------------------------

const EXTERIOR_DIM_SPEED = 4;

function ExteriorDimmer({
  targetOpacity,
  children,
}: {
  targetOpacity: number;
  children: ReactNode;
}) {
  const groupRef = useRef<THREE.Group>(null!);
  useFrame((_, delta) => {
    if (!groupRef.current) return;
    groupRef.current.traverse((obj) => {
      const mesh = obj as THREE.Mesh;
      if (mesh.isMesh && mesh.material) {
        const mat = mesh.material as THREE.Material;
        mat.transparent = true;
        mat.opacity = THREE.MathUtils.lerp(
          mat.opacity,
          targetOpacity,
          delta * EXTERIOR_DIM_SPEED,
        );
      }
    });
  });
  return <group ref={groupRef}>{children}</group>;
}

// ---------------------------------------------------------------------------

function buildDistrictLodTiers(
  world: DerivedObservatoryWorld,
  playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>,
  missionTargetStationId: HuntStationId | null,
): Partial<Record<HuntStationId, ObservatoryLodTier>> {
  const policy = createObservatoryLodPolicy();
  const playerPosition =
    playerFocusRef.current?.position ?? world.camera.desiredTarget;
  return world.districts.reduce<Partial<Record<HuntStationId, ObservatoryLodTier>>>((acc, district) => {
    const dx = district.position[0] - playerPosition[0];
    const dy = district.position[1] - playerPosition[1];
    const dz = district.position[2] - playerPosition[2];
    const distanceToCamera = Math.hypot(dx, dy, dz);
    acc[district.id] = policy.resolveDistrictTier({
      activeStationId: world.districts.find((entry) => entry.active)?.id ?? null,
      distanceToCamera,
      likelyStationId: world.likelyStationId,
      missionTargetStationId,
      selectedStationId: world.districts.find((entry) => entry.likely)?.id ?? null,
      stationId: district.id,
    });
    return acc;
  }, {});
}

export function ObservatoryWorldScene({
  activeHeroInteraction,
  analystPresetId = null,
  cameraResetToken,
  constellations = [],
  eruptionStrengthByRouteStation,
  eruptionStrengthByStation,
  flyByActive,
  ghostTraces = [],
  ghostOpacityScale = 0.2,
  heatmapPressureData = null,
  heatmapVisible = false,
  heatmapPresetMultiplier = 1.0,
  probeGuidance = null,
  spiritAccentColor = null,
  spiritMood = null,
  spiritLevel = 1,
  annotationPins = [],
  replayEnabled = false,
  replayFrameIndex = 0,
  replayFrameMs = null,
  onAnnotationDrop,
  mission,
  missionTargetAssetId,
  missionTargetStationId,
  onFlyByComplete,
  onSelectStation,
  onTriggerHeroProp,
  playerFocusRef,
  playerInteractableAssetId,
  probeLockedTargetStationId,
  probeStatus,
  watchfieldRaised,
  world,
  interiorActive = false,
  interiorStationId = null,
  interiorTransitionPhase = null,
  onInteriorTransitionComplete,
}: ObservatoryWorldSceneProps) {
  const controlsRef = useRef<THREE.EventDispatcher | null>(null);
  const shakeRef = useRef<{ setIntensity: (intensity: number) => void } | null>(null);

  // ANNO-05: Camera focus on annotation pin — snap orbit controls target to pin position
  // OrbitControls dampingFactor provides natural smooth feel without explicit lerp
  useEffect(() => {
    function handleCameraFocus(e: Event) {
      const detail = (e as CustomEvent).detail as
        | { target: [number, number, number]; duration: number }
        | undefined;
      if (!detail?.target || !controlsRef.current) return;
      const controls = controlsRef.current as unknown as { target: THREE.Vector3 };
      if (!controls.target) return;
      controls.target.set(detail.target[0], detail.target[1], detail.target[2]);
    }
    window.addEventListener("observatory:camera-focus", handleCameraFocus);
    return () => window.removeEventListener("observatory:camera-focus", handleCameraFocus);
  }, []);

  const districtLodTiers = useMemo(
    () => buildDistrictLodTiers(world, playerFocusRef, missionTargetStationId),
    [missionTargetStationId, playerFocusRef, world],
  );

  // Phase 43 INTR: compute interior target position from station world position
  const interiorTargetPosition = useMemo(
    () =>
      interiorStationId
        ? (OBSERVATORY_STATION_POSITIONS[interiorStationId] as [number, number, number])
        : null,
    [interiorStationId],
  );

  // Phase 43 INTR: camera transition hook — smooth lerp with FOV narrowing and near-plane adjustment
  useInteriorCameraTransition({
    interiorState: {
      active: interiorActive,
      stationId: interiorStationId,
      transitionPhase: interiorTransitionPhase,
    },
    targetPosition: interiorTargetPosition,
    controlsRef,
    onTransitionComplete: onInteriorTransitionComplete ?? (() => {}),
  });

  // Phase 43 INTR: exterior dimmer opacity — 0.2 when fully inside, 1.0 otherwise
  const exteriorDimOpacity =
    interiorActive && interiorTransitionPhase === "inside" ? 0.2 : 1.0;

  return (
    <>
      <color attach="background" args={["#04080f"]} />
      <ObservatoryStarfield />
      <fogExp2 attach="fog" args={["#060a14", 0.0008]} />
      {/* APR-04: GHOST preset dims ambient by 40% + adds cool desaturation tint */}
      {analystPresetId === "ghost" ? (
        <GhostPresetOverlay
          baseIntensity={world.environment.ambientIntensity}
          baseColor={world.environment.ambientColor}
        />
      ) : (
        <ambientLight intensity={world.environment.ambientIntensity} color={world.environment.ambientColor} />
      )}
      <hemisphereLight args={["#b7d4ff", "#02050b", 0.18]} />
      <directionalLight
        position={world.environment.directionalLightPosition}
        intensity={world.environment.directionalLightIntensity}
        color={world.environment.directionalLightColor}
      />
      <directionalLight position={[-16, 13, -12]} intensity={0.58} color="#5ec3ff" />
      <pointLight
        position={world.environment.pointLightPosition}
        intensity={world.environment.pointLightIntensity}
        color={world.environment.pointLightColor}
      />
      <PlayerAccentLights playerFocusRef={playerFocusRef} />
      <ObservatoryNebulaClouds />

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
      <FovController playerFocusRef={playerFocusRef} probeActive={probeStatus === "active"} boostActive={false} />
      <CameraShake
        ref={shakeRef as never}
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

      {/* Phase 43 INTR: ExteriorDimmer — dims exterior scene to 0.2 opacity when interior active.
          Stays mounted at all times to allow smooth reverse transition back to exterior. */}
      <ExteriorDimmer targetOpacity={exteriorDimOpacity}>
        <ThesisCore core={world.core} />
        <OperatorProbe
          activeRoute={probeStatus === "active"}
          world={world}
          targetStationId={probeLockedTargetStationId ?? missionTargetStationId ?? world.likelyStationId}
        />
        <HeroConsequenceLayer interaction={activeHeroInteraction} mission={mission} world={world} />

        <ObservatoryTransitLayer
          eruptionStrengthByRouteStation={eruptionStrengthByRouteStation}
          missionTargetStationId={missionTargetStationId}
          world={world}
        />
        <ProbeDischargeVFX
          position={[0, 0, 0]}
          probeStatus={probeStatus}
          color={world.core.accentColor}
        />
        <ObservatoryDistrictLayer
          activeHeroInteraction={activeHeroInteraction}
          districtLodTiers={districtLodTiers}
          eruptionStrengthByStation={eruptionStrengthByStation}
          missionTargetAssetId={missionTargetAssetId}
          missionTargetStationId={missionTargetStationId}
          modeOpacityScale={world.modeProfile.layoutOpacityScale}
          onSelectStation={onSelectStation}
          onTriggerHeroProp={onTriggerHeroProp}
          playerFocusRef={playerFocusRef}
          playerInteractableAssetId={playerInteractableAssetId}
          probeStatus={probeStatus}
          watchfieldRaised={watchfieldRaised}
          world={world}
        />
        <GhostTraceLayer traces={ghostTraces} opacityScale={ghostOpacityScale} />
        {/* HEAT-01 through HEAT-05: Threat topology heatmap — ground-plane pressure gradient */}
        {heatmapVisible && heatmapPressureData ? (
          <ThreatTopologyHeatmap
            pressureData={heatmapPressureData}
            stationPositions={OBSERVATORY_STATION_POSITIONS}
            presetOpacityMultiplier={heatmapPresetMultiplier}
          />
        ) : null}
        {/* APR-01: THREAT preset — red wash + danger motes at high-pressure districts */}
        {analystPresetId === "threat" ? (
          <ThreatPresetOverlay districts={world.districts} />
        ) : null}
        {/* APR-02: EVIDENCE preset — gold emissive halos at stations with receipt traces */}
        {analystPresetId === "evidence" ? (
          <EvidencePresetOverlay traces={ghostTraces} />
        ) : null}
        {/* APR-03: RECEIPTS preset — verdict badge markers at stations with receipt history */}
        {analystPresetId === "receipts" ? (
          <ReceiptsPresetOverlay traces={ghostTraces} />
        ) : null}
        {/* PRBI-01 through PRBI-06: Probe delta cards — floating feedback after probe discharge */}
        <ProbeDeltaLayer
          probeGuidance={probeGuidance}
          stationPositions={OBSERVATORY_STATION_POSITIONS}
        />
        {/* CNST-01 through CNST-05: Constellation routes — investigation history in starfield */}
        {constellations.length > 0 ? (
          <ConstellationRoutesLayer
            constellations={constellations}
            spiritAccentColor={spiritAccentColor}
          />
        ) : null}
        {/* SPRT-01 through SPRT-03, SPRT-05: Spirit movement trail — mood + level driven */}
        {spiritAccentColor && spiritMood && spiritMood !== "dormant" ? (
          <SpiritTrailsLayer
            spiritAccentColor={spiritAccentColor}
            spiritMood={spiritMood}
            spiritLevel={spiritLevel ?? 1}
            playerFocusRef={playerFocusRef}
          />
        ) : null}
        {/* SPRT-04: Hidden resonance connections — revealed at spirit level 5 */}
        {spiritAccentColor && (spiritLevel ?? 1) >= 5 ? (
          <SpiritResonanceConnections
            spiritLevel={spiritLevel ?? 1}
            spiritAccentColor={spiritAccentColor}
          />
        ) : null}
        {/* ANNO-01 through ANNO-06: Replay annotation pins — click-to-drop in 3D space */}
        <ReplayAnnotationLayer
          annotationPins={annotationPins}
          replayEnabled={replayEnabled}
          replayFrameIndex={replayFrameIndex}
          replayFrameMs={replayFrameMs}
          spiritAccentColor={spiritAccentColor}
          onDropPin={onAnnotationDrop ?? (() => {})}
        />
      </ExteriorDimmer>

      {/* Phase 43 INTR-02/INTR-03: Station interior scene — conditionally mounted when analyst enters */}
      {interiorActive && interiorStationId && interiorTargetPosition ? (
        <StationInteriorScene
          stationId={interiorStationId}
          stationWorldPosition={interiorTargetPosition}
          onTriggerHeroProp={onTriggerHeroProp}
          missionTargetAssetId={missionTargetAssetId}
          playerInteractableAssetId={playerInteractableAssetId}
        />
      ) : null}
    </>
  );
}
