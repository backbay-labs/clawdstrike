import { CameraShake, OrbitControls } from "@react-three/drei";
import type { RefObject } from "react";
import { useMemo, useRef } from "react";
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
  cameraResetToken,
  eruptionStrengthByRouteStation,
  eruptionStrengthByStation,
  flyByActive,
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
}: ObservatoryWorldSceneProps) {
  const controlsRef = useRef<THREE.EventDispatcher | null>(null);
  const shakeRef = useRef<{ setIntensity: (intensity: number) => void } | null>(null);
  const districtLodTiers = useMemo(
    () => buildDistrictLodTiers(world, playerFocusRef, missionTargetStationId),
    [missionTargetStationId, playerFocusRef, world],
  );

  return (
    <>
      <color attach="background" args={["#04080f"]} />
      <ObservatoryStarfield />
      <fogExp2 attach="fog" args={["#060a14", 0.0008]} />
      <ambientLight intensity={world.environment.ambientIntensity} color={world.environment.ambientColor} />
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
    </>
  );
}
