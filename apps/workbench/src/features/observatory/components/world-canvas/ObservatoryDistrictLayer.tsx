import { memo, useMemo } from "react";
import { MemoizedStationDistrict, MemoizedWatchfieldPerimeter, MissionObjectiveBeacon } from "../../components/ObservatoryWorldCanvas";
import { StationNpcCrew } from "../../world/npcCrew";
import { SpaceStationMesh } from "../../world/districtGeometry";
import { createSpaceStationSeed } from "../../world/districtGeometryResources";
import type { ObservatoryDistrictLayerProps } from "./observatory-world-scene-types";

export function ObservatoryDistrictLayer({
  activeHeroInteraction,
  eruptionStrengthByStation,
  missionTargetAssetId,
  missionTargetStationId,
  onSelectStation,
  onTriggerHeroProp,
  playerFocusRef,
  playerInteractableAssetId,
  probeStatus,
  watchfieldRaised,
  world,
  districtLodTiers,
}: ObservatoryDistrictLayerProps) {
  const heroPropByStation = useMemo(
    () =>
      new Map(
        world.heroProps
          .filter((prop) => prop.stationId !== "core")
          .map((prop) => [prop.stationId, prop] as const),
      ),
    [world.heroProps],
  );

  return (
    <>
      {world.districts.map((district) => (
        <MemoizedStationDistrict
          key={district.id}
          district={district}
          interactionState={
            activeHeroInteraction?.stationId === district.id
              ? "active"
              : district.active
                ? "active"
                : "idle"
          }
          eruptionStrength={eruptionStrengthByStation[district.id] ?? 0}
          missionTarget={missionTargetStationId === district.id}
          modeProfile={world.modeProfile}
          onSelect={onSelectStation}
          onHover={() => undefined}
        />
      ))}

      <MemoizedWatchfieldPerimeter
        watchfield={world.watchfield}
        eruptionStrength={eruptionStrengthByStation.watch ?? 0}
        raisedPosture={watchfieldRaised}
        onSelect={onSelectStation}
        onHover={() => undefined}
      />

      {missionTargetStationId && world.districts
        .filter((district) => district.id === missionTargetStationId)
        .map((district) => (
          <MissionObjectiveBeacon key={`beacon:${district.id}`} position={district.position} label={district.label} />
        ))}

      {world.districts.map((district) => (
        <StationNpcCrew
          key={`npc:${district.id}`}
          stationWorldPos={district.position}
          colorHex={district.colorHex}
          lodTier={districtLodTiers[district.id] ?? "near"}
        />
      ))}

      {/* STN-01: Floating space station geometry */}
      {world.districts.map((district) => (
        <SpaceStationMesh
          key={`station-mesh:${district.id}`}
          position={district.position as [number, number, number]}
          colorHex={district.colorHex}
          seed={createSpaceStationSeed(district.position[0], district.position[2])}
          floatAmplitude={district.floatAmplitude ?? 0.12}
          pulseSpeed={district.pulseSpeed ?? 0.0018}
        />
      ))}
    </>
  );
}
