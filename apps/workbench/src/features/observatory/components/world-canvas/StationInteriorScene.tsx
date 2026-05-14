import { Instance, Instances } from "@react-three/drei";
import { useFrame } from "@react-three/fiber";
import { useEffect, useRef } from "react";
import * as THREE from "three";
import type { MissionInteractionSource } from "../flow-runtime/grounding";
import type { ObservatoryHeroPropRecipe } from "../../world/deriveObservatoryWorld";
import {
  OBSERVATORY_HERO_PROP_ASSETS,
  type ObservatoryHeroPropAssetId,
} from "../../world/propAssets";
import {
  STATION_INTERIOR_CONFIGS,
  type StationInteriorConfig,
} from "../../world/station-interior-config";
import type { HuntStationId } from "../../world/types";

export interface StationInteriorSceneProps {
  stationId: HuntStationId;
  stationWorldPosition: [number, number, number];
  onTriggerHeroProp?: (prop: ObservatoryHeroPropRecipe, meta: MissionInteractionSource) => void;
  missionTargetAssetId: ObservatoryHeroPropRecipe["assetId"] | null;
  playerInteractableAssetId: ObservatoryHeroPropRecipe["assetId"] | null;
}

interface InteriorNpcInstanceProps {
  position: [number, number, number];
  index: number;
}

function InteriorNpcInstance({ position, index }: InteriorNpcInstanceProps) {
  const groupRef = useRef<THREE.Object3D | null>(null);
  const baseY = position[1];

  useFrame(({ clock }) => {
    const obj = groupRef.current;
    if (!obj) return;
    obj.position.set(
      position[0],
      baseY + Math.sin(clock.elapsedTime * 1.5 + index) * 0.06,
      position[2],
    );
  });

  return <Instance ref={groupRef} position={position} />;
}

function InteriorNpcCrew({ config }: { config: StationInteriorConfig }) {
  return (
    <Instances limit={4}>
      <capsuleGeometry args={[0.12, 0.35, 4, 8]} />
      <meshStandardMaterial color={config.accentColor} roughness={0.7} />
      {config.npcs.map((npc, i) => (
        <InteriorNpcInstance key={`npc:${i}`} position={npc.position} index={i} />
      ))}
    </Instances>
  );
}

interface HeroPropMarkerProps {
  config: StationInteriorConfig;
  missionTargetAssetId: ObservatoryHeroPropAssetId | null;
  onTriggerHeroProp?: (prop: ObservatoryHeroPropRecipe, meta: MissionInteractionSource) => void;
}

function HeroPropMarker({
  config,
  missionTargetAssetId,
  onTriggerHeroProp,
}: HeroPropMarkerProps) {
  const meshRef = useRef<THREE.Mesh | null>(null);
  const isMissionTarget = missionTargetAssetId === config.heroPropAssetId;
  const glowColor = OBSERVATORY_HERO_PROP_ASSETS[config.heroPropAssetId].glowColor;

  useFrame(({ clock }) => {
    if (!meshRef.current) return;
    if (isMissionTarget) {
      meshRef.current.scale.setScalar(0.9 + Math.sin(clock.elapsedTime * 3) * 0.15);
    } else {
      meshRef.current.scale.setScalar(1);
    }
  });

  function handleClick() {
    if (!onTriggerHeroProp) return;
    const recipe: ObservatoryHeroPropRecipe = {
      assetId: config.heroPropAssetId,
      position: config.heroPropPosition,
      stationId: config.stationId,
      kind: "hero-prop",
      glowColor,
      fallbackKind: OBSERVATORY_HERO_PROP_ASSETS[config.heroPropAssetId].fallbackKind,
    } as unknown as ObservatoryHeroPropRecipe;
    onTriggerHeroProp(recipe, { source: "click" });
  }

  return (
    <mesh ref={meshRef} position={config.heroPropPosition} onClick={handleClick}>
      <sphereGeometry args={[0.3, 12, 12]} />
      <meshStandardMaterial
        color={glowColor}
        emissive={glowColor}
        emissiveIntensity={isMissionTarget ? 1.5 : 0.6}
        metalness={0.3}
        roughness={0.3}
        toneMapped={false}
      />
    </mesh>
  );
}

export function StationInteriorScene({
  stationId,
  stationWorldPosition,
  onTriggerHeroProp,
  missionTargetAssetId,
}: StationInteriorSceneProps) {
  const config = STATION_INTERIOR_CONFIGS[stationId];
  const [wx, wy, wz] = stationWorldPosition;
  const groupRef = useRef<THREE.Group>(null);

  useEffect(() => {
    return () => {
      groupRef.current?.traverse((obj) => {
        if ((obj as THREE.Mesh).isMesh) {
          const mesh = obj as THREE.Mesh;
          mesh.geometry?.dispose();
          if (Array.isArray(mesh.material)) {
            mesh.material.forEach((m) => m.dispose());
          } else {
            mesh.material?.dispose();
          }
        }
      });
    };
  }, []);

  return (
    <group ref={groupRef} position={[wx, wy, wz]}>
      <ambientLight intensity={0.3} />
      <pointLight
        position={[0, 6, 0]}
        intensity={config.lightIntensity}
        color={config.accentColor}
        distance={25}
        decay={2}
      />

      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0, 0]}>
        <planeGeometry args={[20, 20]} />
        <meshStandardMaterial color={config.wallColor} metalness={0.3} roughness={0.8} />
      </mesh>

      <mesh rotation={[Math.PI / 2, 0, 0]} position={[0, 8, 0]}>
        <planeGeometry args={[20, 20]} />
        <meshStandardMaterial color={config.wallColor} metalness={0.2} roughness={0.9} />
      </mesh>

      <mesh position={[0, 4, -10]}>
        <planeGeometry args={[20, 8]} />
        <meshStandardMaterial color={config.wallColor} metalness={0.1} roughness={0.85} />
      </mesh>
      <mesh position={[0, 1.6, -9.9]}>
        <boxGeometry args={[20, 0.12, 0.04]} />
        <meshStandardMaterial
          color={config.accentColor}
          emissive={config.accentColor}
          emissiveIntensity={0.4}
          toneMapped={false}
        />
      </mesh>

      <mesh position={[0, 4, 10]} rotation={[0, Math.PI, 0]}>
        <planeGeometry args={[20, 8]} />
        <meshStandardMaterial color={config.wallColor} metalness={0.1} roughness={0.85} />
      </mesh>
      <mesh position={[0, 1.6, 9.9]}>
        <boxGeometry args={[20, 0.12, 0.04]} />
        <meshStandardMaterial
          color={config.accentColor}
          emissive={config.accentColor}
          emissiveIntensity={0.4}
          toneMapped={false}
        />
      </mesh>

      <mesh position={[-10, 4, 0]} rotation={[0, Math.PI / 2, 0]}>
        <planeGeometry args={[20, 8]} />
        <meshStandardMaterial color={config.wallColor} metalness={0.1} roughness={0.85} />
      </mesh>
      <mesh position={[-9.9, 1.6, 0]}>
        <boxGeometry args={[0.04, 0.12, 20]} />
        <meshStandardMaterial
          color={config.accentColor}
          emissive={config.accentColor}
          emissiveIntensity={0.4}
          toneMapped={false}
        />
      </mesh>

      <mesh position={[10, 4, 0]} rotation={[0, -Math.PI / 2, 0]}>
        <planeGeometry args={[20, 8]} />
        <meshStandardMaterial color={config.wallColor} metalness={0.1} roughness={0.85} />
      </mesh>
      <mesh position={[9.9, 1.6, 0]}>
        <boxGeometry args={[0.04, 0.12, 20]} />
        <meshStandardMaterial
          color={config.accentColor}
          emissive={config.accentColor}
          emissiveIntensity={0.4}
          toneMapped={false}
        />
      </mesh>

      {config.props.map((prop, i) => (
        <mesh
          key={`prop:${i}`}
          position={prop.position}
          rotation={prop.rotation ?? [0, 0, 0]}
        >
          {prop.type === "box" && (
            <boxGeometry args={prop.args as [number, number, number]} />
          )}
          {prop.type === "cylinder" && (
            <cylinderGeometry args={prop.args as [number, number, number, number]} />
          )}
          {prop.type === "torus" && (
            <torusGeometry args={prop.args as [number, number, number, number]} />
          )}
          {prop.type === "cone" && (
            <coneGeometry args={prop.args as [number, number, number]} />
          )}
          <meshStandardMaterial
            color={prop.color}
            emissive={prop.emissive ?? prop.color}
            emissiveIntensity={prop.emissiveIntensity ?? 0.2}
            metalness={0.5}
            roughness={0.4}
            toneMapped={false}
          />
        </mesh>
      ))}

      <InteriorNpcCrew config={config} />

      <HeroPropMarker
        config={config}
        missionTargetAssetId={missionTargetAssetId}
        onTriggerHeroProp={onTriggerHeroProp}
      />
    </group>
  );
}
