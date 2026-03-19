import { useEffect, useRef } from "react";
import type { Group, Mesh } from "three";
import { useAvatarAsset } from "./useAvatarAsset";
import {
  useObservatoryPlayerAnimation,
  type ObservatoryPlayerFallbackRigRefs,
} from "../animation/useObservatoryPlayerAnimation";
import type { ObservatoryPlayerControllerStateLike } from "../animation/moveSet";

export interface ObservatoryPlayerAvatarProps {
  accentColor?: string;
  assetUrl?: string | null;
  animationAssetUrls?: readonly string[];
  bodyColor?: string;
  castShadow?: boolean;
  controllerState: ObservatoryPlayerControllerStateLike;
  fallbackOnly?: boolean;
  materialSourceUrl?: string | null;
  name?: string;
  positionOffset?: [number, number, number];
  receiveShadow?: boolean;
  rotationOffsetRadians?: number;
  scale?: number;
  trimColor?: string;
  visorColor?: string;
  visible?: boolean;
}

export function ObservatoryPlayerAvatar({
  accentColor = "#9be7ff",
  assetUrl,
  animationAssetUrls = [],
  bodyColor = "#13202d",
  castShadow = true,
  controllerState,
  fallbackOnly = false,
  materialSourceUrl,
  name = "hunt-observatory-player-avatar",
  positionOffset = [0, 0, 0],
  receiveShadow = true,
  rotationOffsetRadians = 0,
  scale = 1,
  trimColor = "#f3d98f",
  visorColor = "#c8fbff",
  visible = true,
}: ObservatoryPlayerAvatarProps) {
  const animatedRootRef = useRef<Group | null>(null);
  const backpackRef = useRef<Group | null>(null);
  const headRef = useRef<Group | null>(null);
  const leftArmRef = useRef<Group | null>(null);
  const leftFootRef = useRef<Group | null>(null);
  const leftLegRef = useRef<Group | null>(null);
  const rightArmRef = useRef<Group | null>(null);
  const rightFootRef = useRef<Group | null>(null);
  const rightLegRef = useRef<Group | null>(null);
  const shellRef = useRef<Group | null>(null);
  const torsoRef = useRef<Group | null>(null);
  const assetState = useAvatarAsset(
    fallbackOnly ? null : assetUrl,
    fallbackOnly ? [] : animationAssetUrls,
    fallbackOnly ? null : materialSourceUrl,
  );
  const fallbackRigRefs: ObservatoryPlayerFallbackRigRefs = {
    backpack: backpackRef,
    head: headRef,
    leftArm: leftArmRef,
    leftFoot: leftFootRef,
    leftLeg: leftLegRef,
    rightArm: rightArmRef,
    rightFoot: rightFootRef,
    rightLeg: rightLegRef,
    shell: shellRef,
    torso: torsoRef,
  };
  const modelScene = assetState.status === "ready" ? assetState.scene : null;
  const modelClips =
    assetState.status === "ready" ? assetState.animations : undefined;
  const activeAction = controllerState.activeAction ?? "idle";
  const isAirborne = !controllerState.grounded;
  const isFlip =
    activeAction === "flip-front" || activeAction === "flip-back";
  const isSprint = Boolean(controllerState.sprinting) && !isAirborne;
  const pulseOpacity = isFlip ? 0.4 : isAirborne ? 0.28 : isSprint ? 0.22 : 0.12;
  const ringScale = isFlip ? 1.35 : isAirborne ? 1.18 : isSprint ? 1.08 : 1;
  const thrusterOpacity = isFlip ? 0.42 : isAirborne ? 0.34 : isSprint ? 0.2 : 0.08;
  const shellEmphasis = isFlip ? 0.78 : isAirborne ? 0.58 : isSprint ? 0.38 : 0.22;

  useObservatoryPlayerAnimation({
    animatedRootRef,
    controllerState,
    fallbackRigRefs,
    modelClips,
    modelScene,
  });

  useEffect(() => {
    if (!modelScene) {
      return;
    }

    modelScene.traverse((child) => {
      const candidate = child as Mesh;

      if (!("isMesh" in candidate) || !candidate.isMesh) {
        return;
      }

      candidate.castShadow = castShadow;
      candidate.receiveShadow = receiveShadow;
    });
  }, [castShadow, modelScene, receiveShadow]);

  return (
    <group
      name={name}
      position={[
        controllerState.position[0] + positionOffset[0],
        controllerState.position[1] + positionOffset[1],
        controllerState.position[2] + positionOffset[2],
      ]}
      rotation={[0, controllerState.facingRadians + rotationOffsetRadians, 0]}
      scale={scale}
      visible={visible}
    >
      <group position={[0, -0.78, 0]}>
        <mesh rotation={[-Math.PI / 2, 0, 0]} scale={[ringScale, ringScale, ringScale]}>
          <ringGeometry args={[0.34, 0.52, 28]} />
          <meshBasicMaterial
            color={accentColor}
            transparent
            opacity={pulseOpacity}
          />
        </mesh>
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.02, 0]}>
          <circleGeometry args={[0.26, 24]} />
          <meshBasicMaterial color="#08111b" transparent opacity={0.24} />
        </mesh>
        {isFlip ? (
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.03, 0]} scale={[1.55, 1.55, 1.55]}>
            <ringGeometry args={[0.42, 0.56, 32]} />
            <meshBasicMaterial color={trimColor} transparent opacity={0.22} />
          </mesh>
        ) : null}
      </group>
      <group ref={animatedRootRef}>
        {modelScene ? (
          <>
            <primitive object={modelScene} />
            <group position={[0, 1.18, -0.26]}>
              <mesh rotation={[Math.PI, 0, 0]}>
                <coneGeometry args={[0.1, 0.5, 12]} />
                <meshBasicMaterial color={visorColor} transparent opacity={thrusterOpacity} />
              </mesh>
            </group>
          </>
        ) : (
          <FallbackObservatoryBody
            accentColor={accentColor}
            bodyColor={bodyColor}
            castShadow={castShadow}
            receiveShadow={receiveShadow}
            refsMap={fallbackRigRefs}
            shellEmphasis={shellEmphasis}
            thrusterOpacity={thrusterOpacity}
            trimColor={trimColor}
            visorColor={visorColor}
          />
        )}
      </group>
    </group>
  );
}

function FallbackObservatoryBody({
  accentColor,
  bodyColor,
  castShadow,
  receiveShadow,
  refsMap,
  shellEmphasis,
  thrusterOpacity,
  trimColor,
  visorColor,
}: {
  accentColor: string;
  bodyColor: string;
  castShadow: boolean;
  receiveShadow: boolean;
  refsMap: ObservatoryPlayerFallbackRigRefs;
  shellEmphasis: number;
  thrusterOpacity: number;
  trimColor: string;
  visorColor: string;
}) {
  return (
    <>
      <group ref={refsMap.leftLeg} position={[-0.18, 0.56, 0]}>
        <mesh castShadow={castShadow} receiveShadow={receiveShadow}>
          <capsuleGeometry args={[0.11, 0.58, 8, 14]} />
          <meshStandardMaterial
            color={bodyColor}
            metalness={0.28}
            roughness={0.38}
          />
        </mesh>
        <group position={[0, -0.44, 0.02]}>
          <group position={[0, -0.04, 0]} ref={refsMap.leftFoot}>
            <mesh castShadow={castShadow} receiveShadow={receiveShadow}>
              <boxGeometry args={[0.22, 0.14, 0.34]} />
              <meshStandardMaterial
                color={trimColor}
                metalness={0.14}
                roughness={0.46}
              />
            </mesh>
          </group>
        </group>
      </group>

      <group ref={refsMap.rightLeg} position={[0.18, 0.56, 0]}>
        <mesh castShadow={castShadow} receiveShadow={receiveShadow}>
          <capsuleGeometry args={[0.11, 0.58, 8, 14]} />
          <meshStandardMaterial
            color={bodyColor}
            metalness={0.28}
            roughness={0.38}
          />
        </mesh>
        <group position={[0, -0.44, 0.02]}>
          <group position={[0, -0.04, 0]} ref={refsMap.rightFoot}>
            <mesh castShadow={castShadow} receiveShadow={receiveShadow}>
              <boxGeometry args={[0.22, 0.14, 0.34]} />
              <meshStandardMaterial
                color={trimColor}
                metalness={0.14}
                roughness={0.46}
              />
            </mesh>
          </group>
        </group>
      </group>

      <group ref={refsMap.torso} position={[0, 1.12, 0]}>
        <mesh castShadow={castShadow} receiveShadow={receiveShadow}>
          <capsuleGeometry args={[0.31, 0.72, 8, 18]} />
          <meshStandardMaterial
            color={bodyColor}
            emissive={accentColor}
            emissiveIntensity={0.08}
            metalness={0.32}
            roughness={0.3}
          />
        </mesh>
        <group ref={refsMap.shell}>
          <mesh
            castShadow={castShadow}
            position={[0, 0.12, 0.03]}
            receiveShadow={receiveShadow}
            rotation={[Math.PI / 2, 0, 0]}
          >
            <torusGeometry args={[0.42, 0.04, 16, 36]} />
            <meshStandardMaterial
              color={accentColor}
              emissive={accentColor}
              emissiveIntensity={0.42 + shellEmphasis}
              metalness={0.2}
              roughness={0.28}
            />
          </mesh>
          <mesh
            castShadow={castShadow}
            position={[0, -0.02, 0.2]}
            receiveShadow={receiveShadow}
          >
            <boxGeometry args={[0.38, 0.18, 0.1]} />
            <meshStandardMaterial
              color={trimColor}
              emissive={trimColor}
              emissiveIntensity={0.12}
              metalness={0.24}
              roughness={0.36}
            />
          </mesh>
        </group>
        <group position={[0, 0.04, -0.28]} ref={refsMap.backpack}>
          <mesh castShadow={castShadow} receiveShadow={receiveShadow}>
            <boxGeometry args={[0.34, 0.42, 0.14]} />
            <meshStandardMaterial
              color="#0d1720"
              emissive={accentColor}
              emissiveIntensity={0.14}
              metalness={0.35}
              roughness={0.28}
            />
          </mesh>
          <mesh
            castShadow={castShadow}
            position={[0, 0.08, 0.08]}
            receiveShadow={receiveShadow}
          >
            <boxGeometry args={[0.18, 0.1, 0.08]} />
            <meshStandardMaterial
              color={accentColor}
              emissive={accentColor}
              emissiveIntensity={0.55 + shellEmphasis * 0.7}
              metalness={0.1}
              roughness={0.22}
            />
          </mesh>
          <mesh rotation={[Math.PI, 0, 0]} position={[0, -0.18, 0.08]}>
            <coneGeometry args={[0.08, 0.38, 12]} />
            <meshBasicMaterial color={visorColor} transparent opacity={thrusterOpacity} />
          </mesh>
        </group>
      </group>

      <group ref={refsMap.head} position={[0, 1.86, 0.02]}>
        <mesh castShadow={castShadow} receiveShadow={receiveShadow}>
          <sphereGeometry args={[0.24, 18, 18]} />
          <meshStandardMaterial
            color="#d8f7ff"
            metalness={0.2}
            roughness={0.18}
          />
        </mesh>
        <mesh
          castShadow={castShadow}
          position={[0, -0.01, 0.18]}
          receiveShadow={receiveShadow}
        >
          <boxGeometry args={[0.24, 0.12, 0.1]} />
          <meshStandardMaterial
            color={visorColor}
            emissive={visorColor}
            emissiveIntensity={0.58}
            metalness={0.1}
            roughness={0.12}
          />
        </mesh>
      </group>

      <group ref={refsMap.leftArm} position={[-0.5, 1.36, 0]}>
        <mesh castShadow={castShadow} receiveShadow={receiveShadow}>
          <capsuleGeometry args={[0.08, 0.5, 6, 12]} />
          <meshStandardMaterial
            color={bodyColor}
            metalness={0.26}
            roughness={0.34}
          />
        </mesh>
        <mesh
          castShadow={castShadow}
          position={[0, -0.36, 0.02]}
          receiveShadow={receiveShadow}
        >
          <sphereGeometry args={[0.09, 12, 12]} />
          <meshStandardMaterial
            color={trimColor}
            metalness={0.12}
            roughness={0.4}
          />
        </mesh>
      </group>

      <group ref={refsMap.rightArm} position={[0.5, 1.36, 0]}>
        <mesh castShadow={castShadow} receiveShadow={receiveShadow}>
          <capsuleGeometry args={[0.08, 0.5, 6, 12]} />
          <meshStandardMaterial
            color={bodyColor}
            metalness={0.26}
            roughness={0.34}
          />
        </mesh>
        <mesh
          castShadow={castShadow}
          position={[0, -0.36, 0.02]}
          receiveShadow={receiveShadow}
        >
          <sphereGeometry args={[0.09, 12, 12]} />
          <meshStandardMaterial
            color={trimColor}
            metalness={0.12}
            roughness={0.4}
          />
        </mesh>
      </group>
    </>
  );
}
