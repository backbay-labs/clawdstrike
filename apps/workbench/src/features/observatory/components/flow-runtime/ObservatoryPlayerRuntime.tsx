import { lazy, Suspense, type RefObject, useEffect, useMemo, useRef } from "react";
import { type RapierRigidBody, CapsuleCollider, RigidBody } from "@react-three/rapier";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { ObservatoryPlayerAvatar } from "../../character/avatar/ObservatoryPlayerAvatar";
import {
  OBSERVATORY_ASTRONAUT_OPERATOR_ANIMATION_URLS,
  OBSERVATORY_ASTRONAUT_OPERATOR_ASSET_URL,
  OBSERVATORY_ASTRONAUT_OPERATOR_TEXTURE_SOURCE_URL,
} from "../../character/avatar/assetManifest";
import { useObservatoryPlayerRuntime } from "../../character/controller/useObservatoryPlayerRuntime";
import { useObservatoryPlayerInput } from "../../character/input/useObservatoryPlayerInput";
import { createObservatoryPlayerCapsuleCollider } from "../../character/physics/colliders";
import type {
  ObservatoryPlayerBodyAdapter,
  ObservatoryPlayerCommand,
} from "../../character/types";
import type {
  DerivedObservatoryWorld,
  ObservatoryHeroPropRecipe,
} from "../../world/deriveObservatoryWorld";
import { shouldAdhereObservatoryPlayerToGround } from "../../world/grounding";
import type { HuntStationId } from "../../world/types";
import {
  createObservatoryGroundQuery,
  createObservatoryGroundScratch,
  resolveGroundHeightFromQuery,
  resolveJumpPadBoostFromQuery,
  resolveNearestDistrictIdFromQuery,
  resolveObservatoryWorldSpawn,
} from "./grounding";
import {
  PLAYER_COLLIDER_HALF_HEIGHT,
  PLAYER_COLLIDER_RADIUS,
  PLAYER_GROUNDED_EPSILON,
  PLAYER_STAND_HEIGHT,
} from "./observatory-player-constants";
import { resolveNearestInteractableHeroProp } from "./observatory-player-interactable";
import type {
  MissionInteractionSource,
  ObservatoryPlayerFocusState,
  ObservatoryPlayerWorldState,
} from "./observatory-player-types";
import { getObservatoryNowMs } from "../../utils/observatory-time";

const LazyCharacterVfx = lazy(() =>
  import("../../vfx/CharacterVFX").then((module) => ({ default: module.CharacterVFX })),
);

export interface ObservatoryPlayerRuntimeProps {
  enableCharacterVfx?: boolean;
  heroProps: ObservatoryHeroPropRecipe[];
  inputEnabled?: boolean;
  onInteractProp?: (prop: ObservatoryHeroPropRecipe, meta: MissionInteractionSource) => void;
  onWorldStateChange?: (state: ObservatoryPlayerWorldState) => void;
  playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>;
  preferredStationId: HuntStationId | null;
  world: DerivedObservatoryWorld;
}

export function ObservatoryPlayerRuntime({
  enableCharacterVfx = false,
  heroProps,
  playerFocusRef,
  inputEnabled = false,
  world,
  preferredStationId,
  onInteractProp,
  onWorldStateChange,
}: ObservatoryPlayerRuntimeProps) {
  const spawn = useMemo(
    () => resolveObservatoryWorldSpawn(world, preferredStationId),
    [preferredStationId, world],
  );
  const groundQuery = useMemo(() => createObservatoryGroundQuery(world), [world]);
  const groundScratchRef = useRef(createObservatoryGroundScratch());
  const bodyRef = useRef<RapierRigidBody | null>(null);
  const directionRef = useRef(new THREE.Vector3());
  const { intent, consumeTransientActions, reset: resetInput } = useObservatoryPlayerInput({
    enabled: inputEnabled,
  });
  const bodyAdapter = useMemo<ObservatoryPlayerBodyAdapter>(
    () => ({
      readSnapshot: () => {
        const body = bodyRef.current;
        if (!body) return null;
        const translation = body.translation();
        const velocity = body.linvel();
        const position: [number, number, number] = [
          translation.x,
          translation.y,
          translation.z,
        ];
        return {
          position,
          velocity: [velocity.x, velocity.y, velocity.z],
          grounded:
            translation.y <=
              resolveGroundHeightFromQuery(
                groundQuery,
                position,
                groundScratchRef.current,
              )
              + PLAYER_STAND_HEIGHT
              + PLAYER_GROUNDED_EPSILON
            && Math.abs(velocity.y) <= 1.6,
          stationId: resolveNearestDistrictIdFromQuery(groundQuery, position),
        };
      },
      applyCommand: (command: ObservatoryPlayerCommand) => {
        const body = bodyRef.current;
        if (!body) return;
        body.setLinvel(
          {
            x: command.linearVelocity[0],
            y: command.linearVelocity[1],
            z: command.linearVelocity[2],
          },
          true,
        );
      },
    }),
    [groundQuery],
  );
  const runtime = useObservatoryPlayerRuntime({ bodyAdapter, spawn });
  const appliedSpawnIdRef = useRef<string | null>(null);
  const jumpPadCooldownUntilRef = useRef(0);
  const wasAirborneRef = useRef(false);
  const lastWorldStateRef = useRef<ObservatoryPlayerWorldState | null>(null);
  const runtimeResetRef = useRef(runtime.reset);
  const inputResetRef = useRef(resetInput);

  useEffect(() => {
    runtimeResetRef.current = runtime.reset;
  }, [runtime.reset]);

  useEffect(() => {
    inputResetRef.current = resetInput;
  }, [resetInput]);

  useEffect(() => {
    const nextState = {
      action: runtime.state.activeAction,
      grounded: runtime.state.grounded,
      position: runtime.state.position,
      sprinting: runtime.state.sprinting,
      stationId: runtime.state.stationId,
    };
    const rootWindow = window as Window & {
      __huntronomerObservatoryPlayer?: typeof nextState;
    };
    rootWindow.__huntronomerObservatoryPlayer = nextState;
    return () => {
      delete rootWindow.__huntronomerObservatoryPlayer;
    };
  }, [runtime.state]);

  useFrame(({ camera }, delta) => {
    const body = bodyRef.current;
    if (body && appliedSpawnIdRef.current !== spawn.id) {
      appliedSpawnIdRef.current = spawn.id;
      body.setTranslation(
        { x: spawn.position[0], y: spawn.position[1], z: spawn.position[2] },
        true,
      );
      body.setLinvel({ x: 0, y: 0, z: 0 }, true);
      inputResetRef.current();
      runtimeResetRef.current(spawn);
      return;
    }

    const direction = directionRef.current;
    camera.getWorldDirection(direction);
    const cameraYawRadians = Math.atan2(direction.x, direction.z);
    const nowMs = getObservatoryNowMs();

    const stepResult = runtime.step(intent, {
      deltaSeconds: delta,
      nowMs,
      cameraYawRadians,
    });
    const nextState = stepResult.state;
    const interactableProp = resolveNearestInteractableHeroProp(heroProps, nextState.position);
    const isAirborne = !nextState.grounded;
    playerFocusRef.current = {
      action: nextState.activeAction,
      airborne: isAirborne,
      facingRadians: nextState.facingRadians,
      moving: nextState.moveMagnitude > 0.12,
      moveVector: nextState.moveVector,
      position: nextState.position,
      sprinting: nextState.sprinting,
      stationId: nextState.stationId,
    };
    if (wasAirborneRef.current && !isAirborne) {
      window.dispatchEvent(new CustomEvent("observatory:shake", { detail: { intensity: 0.7 } }));
    }
    wasAirborneRef.current = isAirborne;
    const nextWorldState: ObservatoryPlayerWorldState = {
      interactableAssetId: interactableProp?.assetId ?? null,
      stationId: nextState.stationId,
    };
    if (
      nextWorldState.interactableAssetId !== lastWorldStateRef.current?.interactableAssetId
      || nextWorldState.stationId !== lastWorldStateRef.current?.stationId
    ) {
      lastWorldStateRef.current = nextWorldState;
      onWorldStateChange?.(nextWorldState);
    }
    if (body && nextState.grounded) {
      const jumpBoost = resolveJumpPadBoostFromQuery(groundQuery, nextState.position);
      if (jumpBoost != null && nowMs >= jumpPadCooldownUntilRef.current) {
        jumpPadCooldownUntilRef.current = nowMs + 850;
        body.setLinvel(
          {
            x: stepResult.command.linearVelocity[0],
            y: jumpBoost,
            z: stepResult.command.linearVelocity[2],
          },
          true,
        );
      }
    }
    if (body) {
      const translation = body.translation();
      const bodyVelocity = body.linvel();
      const groundHeight = resolveGroundHeightFromQuery(
        groundQuery,
        [translation.x, translation.y, translation.z],
        groundScratchRef.current,
      );
      const minBodyY = groundHeight + PLAYER_STAND_HEIGHT;
      const hoverGap = translation.y - minBodyY;
      if (
        shouldAdhereObservatoryPlayerToGround({
          activeFlip: nextState.activeFlip != null,
          hoverGap,
          jumpQueued: intent.jump,
          verticalVelocityY: bodyVelocity.y,
        })
      ) {
        body.setTranslation({ x: translation.x, y: minBodyY, z: translation.z }, true);
        body.setLinvel({ x: bodyVelocity.x, y: 0, z: bodyVelocity.z }, true);
      } else if (translation.y < minBodyY - 0.14 && bodyVelocity.y < 0) {
        body.setTranslation({ x: translation.x, y: minBodyY, z: translation.z }, true);
        body.setLinvel({ x: bodyVelocity.x, y: 0, z: bodyVelocity.z }, true);
      }
    }
    if (intent.interact && interactableProp) {
      onInteractProp?.(interactableProp, { source: "player" });
    }
    if (intent.jump || intent.flipBack || intent.flipFront || intent.interact) {
      consumeTransientActions();
    }
  });

  const playerCollider = useMemo(
    () =>
      createObservatoryPlayerCapsuleCollider(
        spawn,
        PLAYER_COLLIDER_HALF_HEIGHT,
        PLAYER_COLLIDER_RADIUS,
      ),
    [spawn],
  );

  return (
    <>
      <RigidBody
        ref={bodyRef}
        canSleep={false}
        ccd
        colliders={false}
        enabledRotations={[false, false, false]}
        linearDamping={2.8}
        lockRotations
        position={spawn.position}
        type="dynamic"
      >
        <CapsuleCollider
          args={[
            playerCollider.shape.kind === "capsule" ? playerCollider.shape.halfHeight : 0.46,
            playerCollider.shape.kind === "capsule" ? playerCollider.shape.radius : 0.34,
          ]}
          friction={playerCollider.friction}
          restitution={playerCollider.restitution}
        />
      </RigidBody>
      <ObservatoryPlayerAvatar
        accentColor={world.core.accentColor}
        animationAssetUrls={OBSERVATORY_ASTRONAUT_OPERATOR_ANIMATION_URLS}
        assetUrl={OBSERVATORY_ASTRONAUT_OPERATOR_ASSET_URL}
        bodyColor="#0f1926"
        controllerState={runtime.state}
        materialSourceUrl={OBSERVATORY_ASTRONAUT_OPERATOR_TEXTURE_SOURCE_URL}
        positionOffset={[0, -0.8, 0]}
        scale={1.48}
        trimColor="#e9d48c"
        visorColor="#c8fbff"
      />
      {enableCharacterVfx ? (
        <Suspense fallback={null}>
          <LazyCharacterVfx
            position={runtime.state.position}
            grounded={runtime.state.grounded}
            sprinting={runtime.state.sprinting}
            activeAction={runtime.state.activeAction}
            facingRadians={runtime.state.facingRadians}
          />
        </Suspense>
      ) : null}
    </>
  );
}
