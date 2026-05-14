// Ported verbatim from huntronomer apps/desktop/src/features/hunt-observatory/character/controller/runtime.ts
// Import remapped: ../types → ../types (character types), ../animation/moveSet → ../animation/moveSet

import {
  createInitialObservatoryPlayerState,
  DEFAULT_OBSERVATORY_PLAYER_SPAWN,
  mergeObservatoryPlayerConfig,
  type ObservatoryPlayerAction,
  type ObservatoryPlayerBodySnapshot,
  type ObservatoryPlayerCommand,
  type ObservatoryPlayerConfig,
  type ObservatoryPlayerFlipKind,
  type ObservatoryPlayerIntent,
  type ObservatoryPlayerSpawnPoint,
  type ObservatoryPlayerState,
  type ObservatoryPlayerStepContext,
  type ObservatoryPlayerStepResult,
  type ObservatoryVec2,
} from "../types";
import { getObservatoryPlayerMoveSpec } from "../animation/moveSet";

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function expLerp(current: number, target: number, speed: number, deltaSeconds: number): number {
  const alpha = 1 - Math.exp(-speed * deltaSeconds);
  return current + (target - current) * alpha;
}

function normalizeMoveVector(x: number, y: number): ObservatoryVec2 {
  const magnitude = Math.hypot(x, y);
  if (magnitude <= 1e-5) return [0, 0];
  return [x / magnitude, y / magnitude];
}

function rotateMoveVector(move: ObservatoryVec2, yawRadians = 0): ObservatoryVec2 {
  const [x, y] = move;
  const forwardX = Math.sin(yawRadians);
  const forwardZ = Math.cos(yawRadians);
  const rightX = -forwardZ;
  const rightZ = forwardX;
  return [
    rightX * x + forwardX * y,
    rightZ * x + forwardZ * y,
  ];
}

function movementFacingRadians(direction: ObservatoryVec2): number {
  return Math.atan2(direction[0], direction[1]);
}

function shortestAngleDelta(from: number, to: number): number {
  let delta = (to - from) % (Math.PI * 2);
  if (delta > Math.PI) delta -= Math.PI * 2;
  if (delta < -Math.PI) delta += Math.PI * 2;
  return delta;
}

function forwardVector(facingRadians: number): ObservatoryVec2 {
  return [Math.sin(facingRadians), Math.cos(facingRadians)];
}

function createSnapshotFromState(state: ObservatoryPlayerState): ObservatoryPlayerBodySnapshot {
  return {
    position: [...state.position],
    velocity: [...state.velocity],
    grounded: state.grounded,
    stationId: state.stationId,
  };
}

function resolveAction(
  previous: ObservatoryPlayerState,
  grounded: boolean,
  nowMs: number,
  lastJumpAtMs: number | null,
  movementMagnitude: number,
  sprinting: boolean,
  activeFlip: ObservatoryPlayerFlipKind | null,
  velocityY: number,
): ObservatoryPlayerAction {
  if (activeFlip === "front") return "flip-front";
  if (activeFlip === "back") return "flip-back";
  if (!grounded) {
    if (lastJumpAtMs != null && nowMs - lastJumpAtMs <= 140) {
      return "jump-start";
    }
    return "jump-air";
  }
  if (!previous.grounded || (previous.landUntilMs != null && previous.landUntilMs > nowMs)) {
    return "land";
  }
  if (movementMagnitude > 0.14) {
    return sprinting ? "run" : "walk";
  }
  if (Math.abs(velocityY) > 0.12) {
    return "jump-air";
  }
  return "idle";
}

function applyFlipMove(
  kind: ObservatoryPlayerFlipKind,
  facingRadians: number,
  velocity: ObservatoryVec2,
  verticalVelocity: number,
  config: ObservatoryPlayerConfig,
): { velocity: ObservatoryVec2; verticalVelocity: number } {
  const moveSpec = getObservatoryPlayerMoveSpec(kind === "front" ? "front-flip" : "back-flip");
  const [fx, fz] = forwardVector(facingRadians);
  const nextVelocity: ObservatoryVec2 = [...velocity];

  if (kind === "front") {
    nextVelocity[0] += fx * config.flipForwardBoost * (moveSpec.physics?.forwardBoostScale ?? 1);
    nextVelocity[1] += fz * config.flipForwardBoost * (moveSpec.physics?.forwardBoostScale ?? 1);
  } else {
    nextVelocity[0] -= fx * config.flipBackwardBoost * (moveSpec.physics?.backwardBoostScale ?? 1);
    nextVelocity[1] -= fz * config.flipBackwardBoost * (moveSpec.physics?.backwardBoostScale ?? 1);
  }

  return {
    velocity: nextVelocity,
    verticalVelocity: Math.max(
      verticalVelocity,
      config.jumpVelocity * (moveSpec.physics?.minVerticalVelocityScale ?? 0.74),
    ),
  };
}

export function stepObservatoryPlayerState(
  previous: ObservatoryPlayerState,
  intent: ObservatoryPlayerIntent,
  context: ObservatoryPlayerStepContext,
  configInput: Partial<ObservatoryPlayerConfig> = {},
): ObservatoryPlayerStepResult {
  const config = mergeObservatoryPlayerConfig(configInput);
  const body = context.body ?? createSnapshotFromState(previous);
  const moveInput = normalizeMoveVector(intent.moveX, intent.moveY);
  const worldMove = rotateMoveVector(moveInput, context.cameraYawRadians ?? 0);
  const movementMagnitude = Math.hypot(worldMove[0], worldMove[1]);
  const grounded = body.grounded;
  let simulatedGrounded = grounded;
  const stationId = context.nearbyStationId ?? body.stationId ?? previous.stationId ?? null;
  const deltaSeconds = Math.max(0, context.deltaSeconds);
  const nowMs = context.nowMs;

  let facingRadians = previous.facingRadians;
  if (movementMagnitude > 0.08) {
    const targetFacing = movementFacingRadians(worldMove);
    const delta = shortestAngleDelta(facingRadians, targetFacing);
    facingRadians += delta * clamp(deltaSeconds * config.turnLerp, 0, 1);
  }

  const lastGroundedAtMs = grounded ? nowMs : previous.lastGroundedAtMs;
  let jumpBufferUntilMs = previous.jumpBufferUntilMs;
  if (intent.jump) {
    jumpBufferUntilMs = nowMs + config.jumpBufferMs;
  } else if (jumpBufferUntilMs != null && jumpBufferUntilMs < nowMs) {
    jumpBufferUntilMs = null;
  }

  const sprinting = grounded && movementMagnitude > 0.1 && intent.sprint;
  const targetSpeed = config.walkSpeed * (sprinting ? config.sprintMultiplier : 1);
  const targetVelocityX = worldMove[0] * targetSpeed;
  const targetVelocityZ = worldMove[1] * targetSpeed;
  const horizontalAcceleration = grounded ? config.groundAcceleration : config.airAcceleration;
  let velocityX = expLerp(body.velocity[0], targetVelocityX, horizontalAcceleration, deltaSeconds);
  let velocityZ = expLerp(body.velocity[2], targetVelocityZ, horizontalAcceleration, deltaSeconds);
  let velocityY = grounded ? Math.max(body.velocity[1], 0) : body.velocity[1] - config.gravity * deltaSeconds;
  velocityY = Math.max(-config.maxFallSpeed, velocityY);

  const withinCoyoteTime = grounded || nowMs - previous.lastGroundedAtMs <= config.coyoteTimeMs;
  const jumpBuffered = jumpBufferUntilMs != null && jumpBufferUntilMs >= nowMs;
  let lastJumpAtMs = previous.lastJumpAtMs;
  let activeFlip = previous.activeFlip;
  let flipEndsAtMs = previous.flipEndsAtMs;
  let landUntilMs = previous.landUntilMs != null && previous.landUntilMs > nowMs
    ? previous.landUntilMs
    : null;

  if (jumpBuffered && withinCoyoteTime) {
    velocityY = Math.max(config.jumpVelocity, velocityY);
    jumpBufferUntilMs = null;
    lastJumpAtMs = nowMs;
    landUntilMs = null;
    simulatedGrounded = false;
  }

  const canTriggerFlip =
    activeFlip == null &&
    ((lastJumpAtMs != null && nowMs - lastJumpAtMs <= config.flipWindowMs) || !grounded);
  const doubleJumpFrontFlip = intent.jump && !grounded && canTriggerFlip;

  if ((intent.flipFront || doubleJumpFrontFlip) && canTriggerFlip) {
    const next = applyFlipMove("front", facingRadians, [velocityX, velocityZ], velocityY, config);
    velocityX = next.velocity[0];
    velocityZ = next.velocity[1];
    velocityY = next.verticalVelocity;
    activeFlip = "front";
    flipEndsAtMs = nowMs + config.flipDurationMs;
    simulatedGrounded = false;
    if (lastJumpAtMs == null) lastJumpAtMs = nowMs;
  } else if (intent.flipBack && canTriggerFlip) {
    const next = applyFlipMove("back", facingRadians, [velocityX, velocityZ], velocityY, config);
    velocityX = next.velocity[0];
    velocityZ = next.velocity[1];
    velocityY = next.verticalVelocity;
    activeFlip = "back";
    flipEndsAtMs = nowMs + config.flipDurationMs;
    simulatedGrounded = false;
    if (lastJumpAtMs == null) lastJumpAtMs = nowMs;
  }

  if (flipEndsAtMs != null && flipEndsAtMs <= nowMs) {
    activeFlip = null;
    flipEndsAtMs = null;
  }

  if (!previous.grounded && grounded) {
    landUntilMs = nowMs + config.landLockMs;
    activeFlip = null;
    flipEndsAtMs = null;
  }

  const airborneTimeMs = simulatedGrounded ? 0 : previous.airborneTimeMs + deltaSeconds * 1000;
  const activeAction = resolveAction(
    previous,
    simulatedGrounded,
    nowMs,
    lastJumpAtMs,
    movementMagnitude,
    sprinting,
    activeFlip,
    velocityY,
  );

  const state: ObservatoryPlayerState = {
    position: [...body.position],
    velocity: [velocityX, velocityY, velocityZ],
    grounded: simulatedGrounded,
    activeAction,
    facingRadians,
    stationId,
    moveVector: [...worldMove],
    moveMagnitude: movementMagnitude,
    sprinting,
    activeFlip,
    spawnedFrom: previous.spawnedFrom,
    airborneTimeMs,
    lastGroundedAtMs,
    lastJumpAtMs,
    jumpBufferUntilMs,
    landUntilMs,
    flipEndsAtMs,
  };

  const command: ObservatoryPlayerCommand = {
    translation: [...body.position],
    linearVelocity: [...state.velocity],
    facingRadians,
    activeAction,
    stationId,
  };

  return {
    state,
    command,
  };
}

export function createObservatoryPlayerSpawnCommand(
  spawn: ObservatoryPlayerSpawnPoint = DEFAULT_OBSERVATORY_PLAYER_SPAWN,
): ObservatoryPlayerCommand {
  return {
    translation: [...spawn.position],
    linearVelocity: [0, 0, 0],
    facingRadians: spawn.facingRadians,
    activeAction: "idle",
    stationId: spawn.stationId,
  };
}

export function createObservatoryPlayerStateFromSpawn(
  spawn: ObservatoryPlayerSpawnPoint = DEFAULT_OBSERVATORY_PLAYER_SPAWN,
): ObservatoryPlayerState {
  return createInitialObservatoryPlayerState(spawn);
}
