// Ported verbatim from huntronomer apps/desktop/src/features/hunt-observatory/character/types.ts
// Import remapped: ../types → ../../world/types (workbench world types path)

import type { HuntStationId, HuntStationPlacement } from "../world/types";

export type ObservatoryVec2 = [number, number];
export type ObservatoryVec3 = [number, number, number];

export type ObservatoryPlayerAction =
  | "idle"
  | "walk"
  | "run"
  | "jump-start"
  | "jump-air"
  | "land"
  | "flip-front"
  | "flip-back";

export type ObservatoryPlayerFlipKind = "front" | "back";

export interface ObservatoryPlayerIntent {
  moveX: number;
  moveY: number;
  jump: boolean;
  flipFront: boolean;
  flipBack: boolean;
  interact: boolean;
  sprint: boolean;
}

export interface ObservatoryPlayerBindings {
  moveForward: string[];
  moveBackward: string[];
  moveLeft: string[];
  moveRight: string[];
  sprint: string[];
  jump: string[];
  flipFront: string[];
  flipBack: string[];
  interact: string[];
}

export interface ObservatoryPlayerKeyState {
  pressed: Set<string>;
  jumpQueued: boolean;
  flipFrontQueued: boolean;
  flipBackQueued: boolean;
  interactQueued: boolean;
  lastJumpPressedAtMs: number | null;
}

export interface ObservatoryPlayerState {
  position: ObservatoryVec3;
  velocity: ObservatoryVec3;
  grounded: boolean;
  activeAction: ObservatoryPlayerAction;
  facingRadians: number;
  stationId: HuntStationId | null;
  moveVector: ObservatoryVec2;
  moveMagnitude: number;
  sprinting: boolean;
  activeFlip: ObservatoryPlayerFlipKind | null;
  spawnedFrom: string | null;
  airborneTimeMs: number;
  lastGroundedAtMs: number;
  lastJumpAtMs: number | null;
  jumpBufferUntilMs: number | null;
  landUntilMs: number | null;
  flipEndsAtMs: number | null;
}

export interface ObservatoryPlayerConfig {
  walkSpeed: number;
  sprintMultiplier: number;
  groundAcceleration: number;
  airAcceleration: number;
  jumpVelocity: number;
  gravity: number;
  maxFallSpeed: number;
  coyoteTimeMs: number;
  jumpBufferMs: number;
  flipDurationMs: number;
  flipWindowMs: number;
  flipForwardBoost: number;
  flipBackwardBoost: number;
  turnLerp: number;
  landLockMs: number;
}

export interface ObservatoryPlayerBodySnapshot {
  position: ObservatoryVec3;
  velocity: ObservatoryVec3;
  grounded: boolean;
  stationId?: HuntStationId | null;
}

export interface ObservatoryPlayerStepContext {
  deltaSeconds: number;
  nowMs: number;
  cameraYawRadians?: number | null;
  nearbyStationId?: HuntStationId | null;
  body?: ObservatoryPlayerBodySnapshot | null;
}

export interface ObservatoryPlayerCommand {
  translation: ObservatoryVec3;
  linearVelocity: ObservatoryVec3;
  facingRadians: number;
  activeAction: ObservatoryPlayerAction;
  stationId: HuntStationId | null;
}

export interface ObservatoryPlayerStepResult {
  state: ObservatoryPlayerState;
  command: ObservatoryPlayerCommand;
}

export interface ObservatoryPlayerBodyAdapter {
  readSnapshot: () => ObservatoryPlayerBodySnapshot | null;
  applyCommand?: (command: ObservatoryPlayerCommand) => void;
}

export interface ObservatoryPlayerSpawnPoint {
  id: string;
  label: string;
  position: ObservatoryVec3;
  facingRadians: number;
  stationId: HuntStationId | null;
}

export type ObservatoryColliderShape =
  | { kind: "box"; halfExtents: ObservatoryVec3 }
  | { kind: "capsule"; halfHeight: number; radius: number }
  | { kind: "cylinder"; halfHeight: number; radius: number };

export interface ObservatoryColliderSpec {
  id: string;
  translation: ObservatoryVec3;
  rotationEuler?: ObservatoryVec3;
  friction?: number;
  restitution?: number;
  sensor?: boolean;
  userData?: Record<string, string | number | boolean | null>;
  shape: ObservatoryColliderShape;
}

export interface ObservatorySpawnResolutionOptions {
  baseHeight?: number;
  radialOffset?: number;
}

export interface ObservatoryBoundaryColliderOptions {
  arenaRadius?: number;
  wallHeight?: number;
  wallThickness?: number;
  floorThickness?: number;
}

export interface ObservatoryStationPlateOptions {
  radius?: number;
  halfHeight?: number;
  y?: number;
}

export interface ObservatoryPlayerControllerOptions {
  config?: Partial<ObservatoryPlayerConfig>;
  spawn?: ObservatoryPlayerSpawnPoint | null;
  bodyAdapter?: ObservatoryPlayerBodyAdapter | null;
}

export interface ObservatoryPlayerRuntimeApi {
  readonly state: ObservatoryPlayerState;
  readonly config: ObservatoryPlayerConfig;
  readonly spawn: ObservatoryPlayerSpawnPoint;
  readonly lastCommand: ObservatoryPlayerCommand | null;
  reset: (spawn?: ObservatoryPlayerSpawnPoint | null) => ObservatoryPlayerState;
  step: (intent: ObservatoryPlayerIntent, context: ObservatoryPlayerStepContext) => ObservatoryPlayerStepResult;
}

export const DEFAULT_OBSERVATORY_PLAYER_BINDINGS: ObservatoryPlayerBindings = {
  moveForward: ["KeyW", "ArrowUp"],
  moveBackward: ["KeyS", "ArrowDown"],
  moveLeft: ["KeyA", "ArrowLeft"],
  moveRight: ["KeyD", "ArrowRight"],
  sprint: ["ShiftLeft", "ShiftRight"],
  jump: ["Space"],
  flipFront: ["KeyQ"],
  flipBack: ["KeyE"],
  interact: ["KeyF"],
};

export const DEFAULT_OBSERVATORY_PLAYER_CONFIG: ObservatoryPlayerConfig = {
  walkSpeed: 4.4,
  sprintMultiplier: 1.55,
  groundAcceleration: 14,
  airAcceleration: 6,
  jumpVelocity: 6.8,
  gravity: 18,
  maxFallSpeed: 18,
  coyoteTimeMs: 140,
  jumpBufferMs: 120,
  flipDurationMs: 760,
  flipWindowMs: 280,
  flipForwardBoost: 3.6,
  flipBackwardBoost: 3.15,
  turnLerp: 14,
  landLockMs: 120,
};

export const DEFAULT_OBSERVATORY_PLAYER_SPAWN: ObservatoryPlayerSpawnPoint = {
  id: "thesis-core",
  label: "Thesis Core",
  position: [0, 1.18, 6.6],
  facingRadians: Math.PI,
  stationId: null,
};

export function createEmptyObservatoryPlayerIntent(): ObservatoryPlayerIntent {
  return {
    moveX: 0,
    moveY: 0,
    jump: false,
    flipFront: false,
    flipBack: false,
    interact: false,
    sprint: false,
  };
}

export function createEmptyObservatoryPlayerKeyState(): ObservatoryPlayerKeyState {
  return {
    pressed: new Set<string>(),
    jumpQueued: false,
    flipFrontQueued: false,
    flipBackQueued: false,
    interactQueued: false,
    lastJumpPressedAtMs: null,
  };
}

export function createInitialObservatoryPlayerState(
  spawn: ObservatoryPlayerSpawnPoint = DEFAULT_OBSERVATORY_PLAYER_SPAWN,
): ObservatoryPlayerState {
  return {
    position: [...spawn.position],
    velocity: [0, 0, 0],
    grounded: true,
    activeAction: "idle",
    facingRadians: spawn.facingRadians,
    stationId: spawn.stationId,
    moveVector: [0, 0],
    moveMagnitude: 0,
    sprinting: false,
    activeFlip: null,
    spawnedFrom: spawn.id,
    airborneTimeMs: 0,
    lastGroundedAtMs: 0,
    lastJumpAtMs: null,
    jumpBufferUntilMs: null,
    landUntilMs: null,
    flipEndsAtMs: null,
  };
}

export function mergeObservatoryPlayerConfig(
  overrides: Partial<ObservatoryPlayerConfig> = {},
): ObservatoryPlayerConfig {
  return {
    ...DEFAULT_OBSERVATORY_PLAYER_CONFIG,
    ...overrides,
  };
}

export function buildStationSpawnPoint(
  placement: HuntStationPlacement,
  options: ObservatorySpawnResolutionOptions = {},
): ObservatoryPlayerSpawnPoint {
  const radialOffset = options.radialOffset ?? 1.4;
  const angleRadians = (placement.angleDeg * Math.PI) / 180;
  const radius = Math.max(placement.radius - radialOffset, radialOffset + 1.2);
  const x = Math.cos(angleRadians) * radius;
  const z = Math.sin(angleRadians) * radius;
  return {
    id: `station:${placement.id}`,
    label: placement.label,
    position: [x, options.baseHeight ?? 1.18, z],
    facingRadians: angleRadians + Math.PI,
    stationId: placement.id,
  };
}
