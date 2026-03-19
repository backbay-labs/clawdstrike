// Ported verbatim from huntronomer apps/desktop/src/features/hunt-observatory/character/animation/moveSet.ts
// Import remapped: ../types → ../types (same relative path since we're one level deeper)

import type { ObservatoryPlayerState } from "../types";

export const OBSERVATORY_PLAYER_VISUAL_ACTIONS = [
  "idle",
  "walk",
  "run",
  "jump",
  "land",
  "front-flip",
  "back-flip",
] as const;

export type ObservatoryPlayerVisualAction =
  (typeof OBSERVATORY_PLAYER_VISUAL_ACTIONS)[number];

export interface ObservatoryPlayerMoveSpec {
  id: ObservatoryPlayerVisualAction;
  clipCandidates: readonly string[];
  durationSeconds: number;
  oneShot: boolean;
  presentation?: {
    rootLift?: number;
    rootScale?: [number, number, number];
    spinTurns?: number;
    tuckStrength?: number;
  };
  physics?: {
    backwardBoostScale?: number;
    forwardBoostScale?: number;
    minVerticalVelocityScale?: number;
  };
}

export type ObservatoryPlayerPositionTuple = ObservatoryPlayerState["position"];

export type ObservatoryPlayerControllerStateLike = Pick<
  ObservatoryPlayerState,
  "position" | "velocity" | "grounded" | "facingRadians"
> & {
  activeAction?: string | null;
  sprinting?: boolean;
};

export interface ObservatoryPlayerActionResolutionContext {
  previousGrounded?: boolean;
  landTimerSeconds?: number;
}

export interface ObservatoryPlayerActionResolution {
  action: ObservatoryPlayerVisualAction;
  horizontalSpeed: number;
  verticalSpeed: number;
  landTimerSeconds: number;
  usedFallbackAction: boolean;
}

export interface ObservatoryPlayerPose {
  rootOffsetY: number;
  rootScale: [number, number, number];
  bodySpinX: number;
  torsoPitch: number;
  torsoRoll: number;
  headPitch: number;
  headRoll: number;
  leftArmPitch: number;
  rightArmPitch: number;
  leftArmRoll: number;
  rightArmRoll: number;
  leftLegPitch: number;
  rightLegPitch: number;
  leftKneePitch: number;
  rightKneePitch: number;
  leftFootPitch: number;
  rightFootPitch: number;
  backpackPitch: number;
  shellPulse: number;
}

export const OBSERVATORY_PLAYER_MOVE_SPECS = {
  idle: {
    id: "idle",
    clipCandidates: ["idle", "idle-loop", "breathing-idle", "clip0", "base"],
    durationSeconds: 1.2,
    oneShot: false,
    presentation: {
      rootLift: 0.026,
      rootScale: [1, 1, 1],
      tuckStrength: 0,
    },
  },
  walk: {
    id: "walk",
    clipCandidates: ["walk", "walk-forward", "jog", "walking", "walking-man"],
    durationSeconds: 0.78,
    oneShot: false,
    presentation: {
      rootLift: 0.08,
      rootScale: [1, 1, 1],
      tuckStrength: 0.1,
    },
  },
  run: {
    id: "run",
    clipCandidates: ["run", "sprint", "run-forward", "running"],
    durationSeconds: 0.52,
    oneShot: false,
    presentation: {
      rootLift: 0.12,
      rootScale: [1.02, 0.98, 1.02],
      tuckStrength: 0.12,
    },
  },
  jump: {
    id: "jump",
    clipCandidates: ["jump", "jump-start", "jump-air", "air", "fall"],
    durationSeconds: 0.6,
    oneShot: false,
    presentation: {
      rootLift: 0.22,
      rootScale: [1, 1, 1],
      tuckStrength: 0.86,
    },
  },
  land: {
    id: "land",
    clipCandidates: ["land", "landing", "jump-land", "jump-end", "idle"],
    durationSeconds: 0.18,
    oneShot: true,
    presentation: {
      rootLift: -0.16,
      rootScale: [1.04, 0.88, 1.04],
      tuckStrength: 0.2,
    },
  },
  "front-flip": {
    id: "front-flip",
    clipCandidates: ["front-flip", "frontflip", "flip-front", "front_flip", "flip"],
    durationSeconds: 0.72,
    oneShot: true,
    presentation: {
      rootLift: 0.3,
      rootScale: [1.03, 0.94, 1.03],
      spinTurns: -1.15,
      tuckStrength: 1.18,
    },
    physics: {
      forwardBoostScale: 1,
      minVerticalVelocityScale: 0.82,
    },
  },
  "back-flip": {
    id: "back-flip",
    clipCandidates: ["back-flip", "backflip", "flip-back", "back_flip", "flip"],
    durationSeconds: 0.72,
    oneShot: true,
    presentation: {
      rootLift: 0.26,
      rootScale: [1.02, 0.95, 1.02],
      spinTurns: 1.05,
      tuckStrength: 1.08,
    },
    physics: {
      backwardBoostScale: 1,
      minVerticalVelocityScale: 0.76,
    },
  },
} as const satisfies Record<ObservatoryPlayerVisualAction, ObservatoryPlayerMoveSpec>;

export const OBSERVATORY_PLAYER_ACTION_DURATIONS = Object.fromEntries(
  Object.entries(OBSERVATORY_PLAYER_MOVE_SPECS).map(([key, spec]) => [key, spec.durationSeconds]),
) as unknown as Record<ObservatoryPlayerVisualAction, number>;

export const OBSERVATORY_PLAYER_CLIP_CANDIDATES = Object.fromEntries(
  Object.entries(OBSERVATORY_PLAYER_MOVE_SPECS).map(([key, spec]) => [key, spec.clipCandidates]),
) as unknown as Record<ObservatoryPlayerVisualAction, readonly string[]>;

export function getObservatoryPlayerMoveSpec(
  action: ObservatoryPlayerVisualAction,
): ObservatoryPlayerMoveSpec {
  return OBSERVATORY_PLAYER_MOVE_SPECS[action];
}
