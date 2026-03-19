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
    durationSeconds: 0.30,
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

const WALK_SPEED_THRESHOLD = 0.3;
const RUN_SPEED_THRESHOLD = 2.2;
const LAND_HOLD_SECONDS = OBSERVATORY_PLAYER_ACTION_DURATIONS.land;

export function getObservatoryPlayerMoveSpec(
  action: ObservatoryPlayerVisualAction,
): ObservatoryPlayerMoveSpec {
  return OBSERVATORY_PLAYER_MOVE_SPECS[action];
}

const DEFAULT_POSE: ObservatoryPlayerPose = {
  rootOffsetY: 0,
  rootScale: [1, 1, 1],
  bodySpinX: 0,
  torsoPitch: 0,
  torsoRoll: 0,
  headPitch: 0,
  headRoll: 0,
  leftArmPitch: 0,
  rightArmPitch: 0,
  leftArmRoll: 0,
  rightArmRoll: 0,
  leftLegPitch: 0,
  rightLegPitch: 0,
  leftKneePitch: 0.08,
  rightKneePitch: 0.08,
  leftFootPitch: 0,
  rightFootPitch: 0,
  backpackPitch: 0,
  shellPulse: 0,
};

export function mapControllerActionToVisualAction(
  activeAction?: string | null,
): ObservatoryPlayerVisualAction | null {
  const normalized = normalizeActionToken(activeAction);

  if (!normalized) {
    return null;
  }

  switch (normalized) {
    case "idle":
    case "walk":
    case "run":
    case "jump":
    case "land":
    case "front-flip":
    case "back-flip":
      return normalized;
    case "jump-start":
    case "jump-air":
      return "jump";
    case "flip-front":
      return "front-flip";
    case "flip-back":
      return "back-flip";
    default:
      return null;
  }
}

export function resolveObservatoryPlayerAction(
  state: ObservatoryPlayerControllerStateLike,
  context: ObservatoryPlayerActionResolutionContext = {},
): ObservatoryPlayerActionResolution {
  const horizontalSpeed = Math.hypot(state.velocity[0], state.velocity[2]);
  const verticalSpeed = state.velocity[1];
  const explicitAction = mapControllerActionToVisualAction(state.activeAction);

  if (explicitAction) {
    return {
      action: explicitAction,
      horizontalSpeed,
      verticalSpeed,
      landTimerSeconds:
        explicitAction === "land"
          ? LAND_HOLD_SECONDS
          : Math.max(0, context.landTimerSeconds ?? 0),
      usedFallbackAction: false,
    };
  }

  let landTimerSeconds = Math.max(0, context.landTimerSeconds ?? 0);

  if (context.previousGrounded === false && state.grounded) {
    landTimerSeconds = LAND_HOLD_SECONDS;
  }

  if (!state.grounded) {
    return {
      action: "jump",
      horizontalSpeed,
      verticalSpeed,
      landTimerSeconds,
      usedFallbackAction: true,
    };
  }

  if (landTimerSeconds > 0) {
    return {
      action: "land",
      horizontalSpeed,
      verticalSpeed,
      landTimerSeconds,
      usedFallbackAction: true,
    };
  }

  if (
    horizontalSpeed >= RUN_SPEED_THRESHOLD ||
    Boolean(state.sprinting && horizontalSpeed >= WALK_SPEED_THRESHOLD)
  ) {
    return {
      action: "run",
      horizontalSpeed,
      verticalSpeed,
      landTimerSeconds,
      usedFallbackAction: true,
    };
  }

  if (horizontalSpeed >= WALK_SPEED_THRESHOLD) {
    return {
      action: "walk",
      horizontalSpeed,
      verticalSpeed,
      landTimerSeconds,
      usedFallbackAction: true,
    };
  }

  return {
    action: "idle",
    horizontalSpeed,
    verticalSpeed,
    landTimerSeconds,
    usedFallbackAction: true,
  };
}

export function resolveObservatoryActionClipName(
  action: ObservatoryPlayerVisualAction,
  availableClipNames: readonly string[],
): string | null {
  const normalizedByOriginal = new Map(
    availableClipNames.map((name) => [normalizeActionToken(name), name] as const),
  );
  const candidates = OBSERVATORY_PLAYER_CLIP_CANDIDATES[action];

  for (const candidate of candidates) {
    const match = normalizedByOriginal.get(normalizeActionToken(candidate));

    if (match) {
      return match;
    }
  }

  const normalizedClipEntries = availableClipNames.map((name) => ({
    name,
    normalized: normalizeActionToken(name),
  }));

  for (const candidate of candidates) {
    const normalizedCandidate = normalizeActionToken(candidate);
    const partial = normalizedClipEntries.find(
      (entry) =>
        entry.normalized.includes(normalizedCandidate) ||
        normalizedCandidate.includes(entry.normalized),
    );

    if (partial) {
      return partial.name;
    }
  }

  return null;
}

export function sampleObservatoryPlayerPose(input: {
  action: ObservatoryPlayerVisualAction;
  elapsedSeconds: number;
  horizontalSpeed: number;
}): ObservatoryPlayerPose {
  const elapsedSeconds = Math.max(0, input.elapsedSeconds);
  const speedFactor = clamp(
    input.horizontalSpeed <= 0 ? 0 : input.horizontalSpeed / RUN_SPEED_THRESHOLD,
    0,
    1.35,
  );

  switch (input.action) {
    case "walk":
      return sampleWalkPose(elapsedSeconds, clamp(speedFactor, 0.45, 0.88));
    case "run":
      return sampleRunPose(elapsedSeconds, clamp(speedFactor, 0.8, 1.2));
    case "jump":
      return sampleJumpPose(elapsedSeconds);
    case "land":
      return sampleLandPose(elapsedSeconds);
    case "front-flip":
      return sampleFlipPose(elapsedSeconds, -1);
    case "back-flip":
      return sampleFlipPose(elapsedSeconds, 1);
    case "idle":
    default:
      return sampleIdlePose(elapsedSeconds);
  }
}

function sampleIdlePose(elapsedSeconds: number): ObservatoryPlayerPose {
  const sway = Math.sin(elapsedSeconds * 1.35);
  const pulse = Math.sin(elapsedSeconds * 2.2) * 0.5 + 0.5;

  return {
    ...DEFAULT_POSE,
    rootOffsetY: Math.sin(elapsedSeconds * 2.2) * 0.026,
    torsoPitch: 0.06 + sway * 0.015,
    torsoRoll: sway * 0.05,
    headPitch: -0.03 + Math.sin(elapsedSeconds * 1.8) * 0.012,
    headRoll: sway * 0.03,
    leftArmPitch: -0.18 + sway * 0.08,
    rightArmPitch: -0.16 - sway * 0.08,
    leftArmRoll: -0.1,
    rightArmRoll: 0.1,
    leftLegPitch: 0.04,
    rightLegPitch: -0.04,
    backpackPitch: 0.04 + pulse * 0.02,
    shellPulse: pulse * 0.28,
  };
}

function sampleWalkPose(
  elapsedSeconds: number,
  strideFactor: number,
): ObservatoryPlayerPose {
  const cycle = elapsedSeconds * (5.8 + strideFactor * 1.4);
  const swing = Math.sin(cycle) * 0.72 * strideFactor;
  const lift = Math.abs(Math.sin(cycle)) * 0.08 * strideFactor;
  const knee = Math.max(0, Math.sin(cycle + Math.PI * 0.5)) * 0.38;

  return {
    ...DEFAULT_POSE,
    rootOffsetY: lift,
    torsoPitch: -0.11,
    torsoRoll: Math.sin(cycle * 0.5) * 0.05,
    headPitch: 0.03,
    headRoll: -Math.sin(cycle * 0.5) * 0.025,
    leftArmPitch: -swing,
    rightArmPitch: swing,
    leftArmRoll: -0.18,
    rightArmRoll: 0.18,
    leftLegPitch: swing * 1.18,
    rightLegPitch: -swing * 1.18,
    leftKneePitch: 0.14 + knee,
    rightKneePitch: 0.14 + Math.max(0, -Math.sin(cycle + Math.PI * 0.5)) * 0.38,
    leftFootPitch: -Math.max(0, swing) * 0.22,
    rightFootPitch: Math.min(0, swing) * 0.22,
    backpackPitch: 0.08 + lift * 0.3,
    shellPulse: 0.32 + lift * 1.7,
  };
}

function sampleRunPose(elapsedSeconds: number, strideFactor: number): ObservatoryPlayerPose {
  const cycle = elapsedSeconds * (8.6 + strideFactor * 2.4);
  const swing = Math.sin(cycle) * 1.06 * strideFactor;
  const lift = Math.abs(Math.sin(cycle)) * 0.12 * strideFactor;

  return {
    ...DEFAULT_POSE,
    rootOffsetY: lift,
    rootScale: [1.02, 0.98, 1.02],
    torsoPitch: -0.22,
    torsoRoll: Math.sin(cycle * 0.5) * 0.08,
    headPitch: 0.08,
    headRoll: -Math.sin(cycle * 0.5) * 0.035,
    leftArmPitch: -swing * 1.18,
    rightArmPitch: swing * 1.18,
    leftArmRoll: -0.26,
    rightArmRoll: 0.26,
    leftLegPitch: swing * 1.3,
    rightLegPitch: -swing * 1.3,
    leftKneePitch: 0.18 + Math.abs(Math.sin(cycle + Math.PI * 0.5)) * 0.52,
    rightKneePitch: 0.18 + Math.abs(Math.sin(cycle - Math.PI * 0.5)) * 0.52,
    leftFootPitch: -Math.max(0, swing) * 0.28,
    rightFootPitch: Math.min(0, swing) * 0.28,
    backpackPitch: 0.12 + lift * 0.42,
    shellPulse: 0.46 + lift * 1.9,
  };
}

function sampleJumpPose(elapsedSeconds: number): ObservatoryPlayerPose {
  const moveSpec = getObservatoryPlayerMoveSpec("jump");
  const progress = clamp(elapsedSeconds / moveSpec.durationSeconds, 0, 1);
  const arc = Math.sin(progress * Math.PI);
  const tuck =
    (progress < 0.45 ? progress / 0.45 : 1 - (progress - 0.45) / 0.55) *
    (moveSpec.presentation?.tuckStrength ?? 1);

  return {
    ...DEFAULT_POSE,
    rootOffsetY: 0.04 + arc * (moveSpec.presentation?.rootLift ?? 0.18),
    torsoPitch: -0.24,
    headPitch: 0.08,
    leftArmPitch: -1.05,
    rightArmPitch: -1.05,
    leftArmRoll: -0.22,
    rightArmRoll: 0.22,
    leftLegPitch: 0.14 + tuck * 0.86,
    rightLegPitch: 0.14 + tuck * 0.86,
    leftKneePitch: 0.42 + tuck * 0.44,
    rightKneePitch: 0.42 + tuck * 0.44,
    leftFootPitch: -0.08,
    rightFootPitch: -0.08,
    backpackPitch: 0.16,
    shellPulse: 0.58,
  };
}

function sampleLandPose(elapsedSeconds: number): ObservatoryPlayerPose {
  const moveSpec = getObservatoryPlayerMoveSpec("land");
  const progress = clamp(elapsedSeconds / moveSpec.durationSeconds, 0, 1);

  const COMPRESS_Y = 0.74;
  const COMPRESS_PHASE = 0.35; // first 35% = compress down

  let scaleY: number;
  if (progress < COMPRESS_PHASE) {
    const t = progress / COMPRESS_PHASE;
    scaleY = 1 + (COMPRESS_Y - 1) * easeOutQuad(t);
  } else {
    const t = (progress - COMPRESS_PHASE) / (1 - COMPRESS_PHASE);
    scaleY = COMPRESS_Y + (1 - COMPRESS_Y) * easeOutBack(t);
  }

  // Volume-conserving XZ expansion: scaleX = scaleZ = 1 / sqrt(scaleY)
  const scaleXZ = 1 / Math.sqrt(Math.max(scaleY, 0.01));

  // rootOffsetY: compress down proportional to squash depth, recover with same easing
  const compressionDepth = Math.abs(moveSpec.presentation?.rootLift ?? -0.16);
  const compression =
    progress < COMPRESS_PHASE
      ? compressionDepth * easeOutQuad(progress / COMPRESS_PHASE)
      : compressionDepth *
        (1 - easeOutBack((progress - COMPRESS_PHASE) / (1 - COMPRESS_PHASE)));

  const impact = 1 - progress;

  return {
    ...DEFAULT_POSE,
    rootOffsetY: -clamp(compression, 0, compressionDepth),
    rootScale: [scaleXZ, scaleY, scaleXZ],
    torsoPitch: -0.28 * impact,
    torsoRoll: 0,
    headPitch: 0.1 * impact,
    leftArmPitch: 0.18 + impact * 0.22,
    rightArmPitch: 0.18 + impact * 0.22,
    leftArmRoll: -0.18,
    rightArmRoll: 0.18,
    leftLegPitch: -0.12,
    rightLegPitch: -0.12,
    leftKneePitch: 0.68 * impact + 0.18,
    rightKneePitch: 0.68 * impact + 0.18,
    backpackPitch: 0.1 + impact * 0.08,
    shellPulse: 0.42 + impact * 0.2,
  };
}

function sampleFlipPose(
  elapsedSeconds: number,
  direction: -1 | 1,
): ObservatoryPlayerPose {
  const moveSpec = getObservatoryPlayerMoveSpec(
    direction === -1 ? "front-flip" : "back-flip",
  );
  const duration = moveSpec.durationSeconds;
  const progress = clamp(elapsedSeconds / duration, 0, 1);
  const tuckStrength = moveSpec.presentation?.tuckStrength ?? 1;
  const tuck =
    progress < 0.5
      ? (progress / 0.5) * tuckStrength
      : tuckStrength * (1 - easeOutBack((progress - 0.5) / 0.5));
  const eased = easeFlipProgress(progress);
  const spinTurns = moveSpec.presentation?.spinTurns ?? direction;

  return {
    ...DEFAULT_POSE,
    rootOffsetY: 0.05 + Math.sin(progress * Math.PI) * (moveSpec.presentation?.rootLift ?? 0.24),
    rootScale: moveSpec.presentation?.rootScale ?? [1.02, 0.96, 1.02],
    bodySpinX: eased * Math.PI * 2 * spinTurns,
    torsoPitch: 0.04,
    headPitch: -0.08,
    leftArmPitch: -0.42 - tuck * 1.06,
    rightArmPitch: -0.42 - tuck * 1.06,
    leftArmRoll: -0.2,
    rightArmRoll: 0.2,
    leftLegPitch: 0.22 + tuck * 0.98,
    rightLegPitch: 0.22 + tuck * 0.98,
    leftKneePitch: 0.48 + tuck * 0.5,
    rightKneePitch: 0.48 + tuck * 0.5,
    leftFootPitch: -0.16,
    rightFootPitch: -0.16,
    backpackPitch: 0.18 + tuck * 0.2,
    shellPulse: 0.66 + tuck * 0.16,
  };
}

function normalizeActionToken(action?: string | null): string {
  return action?.trim().toLowerCase().replace(/[|_:\s]+/g, "-") ?? "";
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function easeOutQuad(x: number): number {
  return 1 - (1 - x) * (1 - x);
}

function easeOutBack(x: number): number {
  const c1 = 1.70158;
  const c3 = c1 + 1; // 2.70158
  return 1 + c3 * Math.pow(x - 1, 3) + c1 * Math.pow(x - 1, 2);
}

function easeFlipProgress(t: number): number {
  if (t < 0.6) {
    const t2 = t / 0.6;
    return 0.6 * (t2 * t2 * t2);
  }
  const t2 = (t - 0.6) / 0.4;
  return 0.6 + 0.4 * easeOutBack(t2);
}

function easeInOutCubic(value: number): number {
  if (value < 0.5) {
    return 4 * value * value * value;
  }

  return 1 - Math.pow(-2 * value + 2, 3) / 2;
}
