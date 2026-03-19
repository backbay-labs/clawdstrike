import { useFrame } from "@react-three/fiber";
import { useEffect, useRef, type MutableRefObject } from "react";
import {
  AnimationMixer,
  LoopOnce,
  LoopRepeat,
  type AnimationAction,
  type AnimationClip,
  type Group,
  type Object3D,
} from "three";
import {
  getObservatoryPlayerMoveSpec,
  OBSERVATORY_PLAYER_VISUAL_ACTIONS,
  resolveObservatoryActionClipName,
  resolveObservatoryPlayerAction,
  sampleObservatoryPlayerPose,
  WALK_SPEED_THRESHOLD,
  RUN_SPEED_THRESHOLD,
  type ObservatoryPlayerActionResolution,
  type ObservatoryPlayerControllerStateLike,
  type ObservatoryPlayerVisualAction,
} from "./moveSet";

type ObservatoryClipEntry = {
  action: AnimationAction;
  clipName: string;
  oneShot: boolean;
};

export interface ObservatoryPlayerFallbackRigRefs {
  backpack: MutableRefObject<Group | null>;
  head: MutableRefObject<Group | null>;
  leftArm: MutableRefObject<Group | null>;
  leftFoot: MutableRefObject<Group | null>;
  leftLeg: MutableRefObject<Group | null>;
  rightArm: MutableRefObject<Group | null>;
  rightFoot: MutableRefObject<Group | null>;
  rightLeg: MutableRefObject<Group | null>;
  shell: MutableRefObject<Group | null>;
  torso: MutableRefObject<Group | null>;
}

export interface ObservatoryPlayerAnimationSnapshot
  extends ObservatoryPlayerActionResolution {
  actionElapsedSeconds: number;
  assetClipName: string | null;
}

export function useObservatoryPlayerAnimation({
  animatedRootRef,
  controllerState,
  fallbackRigRefs,
  modelClips,
  modelScene,
}: {
  animatedRootRef: MutableRefObject<Group | null>;
  controllerState: ObservatoryPlayerControllerStateLike;
  fallbackRigRefs: ObservatoryPlayerFallbackRigRefs;
  modelClips?: AnimationClip[];
  modelScene?: Object3D | null;
}): MutableRefObject<ObservatoryPlayerAnimationSnapshot> {
  const snapshotRef = useRef<ObservatoryPlayerAnimationSnapshot>({
    action: "idle",
    actionElapsedSeconds: 0,
    assetClipName: null,
    horizontalSpeed: 0,
    landTimerSeconds: 0,
    usedFallbackAction: true,
    verticalSpeed: 0,
  });
  const lastGroundedRef = useRef(controllerState.grounded);
  const currentActionRef = useRef<ObservatoryPlayerVisualAction>("idle");
  const actionElapsedRef = useRef(0);
  const mixerRef = useRef<AnimationMixer | null>(null);
  const clipEntriesRef = useRef<Map<ObservatoryPlayerVisualAction, ObservatoryClipEntry>>(
    new Map(),
  );
  const activeClipNameRef = useRef<string | null>(null);
  const breathElapsedRef = useRef(0);
  const smoothedLeanRef = useRef(0);
  const prevCycleSignRef = useRef(0);
  const hipsBoneRef = useRef<Object3D | null>(null);

  useEffect(() => {
    clipEntriesRef.current.clear();
    activeClipNameRef.current = null;
    mixerRef.current?.stopAllAction();
    mixerRef.current = null;

    if (!modelScene || !modelClips || modelClips.length === 0) {
      return;
    }

    const mixer = new AnimationMixer(modelScene);
    const availableNames = modelClips.map((clip) => clip.name);
    const nextEntries = new Map<ObservatoryPlayerVisualAction, ObservatoryClipEntry>();

    for (const visualAction of OBSERVATORY_PLAYER_VISUAL_ACTIONS) {
      const clipName = resolveObservatoryActionClipName(visualAction, availableNames);

      if (!clipName) {
        continue;
      }

      const clip = modelClips.find((candidate) => candidate.name === clipName);

      if (!clip) {
        continue;
      }

      const action = mixer.clipAction(clip);
      const oneShot = getObservatoryPlayerMoveSpec(visualAction).oneShot;

      action.enabled = true;
      action.clampWhenFinished = oneShot;
      action.setLoop(oneShot ? LoopOnce : LoopRepeat, oneShot ? 1 : Infinity);

      nextEntries.set(visualAction, { action, clipName, oneShot });
    }

    // Start locomotion clips playing at weight 0 — weight-based blending requires all to be active
    for (const locomotionAction of ["idle", "walk", "run"] as const) {
      const entry = nextEntries.get(locomotionAction);
      if (entry) {
        entry.action.setEffectiveWeight(0);
        entry.action.play();
      }
    }

    // Cache hip bone for sprint lean — search common Mixamo + generic names
    hipsBoneRef.current = null;
    for (const boneName of ["Hips", "mixamorigHips", "Root", "Pelvis"]) {
      const found = modelScene.getObjectByName(boneName);
      if (found) {
        hipsBoneRef.current = found;
        break;
      }
    }

    clipEntriesRef.current = nextEntries;
    mixerRef.current = mixer;

    return () => {
      mixer.stopAllAction();
      mixer.uncacheRoot(modelScene);
      clipEntriesRef.current.clear();
      activeClipNameRef.current = null;
      hipsBoneRef.current = null;
      mixerRef.current = null;
    };
  }, [modelClips, modelScene]);

  useFrame((_, delta) => {
    const nextLandTimer = Math.max(
      0,
      snapshotRef.current.landTimerSeconds - delta,
    );
    const resolved = resolveObservatoryPlayerAction(controllerState, {
      previousGrounded: lastGroundedRef.current,
      landTimerSeconds: nextLandTimer,
    });
    const actionChanged = currentActionRef.current !== resolved.action;

    if (actionChanged) {
      actionElapsedRef.current = 0;
    } else {
      actionElapsedRef.current += delta;
    }

    currentActionRef.current = resolved.action;
    lastGroundedRef.current = controllerState.grounded;

    const isLocomotion =
      resolved.action === "idle" ||
      resolved.action === "walk" ||
      resolved.action === "run";

    let suppressSpin: boolean;

    if (isLocomotion) {
      // Weight-based blending — no hard switch
      updateLocomotionWeights(clipEntriesRef.current, resolved.horizontalSpeed);
      suppressSpin = true;

      // Clear any active one-shot clip that may still be fading out
      if (activeClipNameRef.current) {
        const activeEntry = [...clipEntriesRef.current.values()].find(
          (e) => e.clipName === activeClipNameRef.current,
        );
        if (activeEntry?.oneShot) {
          fadeOutClipByName(clipEntriesRef.current, activeClipNameRef.current);
          activeClipNameRef.current = null;
        }
      }
    } else {
      // One-shot actions (jump, land, front-flip, back-flip): hard switch as before
      // Reset locomotion weights to 0 while one-shot plays
      clipEntriesRef.current.get("idle")?.action.setEffectiveWeight(0);
      clipEntriesRef.current.get("walk")?.action.setEffectiveWeight(0);
      clipEntriesRef.current.get("run")?.action.setEffectiveWeight(0);

      const clipEntry = selectClipEntry(clipEntriesRef.current, resolved.action);
      if (clipEntry) {
        playClipEntry(clipEntriesRef.current, clipEntry, activeClipNameRef.current);
        activeClipNameRef.current = clipEntry.clipName;
      } else if (activeClipNameRef.current) {
        fadeOutClipByName(clipEntriesRef.current, activeClipNameRef.current);
        activeClipNameRef.current = null;
      }
      suppressSpin = Boolean(
        activeClipNameRef.current &&
          activeClipNameRef.current ===
            clipEntriesRef.current.get(resolved.action)?.clipName,
      );
    }

    mixerRef.current?.update(delta);

    const pose = sampleObservatoryPlayerPose({
      action: resolved.action,
      elapsedSeconds: actionElapsedRef.current,
      horizontalSpeed: resolved.horizontalSpeed,
    });

    applyRootPose(animatedRootRef.current, pose, suppressSpin);
    applyFallbackPose(fallbackRigRefs, pose);

    // CHR-03: Idle breathing — additive Y oscillation fading to zero when moving
    breathElapsedRef.current += delta;
    const idleWeight = Math.max(0, 1 - resolved.horizontalSpeed / WALK_SPEED_THRESHOLD);
    const breathOffset = Math.sin(breathElapsedRef.current * 1.8) * 0.018 * idleWeight;
    if (animatedRootRef.current) {
      animatedRootRef.current.position.y += breathOffset;
    }

    // CHR-04: Sprint lean — forward tilt proportional to speed, smoothed via expLerp
    const MAX_LEAN_RADIANS = 0.18; // ~10 degrees forward
    const leanTarget =
      Math.min(resolved.horizontalSpeed / RUN_SPEED_THRESHOLD, 1.0) * MAX_LEAN_RADIANS;
    const lerpAlpha = 1 - Math.exp(-8 * delta);
    smoothedLeanRef.current =
      smoothedLeanRef.current + (leanTarget - smoothedLeanRef.current) * lerpAlpha;
    if (hipsBoneRef.current) {
      // Negative X rotation = forward lean in standard right-hand skeleton
      hipsBoneRef.current.rotation.x -= smoothedLeanRef.current;
    }

    // CHR-06: Footstep cycle-zero-crossing detection
    if (
      (resolved.action === "walk" || resolved.action === "run") &&
      controllerState.grounded
    ) {
      // Compute cycle using same formula as sampleWalkPose / sampleRunPose
      const elapsed = actionElapsedRef.current;
      const speedFactor = Math.min(resolved.horizontalSpeed / RUN_SPEED_THRESHOLD, 1.35);
      const cycleRate =
        resolved.action === "walk"
          ? 5.8 + Math.min(Math.max(speedFactor, 0.45), 0.88) * 1.4
          : 8.6 + Math.min(Math.max(speedFactor, 0.8), 1.2) * 2.4;
      const cycleValue = Math.sin(elapsed * cycleRate);
      const cycleSign = cycleValue > 0 ? 1 : cycleValue < 0 ? -1 : 0;

      if (
        prevCycleSignRef.current !== 0 &&
        cycleSign !== 0 &&
        cycleSign !== prevCycleSignRef.current
      ) {
        // Sign flip = foot strike
        window.dispatchEvent(
          new CustomEvent("observatory:footstrike", {
            detail: {
              foot: cycleSign < 0 ? "right" : "left",
              position: controllerState.position,
            },
          }),
        );
      }

      if (cycleSign !== 0) {
        prevCycleSignRef.current = cycleSign;
      }
    } else {
      // Reset sign tracking when not walking/running so first step fires correctly
      prevCycleSignRef.current = 0;
    }

    snapshotRef.current = {
      ...resolved,
      actionElapsedSeconds: actionElapsedRef.current,
      assetClipName: isLocomotion
        ? (clipEntriesRef.current.get(resolved.action)?.clipName ?? null)
        : (activeClipNameRef.current ?? null),
    };
  });

  return snapshotRef;
}

function selectClipEntry(
  entries: Map<ObservatoryPlayerVisualAction, ObservatoryClipEntry>,
  action: ObservatoryPlayerVisualAction,
): ObservatoryClipEntry | null {
  const direct = entries.get(action);

  if (direct) {
    return direct;
  }

  if (action === "front-flip" || action === "back-flip") {
    return entries.get("jump") ?? entries.get("idle") ?? null;
  }

  if (action === "land") {
    return entries.get("idle") ?? null;
  }

  return entries.get("idle") ?? null;
}

function playClipEntry(
  entries: Map<ObservatoryPlayerVisualAction, ObservatoryClipEntry>,
  entry: ObservatoryClipEntry,
  activeClipName: string | null,
): void {
  if (activeClipName === entry.clipName) {
    return;
  }

  if (activeClipName) {
    fadeOutClipByName(entries, activeClipName);
  }

  entry.action.reset();
  entry.action.setEffectiveTimeScale(1);
  entry.action.setEffectiveWeight(1);
  entry.action.fadeIn(entry.oneShot ? 0.06 : 0.14);
  entry.action.play();
}

function fadeOutClipByName(
  entries: Map<ObservatoryPlayerVisualAction, ObservatoryClipEntry>,
  clipName: string,
): void {
  for (const entry of entries.values()) {
    if (entry.clipName === clipName) {
      entry.action.fadeOut(entry.oneShot ? 0.06 : 0.12);
      break;
    }
  }
}

function updateLocomotionWeights(
  entries: Map<ObservatoryPlayerVisualAction, ObservatoryClipEntry>,
  horizontalSpeed: number,
): void {
  const WALK_MIN = WALK_SPEED_THRESHOLD; // 0.3
  const RUN_MIN = RUN_SPEED_THRESHOLD;   // 2.2

  let idleW = 0, walkW = 0, runW = 0;

  if (horizontalSpeed < WALK_MIN) {
    idleW = 1;
  } else if (horizontalSpeed < RUN_MIN) {
    const t = (horizontalSpeed - WALK_MIN) / (RUN_MIN - WALK_MIN);
    idleW = 1 - t;
    walkW = t;
  } else {
    const t = Math.min((horizontalSpeed - RUN_MIN) / 2.0, 1);
    walkW = 1 - t;
    runW = t;
  }

  entries.get("idle")?.action.setEffectiveWeight(idleW);
  entries.get("walk")?.action.setEffectiveWeight(walkW);
  entries.get("run")?.action.setEffectiveWeight(runW);
}

function applyRootPose(
  animatedRoot: Group | null,
  pose: ReturnType<typeof sampleObservatoryPlayerPose>,
  suppressSpin: boolean,
): void {
  if (!animatedRoot) {
    return;
  }

  animatedRoot.position.y = pose.rootOffsetY;
  animatedRoot.rotation.x = suppressSpin ? 0 : pose.bodySpinX;
  animatedRoot.scale.set(
    pose.rootScale[0],
    pose.rootScale[1],
    pose.rootScale[2],
  );
}

function applyFallbackPose(
  rigRefs: ObservatoryPlayerFallbackRigRefs,
  pose: ReturnType<typeof sampleObservatoryPlayerPose>,
): void {
  if (rigRefs.torso.current) {
    rigRefs.torso.current.rotation.x = pose.torsoPitch;
    rigRefs.torso.current.rotation.z = pose.torsoRoll;
  }

  if (rigRefs.head.current) {
    rigRefs.head.current.rotation.x = pose.headPitch;
    rigRefs.head.current.rotation.z = pose.headRoll;
  }

  if (rigRefs.leftArm.current) {
    rigRefs.leftArm.current.rotation.x = pose.leftArmPitch;
    rigRefs.leftArm.current.rotation.z = pose.leftArmRoll;
  }

  if (rigRefs.rightArm.current) {
    rigRefs.rightArm.current.rotation.x = pose.rightArmPitch;
    rigRefs.rightArm.current.rotation.z = pose.rightArmRoll;
  }

  if (rigRefs.leftLeg.current) {
    rigRefs.leftLeg.current.rotation.x = pose.leftLegPitch;
  }

  if (rigRefs.rightLeg.current) {
    rigRefs.rightLeg.current.rotation.x = pose.rightLegPitch;
  }

  if (rigRefs.leftFoot.current) {
    rigRefs.leftFoot.current.rotation.x = pose.leftFootPitch;
    rigRefs.leftFoot.current.rotation.z = 0;
  }

  if (rigRefs.rightFoot.current) {
    rigRefs.rightFoot.current.rotation.x = pose.rightFootPitch;
    rigRefs.rightFoot.current.rotation.z = 0;
  }

  if (rigRefs.backpack.current) {
    rigRefs.backpack.current.rotation.x = pose.backpackPitch;
  }

  if (rigRefs.shell.current) {
    const scale = 1 + pose.shellPulse * 0.08;
    rigRefs.shell.current.scale.set(scale, scale, scale);
    rigRefs.shell.current.rotation.y = pose.shellPulse * 0.14;
  }

  applyKneePose(rigRefs.leftLeg.current, pose.leftKneePitch);
  applyKneePose(rigRefs.rightLeg.current, pose.rightKneePitch);
}

function applyKneePose(leg: Group | null, kneePitch: number): void {
  const kneeJoint = leg?.children[1];

  if (!kneeJoint) {
    return;
  }

  kneeJoint.rotation.x = kneePitch;
}
