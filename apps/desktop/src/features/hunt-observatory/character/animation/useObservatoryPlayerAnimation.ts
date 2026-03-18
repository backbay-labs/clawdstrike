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

    clipEntriesRef.current = nextEntries;
    mixerRef.current = mixer;

    return () => {
      mixer.stopAllAction();
      mixer.uncacheRoot(modelScene);
      clipEntriesRef.current.clear();
      activeClipNameRef.current = null;
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

    const clipEntry = selectClipEntry(clipEntriesRef.current, resolved.action);

    if (clipEntry) {
      playClipEntry(clipEntriesRef.current, clipEntry, activeClipNameRef.current);
      activeClipNameRef.current = clipEntry.clipName;
    } else if (activeClipNameRef.current) {
      fadeOutClipByName(clipEntriesRef.current, activeClipNameRef.current);
      activeClipNameRef.current = null;
    }

    mixerRef.current?.update(delta);

    const pose = sampleObservatoryPlayerPose({
      action: resolved.action,
      elapsedSeconds: actionElapsedRef.current,
      horizontalSpeed: resolved.horizontalSpeed,
    });
    const hasSpecificClip =
      clipEntry?.clipName === clipEntriesRef.current.get(resolved.action)?.clipName;

    applyRootPose(animatedRootRef.current, pose, Boolean(hasSpecificClip));
    applyFallbackPose(fallbackRigRefs, pose);

    snapshotRef.current = {
      ...resolved,
      actionElapsedSeconds: actionElapsedRef.current,
      assetClipName: clipEntry?.clipName ?? null,
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
