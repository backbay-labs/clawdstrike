// Ported from huntronomer apps/desktop/src/features/hunt-observatory/world/missionLoop.ts
import type { HuntObservatorySceneState, HuntStationId } from "./types";
import type { ObservatoryHeroPropAssetId } from "./propAssets";

export type ObservatoryMissionObjectiveId =
  | "acknowledge-horizon-ingress"
  | "resolve-subject-cluster"
  | "arm-operations-scan"
  | "inspect-evidence-arrival"
  | "seal-judgment-finding";

export type ObservatoryMissionBranch = "operations-first" | "evidence-first";

export interface ObservatoryMissionObjective {
  id: ObservatoryMissionObjectiveId;
  stationId: HuntStationId;
  assetId: ObservatoryHeroPropAssetId;
  title: string;
  actionLabel: string;
  hint: string;
  completionRead: string;
}

export interface ObservatoryMissionLoopProgress {
  acknowledgedIngress: boolean;
  subjectsResolved: boolean;
  runArmed: boolean;
  evidenceInspected: boolean;
  findingSealed: boolean;
}

export interface ObservatoryMissionLoopState {
  huntId: string;
  startedAtMs: number;
  completedAtMs: number | null;
  status: "in-progress" | "completed";
  branch: ObservatoryMissionBranch | null;
  completedObjectiveIds: ObservatoryMissionObjectiveId[];
  progress: ObservatoryMissionLoopProgress;
}

export interface ObservatoryMissionLoopOptions {
  branchHint?: ObservatoryMissionBranch | null;
}

const OBJECTIVES: Record<ObservatoryMissionObjectiveId, ObservatoryMissionObjective> = {
  "acknowledge-horizon-ingress": {
    id: "acknowledge-horizon-ingress",
    stationId: "signal",
    assetId: "signal-dish-tower",
    title: "Acknowledge a new Horizon ingress",
    actionLabel: "Acknowledge ingress",
    hint: "Travel to Horizon and use the dish tower to sweep the fresh ingress lane.",
    completionRead: "Hidden ingress paths are now exposed across Horizon.",
  },
  "resolve-subject-cluster": {
    id: "resolve-subject-cluster",
    stationId: "targets",
    assetId: "subjects-lattice-anchor",
    title: "Resolve the active Subjects cluster",
    actionLabel: "Resolve cluster",
    hint: "Move to Subjects and stabilize the live cluster on the lattice anchor.",
    completionRead: "The active subject cluster is resolved and routes are opening toward the next district.",
  },
  "arm-operations-scan": {
    id: "arm-operations-scan",
    stationId: "run",
    assetId: "operations-scan-rig",
    title: "Walk to Operations and arm a scan",
    actionLabel: "Arm scan",
    hint: "Move through the world to Operations and boot the scan rig.",
    completionRead: "Operations is armed and routing execution pressure toward Evidence.",
  },
  "inspect-evidence-arrival": {
    id: "inspect-evidence-arrival",
    stationId: "receipts",
    assetId: "evidence-vault-rack",
    title: "Reach Evidence and inspect the new arrival",
    actionLabel: "Inspect arrival",
    hint: "Cross to Evidence and open the latest arrival on the vault rack.",
    completionRead: "The latest arrivals are fanned out and ready for Judgment.",
  },
  "seal-judgment-finding": {
    id: "seal-judgment-finding",
    stationId: "case-notes",
    assetId: "judgment-dais",
    title: "Finish at Judgment to seal a finding",
    actionLabel: "Seal finding",
    hint: "Climb to Judgment and seal the active finding on the dais.",
    completionRead: "Judgment has sealed the current finding into the hunt scaffold.",
  },
};

export const OBSERVATORY_MISSION_OBJECTIVES: ObservatoryMissionObjective[] = [
  OBJECTIVES["acknowledge-horizon-ingress"],
  OBJECTIVES["resolve-subject-cluster"],
  OBJECTIVES["arm-operations-scan"],
  OBJECTIVES["inspect-evidence-arrival"],
  OBJECTIVES["seal-judgment-finding"],
];

function nextMissionProgress(
  progress: ObservatoryMissionLoopProgress,
  objectiveId: ObservatoryMissionObjectiveId,
): ObservatoryMissionLoopProgress {
  switch (objectiveId) {
    case "acknowledge-horizon-ingress":
      return { ...progress, acknowledgedIngress: true };
    case "resolve-subject-cluster":
      return { ...progress, subjectsResolved: true };
    case "arm-operations-scan":
      return { ...progress, runArmed: true };
    case "inspect-evidence-arrival":
      return { ...progress, evidenceInspected: true };
    case "seal-judgment-finding":
      return { ...progress, findingSealed: true };
  }
}

// NOTE: deriveObservatoryMissionBranch reads station status fields ("receiving" | "active").
// The workbench ObservatoryTab currently sets all station status to "idle" (synthetic scene state).
// This means branch detection will always return "operations-first" until real status flows in
// from a live backend connection.
export function deriveObservatoryMissionBranch(
  sceneState: HuntObservatorySceneState | null,
): ObservatoryMissionBranch {
  const run = sceneState?.stations.find((station) => station.id === "run");
  const evidence = sceneState?.stations.find((station) => station.id === "receipts");
  if (!run || !evidence) return "operations-first";
  if (
    (evidence.status === "receiving" || evidence.status === "active")
    && evidence.artifactCount >= Math.max(2, run.artifactCount)
  ) {
    return "evidence-first";
  }
  if (
    evidence.emphasis > run.emphasis + 0.08
    && evidence.artifactCount > 0
    && sceneState?.likelyStationId === "receipts"
  ) {
    return "evidence-first";
  }
  return "operations-first";
}

export function createObservatoryMissionLoopState(
  huntId: string,
  nowMs = 0,
  options: ObservatoryMissionLoopOptions = {},
): ObservatoryMissionLoopState {
  return {
    huntId,
    startedAtMs: nowMs,
    completedAtMs: null,
    status: "in-progress",
    branch: options.branchHint ?? null,
    completedObjectiveIds: [],
    progress: {
      acknowledgedIngress: false,
      subjectsResolved: false,
      runArmed: false,
      evidenceInspected: false,
      findingSealed: false,
    },
  };
}

function resolveCurrentObjectiveId(
  mission: ObservatoryMissionLoopState,
): ObservatoryMissionObjectiveId | null {
  if (mission.status === "completed") return null;
  if (!mission.progress.acknowledgedIngress) return "acknowledge-horizon-ingress";
  if (!mission.progress.subjectsResolved) return "resolve-subject-cluster";

  const branch = mission.branch ?? "operations-first";
  if (branch === "evidence-first") {
    if (!mission.progress.evidenceInspected) return "inspect-evidence-arrival";
    if (!mission.progress.runArmed) return "arm-operations-scan";
  } else {
    if (!mission.progress.runArmed) return "arm-operations-scan";
    if (!mission.progress.evidenceInspected) return "inspect-evidence-arrival";
  }

  if (!mission.progress.findingSealed) return "seal-judgment-finding";
  return null;
}

export function getCurrentObservatoryMissionObjective(
  mission: ObservatoryMissionLoopState | null,
): ObservatoryMissionObjective | null {
  if (!mission) return null;
  const objectiveId = resolveCurrentObjectiveId(mission);
  return objectiveId ? OBJECTIVES[objectiveId] : null;
}

export function resolveObservatoryMissionProbeTargetStationId(
  mission: ObservatoryMissionLoopState | null,
  options: {
    activeStationId?: HuntStationId | null;
    likelyStationId?: HuntStationId | null;
  } = {},
): HuntStationId | null {
  return (
    getCurrentObservatoryMissionObjective(mission)?.stationId
    ?? options.activeStationId
    ?? options.likelyStationId
    ?? null
  );
}

export function isObservatoryMissionObjectiveProp(
  mission: ObservatoryMissionLoopState | null,
  assetId: ObservatoryHeroPropAssetId,
): boolean {
  return getCurrentObservatoryMissionObjective(mission)?.assetId === assetId;
}

export function completeObservatoryMissionObjective(
  mission: ObservatoryMissionLoopState,
  assetId: ObservatoryHeroPropAssetId,
  nowMs = 0,
  options: ObservatoryMissionLoopOptions = {},
): ObservatoryMissionLoopState {
  const objective = getCurrentObservatoryMissionObjective(mission);
  if (!objective || objective.assetId !== assetId) {
    return mission;
  }
  const completedObjectiveIds = mission.completedObjectiveIds.includes(objective.id)
    ? mission.completedObjectiveIds
    : [...mission.completedObjectiveIds, objective.id];
  const nextProgress = nextMissionProgress(mission.progress, objective.id);
  const nextBranch =
    objective.id === "resolve-subject-cluster"
      ? options.branchHint ?? mission.branch ?? "operations-first"
      : mission.branch ?? options.branchHint ?? null;
  const draft: ObservatoryMissionLoopState = {
    ...mission,
    branch: nextBranch,
    completedObjectiveIds,
    progress: nextProgress,
  };
  const nextObjectiveId = resolveCurrentObjectiveId(draft);
  return {
    ...draft,
    status: nextObjectiveId ? "in-progress" : "completed",
    completedAtMs: nextObjectiveId ? null : nowMs,
  };
}
