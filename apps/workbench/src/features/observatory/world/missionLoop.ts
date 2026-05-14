// Ported from huntronomer apps/desktop/src/features/hunt-observatory/world/missionLoop.ts
import type { HuntPattern, Investigation } from "@/lib/workbench/hunt-types";
import type { HuntObservatorySceneState, HuntStationId } from "./types";
import type { ObservatoryHeroPropAssetId } from "./propAssets";

export type ObservatoryMissionObjectiveId =
  | "acknowledge-horizon-ingress"
  | "resolve-subject-cluster"
  | "arm-operations-scan"
  | "inspect-evidence-arrival"
  | "seal-judgment-finding"
  | "raise-watchfield-perimeter";

export type ObservatoryMissionBranch = "operations-first" | "evidence-first";

export interface ObservatoryMissionObjective {
  id: ObservatoryMissionObjectiveId;
  stationId: HuntStationId;
  assetId: ObservatoryHeroPropAssetId;
  title: string;
  actionLabel: string;
  hint: string;
  completionRead: string;
  supportingStationIds?: HuntStationId[];
  rationale?: string | null;
  confidence?: number;
}

export interface ObservatoryMissionLoopProgress {
  acknowledgedIngress: boolean;
  subjectsResolved: boolean;
  runArmed: boolean;
  evidenceInspected: boolean;
  findingSealed: boolean;
  watchfieldRaised: boolean;
}

export interface ObservatoryMissionPlan {
  briefing: string;
  objectives: ObservatoryMissionObjective[];
}

export interface ObservatoryMissionLoopState {
  huntId: string;
  startedAtMs: number;
  completedAtMs: number | null;
  status: "in-progress" | "completed";
  branch: ObservatoryMissionBranch | null;
  briefing: string;
  completedObjectiveIds: ObservatoryMissionObjectiveId[];
  objectives: ObservatoryMissionObjective[];
  progress: ObservatoryMissionLoopProgress;
}

export interface ObservatoryMissionLoopOptions {
  branchHint?: ObservatoryMissionBranch | null;
  plan?: ObservatoryMissionPlan;
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
  "raise-watchfield-perimeter": {
    id: "raise-watchfield-perimeter",
    stationId: "watch",
    assetId: "watchfield-sentinel-beacon",
    title: "Raise the Watchfield perimeter",
    actionLabel: "Raise perimeter",
    hint: "Move to Watchfield and raise the outer beacon lattice before returning to the finding.",
    completionRead: "The watchfield perimeter is raised and the outer patrol ring is holding.",
  },
};

export const OBSERVATORY_MISSION_OBJECTIVES: ObservatoryMissionObjective[] = [
  OBJECTIVES["acknowledge-horizon-ingress"],
  OBJECTIVES["resolve-subject-cluster"],
  OBJECTIVES["arm-operations-scan"],
  OBJECTIVES["inspect-evidence-arrival"],
  OBJECTIVES["raise-watchfield-perimeter"],
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
    case "raise-watchfield-perimeter":
      return { ...progress, watchfieldRaised: true };
  }
}

function stationArtifactCount(
  sceneState: HuntObservatorySceneState | null,
  stationId: HuntStationId,
): number {
  return sceneState?.stations.find((station) => station.id === stationId)?.artifactCount ?? 0;
}

function stationReason(
  sceneState: HuntObservatorySceneState | null,
  stationId: HuntStationId,
): string | null {
  return sceneState?.stations.find((station) => station.id === stationId)?.reason ?? null;
}

function withObjectiveOverrides(
  objectiveId: ObservatoryMissionObjectiveId,
  overrides: Partial<ObservatoryMissionObjective>,
): ObservatoryMissionObjective {
  return {
    ...OBJECTIVES[objectiveId],
    ...overrides,
  };
}

const COMPOUND_SUPPORT_MAP: Record<HuntStationId, HuntStationId[]> = {
  signal: ["targets", "receipts"],
  targets: ["signal", "receipts"],
  run: ["receipts", "case-notes"],
  receipts: ["run", "signal"],
  "case-notes": ["watch", "receipts"],
  watch: ["case-notes", "signal"],
};

function getStation(
  sceneState: HuntObservatorySceneState | null,
  stationId: HuntStationId,
) {
  return sceneState?.stations.find((station) => station.id === stationId) ?? null;
}

function getStationPressureScore(
  sceneState: HuntObservatorySceneState | null,
  stationId: HuntStationId,
): number {
  const station = getStation(sceneState, stationId);
  if (!station) return 0;
  const statusBoost =
    station.status === "receiving"
      ? 0.18
      : station.status === "active"
        ? 0.1
        : station.status === "warming"
          ? 0.04
          : 0;
  return Math.min(1, station.emphasis * 0.58 + station.affinity * 0.28 + Math.min(0.12, station.artifactCount * 0.03) + statusBoost);
}

function joinStationLabels(labels: string[]): string {
  if (labels.length <= 1) {
    return labels[0] ?? "";
  }
  if (labels.length === 2) {
    return `${labels[0]} and ${labels[1]}`;
  }
  return `${labels.slice(0, -1).join(", ")}, and ${labels[labels.length - 1]}`;
}

function buildCompoundMissionContext(
  sceneState: HuntObservatorySceneState | null,
  primaryId: HuntStationId,
): {
  confidence: number;
  rationale: string;
  supportingStationIds: HuntStationId[];
} | null {
  const primary = getStation(sceneState, primaryId);
  if (!primary) return null;

  const candidateIds = COMPOUND_SUPPORT_MAP[primaryId];
  const supportingStations = candidateIds
    .map((stationId) => getStation(sceneState, stationId))
    .filter((station): station is NonNullable<typeof station> => Boolean(station))
    .filter((station) => {
      const supportScore = getStationPressureScore(sceneState, station.id);
      return (
        supportScore >= 0.36
        || station.status === "receiving"
        || station.status === "active"
        || station.artifactCount > 1
      );
    });

  if (supportingStations.length === 0) {
    return null;
  }

  const primaryScore = getStationPressureScore(sceneState, primaryId);
  const supportScores = supportingStations.map((station) => getStationPressureScore(sceneState, station.id));
  const supportLabels = supportingStations.map((station) => station.label);
  const rationaleParts = supportingStations.map((station) => {
    const reason = station.reason?.trim().replace(/\.$/, "");
    return reason ?? `${station.label} pressure is elevated`;
  });
  const rationale = `${primary.label} should stay paired with ${joinStationLabels(supportLabels)} because ${joinStationLabels(rationaleParts)}.`;
  const confidence = Math.min(
    0.98,
    0.4
      + primaryScore * 0.26
      + (supportScores.reduce((sum, score) => sum + score, 0) / supportScores.length) * 0.28
      + Math.min(0.08, (supportingStations.length - 1) * 0.04),
  );

  return {
    confidence,
    rationale,
    supportingStationIds: supportingStations.map((station) => station.id),
  };
}

export function createObservatoryMissionPlan(input: {
  investigations?: Investigation[];
  patterns?: HuntPattern[];
  sceneState: HuntObservatorySceneState | null;
}): ObservatoryMissionPlan {
  const investigations = input.investigations ?? [];
  const patterns = input.patterns ?? [];
  const branch = deriveObservatoryMissionBranch(input.sceneState);
  const watchCount = stationArtifactCount(input.sceneState, "watch");
  const policyGapCount = investigations.filter((investigation) => investigation.verdict === "policy-gap").length;
  const openInvestigations = investigations.filter(
    (investigation) => investigation.status === "open" || investigation.status === "in-progress",
  ).length;
  const livePatterns = patterns.filter((pattern) => pattern.status !== "dismissed").length;
  const includeWatchfield = watchCount > 0 || openInvestigations >= 2;
  const middleObjectiveIds: ObservatoryMissionObjectiveId[] =
    branch === "evidence-first"
      ? ["inspect-evidence-arrival", "arm-operations-scan"]
      : ["arm-operations-scan", "inspect-evidence-arrival"];
  const watchfieldObjectiveIds: ObservatoryMissionObjectiveId[] = includeWatchfield
    ? ["raise-watchfield-perimeter"]
    : [];
  const sequence: ObservatoryMissionObjectiveId[] = [
    "acknowledge-horizon-ingress",
    "resolve-subject-cluster",
    ...middleObjectiveIds,
    ...watchfieldObjectiveIds,
    "seal-judgment-finding",
  ];

  const objectives = sequence.map((objectiveId) => {
    const compoundSupport = buildCompoundMissionContext(input.sceneState, OBJECTIVES[objectiveId].stationId);
    switch (objectiveId) {
      case "acknowledge-horizon-ingress":
        return withObjectiveOverrides(objectiveId, {
          hint: stationReason(input.sceneState, "signal") ?? OBJECTIVES[objectiveId].hint,
          supportingStationIds: compoundSupport?.supportingStationIds,
          rationale: compoundSupport?.rationale ?? null,
          confidence: compoundSupport?.confidence,
        });
      case "resolve-subject-cluster":
        return withObjectiveOverrides(objectiveId, {
          hint: stationReason(input.sceneState, "targets") ?? OBJECTIVES[objectiveId].hint,
          supportingStationIds: compoundSupport?.supportingStationIds,
          rationale: compoundSupport?.rationale ?? null,
          confidence: compoundSupport?.confidence,
        });
      case "arm-operations-scan":
        return withObjectiveOverrides(objectiveId, {
          hint: stationReason(input.sceneState, "run") ?? OBJECTIVES[objectiveId].hint,
          supportingStationIds: compoundSupport?.supportingStationIds,
          rationale: compoundSupport?.rationale ?? null,
          confidence: compoundSupport?.confidence,
        });
      case "inspect-evidence-arrival":
        return withObjectiveOverrides(objectiveId, {
          hint: stationReason(input.sceneState, "receipts") ?? OBJECTIVES[objectiveId].hint,
          supportingStationIds: compoundSupport?.supportingStationIds,
          rationale: compoundSupport?.rationale ?? null,
          confidence: compoundSupport?.confidence,
        });
      case "raise-watchfield-perimeter":
        return withObjectiveOverrides(objectiveId, {
          hint: stationReason(input.sceneState, "watch") ?? OBJECTIVES[objectiveId].hint,
          supportingStationIds: compoundSupport?.supportingStationIds,
          rationale: compoundSupport?.rationale ?? null,
          confidence: compoundSupport?.confidence,
        });
      case "seal-judgment-finding":
        {
          const judgmentPressureCount = Math.max(policyGapCount, livePatterns, openInvestigations);
        return withObjectiveOverrides(objectiveId, {
          hint:
            stationReason(input.sceneState, "case-notes")
            ?? (judgmentPressureCount > 0
              ? `Judgment is holding ${judgmentPressureCount} live pressure lane${judgmentPressureCount === 1 ? "" : "s"} for sealing.`
              : OBJECTIVES[objectiveId].hint),
          supportingStationIds: compoundSupport?.supportingStationIds,
          rationale: compoundSupport?.rationale ?? null,
          confidence: compoundSupport?.confidence,
        });
        }
    }
  });

  const compoundObjective = objectives.find((objective) => objective.supportingStationIds?.length);
  const briefing =
    branch === "evidence-first"
      ? `Evidence is outrunning Operations, so route the loop through receipts before returning to the scan rig.${compoundObjective?.rationale ? ` Compound recommendation: ${compoundObjective.rationale}` : ""}${includeWatchfield ? " Watchfield pressure is high enough to raise the perimeter before sealing the finding." : ""}`
      : `Operations is carrying the current load, so stabilize the run lane before fanning evidence into Judgment.${compoundObjective?.rationale ? ` Compound recommendation: ${compoundObjective.rationale}` : ""}${includeWatchfield ? " Watchfield pressure is high enough to raise the perimeter before sealing the finding." : ""}`;

  return {
    briefing,
    objectives,
  };
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
  const plan = options.plan ?? createObservatoryMissionPlan({ sceneState: null });
  return {
    huntId,
    startedAtMs: nowMs,
    completedAtMs: null,
    status: "in-progress",
    branch: options.branchHint ?? null,
    briefing: plan.briefing,
    completedObjectiveIds: [],
    objectives: plan.objectives,
    progress: {
      acknowledgedIngress: false,
      subjectsResolved: false,
      runArmed: false,
      evidenceInspected: false,
      findingSealed: false,
      watchfieldRaised: false,
    },
  };
}

function resolveCurrentObjectiveId(
  mission: ObservatoryMissionLoopState,
): ObservatoryMissionObjectiveId | null {
  if (mission.status === "completed") return null;
  if (mission.objectives.length > 0) {
    return mission.objectives.find(
      (objective) => !mission.completedObjectiveIds.includes(objective.id),
    )?.id ?? null;
  }
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
  if (!objectiveId) return null;
  return mission.objectives.find((objective) => objective.id === objectiveId) ?? OBJECTIVES[objectiveId];
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
