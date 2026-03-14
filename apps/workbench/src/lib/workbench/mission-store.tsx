import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useReducer,
  useRef,
  type ReactNode,
} from "react";
import {
  advanceMission as engineAdvanceMission,
  attachMissionFindings as engineAttachMissionFindings,
  buildMissionStagesForDriver,
  createMission as engineCreateMission,
  startMission as engineStartMission,
} from "./mission-control";
import type {
  CreateMissionConfig,
  Mission,
  MissionEvidence,
  MissionExecutionBundle,
  MissionRuntimeEvent,
  MissionStage,
} from "./mission-types";

interface MissionState {
  missions: Mission[];
  activeMissionId: string | null;
  loading: boolean;
}

type MissionAction =
  | { type: "CREATE"; mission: Mission }
  | { type: "SET_ACTIVE"; missionId: string | null }
  | { type: "START"; missionId: string; execution: MissionExecutionBundle }
  | { type: "ADVANCE"; missionId: string }
  | { type: "ATTACH_FINDINGS"; missionId: string; findingIds: string[] }
  | { type: "LOAD"; missions: Mission[] };

function missionReducer(state: MissionState, action: MissionAction): MissionState {
  switch (action.type) {
    case "CREATE":
      return {
        ...state,
        missions: [action.mission, ...state.missions],
        activeMissionId: action.mission.id,
      };
    case "SET_ACTIVE":
      return {
        ...state,
        activeMissionId:
          action.missionId === null
            ? null
            : state.missions.some((mission) => mission.id === action.missionId)
              ? action.missionId
              : state.activeMissionId,
      };
    case "START":
      return {
        ...state,
        missions: state.missions.map((mission) =>
          mission.id === action.missionId
            ? engineStartMission(mission, action.execution)
            : mission,
        ),
      };
    case "ADVANCE":
      return {
        ...state,
        missions: state.missions.map((mission) =>
          mission.id === action.missionId ? engineAdvanceMission(mission) : mission,
        ),
      };
    case "ATTACH_FINDINGS":
      return {
        ...state,
        missions: state.missions.map((mission) =>
          mission.id === action.missionId
            ? engineAttachMissionFindings(mission, action.findingIds)
            : mission,
        ),
      };
    case "LOAD": {
      const activeMissionId =
        state.activeMissionId &&
        action.missions.some((mission) => mission.id === state.activeMissionId)
          ? state.activeMissionId
          : action.missions[0]?.id ?? null;
      return {
        missions: action.missions,
        activeMissionId,
        loading: false,
      };
    }
    default:
      return state;
  }
}

const STORAGE_KEY = "clawdstrike_workbench_missions";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function asNonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function asNonEmptyStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0)
    : [];
}

function asNumber(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function asNullableNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asNullableText(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

function parseMissionDriver(value: unknown): Mission["driver"] | null {
  switch (value) {
    case "claude_code":
    case "openclaw":
      return value;
    default:
      return null;
  }
}

function normalizeMissionStatus(value: unknown): Mission["status"] {
  switch (value) {
    case "draft":
    case "active":
    case "blocked":
    case "completed":
    case "aborted":
      return value;
    default:
      return "draft";
  }
}

function normalizeMissionDriver(
  value: unknown,
  fallback: Mission["driver"] = "claude_code",
): Mission["driver"] {
  return parseMissionDriver(value) ?? fallback;
}

function normalizeMissionPriority(value: unknown): Mission["priority"] {
  switch (value) {
    case "low":
    case "medium":
    case "high":
    case "critical":
      return value;
    default:
      return "medium";
  }
}

function normalizeMissionLaunchState(value: unknown): Mission["launchState"] {
  switch (value) {
    case "ready":
    case "degraded":
    case "blocked":
      return value;
    default:
      return null;
  }
}

function normalizeMissionStageStatus(value: unknown): MissionStage["status"] {
  switch (value) {
    case "pending":
    case "in_progress":
    case "completed":
    case "blocked":
      return value;
    default:
      return "pending";
  }
}

function normalizeMissionEvidenceType(value: unknown): MissionEvidence["type"] {
  switch (value) {
    case "signal":
    case "finding":
    case "receipt":
    case "runtime_event":
    case "session":
    case "note":
      return value;
    default:
      return "note";
  }
}

function normalizeMissionRuntimeEventKind(value: unknown): MissionRuntimeEvent["kind"] {
  switch (value) {
    case "session_started":
    case "launch_blocked":
    case "tool_call":
    case "policy_block":
    case "artifact_collected":
    case "summary":
      return value;
    default:
      return "summary";
  }
}

function legacySentinelIdForMission(missionId: string): string {
  return `sen_legacy_${missionId}`;
}

function findSentinelIdInStages(value: unknown): string | null {
  if (!Array.isArray(value)) {
    return null;
  }

  for (const entry of value) {
    if (!isRecord(entry)) {
      continue;
    }
    const sentinelId = asNonEmptyString(entry.ownerSentinelId);
    if (sentinelId) {
      return sentinelId;
    }
  }

  return null;
}

function findSentinelIdInRuntimeEvents(value: unknown): string | null {
  if (!Array.isArray(value)) {
    return null;
  }

  for (const entry of value) {
    if (!isRecord(entry)) {
      continue;
    }
    const sentinelId = asNonEmptyString(entry.sentinelId);
    if (sentinelId) {
      return sentinelId;
    }
  }

  return null;
}

function inferMissionDriver(mission: Record<string, unknown>): Mission["driver"] {
  const stageDriver = Array.isArray(mission.stages)
    ? mission.stages.find((entry) => isRecord(entry) && parseMissionDriver(entry.driver) !== null)
    : null;
  const runtimeEventDriver = Array.isArray(mission.runtimeEvents)
    ? mission.runtimeEvents.find((entry) => isRecord(entry) && parseMissionDriver(entry.driver) !== null)
    : null;

  return (
    parseMissionDriver(mission.driver) ??
    (stageDriver && isRecord(stageDriver) ? parseMissionDriver(stageDriver.driver) : null) ??
    (runtimeEventDriver && isRecord(runtimeEventDriver)
      ? parseMissionDriver(runtimeEventDriver.driver)
      : null) ??
    "claude_code"
  );
}

function inferPrimarySentinelId(mission: Record<string, unknown>, missionId: string): string {
  return (
    asNonEmptyString(mission.primarySentinelId) ??
    asNonEmptyStringArray(mission.assignedSentinelIds)[0] ??
    findSentinelIdInStages(mission.stages) ??
    findSentinelIdInRuntimeEvents(mission.runtimeEvents) ??
    legacySentinelIdForMission(missionId)
  );
}

function normalizeMissionStages(
  value: unknown,
  missionDriver: Mission["driver"],
  primarySentinelId: string,
): MissionStage[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.flatMap((entry, index) => {
    if (!isRecord(entry)) {
      return [];
    }

    const label = asString(entry.label, `Stage ${index + 1}`);
    return [
      {
        id: asString(entry.id, `legacy_stage_${index}`),
        label,
        summary: asString(entry.summary, label),
        status: normalizeMissionStageStatus(entry.status),
        ownerSentinelId: asString(entry.ownerSentinelId, primarySentinelId),
        driver: normalizeMissionDriver(entry.driver, missionDriver),
        startedAt: asNullableNumber(entry.startedAt),
        completedAt: asNullableNumber(entry.completedAt),
      },
    ];
  });
}

function repairMissionStages(
  stages: MissionStage[],
  missionStatus: Mission["status"],
  startedAt: number | null,
  updatedAt: number,
  completedAt: number | null,
): MissionStage[] {
  if (stages.length === 0) {
    return stages;
  }

  const activeAnchor = startedAt ?? updatedAt;
  const completedAnchor = completedAt ?? updatedAt;

  switch (missionStatus) {
    case "active": {
      if (stages.some((stage) => stage.status === "in_progress")) {
        return stages;
      }

      let activatedPendingStage = false;
      let sawCompletedStage = false;
      const repairedAfterCompleted = stages.map((stage) => {
        if (stage.status === "completed") {
          sawCompletedStage = true;
          return stage;
        }
        if (!activatedPendingStage && sawCompletedStage && stage.status === "pending") {
          activatedPendingStage = true;
          return {
            ...stage,
            status: "in_progress" as const,
            startedAt: stage.startedAt ?? activeAnchor,
          };
        }
        return stage;
      });

      if (repairedAfterCompleted.some((stage) => stage.status === "in_progress")) {
        return repairedAfterCompleted;
      }

      if (stages.length === 1) {
        return [
          {
            ...stages[0],
            status: "in_progress",
            startedAt: stages[0].startedAt ?? activeAnchor,
          },
        ];
      }

      return stages.map((stage, index) => {
        if (index === 0) {
          return {
            ...stage,
            status: "completed",
            startedAt: stage.startedAt ?? activeAnchor,
            completedAt: stage.completedAt ?? activeAnchor,
          };
        }
        if (index === 1) {
          return {
            ...stage,
            status: "in_progress",
            startedAt: stage.startedAt ?? activeAnchor,
          };
        }
        return stage;
      });
    }
    case "blocked":
      return stages.some((stage) => stage.status === "blocked")
        ? stages
        : stages.map((stage, index) =>
            index === 0
              ? {
                  ...stage,
                  status: "blocked",
                  startedAt: stage.startedAt ?? activeAnchor,
                }
              : stage,
          );
    case "completed":
      return stages.every((stage) => stage.status === "completed")
        ? stages
        : stages.map((stage) => ({
            ...stage,
            status: "completed",
            startedAt: stage.startedAt ?? activeAnchor,
            completedAt: stage.completedAt ?? completedAnchor,
          }));
    default:
      return stages;
  }
}

function normalizeMissionRuntimeEvents(
  value: unknown,
  missionId: string,
  missionDriver: Mission["driver"],
  primarySentinelId: string,
  fallbackStageId: string,
  fallbackCreatedAt: number,
): MissionRuntimeEvent[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.flatMap((entry, index) => {
    if (!isRecord(entry)) {
      return [];
    }

    return [
      {
        id: asString(entry.id, `legacy_event_${index}`),
        missionId: asString(entry.missionId, missionId),
        sentinelId: asString(entry.sentinelId, primarySentinelId),
        driver: normalizeMissionDriver(entry.driver, missionDriver),
        sessionRef: asString(entry.sessionRef),
        stageId: asString(entry.stageId, fallbackStageId),
        kind: normalizeMissionRuntimeEventKind(entry.kind),
        summary: asString(entry.summary),
        toolName: typeof entry.toolName === "string" ? entry.toolName : undefined,
        receiptRef: asNullableText(entry.receiptRef),
        signalId: asNullableText(entry.signalId),
        createdAt: asNumber(entry.createdAt, fallbackCreatedAt),
      },
    ];
  });
}

function normalizeMissionEvidence(
  value: unknown,
  fallbackCreatedAt: number,
): MissionEvidence[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.flatMap((entry, index) => {
    if (!isRecord(entry)) {
      return [];
    }

    const label = asString(entry.label, `Evidence ${index + 1}`);
    return [
      {
        id: asString(entry.id, `legacy_evidence_${index}`),
        type: normalizeMissionEvidenceType(entry.type),
        label,
        ref: asString(entry.ref),
        summary: asString(entry.summary, label),
        createdAt: asNumber(entry.createdAt, fallbackCreatedAt),
      },
    ];
  });
}

function normalizeMission(mission: Record<string, unknown>): Mission {
  const now = Date.now();
  const missionId = asString(mission.id);
  const driver = inferMissionDriver(mission);
  const status = normalizeMissionStatus(mission.status);
  const createdAt = asNumber(mission.createdAt, now);
  const updatedAt = asNumber(mission.updatedAt, createdAt);
  const startedAt = asNullableNumber(mission.startedAt);
  const completedAt = asNullableNumber(mission.completedAt);
  const assignedSentinelIds = asNonEmptyStringArray(mission.assignedSentinelIds);
  const normalizedPrimarySentinelId = inferPrimarySentinelId(mission, missionId);
  const normalizedAssignedSentinelIds =
    normalizedPrimarySentinelId && !assignedSentinelIds.includes(normalizedPrimarySentinelId)
      ? [normalizedPrimarySentinelId, ...assignedSentinelIds]
      : assignedSentinelIds;
  const normalizedStages = normalizeMissionStages(mission.stages, driver, normalizedPrimarySentinelId);
  const stages = repairMissionStages(
    normalizedStages.length > 0
      ? normalizedStages
      : buildMissionStagesForDriver(normalizedPrimarySentinelId, driver),
    status,
    startedAt,
    updatedAt,
    completedAt,
  );
  const fallbackStageId = stages[0]?.id ?? "";

  return {
    id: missionId,
    title: asString(mission.title),
    objective: asString(mission.objective),
    status,
    launchState: normalizeMissionLaunchState(mission.launchState),
    launchSummary: asNullableText(mission.launchSummary),
    launchHints: asStringArray(mission.launchHints),
    controlPlaneRef: asNullableText(mission.controlPlaneRef),
    priority: normalizeMissionPriority(mission.priority),
    assignedSentinelIds: normalizedAssignedSentinelIds,
    primarySentinelId: normalizedPrimarySentinelId,
    driver,
    stages,
    runtimeEvents: normalizeMissionRuntimeEvents(
      mission.runtimeEvents,
      asString(mission.id),
      driver,
      normalizedPrimarySentinelId,
      fallbackStageId,
      updatedAt,
    ),
    evidence: normalizeMissionEvidence(mission.evidence, updatedAt),
    signalIds: asNonEmptyStringArray(mission.signalIds),
    findingIds: asNonEmptyStringArray(mission.findingIds),
    createdAt,
    updatedAt,
    startedAt,
    completedAt,
  };
}

function loadPersistedMissions(): MissionState | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    if (
      !parsed ||
      typeof parsed !== "object" ||
      !Array.isArray((parsed as { missions?: unknown }).missions)
    ) {
      return null;
    }
    const persisted = parsed as {
      missions: unknown[];
      activeMissionId?: unknown;
    };
    const missions = persisted.missions
      .flatMap((mission) => {
        if (!isRecord(mission)) {
          return [];
        }
        if (typeof mission.id !== "string" || typeof mission.title !== "string") {
          return [];
        }
        return [normalizeMission(mission)];
      });
    const activeMissionId =
      typeof persisted.activeMissionId === "string" &&
      missions.some((mission) => mission.id === persisted.activeMissionId)
        ? persisted.activeMissionId
        : missions[0]?.id ?? null;
    return {
      missions,
      activeMissionId,
      loading: false,
    };
  } catch (error) {
    console.warn("[mission-store] load failed:", error);
    return null;
  }
}

function persistMissions(state: MissionState): void {
  try {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        missions: state.missions,
        activeMissionId: state.activeMissionId,
      }),
    );
  } catch (error) {
    console.error("[mission-store] persist failed:", error);
  }
}

function getInitialState(): MissionState {
  return (
    loadPersistedMissions() ?? {
      missions: [],
      activeMissionId: null,
      loading: false,
    }
  );
}

interface MissionContextValue {
  missions: Mission[];
  activeMission: Mission | undefined;
  createMission: (config: CreateMissionConfig) => Mission;
  setActiveMission: (missionId: string | null) => void;
  startMission: (missionId: string, execution: MissionExecutionBundle) => void;
  advanceMission: (missionId: string) => void;
  attachFindings: (missionId: string, findingIds: string[]) => void;
}

const MissionContext = createContext<MissionContextValue | null>(null);

export function useMissions(): MissionContextValue {
  const ctx = useContext(MissionContext);
  if (!ctx) throw new Error("useMissions must be used within MissionProvider");
  return ctx;
}

export function MissionProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(missionReducer, undefined, getInitialState);
  const persistRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (persistRef.current) clearTimeout(persistRef.current);
    persistRef.current = setTimeout(() => persistMissions(state), 500);
    return () => {
      if (persistRef.current) clearTimeout(persistRef.current);
    };
  }, [state]);

  const createMission = useCallback((config: CreateMissionConfig) => {
    const mission = engineCreateMission(config);
    dispatch({ type: "CREATE", mission });
    return mission;
  }, []);

  const setActiveMission = useCallback((missionId: string | null) => {
    dispatch({ type: "SET_ACTIVE", missionId });
  }, []);

  const startMission = useCallback((missionId: string, execution: MissionExecutionBundle) => {
    dispatch({ type: "START", missionId, execution });
  }, []);

  const advanceMission = useCallback((missionId: string) => {
    dispatch({ type: "ADVANCE", missionId });
  }, []);

  const attachFindings = useCallback((missionId: string, findingIds: string[]) => {
    dispatch({ type: "ATTACH_FINDINGS", missionId, findingIds });
  }, []);

  const value: MissionContextValue = {
    missions: state.missions,
    activeMission: state.missions.find((mission) => mission.id === state.activeMissionId),
    createMission,
    setActiveMission,
    startMission,
    advanceMission,
    attachFindings,
  };

  return <MissionContext.Provider value={value}>{children}</MissionContext.Provider>;
}
