import type { Signal } from "./signal-pipeline";
import {
  createMissionTimelineEntry,
  type MissionLaunchSession,
  type MissionTimelineEntry,
} from "./mission-manager";
import type { Mission } from "./mission-types";
import type { Sentinel } from "./sentinel-types";

export interface MissionEvidenceRef {
  id: string;
  kind: "session" | "receipt" | "transcript" | "note";
  refId: string;
  label: string;
  summary: string;
  severity: Signal["severity"];
  sourceSentinelId: string;
  createdAt: number;
}

export interface MissionLaunchPackage {
  sessions: MissionLaunchSession[];
  timeline: MissionTimelineEntry[];
  evidence: MissionEvidenceRef[];
  signals: Signal[];
}

function randomRef(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
}

function defaultMissionTarget(sentinel: Sentinel): string {
  return sentinel.runtime.targetRef ?? (
    sentinel.runtime.driver === "claude_code" ? "/workspace" : "gateway://hunt-pod"
  );
}

function missionSeverity(mission: Mission): Signal["severity"] {
  switch (mission.launchState) {
    case "blocked":
      return "high";
    case "degraded":
      return "medium";
    case "ready":
      return "low";
    default:
      return mission.status === "completed" ? "info" : "low";
  }
}

export function buildMissionLaunchPackage(
  mission: Mission,
  sentinels: Sentinel[],
): MissionLaunchPackage {
  const assignedSentinels = sentinels.filter((sentinel) =>
    mission.assignedSentinelIds.includes(sentinel.id),
  );
  const severity = missionSeverity(mission);
  const sessions: MissionLaunchSession[] = [];
  const timeline: MissionTimelineEntry[] = [];
  const evidence: MissionEvidenceRef[] = [];

  for (const sentinel of assignedSentinels) {
    const runtimeRef = sentinel.runtime.runtimeRef ?? `${mission.driver}_runtime_${sentinel.id}`;
    const sessionRef = sentinel.runtime.sessionRef ?? `${mission.driver}_session_${sentinel.id}`;
    const target = defaultMissionTarget(sentinel);

    sessions.push({
      sentinelId: sentinel.id,
      runtimeRef,
      sessionRef,
      lastEventAt: mission.updatedAt,
    });

    timeline.push(
      createMissionTimelineEntry(
        "runtime_event",
        sentinel.id,
        `${sentinel.name} is staged for mission "${mission.title}" against ${target}.`,
        mission.updatedAt,
      ),
    );

    evidence.push({
      id: randomRef("mev"),
      kind: "session",
      refId: sessionRef,
      label: `${sentinel.name} launch session`,
      summary: `Prepared ${sentinel.runtime.driver} runtime for ${target}.`,
      severity,
      sourceSentinelId: sentinel.id,
      createdAt: mission.updatedAt,
    });

    if (mission.launchSummary) {
      evidence.push({
        id: randomRef("mev"),
        kind: "note",
        refId: runtimeRef,
        label: `${sentinel.name} launch summary`,
        summary: mission.launchSummary,
        severity,
        sourceSentinelId: sentinel.id,
        createdAt: mission.updatedAt,
      });
    }
  }

  return {
    sessions,
    timeline,
    evidence,
    signals: [],
  };
}
