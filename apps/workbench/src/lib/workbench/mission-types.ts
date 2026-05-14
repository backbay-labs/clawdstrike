import type { Signal } from "./signal-pipeline";
import type { Sentinel, SentinelDriverKind } from "./sentinel-types";

export type MissionDriverKind = Extract<SentinelDriverKind, "claude_code" | "openclaw">;
export type MissionLaunchState = "ready" | "degraded" | "blocked";
export type MissionStatus = "draft" | "active" | "blocked" | "completed" | "aborted";
export type MissionPriority = "low" | "medium" | "high" | "critical";
export type MissionStageStatus = "pending" | "in_progress" | "completed" | "blocked";
export type MissionEvidenceType =
  | "signal"
  | "finding"
  | "receipt"
  | "runtime_event"
  | "session"
  | "note";
export type MissionRuntimeEventKind =
  | "session_started"
  | "launch_blocked"
  | "tool_call"
  | "policy_block"
  | "artifact_collected"
  | "summary";

export interface MissionLaunchContext {
  claude?: {
    mcpStatus?: {
      running: boolean;
      url?: string | null;
      error?: string | null;
    } | null;
  };
  openclaw?: {
    connected: boolean;
    hushdUrl?: string | null;
    agentCount?: number;
  };
}

export interface MissionStage {
  id: string;
  label: string;
  summary: string;
  status: MissionStageStatus;
  ownerSentinelId: string;
  driver: MissionDriverKind;
  startedAt: number | null;
  completedAt: number | null;
}

export interface MissionEvidence {
  id: string;
  type: MissionEvidenceType;
  label: string;
  ref: string;
  summary: string;
  createdAt: number;
}

export interface MissionRuntimeEvent {
  id: string;
  missionId: string;
  sentinelId: string;
  driver: MissionDriverKind;
  sessionRef: string;
  stageId: string;
  kind: MissionRuntimeEventKind;
  summary: string;
  toolName?: string;
  receiptRef?: string | null;
  signalId?: string | null;
  createdAt: number;
}

export interface Mission {
  id: string;
  title: string;
  objective: string;
  status: MissionStatus;
  launchState: MissionLaunchState | null;
  launchSummary: string | null;
  launchHints: string[];
  controlPlaneRef: string | null;
  priority: MissionPriority;
  assignedSentinelIds: string[];
  primarySentinelId: string;
  driver: MissionDriverKind;
  stages: MissionStage[];
  runtimeEvents: MissionRuntimeEvent[];
  evidence: MissionEvidence[];
  signalIds: string[];
  findingIds: string[];
  createdAt: number;
  updatedAt: number;
  startedAt: number | null;
  completedAt: number | null;
}

export interface CreateMissionConfig {
  title: string;
  objective: string;
  priority: MissionPriority;
  sentinel: Sentinel;
  additionalSentinelIds?: string[];
}

export interface MissionExecutionBundle {
  runtimeRef: string;
  sessionRef: string;
  launchState: MissionLaunchState;
  launchSummary: string;
  launchHints: string[];
  controlPlaneRef: string | null;
  runtimeEvents: MissionRuntimeEvent[];
  evidence: MissionEvidence[];
  signals: Signal[];
}
