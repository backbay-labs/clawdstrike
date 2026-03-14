import type { Signal, SignalCluster } from "./signal-pipeline";
import type { SentinelMutablePatch } from "./sentinel-manager";
import type { Sentinel } from "./sentinel-types";
import { generateId } from "./sentinel-types";
import {
  attachMissionFindings,
  createMission as createMissionDraft,
  executeMissionDriver,
  startMission,
} from "./mission-control";
import type {
  Mission,
  MissionDriverKind,
  MissionLaunchContext,
  MissionPriority,
  MissionStage,
} from "./mission-types";

export type { Mission, MissionDriverKind, MissionPriority };

export type MissionStep = MissionStage;

export type MissionTemplateId =
  | "claude_repo_triage"
  | "claude_fix_verification"
  | "openclaw_phishing_triage"
  | "openclaw_login_validation";

export interface MissionTemplateDefinition {
  id: MissionTemplateId;
  driver: MissionDriverKind;
  label: string;
  description: string;
  targetLabel: string;
  suggestedObjective: string;
  stepTitles: string[];
}

export interface MissionTimelineEntry {
  id: string;
  type: "created" | "runtime_event" | "finding_created";
  sentinelId: string | null;
  summary: string;
  timestamp: number;
  receiptRef?: string;
  signalId?: string;
  severity?: Signal["severity"];
}

export interface MissionLaunchSession {
  sentinelId: string;
  runtimeRef: string;
  sessionRef: string;
  lastEventAt: number;
}

export interface CreateMissionConfig {
  sentinel: Sentinel;
  templateId: MissionTemplateId;
  objective: string;
  priority: MissionPriority;
}

export interface MissionExecutionResult {
  mission: Mission;
  runtimePatch: SentinelMutablePatch;
  signals: Signal[];
  cluster: SignalCluster;
}

const MISSION_TEMPLATES: readonly MissionTemplateDefinition[] = [
  {
    id: "claude_repo_triage",
    driver: "claude_code",
    label: "Repo Triage",
    description: "Inspect a repo lane, run focused checks, and surface a code-facing finding.",
    targetLabel: "Workspace / repo path",
    suggestedObjective: "Inspect the auth and approval flows for risky code paths and patch candidates.",
    stepTitles: [
      "Open workspace context",
      "Inspect targeted files",
      "Run focused checks",
      "Draft remediation summary",
    ],
  },
  {
    id: "claude_fix_verification",
    driver: "claude_code",
    label: "Fix Verification",
    description: "Validate a proposed fix, run checks, and summarize any remaining risk.",
    targetLabel: "Workspace / repo path",
    suggestedObjective: "Verify the latest fix and report any remaining risk or policy drift.",
    stepTitles: [
      "Load change context",
      "Run verification commands",
      "Review patch impact",
      "Emit final assessment",
    ],
  },
  {
    id: "openclaw_phishing_triage",
    driver: "openclaw",
    label: "Phishing Triage",
    description: "Drive a browser lane to inspect redirects, capture IOCs, and summarize phishing risk.",
    targetLabel: "Gateway / node / target URL",
    suggestedObjective: "Investigate a suspicious link and capture redirect, form, and IOC evidence.",
    stepTitles: [
      "Connect hunt pod",
      "Open suspicious target",
      "Capture redirect and IOC evidence",
      "Summarize operator guidance",
    ],
  },
  {
    id: "openclaw_login_validation",
    driver: "openclaw",
    label: "Login Validation",
    description: "Exercise a login flow on an OpenClaw node and report security regressions.",
    targetLabel: "Gateway / node / target URL",
    suggestedObjective: "Validate login hardening and detect risky redirects, capture, or injection points.",
    stepTitles: [
      "Connect hunt pod",
      "Exercise login flow",
      "Collect browser evidence",
      "Publish mission summary",
    ],
  },
] as const;

function titleFromTemplate(template: MissionTemplateDefinition, sentinel: Sentinel): string {
  return `${template.label} · ${sentinel.name}`;
}

function buildCluster(signals: Signal[]): SignalCluster {
  return {
    id: generateId("enr"),
    signalIds: signals.map((signal) => signal.id),
    maxConfidence: signals.reduce((max, signal) => Math.max(max, signal.confidence), 0),
    strategies: signals.length > 1 ? ["agent_affinity", "time_window"] : ["pattern_match"],
    createdAt: Date.now(),
  };
}

function buildRuntimePatch(
  sentinel: Sentinel,
  runtimeRef: string,
  sessionRef: string,
  launchState: Mission["launchState"],
): SentinelMutablePatch {
  const health =
    launchState === "blocked" ? "offline" : launchState === "degraded" ? "degraded" : "ready";

  return {
    runtime: {
      driver: sentinel.runtime.driver,
      targetRef: sentinel.runtime.targetRef,
      runtimeRef,
      sessionRef,
      health,
      lastHeartbeatAt: Date.now(),
    },
  };
}

export function createMissionTimelineEntry(
  type: MissionTimelineEntry["type"],
  sentinelId: string | null,
  summary: string,
  timestamp = Date.now(),
  extras: Pick<MissionTimelineEntry, "receiptRef" | "signalId" | "severity"> = {},
): MissionTimelineEntry {
  return {
    id: generateId("enr"),
    type,
    sentinelId,
    summary,
    timestamp,
    ...extras,
  };
}

export function getMissionTemplates(): readonly MissionTemplateDefinition[] {
  return MISSION_TEMPLATES;
}

export function getMissionTemplatesForDriver(
  driver: MissionDriverKind,
): readonly MissionTemplateDefinition[] {
  return MISSION_TEMPLATES.filter((template) => template.driver === driver);
}

export function getMissionTemplate(templateId: MissionTemplateId): MissionTemplateDefinition {
  const template = MISSION_TEMPLATES.find((candidate) => candidate.id === templateId);
  if (!template) {
    throw new Error(`Unknown mission template: ${templateId}`);
  }
  return template;
}

export function createMission(config: CreateMissionConfig): Mission {
  const template = getMissionTemplate(config.templateId);

  return createMissionDraft({
    title: titleFromTemplate(template, config.sentinel),
    objective: config.objective.trim() || template.suggestedObjective,
    priority: config.priority,
    sentinel: config.sentinel,
  });
}

export function executeMission(
  mission: Mission,
  sentinel: Sentinel,
  context: MissionLaunchContext = {},
): MissionExecutionResult {
  const execution = executeMissionDriver(mission, sentinel, context);

  return {
    mission: startMission(mission, execution),
    runtimePatch: buildRuntimePatch(
      sentinel,
      execution.runtimeRef,
      execution.sessionRef,
      execution.launchState,
    ),
    signals: execution.signals,
    cluster: buildCluster(execution.signals),
  };
}

export function linkMissionFinding(mission: Mission, findingId: string): Mission {
  return attachMissionFindings(mission, [findingId]);
}
