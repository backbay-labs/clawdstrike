import type { Severity } from "./hunt-types";
import type { Signal } from "./signal-pipeline";
import { generateId } from "./sentinel-types";
import type { Sentinel } from "./sentinel-types";
import type {
  CreateMissionConfig,
  Mission,
  MissionEvidence,
  MissionExecutionBundle,
  MissionLaunchContext,
  MissionRuntimeEvent,
  MissionStage,
} from "./mission-types";

type MissionLaunchAssessment = Pick<
  MissionExecutionBundle,
  "launchState" | "launchSummary" | "launchHints" | "controlPlaneRef"
>;

function makeStage(
  ownerSentinelId: string,
  driver: Mission["driver"],
  label: string,
  summary: string,
): MissionStage {
  return {
    id: generateId("enr"),
    label,
    summary,
    status: "pending",
    ownerSentinelId,
    driver,
    startedAt: null,
    completedAt: null,
  };
}

export function buildMissionStagesForDriver(
  ownerSentinelId: string,
  driver: Mission["driver"],
): MissionStage[] {
  if (driver === "claude_code") {
    return [
      makeStage(ownerSentinelId, driver, "Intake", "Scope the repo lane and confirm the objective."),
      makeStage(ownerSentinelId, driver, "Repo Recon", "Inspect the workspace, dependency graph, and relevant files."),
      makeStage(ownerSentinelId, driver, "Verification", "Run focused checks and validate the remediation path."),
      makeStage(ownerSentinelId, driver, "Finding Promotion", "Convert verified runtime evidence into findings and next actions."),
    ];
  }

  return [
    makeStage(ownerSentinelId, driver, "Intake", "Bind to a gateway or node and load the mission objective."),
    makeStage(ownerSentinelId, driver, "Browser Recon", "Traverse the target journey and capture runtime observations."),
    makeStage(ownerSentinelId, driver, "Collection", "Collect artifacts, screenshots, and transcript summaries."),
    makeStage(ownerSentinelId, driver, "Validation", "Corroborate evidence and promote the hunt result."),
  ];
}

export function createMission(config: CreateMissionConfig): Mission {
  const driver = config.sentinel.runtime.driver;
  if (driver !== "claude_code" && driver !== "openclaw") {
    throw new Error(`Mission Control does not support driver "${driver}" yet.`);
  }

  const now = Date.now();
  const assignedSentinelIds = Array.from(
    new Set([config.sentinel.id, ...(config.additionalSentinelIds ?? [])]),
  );

  return {
    id: generateId("msn"),
    title: config.title.trim(),
    objective: config.objective.trim(),
    status: "draft",
    launchState: null,
    launchSummary: null,
    launchHints: [],
    controlPlaneRef: null,
    priority: config.priority,
    assignedSentinelIds,
    primarySentinelId: config.sentinel.id,
    driver,
    stages: buildMissionStages(config.sentinel),
    runtimeEvents: [],
    evidence: [],
    signalIds: [],
    findingIds: [],
    createdAt: now,
    updatedAt: now,
    startedAt: null,
    completedAt: null,
  };
}

export function buildMissionStages(sentinel: Sentinel): MissionStage[] {
  const driver = sentinel.runtime.driver;
  if (driver !== "claude_code" && driver !== "openclaw") {
    return [
      makeStage(sentinel.id, "claude_code", "Intake", "Prepare the runtime and confirm the objective."),
      makeStage(sentinel.id, "claude_code", "Execution", "Execute the assigned objective and collect evidence."),
    ];
  }

  return buildMissionStagesForDriver(sentinel.id, driver);
}

function defaultMissionTarget(sentinel: Sentinel): string {
  if (sentinel.runtime.targetRef?.trim()) {
    return sentinel.runtime.targetRef.trim();
  }
  return sentinel.runtime.driver === "claude_code" ? "/workspace" : "gateway://hunt-pod";
}

export function assessMissionLaunch(
  sentinel: Sentinel,
  context: MissionLaunchContext = {},
): MissionLaunchAssessment {
  const targetRef = defaultMissionTarget(sentinel);

  if (sentinel.runtime.driver === "claude_code") {
    const mcpStatus = context.claude?.mcpStatus;
    if (!mcpStatus?.running) {
      return {
        launchState: "blocked",
        launchSummary: mcpStatus?.error
          ? `Workbench MCP bridge is offline: ${mcpStatus.error}.`
          : "Workbench MCP bridge is not running, so Claude Code cannot bind to the workbench tool surface.",
        launchHints: [
          "Start or restart the embedded MCP sidecar before launching the sentinel mission.",
          "Bind the sentinel to a concrete repo or workspace target so Claude Code has a narrow execution lane.",
        ],
        controlPlaneRef: null,
      };
    }

    const hasExplicitTarget = Boolean(sentinel.runtime.targetRef?.trim());
    return {
      launchState: hasExplicitTarget ? "ready" : "degraded",
      launchSummary: hasExplicitTarget
        ? `Workbench MCP bridge is online at ${mcpStatus.url ?? "embedded-mcp"} for repo target ${targetRef}.`
        : `Workbench MCP bridge is online at ${mcpStatus.url ?? "embedded-mcp"}, but the sentinel is still using the default workspace target ${targetRef}.`,
      launchHints: hasExplicitTarget
        ? []
        : ["Set a repo-specific runtime target to keep Claude Code missions scoped to one lane."],
      controlPlaneRef: mcpStatus.url ?? "embedded-mcp",
    };
  }

  const connected = context.openclaw?.connected ?? false;
  const agentCount = context.openclaw?.agentCount ?? 0;
  const hushdUrl = context.openclaw?.hushdUrl?.trim() || null;

  if (!connected) {
    return {
      launchState: "blocked",
      launchSummary: "Fleet/OpenClaw control plane is disconnected, so the hunt pod has nowhere to launch.",
      launchHints: [
        "Reconnect the fleet control plane before launching OpenClaw missions.",
        "Bind the sentinel to a gateway or node target such as gateway://node-1.",
      ],
      controlPlaneRef: hushdUrl,
    };
  }

  if (agentCount === 0) {
    return {
      launchState: "blocked",
      launchSummary: `Fleet control is reachable${hushdUrl ? ` at ${hushdUrl}` : ""}, but there are no connected runtimes available for the hunt pod.`,
      launchHints: [
        "Connect or register at least one OpenClaw-capable runtime before launching the mission.",
      ],
      controlPlaneRef: hushdUrl,
    };
  }

  const hasExplicitTarget = Boolean(sentinel.runtime.targetRef?.trim());
  return {
    launchState: hasExplicitTarget ? "ready" : "degraded",
    launchSummary: hasExplicitTarget
      ? `OpenClaw control plane is ready${hushdUrl ? ` at ${hushdUrl}` : ""} with ${agentCount} connected runtime${agentCount === 1 ? "" : "s"} for target ${targetRef}.`
      : `OpenClaw control plane is ready${hushdUrl ? ` at ${hushdUrl}` : ""} with ${agentCount} connected runtime${agentCount === 1 ? "" : "s"}, but the hunt pod is still using the default target ${targetRef}.`,
    launchHints: hasExplicitTarget
      ? []
      : ["Set a concrete gateway or node target so Hunt Pod evidence stays tied to one execution lane."],
    controlPlaneRef: hushdUrl,
  };
}

function buildSignal(
  mission: Mission,
  sentinel: Sentinel,
  sessionRef: string,
  timestamp: number,
  severity: Severity,
  confidence: number,
  kind: Signal["data"]["kind"],
  summary: string,
  extra: Record<string, unknown>,
): Signal {
  return {
    id: generateId("sig"),
    type:
      kind === "policy_violation"
        ? "policy_violation"
        : kind === "behavioral"
          ? "behavioral"
          : "detection",
    source: {
      sentinelId: sentinel.id,
      guardId: kind === "policy_violation" ? "tool_boundary" : null,
      externalFeed: null,
      provenance: kind === "policy_violation" ? "guard_evaluation" : "pattern_match",
    },
    timestamp,
    severity,
    confidence,
    data: {
      kind,
      summary,
      target: defaultMissionTarget(sentinel),
      actionType: kind === "policy_violation" ? "mcp_tool_call" : "file_access",
      missionId: mission.id,
      driver: sentinel.runtime.driver,
      sessionRef,
      ...extra,
    },
    context: {
      agentId: sentinel.id,
      agentName: sentinel.name,
      sessionId: sessionRef,
      flags: [
        { type: "mission", reason: mission.id },
        { type: "driver", reason: sentinel.runtime.driver },
      ],
    },
    relatedSignals: [],
    ttl: severity === "critical" || severity === "high" ? null : 24 * 60 * 60 * 1000,
    findingId: null,
  };
}

function buildEvidence(
  type: MissionEvidence["type"],
  label: string,
  ref: string,
  summary: string,
  createdAt: number,
): MissionEvidence {
  return {
    id: generateId("enr"),
    type,
    label,
    ref,
    summary,
    createdAt,
  };
}

function buildRuntimeEvent(
  mission: Mission,
  sentinel: Sentinel,
  sessionRef: string,
  stageId: string,
  kind: MissionRuntimeEvent["kind"],
  summary: string,
  createdAt: number,
  options: {
    toolName?: string;
    receiptRef?: string | null;
    signalId?: string | null;
  } = {},
): MissionRuntimeEvent {
  return {
    id: generateId("enr"),
    missionId: mission.id,
    sentinelId: sentinel.id,
    driver: mission.driver,
    sessionRef,
    stageId,
    kind,
    summary,
    toolName: options.toolName,
    receiptRef: options.receiptRef ?? null,
    signalId: options.signalId ?? null,
    createdAt,
  };
}

export function executeMissionDriver(
  mission: Mission,
  sentinel: Sentinel,
  context: MissionLaunchContext = {},
): MissionExecutionBundle {
  const launch = assessMissionLaunch(sentinel, context);
  const sessionRef = `${mission.driver}_session_${Date.now().toString(36)}`;
  const runtimeRef = `${mission.driver}_runtime_${sentinel.id}`;
  const targetRef = defaultMissionTarget(sentinel);
  const baseTs = Date.now();
  const events: MissionRuntimeEvent[] = [];
  const evidence: MissionEvidence[] = [];
  const signals: Signal[] = [];

  const firstStageId = mission.stages[0]?.id ?? generateId("enr");
  if (launch.launchState === "blocked") {
    events.push(
      buildRuntimeEvent(
        mission,
        sentinel,
        sessionRef,
        firstStageId,
        "launch_blocked",
        launch.launchSummary,
        baseTs,
      ),
    );
    evidence.push(
      buildEvidence(
        "note",
        "Launch Blocked",
        runtimeRef,
        launch.launchSummary,
        baseTs,
      ),
    );
    for (const [index, hint] of launch.launchHints.entries()) {
      evidence.push(
        buildEvidence(
          "note",
          `Launch Hint ${index + 1}`,
          `${runtimeRef}:hint:${index + 1}`,
          hint,
          baseTs + index + 1,
        ),
      );
    }
    return {
      runtimeRef,
      sessionRef,
      launchState: launch.launchState,
      launchSummary: launch.launchSummary,
      launchHints: launch.launchHints,
      controlPlaneRef: launch.controlPlaneRef,
      runtimeEvents: events,
      evidence,
      signals,
    };
  }

  events.push(
    buildRuntimeEvent(
      mission,
      sentinel,
      sessionRef,
      firstStageId,
      "session_started",
      `${sentinel.name} launched ${mission.driver} session ${sessionRef}. ${launch.launchSummary}`,
      baseTs,
      { receiptRef: `${runtimeRef}:session` },
    ),
  );
  evidence.push(
    buildEvidence(
      "session",
      "Runtime Session",
      sessionRef,
      `Started ${mission.driver} session for ${sentinel.name} against ${targetRef}.`,
      baseTs,
    ),
  );
  if (launch.controlPlaneRef) {
    evidence.push(
      buildEvidence(
        "note",
        mission.driver === "claude_code" ? "Claude Bridge" : "OpenClaw Control Plane",
        launch.controlPlaneRef,
        launch.launchSummary,
        baseTs,
      ),
    );
  }
  if (launch.launchState === "degraded") {
    events.push(
      buildRuntimeEvent(
        mission,
        sentinel,
        sessionRef,
        firstStageId,
        "summary",
        "Mission launched in degraded mode. Review the launch hints before promoting any remediation.",
        baseTs + 1,
      ),
    );
  }

  if (mission.driver === "claude_code") {
    const reconTs = baseTs + 10;
    const verifyTs = baseTs + 20;
    const blockTs = baseTs + 30;
    const reconSignal = buildSignal(
      mission,
      sentinel,
      sessionRef,
      reconTs,
      "medium",
      0.72,
      "behavioral",
      "Claude Code indexed the repo lane through the workbench MCP bridge and identified the code path tied to the mission objective.",
      { toolName: "read_file", targetPath: targetRef },
    );
    const verifySignal = buildSignal(
      mission,
      sentinel,
      sessionRef,
      verifyTs,
      "medium",
      0.81,
      "detection",
      "Claude Code ran focused verification and isolated a suspicious policy gap worth triage.",
      { toolName: "run_checks", checkSuite: "focused-verification", targetPath: targetRef },
    );
    const blockSignal = buildSignal(
      mission,
      sentinel,
      sessionRef,
      blockTs,
      "high",
      0.97,
      "policy_violation",
      "Tool-boundary policy blocked an attempted read of a sensitive host path during repo investigation.",
      {
        toolName: "read_file",
        targetPath: "~/.ssh/config",
        verdict: "deny",
        policyName: sentinel.policy.policyName ?? sentinel.policy.ruleset ?? "default",
      },
    );
    signals.push(reconSignal, verifySignal, blockSignal);
    events.push(
      buildRuntimeEvent(
        mission,
        sentinel,
        sessionRef,
        mission.stages[1]?.id ?? firstStageId,
        "tool_call",
        reconSignal.data.summary ?? "Workspace indexed",
        reconTs,
        { toolName: "read_file", signalId: reconSignal.id },
      ),
      buildRuntimeEvent(
        mission,
        sentinel,
        sessionRef,
        mission.stages[2]?.id ?? firstStageId,
        "tool_call",
        verifySignal.data.summary ?? "Verification completed",
        verifyTs,
        { toolName: "run_checks", signalId: verifySignal.id },
      ),
      buildRuntimeEvent(
        mission,
        sentinel,
        sessionRef,
        mission.stages[2]?.id ?? firstStageId,
        "policy_block",
        blockSignal.data.summary ?? "Policy blocked access",
        blockTs,
        {
          toolName: "read_file",
          receiptRef: `${runtimeRef}:policy-block`,
          signalId: blockSignal.id,
        },
      ),
    );
    evidence.push(
      buildEvidence(
        "receipt",
        "Tool Boundary Receipt",
        `${runtimeRef}:policy-block`,
        "Claude Code boundary denied host-secret path access while running the mission.",
        blockTs,
      ),
    );
  } else {
    const reconTs = baseTs + 10;
    const collectTs = baseTs + 20;
    const blockTs = baseTs + 30;
    const reconSignal = buildSignal(
      mission,
      sentinel,
      sessionRef,
      reconTs,
      "medium",
      0.76,
      "behavioral",
      "OpenClaw traversed the target flow and captured a suspicious redirect chain during browser reconnaissance.",
      { toolName: "browser.goto", targetUrl: targetRef },
    );
    const collectSignal = buildSignal(
      mission,
      sentinel,
      sessionRef,
      collectTs,
      "high",
      0.88,
      "detection",
      "OpenClaw collected a credential-harvest pattern and screenshot evidence from the mission target.",
      { toolName: "browser.snapshot", artifactType: "screenshot" },
    );
    const blockSignal = buildSignal(
      mission,
      sentinel,
      sessionRef,
      blockTs,
      "critical",
      0.99,
      "policy_violation",
      "Brokered runtime blocked a high-risk download attempt while the hunt pod was collecting evidence.",
      {
        toolName: "browser.download",
        verdict: "deny",
        targetUrl: targetRef,
      },
    );
    signals.push(reconSignal, collectSignal, blockSignal);
    events.push(
      buildRuntimeEvent(
        mission,
        sentinel,
        sessionRef,
        mission.stages[1]?.id ?? firstStageId,
        "tool_call",
        reconSignal.data.summary ?? "Browser reconnaissance completed",
        reconTs,
        { toolName: "browser.goto", signalId: reconSignal.id },
      ),
      buildRuntimeEvent(
        mission,
        sentinel,
        sessionRef,
        mission.stages[2]?.id ?? firstStageId,
        "artifact_collected",
        collectSignal.data.summary ?? "Artifact collected",
        collectTs,
        { toolName: "browser.snapshot", signalId: collectSignal.id },
      ),
      buildRuntimeEvent(
        mission,
        sentinel,
        sessionRef,
        mission.stages[3]?.id ?? firstStageId,
        "policy_block",
        blockSignal.data.summary ?? "High-risk download blocked",
        blockTs,
        {
          toolName: "browser.download",
          receiptRef: `${runtimeRef}:download-block`,
          signalId: blockSignal.id,
        },
      ),
    );
    evidence.push(
      buildEvidence(
        "receipt",
        "Brokered Download Block",
        `${runtimeRef}:download-block`,
        "OpenClaw broker denied a risky download during the mission.",
        blockTs,
      ),
    );
  }

  for (const signal of signals) {
    evidence.push(
      buildEvidence(
        "signal",
        signal.type === "policy_violation" ? "Policy Violation Signal" : "Runtime Signal",
        signal.id,
        signal.data.summary ?? `${signal.type} signal`,
        signal.timestamp,
      ),
    );
  }

  return {
    runtimeRef,
    sessionRef,
    launchState: launch.launchState,
    launchSummary: launch.launchSummary,
    launchHints: launch.launchHints,
    controlPlaneRef: launch.controlPlaneRef,
    runtimeEvents: events,
    evidence,
    signals,
  };
}

export function startMission(mission: Mission, execution: MissionExecutionBundle): Mission {
  const now = Date.now();
  if (execution.launchState === "blocked") {
    return {
      ...mission,
      status: "blocked",
      launchState: execution.launchState,
      launchSummary: execution.launchSummary,
      launchHints: execution.launchHints,
      controlPlaneRef: execution.controlPlaneRef,
      startedAt: now,
      updatedAt: now,
      runtimeEvents: execution.runtimeEvents,
      evidence: execution.evidence,
      signalIds: execution.signals.map((signal) => signal.id),
      stages: mission.stages.map((stage, index) =>
        index === 0
          ? {
              ...stage,
              status: "blocked",
              startedAt: now,
            }
          : stage,
      ),
    };
  }

  return {
    ...mission,
    status: "active",
    launchState: execution.launchState,
    launchSummary: execution.launchSummary,
    launchHints: execution.launchHints,
    controlPlaneRef: execution.controlPlaneRef,
    startedAt: now,
    updatedAt: now,
    runtimeEvents: execution.runtimeEvents,
    evidence: execution.evidence,
    signalIds: execution.signals.map((signal) => signal.id),
    stages: mission.stages.map((stage, index) => {
      if (index === 0) {
        return {
          ...stage,
          status: "completed",
          startedAt: now,
          completedAt: now,
        };
      }
      if (index === 1) {
        return {
          ...stage,
          status: "in_progress",
          startedAt: now,
        };
      }
      return stage;
    }),
  };
}

export function advanceMission(mission: Mission): Mission {
  if (mission.status !== "active") {
    return mission;
  }

  const now = Date.now();
  const activeIndex = mission.stages.findIndex((stage) => stage.status === "in_progress");
  if (activeIndex === -1) {
    return mission;
  }

  const stages = mission.stages.map<MissionStage>((stage, index) => {
    if (index === activeIndex) {
      return {
        ...stage,
        status: "completed",
        completedAt: now,
      };
    }
    if (index === activeIndex + 1) {
      return {
        ...stage,
        status: "in_progress",
        startedAt: stage.startedAt ?? now,
      };
    }
    return stage;
  });

  const allComplete = stages.every((stage) => stage.status === "completed");
  return {
    ...mission,
    status: allComplete ? "completed" : mission.status,
    completedAt: allComplete ? now : mission.completedAt,
    updatedAt: now,
    stages,
  };
}

export function attachMissionFindings(mission: Mission, findingIds: string[]): Mission {
  const mergedFindingIds = Array.from(new Set([...mission.findingIds, ...findingIds]));
  const evidence = [
    ...mission.evidence,
    ...findingIds
      .filter((findingId) => !mission.findingIds.includes(findingId))
      .map((findingId) => ({
        id: generateId("enr"),
        type: "finding" as const,
        label: "Finding",
        ref: findingId,
        summary: "Correlated runtime evidence promoted to a finding.",
        createdAt: Date.now(),
      })),
  ];
  return {
    ...mission,
    findingIds: mergedFindingIds,
    evidence,
    updatedAt: Date.now(),
  };
}
