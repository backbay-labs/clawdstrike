import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  IconArrowRight,
  IconBrain,
  IconChevronRight,
  IconCircleCheck,
  IconFlag3,
  IconNetwork,
  IconPlayerPlay,
  IconRadar,
  IconRoute,
  IconTarget,
  IconTerminal2,
  IconRotateClockwise2,
  IconPlugConnected,
  IconPlugConnectedX,
} from "@tabler/icons-react";
import { ClaudeCodeHint } from "@/components/workbench/shared/claude-code-hint";
import { cn } from "@/lib/utils";
import { assessMissionLaunch, executeMissionDriver } from "@/lib/workbench/mission-control";
import { useMissions } from "@/features/missions/stores/mission-store";
import type {
  MissionEvidence,
  MissionLaunchContext,
  MissionLaunchState,
  MissionPriority,
  MissionStatus,
} from "@/lib/workbench/mission-types";
import { correlateSignals } from "@/lib/workbench/signal-pipeline";
import { useSignals } from "@/features/findings/stores/signal-store";
import { useFindings } from "@/features/findings/stores/finding-store";
import { getSentinelDriverDefinition, getSentinelExecutionModeConfig } from "@/lib/workbench/sentinel-manager";
import { useSentinels } from "@/features/sentinels/stores/sentinel-store";
import { useFleetConnection } from "@/features/fleet/use-fleet-connection";
import { useMcpStatus } from "@/lib/workbench/use-mcp-status";
import { signReceiptNative, signReceiptPersistentNative } from "@/lib/tauri-commands";
import { generateId } from "@/lib/workbench/sentinel-types";

const PRIORITIES: readonly MissionPriority[] = ["low", "medium", "high", "critical"];

const STATUS_COLORS: Record<MissionStatus, string> = {
  draft: "#6f7f9a",
  active: "#d4a84b",
  blocked: "#c45c5c",
  completed: "#3dbf84",
  aborted: "#8b5555",
};

const LAUNCH_COLORS: Record<MissionLaunchState, string> = {
  ready: "#3dbf84",
  degraded: "#d4a84b",
  blocked: "#c45c5c",
};

const DRIVER_OBJECTIVES = {
  claude_code: [
    "Inspect the authz and policy surfaces for a minimal high-confidence fix.",
    "Trace an emerging finding through the repo and verify the remediation path.",
    "Review a codepath for unsafe tool access and promote a finding if corroborated.",
  ],
  openclaw: [
    "Walk a suspected phishing flow and capture the credential-harvest evidence chain.",
    "Validate a login journey for malicious redirects and high-risk download behavior.",
    "Collect browser/runtime evidence for a suspicious external target and summarize the blast radius.",
  ],
} as const;

function relativeTime(epochMs: number): string {
  const diffSecs = Math.floor((Date.now() - epochMs) / 1000);
  if (diffSecs < 60) return `${diffSecs}s ago`;
  if (diffSecs < 3600) return `${Math.floor(diffSecs / 60)}m ago`;
  if (diffSecs < 86400) return `${Math.floor(diffSecs / 3600)}h ago`;
  return `${Math.floor(diffSecs / 86400)}d ago`;
}

function launchStateLabel(state: MissionLaunchState): string {
  return state === "ready" ? "Ready" : state === "degraded" ? "Degraded" : "Blocked";
}

function launchStateToRuntimeHealth(state: MissionLaunchState): "ready" | "degraded" | "offline" {
  return state === "ready" ? "ready" : state === "degraded" ? "degraded" : "offline";
}

async function createLaunchReceiptEvidence(
  missionId: string,
  title: string,
  driver: string,
  objective: string,
  launchState: MissionLaunchState,
): Promise<MissionEvidence | null> {
  const payload = JSON.stringify({
    mission_id: missionId,
    title,
    driver,
    objective,
    launch_state: launchState,
    timestamp: new Date().toISOString(),
  });
  const payloadBytes = new TextEncoder().encode(payload);
  const hashBuffer = await crypto.subtle.digest("SHA-256", payloadBytes.buffer as ArrayBuffer);
  const contentHash = Array.from(new Uint8Array(hashBuffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  const signed =
    (await signReceiptPersistentNative(contentHash, launchState !== "blocked")) ??
    (await signReceiptNative(contentHash, launchState !== "blocked"));

  if (!signed) {
    return null;
  }

  return {
    id: generateId("enr"),
    type: "receipt",
    label: "Signed Launch Receipt",
    ref: signed.receipt_hash,
    summary: `${driver.replace("_", " ")} mission launch signed with a ${signed.key_type} key.`,
    createdAt: Date.now(),
  };
}

export function MissionControlPage() {
  const [searchParams] = useSearchParams();
  const { status: mcpStatus, refresh: refreshMcpStatus, handleRestart: restartMcpServer, isRestarting } = useMcpStatus();
  const { connection, agents } = useFleetConnection();
  const {
    missions,
    activeMission,
    createMission,
    setActiveMission,
    startMission,
    advanceMission,
    attachFindings,
  } = useMissions();
  const { sentinels, updateSentinel } = useSentinels();
  const { ingestSignal } = useSignals();
  const { createFromCluster, findings } = useFindings();

  const mountedRef = useRef(true);
  useEffect(() => () => { mountedRef.current = false; }, []);

  const eligibleSentinels = useMemo(
    () =>
      sentinels.filter((sentinel) =>
        sentinel.status !== "retired" &&
        (sentinel.runtime.driver === "claude_code" || sentinel.runtime.driver === "openclaw"),
      ),
    [sentinels],
  );

  const [selectedSentinelId, setSelectedSentinelId] = useState<string>("");
  const [title, setTitle] = useState("");
  const [objective, setObjective] = useState("");
  const [priority, setPriority] = useState<MissionPriority>("high");

  useEffect(() => {
    const fromQuery = searchParams.get("sentinel");
    const preferred =
      (fromQuery && eligibleSentinels.some((sentinel) => sentinel.id === fromQuery) ? fromQuery : null) ??
      eligibleSentinels[0]?.id ??
      "";
    setSelectedSentinelId((current) => (current ? current : preferred));
  }, [eligibleSentinels, searchParams]);

  const selectedSentinel = eligibleSentinels.find((sentinel) => sentinel.id === selectedSentinelId);
  const selectedDriver = selectedSentinel ? getSentinelDriverDefinition(selectedSentinel.runtime.driver) : null;
  const selectedExecutionMode = selectedSentinel
    ? getSentinelExecutionModeConfig(selectedSentinel.runtime.executionMode)
    : null;
  const missionRuntimeContext = useMemo<MissionLaunchContext>(
    () => ({
      claude: { mcpStatus },
      openclaw: {
        connected: connection.connected,
        hushdUrl: connection.hushdUrl || null,
        agentCount: agents.length,
      },
    }),
    [agents.length, connection.connected, connection.hushdUrl, mcpStatus],
  );
  const selectedLaunch = selectedSentinel
    ? assessMissionLaunch(selectedSentinel, missionRuntimeContext)
    : null;

  const missionList = missions;
  const displayedMission = activeMission ?? missionList[0];
  const counts = useMemo(() => {
    const active = missions.filter((mission) => mission.status === "active").length;
    const completed = missions.filter((mission) => mission.status === "completed").length;
    return { total: missions.length, active, completed };
  }, [missions]);

  const objectivePresets = selectedSentinel
    ? DRIVER_OBJECTIVES[selectedSentinel.runtime.driver as keyof typeof DRIVER_OBJECTIVES] ?? []
    : [];

  const handleLaunch = useCallback(async () => {
    if (!selectedSentinel || !objective.trim()) return;

    const nextMission = createMission({
      title: title.trim() || `${selectedDriver?.label ?? "Sentinel"} Mission`,
      objective: objective.trim(),
      priority,
      sentinel: selectedSentinel,
    });

    const execution = executeMissionDriver(nextMission, selectedSentinel, missionRuntimeContext);
    const signedReceipt = await createLaunchReceiptEvidence(
      nextMission.id,
      nextMission.title,
      nextMission.driver,
      nextMission.objective,
      execution.launchState,
    );
    if (!mountedRef.current) return;
    if (signedReceipt) {
      execution.evidence.push(signedReceipt);
    }
    startMission(nextMission.id, execution);

    execution.signals.forEach((signal) => ingestSignal(signal));
    if (execution.signals.length > 0) {
      const clusters = correlateSignals(execution.signals);
      const createdFindingIds: string[] = [];
      for (const cluster of clusters) {
        const finding = createFromCluster(cluster, execution.signals, selectedSentinel.name);
        if (finding) {
          createdFindingIds.push(finding.id);
        }
      }
      if (createdFindingIds.length > 0) {
        attachFindings(nextMission.id, createdFindingIds);
      }
    }

    updateSentinel(selectedSentinel.id, {
      status: execution.launchState === "blocked" ? "paused" : "active",
      runtime: {
        runtimeRef: execution.runtimeRef,
        sessionRef: execution.sessionRef,
        health: launchStateToRuntimeHealth(execution.launchState),
        lastHeartbeatAt: execution.launchState === "blocked" ? null : Date.now(),
      },
    });
    setActiveMission(nextMission.id);
  }, [
    attachFindings,
    createFromCluster,
    createMission,
    ingestSignal,
    missionRuntimeContext,
    objective,
    priority,
    selectedDriver?.label,
    selectedSentinel,
    setActiveMission,
    startMission,
    title,
    updateSentinel,
  ]);

  const handleAdvance = useCallback(() => {
    if (!displayedMission) return;
    advanceMission(displayedMission.id);
  }, [advanceMission, displayedMission]);

  if (eligibleSentinels.length === 0) {
    return (
      <div className="flex h-full w-full flex-col items-center justify-center bg-[#05060a] px-8">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-[#2d3240]/60 bg-[#131721]">
          <IconFlag3 size={22} stroke={1.5} className="text-[#d4a84b]" />
        </div>
        <h1 className="mt-4 text-lg font-semibold text-[#ece7dc]">Mission Control</h1>
        <p className="mt-2 max-w-md text-center text-[12px] leading-relaxed text-[#6f7f9a]">
          Create a `claude_code` or `openclaw` sentinel first. Mission Control launches
          runtime-backed missions and promotes their evidence into signals and findings.
        </p>
        <Link
          to="/sentinels/create"
          className="mt-6 inline-flex items-center gap-2 rounded-md border border-[#d4a84b]/30 bg-[#d4a84b]/5 px-4 py-2 text-[11px] font-medium text-[#d4a84b] transition-colors hover:bg-[#d4a84b]/10"
        >
          <IconRadar size={13} stroke={1.5} />
          Create Sentinel
        </Link>
      </div>
    );
  }

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#05060a]">
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <IconFlag3 size={18} stroke={1.5} className="text-[#d4a84b]" />
            <div>
              <h1 className="text-sm font-semibold tracking-[-0.01em] text-[#ece7dc]">
                Mission Control
              </h1>
              <p className="mt-0.5 text-[11px] text-[#6f7f9a]">
                Claude Code and OpenClaw execution routed into evidence-native detection.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3 text-[10px] text-[#6f7f9a]/60">
            <span>{counts.total} missions</span>
            <span>{counts.active} active</span>
            <span>{counts.completed} completed</span>
          </div>
        </div>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-[320px_minmax(0,1fr)]">
        <div className="overflow-auto border-r border-[#2d3240]/60 bg-[#0b0d13]">
          <div className="border-b border-[#2d3240]/60 px-4 py-4">
            <h2 className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50">
              Launch Mission
            </h2>
            <div className="mt-4 flex flex-col gap-3">
              <div className="flex flex-col gap-1.5">
                <label className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/50">
                  Sentinel
                </label>
                <select
                  value={selectedSentinelId}
                  onChange={(event) => setSelectedSentinelId(event.target.value)}
                  className="rounded-md border border-[#2d3240]/60 bg-[#05060a] px-3 py-2 text-[12px] text-[#ece7dc] outline-none focus:border-[#d4a84b]/40"
                >
                  {eligibleSentinels.map((sentinel) => {
                    const driver = getSentinelDriverDefinition(sentinel.runtime.driver);
                    return (
                      <option key={sentinel.id} value={sentinel.id}>
                        {sentinel.name} · {driver.label}
                      </option>
                    );
                  })}
                </select>
              </div>

              {selectedSentinel && selectedDriver && selectedExecutionMode && (
                <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721]/60 p-3">
                  <div className="flex items-center gap-2">
                    {selectedSentinel.runtime.driver === "claude_code" ? (
                      <IconTerminal2 size={14} stroke={1.5} className="text-[#8b7355]" />
                    ) : (
                      <IconNetwork size={14} stroke={1.5} className="text-[#55788b]" />
                    )}
                    <span className="text-[11px] font-semibold text-[#ece7dc]">
                      {selectedDriver.label}
                    </span>
                  </div>
                  <p className="mt-1 text-[10px] leading-relaxed text-[#6f7f9a]/65">
                    {selectedDriver.description}
                  </p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    <span className="rounded-full border border-[#2d3240]/40 bg-[#05060a] px-2 py-0.5 text-[8px] font-medium uppercase tracking-[0.08em] text-[#ece7dc]/65">
                      {selectedExecutionMode.label}
                    </span>
                    <span className="rounded-full border border-[#2d3240]/40 bg-[#05060a] px-2 py-0.5 text-[8px] font-medium uppercase tracking-[0.08em] text-[#6f7f9a]/60">
                      Tier {selectedSentinel.runtime.enforcementTier}
                    </span>
                  </div>
                </div>
              )}

              {selectedSentinel && selectedLaunch && (
                <div className="rounded-lg border border-[#2d3240]/60 bg-[#0b0d13] p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2">
                      {selectedSentinel.runtime.driver === "claude_code" ? (
                        <IconTerminal2 size={14} stroke={1.5} className="text-[#d4a84b]" />
                      ) : selectedLaunch.launchState === "blocked" ? (
                        <IconPlugConnectedX size={14} stroke={1.5} className="text-[#c45c5c]" />
                      ) : (
                        <IconPlugConnected size={14} stroke={1.5} className="text-[#3dbf84]" />
                      )}
                      <span className="text-[11px] font-semibold text-[#ece7dc]">Runtime Readiness</span>
                    </div>
                    <span
                      className="rounded-full px-2 py-0.5 text-[8px] font-semibold uppercase tracking-[0.08em]"
                      style={{
                        backgroundColor: LAUNCH_COLORS[selectedLaunch.launchState] + "15",
                        color: LAUNCH_COLORS[selectedLaunch.launchState],
                      }}
                    >
                      {launchStateLabel(selectedLaunch.launchState)}
                    </span>
                  </div>
                  <p className="mt-2 text-[10px] leading-relaxed text-[#6f7f9a]/70">
                    {selectedLaunch.launchSummary}
                  </p>
                  {selectedLaunch.controlPlaneRef && (
                    <div className="mt-2 text-[9px] font-mono text-[#6f7f9a]/45">
                      {selectedLaunch.controlPlaneRef}
                    </div>
                  )}
                  {selectedLaunch.launchHints.length > 0 && (
                    <div className="mt-2 flex flex-col gap-1">
                      {selectedLaunch.launchHints.map((hint) => (
                        <div key={hint} className="text-[9px] leading-relaxed text-[#c1b6a0]/70">
                          {hint}
                        </div>
                      ))}
                    </div>
                  )}
                  {selectedSentinel.runtime.driver === "claude_code" && (
                    <div className="mt-3 flex gap-2">
                      <button
                        onClick={() => void refreshMcpStatus()}
                        className="inline-flex items-center gap-1.5 rounded-md border border-[#2d3240]/50 bg-[#131721]/50 px-2.5 py-1 text-[9px] font-medium text-[#ece7dc]/70 transition-colors hover:border-[#d4a84b]/20 hover:text-[#ece7dc]"
                      >
                        <IconRotateClockwise2 size={11} stroke={1.5} />
                        Refresh Bridge
                      </button>
                      <button
                        onClick={() => void restartMcpServer()}
                        disabled={isRestarting}
                        className="inline-flex items-center gap-1.5 rounded-md border border-[#d4a84b]/30 bg-[#d4a84b]/5 px-2.5 py-1 text-[9px] font-medium text-[#d4a84b] transition-colors hover:bg-[#d4a84b]/10 disabled:opacity-50"
                      >
                        <IconRotateClockwise2 size={11} stroke={1.5} />
                        {isRestarting ? "Restarting…" : "Restart Bridge"}
                      </button>
                    </div>
                  )}
                </div>
              )}

              <div className="flex flex-col gap-1.5">
                <label className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/50">
                  Title
                </label>
                <input
                  value={title}
                  onChange={(event) => setTitle(event.target.value)}
                  placeholder="Credential harvest triage"
                  maxLength={128}
                  className="rounded-md border border-[#2d3240]/60 bg-[#05060a] px-3 py-2 text-[12px] text-[#ece7dc] outline-none focus:border-[#d4a84b]/40"
                />
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/50">
                  Objective
                </label>
                <textarea
                  value={objective}
                  onChange={(event) => setObjective(event.target.value)}
                  rows={4}
                  maxLength={2048}
                  placeholder="Describe what the sentinel should verify, collect, or harden."
                  className="rounded-md border border-[#2d3240]/60 bg-[#05060a] px-3 py-2 text-[12px] text-[#ece7dc] outline-none focus:border-[#d4a84b]/40 resize-none"
                />
                {objectivePresets.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {objectivePresets.map((preset) => (
                      <button
                        key={preset}
                        onClick={() => setObjective(preset)}
                        className="rounded-md border border-[#2d3240]/40 bg-[#131721]/40 px-2 py-1 text-left text-[9px] text-[#6f7f9a]/65 transition-colors hover:border-[#d4a84b]/20 hover:text-[#ece7dc]"
                      >
                        {preset}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/50">
                  Priority
                </label>
                <div className="flex gap-1.5">
                  {PRIORITIES.map((candidate) => (
                    <button
                      key={candidate}
                      onClick={() => setPriority(candidate)}
                      className={cn(
                        "rounded-md px-2 py-1 text-[10px] font-medium capitalize transition-colors",
                        priority === candidate
                          ? "bg-[#d4a84b]/10 text-[#d4a84b]"
                          : "text-[#6f7f9a]/60 hover:bg-[#131721]/40 hover:text-[#ece7dc]",
                      )}
                    >
                      {candidate}
                    </button>
                  ))}
                </div>
              </div>

              {selectedSentinel?.runtime.driver === "claude_code" && (
                <ClaudeCodeHint
                  hint="Claude Code sentinel missions work best with a repo-scoped objective and a concrete verification target."
                  prompt={`Inspect ${selectedSentinel.runtime.targetRef ?? "the configured workspace"} for: ${objective || "the mission objective"}, produce evidence-backed findings, and stop at the tool boundary when a policy block is encountered.`}
                />
              )}

              <button
                onClick={handleLaunch}
                disabled={!selectedSentinel || objective.trim().length === 0}
                className="mt-1 inline-flex items-center justify-center gap-2 rounded-md border border-[#d4a84b]/30 bg-[#d4a84b]/5 px-4 py-2 text-[11px] font-medium text-[#d4a84b] transition-colors hover:bg-[#d4a84b]/10 disabled:cursor-not-allowed disabled:opacity-50"
              >
                <IconPlayerPlay size={13} stroke={1.5} />
                {selectedLaunch?.launchState === "blocked" ? "Launch Blocked Mission" : "Launch Mission"}
              </button>
            </div>
          </div>

          <div className="px-3 py-3">
            <div className="mb-2 px-1 text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/45">
              Mission Queue
            </div>
            <div className="flex flex-col gap-2">
              {missionList.map((mission) => (
                <button
                  key={mission.id}
                  onClick={() => setActiveMission(mission.id)}
                  className={cn(
                    "rounded-lg border px-3 py-3 text-left transition-colors",
                    displayedMission?.id === mission.id
                      ? "border-[#d4a84b]/30 bg-[#d4a84b]/5"
                      : "border-[#2d3240]/50 bg-[#131721]/30 hover:border-[#2d3240]",
                  )}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-[11px] font-semibold text-[#ece7dc]">{mission.title}</div>
                      <div className="mt-1 text-[9px] uppercase tracking-[0.08em] text-[#6f7f9a]/45">
                        {mission.driver.replace("_", " ")}
                      </div>
                    </div>
                    <span
                      className="rounded-full px-1.5 py-0.5 text-[8px] font-semibold uppercase tracking-[0.08em]"
                      style={{
                        backgroundColor: STATUS_COLORS[mission.status] + "15",
                        color: STATUS_COLORS[mission.status],
                      }}
                    >
                      {mission.status}
                    </span>
                  </div>
                  <div className="mt-2 flex items-center gap-2 text-[9px] text-[#6f7f9a]/50">
                    <span>{mission.signalIds.length} signals</span>
                    <span>{mission.findingIds.length} findings</span>
                    <span>{relativeTime(mission.updatedAt)}</span>
                  </div>
                </button>
              ))}
              {missionList.length === 0 && (
                <div className="rounded-lg border border-dashed border-[#2d3240]/40 px-3 py-5 text-center text-[11px] text-[#6f7f9a]/45">
                  No missions launched yet.
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="overflow-auto px-6 py-5">
          {displayedMission ? (
            <div className="mx-auto flex max-w-4xl flex-col gap-5">
              <div className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13] p-5">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <IconTarget size={16} stroke={1.5} className="text-[#d4a84b]" />
                      <h2 className="text-lg font-semibold text-[#ece7dc]">{displayedMission.title}</h2>
                    </div>
                    <p className="mt-2 max-w-2xl text-[12px] leading-relaxed text-[#6f7f9a]/75">
                      {displayedMission.objective}
                    </p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <Badge>{getSentinelDriverDefinition(displayedMission.driver).label}</Badge>
                      <Badge>{displayedMission.priority}</Badge>
                      {displayedMission.launchState && (
                        <Badge>{launchStateLabel(displayedMission.launchState)}</Badge>
                      )}
                      <Badge>{displayedMission.signalIds.length} signals</Badge>
                      <Badge>{displayedMission.findingIds.length} findings</Badge>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleAdvance}
                      disabled={displayedMission.status !== "active"}
                      className="inline-flex items-center gap-1.5 rounded-md border border-[#2d3240]/50 bg-[#131721]/50 px-3 py-1.5 text-[10px] font-medium text-[#ece7dc]/75 transition-colors hover:border-[#d4a84b]/20 hover:text-[#ece7dc] disabled:opacity-40"
                    >
                      <IconArrowRight size={12} stroke={1.5} />
                      Advance Stage
                    </button>
                  </div>
                </div>
              </div>

              <div className="grid gap-5 lg:grid-cols-[minmax(0,1.2fr)_360px]">
                <div className="flex flex-col gap-5">
                  <section className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13] p-5">
                    <div className="mb-4 flex items-center gap-2">
                      <IconRoute size={15} stroke={1.5} className="text-[#6f7f9a]/70" />
                      <h3 className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/55">
                        Stages
                      </h3>
                    </div>
                    <div className="flex flex-col gap-3">
                      {displayedMission.stages.map((stage, index) => {
                        const isCompleted = stage.status === "completed";
                        const isActive = stage.status === "in_progress";
                        return (
                          <div key={stage.id} className="flex gap-3">
                            <div className="flex flex-col items-center">
                              <div
                                className={cn(
                                  "mt-0.5 flex h-6 w-6 items-center justify-center rounded-full border text-[10px] font-semibold",
                                  isCompleted
                                    ? "border-[#3dbf84]/30 bg-[#3dbf84]/10 text-[#3dbf84]"
                                    : isActive
                                      ? "border-[#d4a84b]/30 bg-[#d4a84b]/10 text-[#d4a84b]"
                                      : "border-[#2d3240]/60 bg-[#131721]/60 text-[#6f7f9a]/55",
                                )}
                              >
                                {isCompleted ? <IconCircleCheck size={12} stroke={1.8} /> : index + 1}
                              </div>
                              {index < displayedMission.stages.length - 1 && (
                                <div className="h-full w-px bg-[#2d3240]/60" />
                              )}
                            </div>
                            <div className="pb-4">
                              <div className="flex items-center gap-2">
                                <span className="text-[12px] font-semibold text-[#ece7dc]">{stage.label}</span>
                                <span className="text-[9px] uppercase tracking-[0.08em] text-[#6f7f9a]/45">
                                  {stage.status.replace("_", " ")}
                                </span>
                              </div>
                              <p className="mt-1 text-[11px] leading-relaxed text-[#6f7f9a]/65">
                                {stage.summary}
                              </p>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </section>

                  <section className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13] p-5">
                    <div className="mb-4 flex items-center gap-2">
                      <IconNetwork size={15} stroke={1.5} className="text-[#6f7f9a]/70" />
                      <h3 className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/55">
                        Runtime Timeline
                      </h3>
                    </div>
                    <div className="flex flex-col gap-3">
                      {displayedMission.runtimeEvents.map((event) => (
                        <div
                          key={event.id}
                          className="rounded-lg border border-[#2d3240]/50 bg-[#131721]/35 px-3 py-3"
                        >
                          <div className="flex items-center justify-between gap-3">
                            <span className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#d4a84b]/75">
                              {event.kind.replace("_", " ")}
                            </span>
                            <span className="text-[9px] font-mono text-[#6f7f9a]/45">
                              {relativeTime(event.createdAt)}
                            </span>
                          </div>
                          <p className="mt-1 text-[11px] leading-relaxed text-[#ece7dc]/75">
                            {event.summary}
                          </p>
                          <div className="mt-2 flex flex-wrap gap-2 text-[9px] text-[#6f7f9a]/50">
                            {event.toolName && <span>tool: {event.toolName}</span>}
                            <span>session: {event.sessionRef}</span>
                            {event.signalId && <span>signal: {event.signalId.slice(0, 12)}</span>}
                          </div>
                        </div>
                      ))}
                    </div>
                  </section>
                </div>

                <div className="flex flex-col gap-5">
                  {(displayedMission.launchSummary || displayedMission.launchHints.length > 0) && (
                    <section className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13] p-5">
                      <div className="mb-4 flex items-center gap-2">
                        <IconRadar size={15} stroke={1.5} className="text-[#6f7f9a]/70" />
                        <h3 className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/55">
                          Launch Posture
                        </h3>
                      </div>
                      {displayedMission.launchState && (
                        <div
                          className="inline-flex rounded-full px-2 py-0.5 text-[8px] font-semibold uppercase tracking-[0.08em]"
                          style={{
                            backgroundColor: LAUNCH_COLORS[displayedMission.launchState] + "15",
                            color: LAUNCH_COLORS[displayedMission.launchState],
                          }}
                        >
                          {launchStateLabel(displayedMission.launchState)}
                        </div>
                      )}
                      {displayedMission.launchSummary && (
                        <p className="mt-3 text-[11px] leading-relaxed text-[#ece7dc]/75">
                          {displayedMission.launchSummary}
                        </p>
                      )}
                      {displayedMission.controlPlaneRef && (
                        <div className="mt-2 text-[9px] font-mono text-[#6f7f9a]/45">
                          {displayedMission.controlPlaneRef}
                        </div>
                      )}
                      {displayedMission.launchHints.length > 0 && (
                        <div className="mt-3 flex flex-col gap-1.5">
                          {displayedMission.launchHints.map((hint) => (
                            <div key={hint} className="text-[10px] leading-relaxed text-[#c1b6a0]/70">
                              {hint}
                            </div>
                          ))}
                        </div>
                      )}
                    </section>
                  )}

                  <section className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13] p-5">
                    <div className="mb-4 flex items-center gap-2">
                      <IconBrain size={15} stroke={1.5} className="text-[#6f7f9a]/70" />
                      <h3 className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/55">
                        Evidence
                      </h3>
                    </div>
                    <div className="flex flex-col gap-2.5">
                      {displayedMission.evidence.map((item) => (
                        <div
                          key={item.id}
                          className="rounded-lg border border-[#2d3240]/50 bg-[#131721]/35 px-3 py-3"
                        >
                          <div className="text-[10px] font-semibold text-[#ece7dc]">{item.label}</div>
                          <p className="mt-1 text-[10px] leading-relaxed text-[#6f7f9a]/65">
                            {item.summary}
                          </p>
                          <div className="mt-2 text-[9px] font-mono text-[#6f7f9a]/45">{item.ref}</div>
                        </div>
                      ))}
                    </div>
                  </section>

                  <section className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13] p-5">
                    <div className="mb-4 flex items-center gap-2">
                      <IconChevronRight size={15} stroke={1.5} className="text-[#6f7f9a]/70" />
                      <h3 className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/55">
                        Findings
                      </h3>
                    </div>
                    <div className="flex flex-col gap-2.5">
                      {displayedMission.findingIds.length === 0 && (
                        <div className="text-[11px] text-[#6f7f9a]/45">
                          Findings will appear here when runtime signals correlate.
                        </div>
                      )}
                      {displayedMission.findingIds.map((findingId) => {
                        const finding = findings.find((entry) => entry.id === findingId);
                        return finding ? (
                          <Link
                            key={findingId}
                            to={`/findings/${findingId}`}
                            className="rounded-lg border border-[#2d3240]/50 bg-[#131721]/35 px-3 py-3 transition-colors hover:border-[#d4a84b]/20"
                          >
                            <div className="text-[11px] font-semibold text-[#ece7dc]">{finding.title}</div>
                            <div className="mt-1 flex items-center gap-2 text-[9px] text-[#6f7f9a]/55">
                              <span>{finding.severity}</span>
                              <span>{Math.round(finding.confidence * 100)}% confidence</span>
                            </div>
                          </Link>
                        ) : null;
                      })}
                    </div>
                  </section>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex h-full items-center justify-center text-[12px] text-[#6f7f9a]/50">
              Launch a mission to start building runtime evidence.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Badge({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded-full border border-[#2d3240]/40 bg-[#131721] px-2 py-0.5 text-[8px] font-medium uppercase tracking-[0.08em] text-[#6f7f9a]/60">
      {children}
    </span>
  );
}
