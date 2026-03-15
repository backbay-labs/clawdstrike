import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  IconArrowLeft,
  IconPlayerPlay,
  IconPlayerPause,
  IconArchive,
  IconActivity,
  IconTarget,
  IconDatabase,
  IconSettings,
  IconDiamond,
  IconMoon,
  IconStar,
  IconKey,
  IconCrown,
  IconSpiral,
  IconWaveSine,
  IconEyeCheck,
  IconCopy,
  IconCheck,
  IconFlag3,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { SubTabBar, type SubTab } from "../shared/sub-tab-bar";
import { useOperator } from "@/lib/workbench/operator-store";
import {
  activateSentinel,
  pauseSentinel,
  retireSentinel,
  validateStatusTransition,
  deriveSigilColor,
  getSentinelDriverDefinition,
  getSentinelExecutionModeConfig,
} from "@/lib/workbench/sentinel-manager";
import type {
  Sentinel,
  SentinelMode,
  SentinelStatus,
  SentinelRuntimeHealth,
  SentinelGoal,
  SigilType,
} from "@/lib/workbench/sentinel-manager";


const MODE_COLORS: Record<SentinelMode, string> = {
  watcher: "#5b8def",
  hunter: "#d4784b",
  curator: "#8b7355",
  liaison: "#7b6b8b",
};

const MODE_LABELS: Record<SentinelMode, string> = {
  watcher: "Watcher",
  hunter: "Hunter",
  curator: "Curator",
  liaison: "Liaison",
};

const STATUS_DOT_COLORS: Record<SentinelStatus, string> = {
  active: "#3dbf84",
  paused: "#d4a84b",
  retired: "#6f7f9a",
};

const STATUS_LABELS: Record<SentinelStatus, string> = {
  active: "Active",
  paused: "Paused",
  retired: "Retired",
};

const RUNTIME_HEALTH_COLORS: Record<SentinelRuntimeHealth, string> = {
  planned: "#6f7f9a",
  ready: "#3dbf84",
  degraded: "#d4a84b",
  offline: "#c45c5c",
};

const RUNTIME_HEALTH_LABELS: Record<SentinelRuntimeHealth, string> = {
  planned: "Planned",
  ready: "Ready",
  degraded: "Degraded",
  offline: "Offline",
};

const SIGIL_ICONS: Record<SigilType, typeof IconDiamond> = {
  diamond: IconDiamond,
  eye: IconEyeCheck,
  wave: IconWaveSine,
  crown: IconCrown,
  spiral: IconSpiral,
  key: IconKey,
  star: IconStar,
  moon: IconMoon,
};

const GOAL_TYPE_COLORS: Record<string, string> = {
  detect: "#5b8def",
  hunt: "#d4784b",
  monitor: "#3dbf84",
  enrich: "#7b6b8b",
};

type DetailTab = "signals" | "goals" | "memory" | "config";


function relativeTime(epochMs: number): string {
  const now = Date.now();
  const diffSecs = Math.floor((now - epochMs) / 1000);
  if (diffSecs < 0) return "just now";
  if (diffSecs < 60) return `${diffSecs}s ago`;
  if (diffSecs < 3600) return `${Math.floor(diffSecs / 60)}m ago`;
  if (diffSecs < 86400) return `${Math.floor(diffSecs / 3600)}h ago`;
  return `${Math.floor(diffSecs / 86400)}d ago`;
}

function formatUptime(ms: number): string {
  const hours = Math.floor(ms / (1000 * 60 * 60));
  if (hours < 24) return `${hours}h`;
  const days = Math.floor(hours / 24);
  const remainHours = hours % 24;
  return `${days}d ${remainHours}h`;
}

function formatDate(epochMs: number): string {
  return new Date(epochMs).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}


function SigilAvatar({
  sigil,
  fingerprint,
  size = 28,
}: {
  sigil: SigilType;
  fingerprint: string;
  size?: number;
}) {
  const Icon = SIGIL_ICONS[sigil];
  const color = deriveSigilColor(fingerprint);

  return (
    <div
      className="flex items-center justify-center rounded-lg shrink-0"
      style={{
        width: size + 12,
        height: size + 12,
        backgroundColor: color + "18",
      }}
    >
      <Icon size={size} stroke={1.5} style={{ color }} />
    </div>
  );
}


function CopyableText({ text, truncate = true }: { text: string; truncate?: boolean }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [text]);

  return (
    <button
      onClick={handleCopy}
      className="group flex items-center gap-1 text-[10px] font-mono text-[#ece7dc]/60 hover:text-[#ece7dc]/80 transition-colors"
      title="Click to copy"
    >
      <span className={cn(truncate && "truncate max-w-[120px]")}>{text}</span>
      {copied ? (
        <IconCheck size={10} stroke={2} className="text-[#3dbf84] shrink-0" />
      ) : (
        <IconCopy
          size={10}
          stroke={1.5}
          className="text-[#6f7f9a]/30 group-hover:text-[#6f7f9a] shrink-0 transition-colors"
        />
      )}
    </button>
  );
}


function StatsSidebar({ sentinel }: { sentinel: Sentinel }) {
  const runtimeDriver = getSentinelDriverDefinition(sentinel.runtime.driver);
  const executionMode = getSentinelExecutionModeConfig(sentinel.runtime.executionMode);

  return (
    <div className="flex flex-col gap-5 h-full overflow-auto">
      {/* Lifetime stats */}
      <StatsSection title="Lifetime">
        <StatRow label="Created" value={formatDate(sentinel.createdAt)} />
        <StatRow label="Uptime" value={formatUptime(sentinel.stats.uptimeMs)} mono />
        <StatRow
          label="Signals"
          value={sentinel.stats.signalsGenerated.toLocaleString()}
          mono
        />
        <StatRow
          label="Findings"
          value={sentinel.stats.findingsCreated.toLocaleString()}
          mono
        />
        <StatRow
          label="Intel"
          value={sentinel.stats.intelProduced.toLocaleString()}
          mono
        />
        <StatRow
          label="FP Suppressed"
          value={sentinel.stats.falsePositivesSuppressed.toLocaleString()}
          mono
        />
      </StatsSection>

      <StatsSection title="Runtime">
        <StatRow label="Driver" value={runtimeDriver.label} />
        <StatRow label="Execution" value={executionMode.label} />
        <StatRow label="Tier" value={`Tier ${sentinel.runtime.enforcementTier}`} />
        <StatRow label="Health" value={RUNTIME_HEALTH_LABELS[sentinel.runtime.health]} />
        {sentinel.runtime.targetRef && (
          <StatRow label="Target" value={sentinel.runtime.targetRef} mono />
        )}
        <StatRow
          label="Heartbeat"
          value={
            sentinel.runtime.lastHeartbeatAt
              ? relativeTime(sentinel.runtime.lastHeartbeatAt)
              : "not yet reported"
          }
        />
      </StatsSection>

      {/* Memory summary */}
      <StatsSection title="Memory">
        <StatRow
          label="Patterns"
          value={sentinel.memory.knownPatterns.length.toString()}
          mono
        />
        <StatRow
          label="Baselines"
          value={`${sentinel.memory.baselineProfiles.length} agents`}
          mono
        />
        <StatRow
          label="FP Hashes"
          value={sentinel.memory.falsePositiveHashes.length.toString()}
          mono
        />
        <StatRow
          label="Last Updated"
          value={relativeTime(sentinel.memory.lastUpdated)}
        />
      </StatsSection>

      {/* Swarms */}
      {sentinel.swarms.length > 0 && (
        <StatsSection title="Swarms">
          {sentinel.swarms.map((s) => (
            <div
              key={s.swarmId}
              className="flex items-center gap-2 text-[10px]"
            >
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-[#3dbf84] shrink-0" />
              <span className="text-[#ece7dc]/60 font-mono truncate">
                {s.swarmId.slice(0, 16)}
              </span>
              <span className="text-[#6f7f9a]/40 capitalize ml-auto shrink-0">
                {s.role}
              </span>
            </div>
          ))}
        </StatsSection>
      )}

      {/* Last active */}
      <div className="mt-auto pt-3 border-t border-[#2d3240]/40">
        <span className="text-[9px] text-[#6f7f9a]/40">
          Last active:{" "}
          {sentinel.stats.lastActiveAt > 0
            ? relativeTime(sentinel.stats.lastActiveAt)
            : "never"}
        </span>
      </div>
    </div>
  );
}

function StatsSection({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-2">
      <h4 className="text-[9px] font-semibold uppercase tracking-[0.1em] text-[#6f7f9a]/50">
        {title}
      </h4>
      <div className="flex flex-col gap-1.5">{children}</div>
    </div>
  );
}

function StatRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-baseline justify-between text-[10px]">
      <span className="text-[#6f7f9a]/50">{label}</span>
      <span className={cn("text-[#ece7dc]/70", mono && "font-mono")}>
        {value}
      </span>
    </div>
  );
}


function SignalsTab({ sentinel }: { sentinel: Sentinel }) {
  // In a real implementation this would pull from SignalProvider filtered by sentinelId.
  // For now we show a placeholder that communicates the design intent.
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3">
      <IconActivity size={28} stroke={1} className="text-[#6f7f9a]/20" />
      <p className="text-[12px] text-[#6f7f9a]/50">
        Signal stream for{" "}
        <span className="font-semibold text-[#ece7dc]/60">
          {sentinel.name}
        </span>
      </p>
      <p className="text-[10px] text-[#6f7f9a]/30 max-w-xs text-center">
        Signals generated by this sentinel will appear here in real time.
        Connect to the fleet and activate the sentinel to begin.
      </p>
      <div className="flex items-center gap-3 mt-2">
        <span className="text-[10px] font-mono text-[#6f7f9a]/40">
          {sentinel.stats.signalsGenerated} lifetime signals
        </span>
      </div>
    </div>
  );
}


function GoalsTab({
  sentinel,
  onUpdateGoals,
}: {
  sentinel: Sentinel;
  onUpdateGoals?: (goals: SentinelGoal[]) => void;
}) {
  const goals = sentinel.goals;

  if (goals.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 gap-3">
        <IconTarget size={28} stroke={1} className="text-[#6f7f9a]/20" />
        <p className="text-[12px] text-[#6f7f9a]/50">
          No goals configured
        </p>
        <p className="text-[10px] text-[#6f7f9a]/30">
          Add goals to define what this sentinel should detect, hunt, or monitor.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3 py-4">
      {goals.map((goal, idx) => {
        const typeColor = GOAL_TYPE_COLORS[goal.type] ?? "#6f7f9a";

        return (
          <div
            key={idx}
            className="rounded-lg border border-[#2d3240]/60 bg-[#0b0d13]/60 p-4 flex flex-col gap-2.5"
          >
            <div className="flex items-center gap-2">
              <span
                className="rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase"
                style={{
                  backgroundColor: typeColor + "15",
                  color: typeColor,
                }}
              >
                {goal.type}
              </span>
              <span className="text-[11px] text-[#ece7dc]/80 flex-1 truncate">
                {goal.description || "(no description)"}
              </span>
            </div>

            {/* Sources */}
            <div className="flex flex-wrap gap-1.5">
              {goal.sources.map((source, si) => (
                <span
                  key={si}
                  className="rounded-full px-2 py-0.5 text-[8px] font-mono text-[#6f7f9a]/60 bg-[#131721] border border-[#2d3240]/40"
                >
                  {source.type}: {source.identifier}
                </span>
              ))}
            </div>

            {/* Escalation */}
            <div className="flex items-center gap-4 text-[9px] text-[#6f7f9a]/50">
              <span>
                Confidence threshold:{" "}
                <span className="font-mono text-[#ece7dc]/60">
                  {Math.round(goal.escalation.minConfidence * 100)}%
                </span>
              </span>
              <span>
                Min severity:{" "}
                <span className="font-mono text-[#ece7dc]/60 capitalize">
                  {goal.escalation.minSeverity}
                </span>
              </span>
              <span>
                Human confirm:{" "}
                <span className="font-mono text-[#ece7dc]/60">
                  {goal.escalation.requireHumanConfirmation ? "yes" : "no"}
                </span>
              </span>
            </div>

            {/* Pattern refs */}
            {goal.patterns && goal.patterns.length > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="text-[8px] uppercase tracking-wider text-[#6f7f9a]/40">
                  Patterns
                </span>
                {goal.patterns.map((p) => (
                  <span
                    key={p.id}
                    className="rounded-full px-2 py-0.5 text-[8px] font-mono text-[#d4a84b]/60 bg-[#d4a84b]/5 border border-[#d4a84b]/10"
                  >
                    {p.id.slice(0, 12)}
                  </span>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}


function MemoryTab({ sentinel }: { sentinel: Sentinel }) {
  const { memory } = sentinel;

  return (
    <div className="flex flex-col gap-6 py-4">
      {/* Known Patterns */}
      <div>
        <h3 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50 mb-2">
          Known Patterns ({memory.knownPatterns.length})
        </h3>
        {memory.knownPatterns.length === 0 ? (
          <p className="text-[10px] text-[#6f7f9a]/30 py-4">
            No patterns discovered yet. Patterns are learned through monitoring
            and swarm intel exchange.
          </p>
        ) : (
          <div className="flex flex-col gap-1">
            {memory.knownPatterns.map((pattern) => (
              <div
                key={pattern.id}
                className="flex items-center gap-3 rounded-md px-3 py-2 text-[10px] bg-[#0b0d13]/40 border border-[#2d3240]/30"
              >
                <span className="text-[#ece7dc]/70 truncate flex-1">
                  {pattern.name}
                </span>
                <span className="font-mono text-[#6f7f9a]/40 shrink-0">
                  {pattern.localMatchCount} match{pattern.localMatchCount !== 1 ? "es" : ""}
                </span>
                <span
                  className="rounded-full px-1.5 py-0.5 text-[7px] font-medium uppercase border"
                  style={{
                    color:
                      pattern.source === "imported_intel"
                        ? "#7b6b8b"
                        : pattern.source === "builtin"
                          ? "#5b8def"
                          : "#d4a84b",
                    borderColor:
                      pattern.source === "imported_intel"
                        ? "#7b6b8b30"
                        : pattern.source === "builtin"
                          ? "#5b8def30"
                          : "#d4a84b30",
                    backgroundColor:
                      pattern.source === "imported_intel"
                        ? "#7b6b8b10"
                        : pattern.source === "builtin"
                          ? "#5b8def10"
                          : "#d4a84b10",
                  }}
                >
                  {pattern.source.replace("_", " ")}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Baseline Profiles */}
      <div>
        <h3 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50 mb-2">
          Baseline Profiles ({memory.baselineProfiles.length})
        </h3>
        {memory.baselineProfiles.length === 0 ? (
          <p className="text-[10px] text-[#6f7f9a]/30 py-4">
            No baseline profiles computed. Baselines are built from observed
            agent behavior over time.
          </p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {memory.baselineProfiles.map((baseline) => (
              <div
                key={baseline.agentId}
                className="rounded-md border border-[#2d3240]/40 bg-[#0b0d13]/40 px-3 py-2"
              >
                <div className="text-[10px] font-mono text-[#ece7dc]/60 truncate">
                  {baseline.agentName || baseline.agentId}
                </div>
                <div className="text-[9px] text-[#6f7f9a]/40 mt-0.5">
                  avg {baseline.avgDailyEvents}/day
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* False Positive Hashes */}
      <div>
        <h3 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50 mb-2">
          False Positive Hashes ({memory.falsePositiveHashes.length})
        </h3>
        {memory.falsePositiveHashes.length === 0 ? (
          <p className="text-[10px] text-[#6f7f9a]/30 py-4">
            No false positives recorded. Hashes of dismissed signals are stored
            here to suppress recurrence.
          </p>
        ) : (
          <div className="flex flex-col gap-1">
            {memory.falsePositiveHashes.map((hash, idx) => (
              <div
                key={idx}
                className="flex items-center gap-2 rounded-md px-3 py-1.5 text-[10px] bg-[#0b0d13]/40 border border-[#2d3240]/30"
              >
                <span className="font-mono text-[#6f7f9a]/50 truncate">
                  {hash}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}


function ConfigTab({ sentinel }: { sentinel: Sentinel }) {
  const { currentOperator } = useOperator();
  const runtimeDriver = getSentinelDriverDefinition(sentinel.runtime.driver);
  const executionMode = getSentinelExecutionModeConfig(sentinel.runtime.executionMode);
  const isOwnedByCurrentOperator =
    sentinel.ownerPublicKey != null &&
    currentOperator != null &&
    sentinel.ownerPublicKey === currentOperator.publicKey;

  return (
    <div className="flex flex-col gap-6 py-4">
      {/* Policy */}
      <ConfigSection title="Policy">
        <ConfigRow label="Ruleset" value={sentinel.policy.ruleset ?? "---"} />
        {sentinel.policy.policyName && (
          <ConfigRow label="Policy Name" value={sentinel.policy.policyName} />
        )}
        {sentinel.policy.version && (
          <ConfigRow label="Version" value={sentinel.policy.version} mono />
        )}
        {sentinel.policy.policyId && (
          <ConfigRow label="Policy ID" value={sentinel.policy.policyId} mono />
        )}
      </ConfigSection>

      {/* Schedule */}
      <ConfigSection title="Schedule">
        <ConfigRow
          label="Cron"
          value={sentinel.schedule ?? "None (continuous)"}
          mono={!!sentinel.schedule}
        />
      </ConfigSection>

      <ConfigSection title="Runtime">
        <ConfigRow label="Driver" value={runtimeDriver.label} />
        <ConfigRow label="Execution" value={executionMode.label} />
        <ConfigRow label="Tier" value={`Tier ${sentinel.runtime.enforcementTier}`} />
        <ConfigRow label="Health" value={RUNTIME_HEALTH_LABELS[sentinel.runtime.health]} />
        <ConfigRow label="Endpoint" value={sentinel.runtime.endpointType} />
        <ConfigRow
          label="Receipts"
          value={sentinel.runtime.receiptsEnabled ? "Enabled" : "Disabled"}
        />
        <ConfigRow
          label="Signal Emission"
          value={sentinel.runtime.emitsSignals ? "Enabled" : "Disabled"}
        />
        {sentinel.runtime.targetRef && (
          <ConfigRow label="Target" value={sentinel.runtime.targetRef} mono />
        )}
        {sentinel.runtime.runtimeRef && (
          <ConfigRow label="Runtime Ref" value={sentinel.runtime.runtimeRef} mono />
        )}
        {sentinel.runtime.sessionRef && (
          <ConfigRow label="Session Ref" value={sentinel.runtime.sessionRef} mono />
        )}
        {sentinel.runtime.lastHeartbeatAt && (
          <ConfigRow
            label="Last Heartbeat"
            value={relativeTime(sentinel.runtime.lastHeartbeatAt)}
          />
        )}
      </ConfigSection>

      {/* Identity */}
      <ConfigSection title="Identity">
        <div className="flex items-baseline justify-between text-[10px]">
          <span className="text-[#6f7f9a]/50">Fingerprint</span>
          <CopyableText text={sentinel.identity.fingerprint} />
        </div>
        <div className="flex items-baseline justify-between text-[10px]">
          <span className="text-[#6f7f9a]/50">Public Key</span>
          <CopyableText text={sentinel.identity.publicKey} />
        </div>
        <ConfigRow label="Sigil" value={sentinel.identity.sigil} />
        <ConfigRow label="Nickname" value={sentinel.identity.nickname} />
      </ConfigSection>

      {/* Mode & status */}
      <ConfigSection title="Status">
        <ConfigRow label="Mode" value={MODE_LABELS[sentinel.mode]} />
        <ConfigRow label="Status" value={STATUS_LABELS[sentinel.status]} />
        <div className="flex items-baseline justify-between text-[10px]">
          <span className="text-[#6f7f9a]/50">Owner</span>
          <span className="flex items-center gap-1.5 text-[#ece7dc]/70">
            {isOwnedByCurrentOperator && currentOperator?.sigil && (
              <span className="text-sm">{currentOperator.sigil}</span>
            )}
            {sentinel.owner}
            {isOwnedByCurrentOperator && (
              <span className="text-[9px] text-[#d4a84b]/70">(You)</span>
            )}
          </span>
        </div>
        {sentinel.fleetAgentId && (
          <ConfigRow label="Fleet Agent" value={sentinel.fleetAgentId} mono />
        )}
      </ConfigSection>

      {/* Timestamps */}
      <ConfigSection title="Timestamps">
        <ConfigRow label="Created" value={formatDate(sentinel.createdAt)} />
        <ConfigRow label="Updated" value={formatDate(sentinel.updatedAt)} />
      </ConfigSection>
    </div>
  );
}

function ConfigSection({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-[#2d3240]/60 bg-[#0b0d13]/60 overflow-hidden">
      <div className="px-4 py-2 border-b border-[#2d3240]/40">
        <h3 className="text-[9px] font-semibold uppercase tracking-[0.1em] text-[#6f7f9a]/50">
          {title}
        </h3>
      </div>
      <div className="px-4 py-3 flex flex-col gap-2">{children}</div>
    </div>
  );
}

function ConfigRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-baseline justify-between text-[10px]">
      <span className="text-[#6f7f9a]/50">{label}</span>
      <span className={cn("text-[#ece7dc]/70", mono && "font-mono")}>
        {value}
      </span>
    </div>
  );
}


export function SentinelDetail({
  sentinel,
  onUpdate,
}: {
  sentinel: Sentinel;
  onUpdate: (updated: Sentinel) => void;
}) {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<DetailTab>("signals");

  const modeColor = MODE_COLORS[sentinel.mode];
  const statusDot = STATUS_DOT_COLORS[sentinel.status];
  const runtimeDriver = getSentinelDriverDefinition(sentinel.runtime.driver);
  const executionMode = getSentinelExecutionModeConfig(sentinel.runtime.executionMode);
  const runtimeHealthDot = RUNTIME_HEALTH_COLORS[sentinel.runtime.health];
  const canLaunchMission =
    sentinel.runtime.driver === "claude_code" || sentinel.runtime.driver === "openclaw";

  const canActivate = validateStatusTransition(sentinel.status, "active");
  const canPause = validateStatusTransition(sentinel.status, "paused");
  const canRetire = validateStatusTransition(sentinel.status, "retired");

  const handleActivate = useCallback(() => {
    try {
      onUpdate(activateSentinel(sentinel));
    } catch (err) {
      console.error("[sentinel-detail] Failed to activate:", err);
    }
  }, [sentinel, onUpdate]);

  const handlePause = useCallback(() => {
    try {
      onUpdate(pauseSentinel(sentinel));
    } catch (err) {
      console.error("[sentinel-detail] Failed to pause:", err);
    }
  }, [sentinel, onUpdate]);

  const handleRetire = useCallback(() => {
    try {
      onUpdate(retireSentinel(sentinel));
    } catch (err) {
      console.error("[sentinel-detail] Failed to retire:", err);
    }
  }, [sentinel, onUpdate]);

  const tabs: SubTab[] = [
    { id: "signals", label: "Signals", icon: IconActivity },
    { id: "goals", label: "Goals", icon: IconTarget },
    { id: "memory", label: "Memory", icon: IconDatabase },
    { id: "config", label: "Config", icon: IconSettings },
  ];

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#05060a]">
      {/* Header */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-4">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate("/sentinels")}
            className="text-[#6f7f9a]/50 hover:text-[#ece7dc] transition-colors shrink-0"
          >
            <IconArrowLeft size={16} stroke={1.5} />
          </button>

          <SigilAvatar
            sigil={sentinel.identity.sigil}
            fingerprint={sentinel.identity.fingerprint}
            size={24}
          />

          <div className="min-w-0 flex-1">
            <h1 className="text-sm font-semibold text-[#ece7dc] tracking-[-0.01em] truncate">
              {sentinel.name}
            </h1>
            <div className="flex items-center gap-2 mt-0.5">
              <span
                className="inline-block h-1.5 w-1.5 rounded-full shrink-0"
                style={{ backgroundColor: statusDot }}
              />
              <span
                className="rounded px-1.5 py-0.5 text-[9px] font-medium uppercase"
                style={{
                  backgroundColor: modeColor + "15",
                  color: modeColor,
                }}
              >
                {MODE_LABELS[sentinel.mode]}
              </span>
              <span className="text-[10px] text-[#6f7f9a]/50 capitalize">
                {STATUS_LABELS[sentinel.status]}
              </span>
              <span className="rounded border border-[#2d3240]/40 bg-[#131721]/70 px-1.5 py-0.5 text-[9px] font-medium text-[#ece7dc]/70">
                {runtimeDriver.label}
              </span>
              <span className="inline-flex items-center gap-1 text-[10px] text-[#6f7f9a]/50">
                <span
                  className="inline-block h-1.5 w-1.5 rounded-full shrink-0"
                  style={{ backgroundColor: runtimeHealthDot }}
                />
                {executionMode.label} · Tier {sentinel.runtime.enforcementTier}
              </span>
              <span className="text-[10px] font-mono text-[#6f7f9a]/30">
                {sentinel.identity.fingerprint.slice(0, 8)}...{sentinel.identity.fingerprint.slice(-4)}
              </span>
            </div>
          </div>

          {/* Status controls */}
          <div className="flex items-center gap-1.5 shrink-0">
            {canLaunchMission && (
              <button
                onClick={() => navigate(`/missions?sentinel=${sentinel.id}`)}
                className="flex items-center gap-1 rounded-md border border-[#55788b]/20 bg-[#55788b]/5 px-2.5 py-1.5 text-[10px] font-medium text-[#7ea6bb] hover:bg-[#55788b]/10 transition-colors"
              >
                <IconFlag3 size={12} stroke={1.5} />
                Mission
              </button>
            )}
            {canActivate && (
              <button
                onClick={handleActivate}
                className="flex items-center gap-1 rounded-md border border-[#3dbf84]/20 bg-[#3dbf84]/5 px-2.5 py-1.5 text-[10px] font-medium text-[#3dbf84] hover:bg-[#3dbf84]/10 transition-colors"
              >
                <IconPlayerPlay size={12} stroke={1.5} />
                Activate
              </button>
            )}
            {canPause && (
              <button
                onClick={handlePause}
                className="flex items-center gap-1 rounded-md border border-[#d4a84b]/20 bg-[#d4a84b]/5 px-2.5 py-1.5 text-[10px] font-medium text-[#d4a84b] hover:bg-[#d4a84b]/10 transition-colors"
              >
                <IconPlayerPause size={12} stroke={1.5} />
                Pause
              </button>
            )}
            {canRetire && (
              <button
                onClick={handleRetire}
                className="flex items-center gap-1 rounded-md border border-[#6f7f9a]/20 bg-[#6f7f9a]/5 px-2.5 py-1.5 text-[10px] font-medium text-[#6f7f9a] hover:bg-[#6f7f9a]/10 transition-colors"
              >
                <IconArchive size={12} stroke={1.5} />
                Retire
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Two-column layout */}
      <div className="flex flex-1 min-h-0">
        {/* Main content — left 2/3 */}
        <div className="flex flex-col flex-1 min-w-0 border-r border-[#2d3240]/60">
          {/* Tabs */}
          <SubTabBar tabs={tabs} activeTab={activeTab} onTabChange={(id) => setActiveTab(id as DetailTab)} />

          {/* Tab content */}
          <div className="flex-1 overflow-auto px-5">
            {activeTab === "signals" && <SignalsTab sentinel={sentinel} />}
            {activeTab === "goals" && <GoalsTab sentinel={sentinel} />}
            {activeTab === "memory" && <MemoryTab sentinel={sentinel} />}
            {activeTab === "config" && <ConfigTab sentinel={sentinel} />}
          </div>
        </div>

        {/* Stats sidebar — right 1/3 */}
        <div className="w-[320px] shrink-0 bg-[#0b0d13] px-5 py-5 hidden lg:block">
          <StatsSidebar sentinel={sentinel} />
        </div>
      </div>
    </div>
  );
}
