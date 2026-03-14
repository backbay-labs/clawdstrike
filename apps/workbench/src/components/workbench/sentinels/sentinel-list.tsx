import { useState, useMemo } from "react";
import { Link } from "react-router-dom";
import {
  IconEye,
  IconSearch,
  IconBrain,
  IconUsers,
  IconPlus,
  IconFilter,
  IconDiamond,
  IconMoon,
  IconStar,
  IconKey,
  IconCrown,
  IconSpiral,
  IconWaveSine,
  IconEyeCheck,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type {
  Sentinel,
  SentinelMode,
  SentinelStatus,
} from "@/lib/workbench/sentinel-manager";
import {
  deriveSigilColor,
  getSentinelDriverDefinition,
  getSentinelExecutionModeConfig,
} from "@/lib/workbench/sentinel-manager";
import type { SigilType } from "@/lib/workbench/sentinel-manager";


const MODE_COLORS: Record<SentinelMode, string> = {
  watcher: "#5b8def",
  hunter: "#d4784b",
  curator: "#8b7355",
  liaison: "#7b6b8b",
};

const MODE_ICONS: Record<SentinelMode, typeof IconEye> = {
  watcher: IconEye,
  hunter: IconSearch,
  curator: IconBrain,
  liaison: IconUsers,
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

type ModeFilter = "all" | SentinelMode;
type StatusFilter = "all" | SentinelStatus;


function relativeTime(epochMs: number): string {
  const now = Date.now();
  const diffSecs = Math.floor((now - epochMs) / 1000);
  if (diffSecs < 0) return "just now";
  if (diffSecs < 60) return `${diffSecs}s ago`;
  if (diffSecs < 3600) return `${Math.floor(diffSecs / 60)}m ago`;
  if (diffSecs < 86400) return `${Math.floor(diffSecs / 3600)}h ago`;
  return `${Math.floor(diffSecs / 86400)}d ago`;
}


function SigilAvatar({
  sigil,
  fingerprint,
  size = 24,
}: {
  sigil: SigilType;
  fingerprint: string;
  size?: number;
}) {
  const Icon = SIGIL_ICONS[sigil];
  const color = deriveSigilColor(fingerprint);

  return (
    <div
      className="flex items-center justify-center rounded-md shrink-0"
      style={{
        width: size + 8,
        height: size + 8,
        backgroundColor: color + "18",
      }}
    >
      <Icon size={size} stroke={1.5} style={{ color }} />
    </div>
  );
}


function SentinelCard({ sentinel }: { sentinel: Sentinel }) {
  const modeColor = MODE_COLORS[sentinel.mode];
  const ModeIcon = MODE_ICONS[sentinel.mode];
  const statusDot = STATUS_DOT_COLORS[sentinel.status];
  const driver = getSentinelDriverDefinition(sentinel.runtime.driver);
  const executionMode = getSentinelExecutionModeConfig(sentinel.runtime.executionMode);

  return (
    <Link
      to={`/sentinels/${sentinel.id}`}
      className="group flex flex-col rounded-lg border border-[#2d3240]/60 bg-[#0b0d13] hover:border-[#2d3240] hover:bg-[#0b0d13]/80 transition-all duration-200 overflow-hidden"
    >
      {/* Top accent border */}
      <div
        className="h-[2px] w-full shrink-0"
        style={{ backgroundColor: modeColor + "40" }}
      />

      <div className="flex flex-col gap-3 px-4 py-4">
        {/* Header: sigil + name + mode */}
        <div className="flex items-start gap-3">
          <SigilAvatar
            sigil={sentinel.identity.sigil}
            fingerprint={sentinel.identity.fingerprint}
            size={22}
          />
          <div className="min-w-0 flex-1">
            <h3 className="text-[13px] font-semibold text-[#ece7dc] truncate group-hover:text-[#d4a84b] transition-colors">
              {sentinel.name}
            </h3>
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
                <span className="inline-flex items-center gap-1">
                  <ModeIcon size={9} stroke={1.5} />
                  {MODE_LABELS[sentinel.mode]}
                </span>
              </span>
              <span className="text-[9px] text-[#6f7f9a]/60 capitalize">
                {STATUS_LABELS[sentinel.status]}
              </span>
            </div>
            <div className="mt-1 flex items-center gap-1.5 flex-wrap">
              <span className="rounded-full border border-[#2d3240]/40 bg-[#131721] px-2 py-0.5 text-[8px] font-medium uppercase tracking-[0.08em] text-[#ece7dc]/65">
                {driver.label}
              </span>
              <span className="rounded-full border border-[#2d3240]/40 bg-[#131721] px-2 py-0.5 text-[8px] font-medium uppercase tracking-[0.08em] text-[#6f7f9a]/60">
                {executionMode.label} · Tier {sentinel.runtime.enforcementTier}
              </span>
            </div>
          </div>
        </div>

        {/* Goal summary */}
        {sentinel.goals.length > 0 && (
          <p className="text-[10px] text-[#6f7f9a]/70 truncate leading-relaxed">
            {sentinel.goals[0].description}
          </p>
        )}

        {/* Schedule (for hunters) or source info (for watchers) */}
        {sentinel.mode === "hunter" && sentinel.schedule && (
          <div className="flex items-center gap-1.5">
            <span className="text-[9px] text-[#6f7f9a]/40 uppercase tracking-wider">Schedule</span>
            <span className="text-[10px] font-mono text-[#ece7dc]/50">
              {sentinel.schedule}
            </span>
          </div>
        )}

        {!sentinel.schedule && sentinel.runtime.targetRef && (
          <div className="flex items-center gap-1.5">
            <span className="text-[9px] text-[#6f7f9a]/40 uppercase tracking-wider">Target</span>
            <span className="text-[10px] font-mono text-[#ece7dc]/50 truncate">
              {sentinel.runtime.targetRef}
            </span>
          </div>
        )}

        {/* Metrics row */}
        <div className="flex items-center gap-4 border-t border-[#2d3240]/40 pt-3">
          <MetricPill
            label="Signals"
            value={sentinel.stats.signalsGenerated}
          />
          <MetricPill
            label="Findings"
            value={sentinel.stats.findingsCreated}
          />
          <MetricPill
            label="Intel"
            value={sentinel.stats.intelProduced}
          />
        </div>

        {/* Bottom row: memory + last active */}
        <div className="flex items-center justify-between">
          <span className="text-[9px] text-[#6f7f9a]/40">
            {sentinel.memory.knownPatterns.length} pattern{sentinel.memory.knownPatterns.length !== 1 ? "s" : ""} in memory
          </span>
          <span className="text-[9px] font-mono text-[#6f7f9a]/40">
            {sentinel.stats.lastActiveAt > 0
              ? relativeTime(sentinel.stats.lastActiveAt)
              : "never"}
          </span>
        </div>

        {/* Swarm tags */}
        {sentinel.swarms.length > 0 && (
          <div className="flex items-center gap-1.5 flex-wrap">
            {sentinel.swarms.map((s) => (
              <span
                key={s.swarmId}
                className="rounded-full px-2 py-0.5 text-[8px] font-mono text-[#6f7f9a]/60 bg-[#131721] border border-[#2d3240]/40"
              >
                {s.swarmId.slice(0, 12)}
              </span>
            ))}
          </div>
        )}
      </div>
    </Link>
  );
}

function MetricPill({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex flex-col items-center">
      <span className="text-[13px] font-semibold font-mono text-[#ece7dc]/80">
        {value.toLocaleString()}
      </span>
      <span className="text-[8px] uppercase tracking-wider text-[#6f7f9a]/40">
        {label}
      </span>
    </div>
  );
}


function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-24 gap-4">
      <div className="w-16 h-16 rounded-xl bg-[#131721] flex items-center justify-center">
        <IconEye size={28} stroke={1} className="text-[#6f7f9a]/30" />
      </div>
      <div className="text-center">
        <p className="text-[13px] text-[#ece7dc]/70">
          No sentinels deployed yet
        </p>
        <p className="mt-1 text-[11px] text-[#6f7f9a]/50">
          Create your first sentinel to begin autonomous monitoring
        </p>
      </div>
      <Link
        to="/sentinels/create"
        className="flex items-center gap-1.5 rounded-md bg-[#d4a84b]/10 border border-[#d4a84b]/20 px-4 py-2 text-[11px] font-medium text-[#d4a84b] hover:bg-[#d4a84b]/20 transition-colors"
      >
        <IconPlus size={13} stroke={1.5} />
        Create Sentinel
      </Link>
    </div>
  );
}


export function SentinelList({ sentinels }: { sentinels: Sentinel[] }) {
  const [modeFilter, setModeFilter] = useState<ModeFilter>("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");

    const counts = useMemo(() => {
    let active = 0;
    let paused = 0;
    let retired = 0;
    for (const s of sentinels) {
      if (s.status === "active") active++;
      else if (s.status === "paused") paused++;
      else retired++;
    }
    return { total: sentinels.length, active, paused, retired };
  }, [sentinels]);

  // Filtered list
  const filtered = useMemo(() => {
    let list = [...sentinels];
    if (modeFilter !== "all") {
      list = list.filter((s) => s.mode === modeFilter);
    }
    if (statusFilter !== "all") {
      list = list.filter((s) => s.status === statusFilter);
    }
    // Sort: active first, then paused, then retired; within group by updatedAt desc
    list.sort((a, b) => {
      const statusOrder: Record<SentinelStatus, number> = {
        active: 0,
        paused: 1,
        retired: 2,
      };
      const ord = statusOrder[a.status] - statusOrder[b.status];
      if (ord !== 0) return ord;
      return b.updatedAt - a.updatedAt;
    });
    return list;
  }, [sentinels, modeFilter, statusFilter]);

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#05060a]">
      {/* Header */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <IconEye size={18} className="text-[#d4a84b]" stroke={1.5} />
            <div>
              <h1 className="text-sm font-semibold text-[#ece7dc] tracking-[-0.01em]">
                Sentinels
              </h1>
              <p className="text-[11px] text-[#6f7f9a] mt-0.5">
                {counts.active} active
                {counts.paused > 0 && ` \u00b7 ${counts.paused} paused`}
                {counts.retired > 0 && ` \u00b7 ${counts.retired} retired`}
              </p>
            </div>
          </div>
          <Link
            to="/sentinels/create"
            className="flex items-center gap-1.5 rounded-md bg-[#d4a84b]/10 border border-[#d4a84b]/20 px-3 py-1.5 text-[11px] font-medium text-[#d4a84b] hover:bg-[#d4a84b]/20 transition-colors"
          >
            <IconPlus size={13} stroke={1.5} />
            Create Sentinel
          </Link>
        </div>
      </div>

      {/* Filter bar */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-2.5 flex items-center gap-4">
        <div className="flex items-center gap-2">
          <IconFilter size={12} stroke={1.5} className="text-[#6f7f9a]/40" />
          <span className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/50">
            Mode
          </span>
          <div className="flex items-center gap-1">
            {(["all", "watcher", "hunter", "curator", "liaison"] as ModeFilter[]).map(
              (m) => (
                <button
                  key={m}
                  onClick={() => setModeFilter(m)}
                  className={cn(
                    "rounded-md px-2.5 py-1 text-[10px] font-medium capitalize transition-colors",
                    modeFilter === m
                      ? "bg-[#d4a84b]/10 text-[#d4a84b]"
                      : "text-[#6f7f9a]/60 hover:text-[#ece7dc] hover:bg-[#131721]/40",
                  )}
                >
                  {m}
                </button>
              ),
            )}
          </div>
        </div>

        <div className="h-4 w-px bg-[#2d3240]/40" />

        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/50">
            Status
          </span>
          <div className="flex items-center gap-1">
            {(["all", "active", "paused", "retired"] as StatusFilter[]).map(
              (s) => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={cn(
                    "rounded-md px-2.5 py-1 text-[10px] font-medium capitalize transition-colors",
                    statusFilter === s
                      ? "bg-[#d4a84b]/10 text-[#d4a84b]"
                      : "text-[#6f7f9a]/60 hover:text-[#ece7dc] hover:bg-[#131721]/40",
                  )}
                >
                  {s}
                </button>
              ),
            )}
          </div>
        </div>

        <span className="ml-auto text-[10px] text-[#6f7f9a]/40">
          {filtered.length} result{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto px-6 py-5">
        {sentinels.length === 0 ? (
          <EmptyState />
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16">
            <p className="text-[12px] text-[#6f7f9a]/40">
              No sentinels match the current filters
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {filtered.map((sentinel) => (
              <SentinelCard key={sentinel.id} sentinel={sentinel} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
