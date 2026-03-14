import { useMemo } from "react";
import { Link } from "react-router-dom";
import { motion } from "motion/react";
import {
  IconPencil,
  IconShieldCheck,
  IconGavel,
  IconServer,
  IconBooks,
  IconRadar,
  IconAlertTriangle,
  IconNetwork,
  IconFlask,
  IconFileAnalytics,
  IconCertificate,
  IconSitemap,
  IconInfoCircle,
  IconCheck,
  IconArrowRight,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { ClaudeCodeHint } from "@/components/workbench/shared/claude-code-hint";
import { useWorkbench, useMultiPolicy } from "@/lib/workbench/multi-policy-store";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import { useSentinels } from "@/lib/workbench/sentinel-store";
import { useFindings } from "@/lib/workbench/finding-store";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import { SEVERITY_COLORS } from "@/lib/workbench/finding-constants";
import type { GuardId } from "@/lib/workbench/types";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CATEGORY_LABELS: Record<string, string> = {
  filesystem: "Filesystem",
  network: "Network",
  content: "Content",
  tools: "Tools",
  detection: "Detection",
  cua: "Desktop",
};

const CATEGORY_ORDER = [
  "filesystem",
  "network",
  "content",
  "tools",
  "detection",
  "cua",
];

const VERDICT_COLORS: Record<string, string> = {
  allow: "#3dbf84",
  deny: "#c45c5c",
  warn: "#d4a84b",
};

// ---------------------------------------------------------------------------
// Health Ring — SVG arc showing enabled/total guard coverage
// ---------------------------------------------------------------------------

function HealthRing({
  enabled,
  total,
}: {
  enabled: number;
  total: number;
}) {
  const pct = total > 0 ? enabled / total : 0;
  const radius = 34;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference * (1 - pct);

  return (
    <div className="relative w-[76px] h-[76px] shrink-0">
      <svg viewBox="0 0 80 80" className="w-full h-full -rotate-90">
        {/* Track */}
        <circle
          cx="40"
          cy="40"
          r={radius}
          fill="none"
          stroke="#2d3240"
          strokeWidth="3.5"
        />
        {/* Active arc — stroke-draw animation */}
        <motion.circle
          cx="40"
          cy="40"
          r={radius}
          fill="none"
          stroke="#d4a84b"
          strokeWidth="3.5"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: dashOffset }}
          transition={{ duration: 1, ease: "easeOut" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-syne font-bold text-[#ece7dc] leading-none">
          {enabled}
        </span>
        <span className="text-[9px] font-mono text-[#6f7f9a]">/{total}</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Guard tile — compact indicator in the coverage matrix
// ---------------------------------------------------------------------------

function GuardTile({
  name,
  enabled,
  verdict,
}: {
  name: string;
  enabled: boolean;
  verdict: string;
}) {
  const color = enabled ? VERDICT_COLORS[verdict] || "#6f7f9a" : "#2d324060";

  return (
    <div
      className={cn(
        "flex items-center gap-2 px-3 py-2 rounded-md transition-all duration-150",
        enabled ? "bg-[#131721]/80" : "bg-transparent",
      )}
    >
      <span
        className={cn(
          "w-1.5 h-1.5 rounded-full shrink-0",
          enabled && "animate-[pulse_3s_ease-in-out_infinite]",
        )}
        style={{ backgroundColor: color }}
      />
      <span
        className={cn(
          "text-[11px] font-mono truncate",
          enabled ? "text-[#ece7dc]" : "text-[#6f7f9a]/40",
        )}
      >
        {name}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Navigation card — contextual link with live state indicator
// ---------------------------------------------------------------------------

function NavCard({
  icon,
  label,
  detail,
  href,
  accent,
}: {
  icon: React.ReactNode;
  label: string;
  detail: string;
  href: string;
  accent?: string;
}) {
  return (
    <Link
      to={href}
      className="group flex items-center gap-3.5 px-4 py-3.5 rounded-lg border border-[#2d3240]/40 bg-[#0b0d13]/40 hover:border-[#2d3240] hover:bg-[#0b0d13] transition-all duration-150 card-shadow"
    >
      <div className="w-8 h-8 rounded-md bg-[#131721] flex items-center justify-center text-[#6f7f9a] group-hover:text-[#d4a84b] transition-colors shrink-0">
        {icon}
      </div>
      <div className="min-w-0">
        <div className="text-xs font-medium text-[#ece7dc] truncate">
          {label}
        </div>
        <div className={cn("text-[10px] truncate", accent || "text-[#6f7f9a]")}>
          {detail}
        </div>
      </div>
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Quick Start Guide — shown until the user has made meaningful progress
// ---------------------------------------------------------------------------

function QuickStartGuide({
  fleetConnected,
  sentinelCount,
  findingsCount,
}: {
  fleetConnected: boolean;
  sentinelCount: number;
  findingsCount: number;
}) {
  // Hide once all three milestones are met
  if (sentinelCount > 0 && findingsCount > 0 && fleetConnected) return null;

  const steps = [
    {
      num: 1,
      title: "Connect to Fleet",
      desc: "Link your hushd daemon to enable live enforcement",
      done: fleetConnected,
      href: "/settings",
    },
    {
      num: 2,
      title: "Deploy a Sentinel",
      desc: "Create an autonomous security monitor for your agents",
      done: sentinelCount > 0,
      href: "/fleet",
    },
    {
      num: 3,
      title: "Review Findings",
      desc: "Investigate threats detected by your sentinels",
      done: findingsCount > 0,
      href: "/audit",
    },
  ];

  // Determine the first incomplete step so we can accent it
  const nextStepIdx = steps.findIndex((s) => !s.done);

  return (
    <div>
      <h2 className="text-[10px] font-mono font-semibold text-[#d4a84b] uppercase tracking-[0.15em] mb-3">
        Quick Start
      </h2>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {steps.map((step, idx) => {
          const isNext = idx === nextStepIdx;
          return (
            <Link
              key={step.num}
              to={step.href}
              className={cn(
                "group relative flex items-start gap-3 px-4 py-4 rounded-lg border transition-all duration-200",
                step.done
                  ? "border-[#3dbf84]/20 bg-[#3dbf84]/[0.03]"
                  : isNext
                    ? "border-[#d4a84b]/30 bg-[#d4a84b]/[0.04] hover:border-[#d4a84b]/50"
                    : "border-[#2d3240]/40 bg-[#0b0d13]/40 hover:border-[#2d3240]",
              )}
            >
              {/* Step number or checkmark */}
              <div
                className={cn(
                  "w-7 h-7 rounded-full flex items-center justify-center shrink-0 text-xs font-bold transition-colors",
                  step.done
                    ? "bg-[#3dbf84]/15 text-[#3dbf84]"
                    : isNext
                      ? "bg-[#d4a84b]/15 text-[#d4a84b] ring-1 ring-[#d4a84b]/30"
                      : "bg-[#2d3240]/40 text-[#6f7f9a]/60",
                )}
              >
                {step.done ? (
                  <IconCheck size={14} stroke={2.5} />
                ) : (
                  step.num
                )}
              </div>

              <div className="min-w-0 flex-1">
                <div
                  className={cn(
                    "text-xs font-medium",
                    step.done
                      ? "text-[#3dbf84]/80"
                      : "text-[#ece7dc]",
                  )}
                >
                  {step.title}
                </div>
                <div className="text-[10px] text-[#6f7f9a] mt-0.5 leading-relaxed">
                  {step.desc}
                </div>
              </div>

              {/* Arrow hint for the active step */}
              {isNext && !step.done && (
                <IconArrowRight
                  size={14}
                  stroke={1.5}
                  className="text-[#d4a84b]/40 group-hover:text-[#d4a84b] transition-colors shrink-0 mt-1.5"
                />
              )}
            </Link>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sentinel Summary Card — shows total, active/paused/retired, mini sigils
// ---------------------------------------------------------------------------

function SentinelSummaryCard({
  total,
  active,
  paused,
  retired,
}: {
  total: number;
  active: number;
  paused: number;
  retired: number;
}) {
  return (
    <div className="rounded-lg border border-[#2d3240]/40 bg-[#0b0d13]/60 p-4">
      <div className="flex items-center gap-2 mb-3">
        <IconRadar size={15} stroke={1.5} className="text-[#8b5555]" />
        <span className="text-[10px] font-mono font-semibold text-[#8b5555] uppercase tracking-wider">
          Sentinels
        </span>
      </div>
      <div className="flex items-baseline gap-3">
        <span className="text-2xl font-syne font-bold text-[#ece7dc] leading-none">
          {total}
        </span>
        <span className="text-[10px] font-mono text-[#6f7f9a]">total</span>
      </div>
      <div className="flex items-center gap-3 mt-2 text-[10px] font-mono">
        <span className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-[#3dbf84]" />
          <span className="text-[#ece7dc]">{active}</span>
          <span className="text-[#6f7f9a]">active</span>
        </span>
        <span className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-[#d4a84b]" />
          <span className="text-[#ece7dc]">{paused}</span>
          <span className="text-[#6f7f9a]">paused</span>
        </span>
        <span className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-[#6f7f9a]/40" />
          <span className="text-[#ece7dc]">{retired}</span>
          <span className="text-[#6f7f9a]">retired</span>
        </span>
      </div>
      {/* Mini sigil placeholders for active sentinels */}
      {active > 0 && (
        <div className="flex items-center gap-1.5 mt-3">
          {Array.from({ length: Math.min(active, 8) }).map((_, i) => (
            <div
              key={i}
              className="w-5 h-5 rounded-full bg-[#131721] border border-[#2d3240]/60 flex items-center justify-center"
            >
              <span className="text-[7px] font-mono text-[#6f7f9a]">
                {String.fromCharCode(65 + i)}
              </span>
            </div>
          ))}
          {active > 8 && (
            <span className="text-[9px] font-mono text-[#6f7f9a]">
              +{active - 8}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Findings Summary Card — emerging (highlighted), confirmed, total, severity bars
// ---------------------------------------------------------------------------

function FindingsSummaryCard({
  emerging,
  confirmed,
  total,
  severityCounts,
}: {
  emerging: number;
  confirmed: number;
  total: number;
  severityCounts: Record<string, number>;
}) {
  const maxSeverity = Math.max(1, ...Object.values(severityCounts));

  return (
    <div className="rounded-lg border border-[#2d3240]/40 bg-[#0b0d13]/60 p-4">
      <div className="flex items-center gap-2 mb-3">
        <IconAlertTriangle size={15} stroke={1.5} className="text-[#d4a84b]" />
        <span className="text-[10px] font-mono font-semibold text-[#d4a84b] uppercase tracking-wider">
          Findings
        </span>
      </div>
      <div className="flex items-baseline gap-3">
        <span className="text-2xl font-syne font-bold text-[#ece7dc] leading-none">
          {total}
        </span>
        <span className="text-[10px] font-mono text-[#6f7f9a]">total</span>
      </div>
      <div className="flex items-center gap-3 mt-2 text-[10px] font-mono">
        <span className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-[#d4a84b] animate-pulse" />
          <span className="text-[#d4a84b] font-semibold">{emerging}</span>
          <span className="text-[#d4a84b]">emerging</span>
        </span>
        <span className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-[#3dbf84]" />
          <span className="text-[#ece7dc]">{confirmed}</span>
          <span className="text-[#6f7f9a]">confirmed</span>
        </span>
      </div>
      {/* Severity breakdown mini-bars */}
      <div className="flex items-end gap-1 mt-3 h-5">
        {(["critical", "high", "medium", "low"] as const).map((sev) => {
          const count = severityCounts[sev] ?? 0;
          const heightPct = maxSeverity > 0 ? (count / maxSeverity) * 100 : 0;
          return (
            <div
              key={sev}
              className="flex flex-col items-center gap-0.5"
              title={`${sev}: ${count}`}
            >
              <div
                className="w-3 rounded-sm transition-all duration-500"
                style={{
                  height: `${Math.max(heightPct, 8)}%`,
                  backgroundColor: SEVERITY_COLORS[sev] ?? "#6f7f9a",
                  opacity: count > 0 ? 1 : 0.2,
                }}
              />
            </div>
          );
        })}
        <span className="text-[8px] font-mono text-[#6f7f9a] ml-1.5 leading-none self-end">
          severity
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Home Page
// ---------------------------------------------------------------------------

export function HomePage() {
  const { state } = useWorkbench();
  const { tabs } = useMultiPolicy();
  const { connection } = useFleetConnection();
  const { activePolicy, validation, dirty } = state;

  // ---- Guard analysis ----
  const { enabledCount, totalCount, guardsByCategory } = useMemo(() => {
    let enabled = 0;
    const byCategory: Record<
      string,
      { name: string; enabled: boolean; verdict: string }[]
    > = {};

    for (const guard of GUARD_REGISTRY) {
      const cfg = activePolicy.guards[guard.id as GuardId];
      const isEnabled = !!(cfg && "enabled" in cfg && cfg.enabled);
      if (isEnabled) enabled++;

      const cat = guard.category;
      if (!byCategory[cat]) byCategory[cat] = [];
      byCategory[cat].push({
        name: guard.name,
        enabled: isEnabled,
        verdict: guard.defaultVerdict,
      });
    }

    return {
      enabledCount: enabled,
      totalCount: GUARD_REGISTRY.length,
      guardsByCategory: byCategory,
    };
  }, [activePolicy]);

  // ---- Validation status ----
  const errorCount = validation.errors.length;
  const warningCount = validation.warnings.length;
  let validationText: string;
  let validationColor: string;

  if (errorCount > 0) {
    validationText = `${errorCount} error${errorCount !== 1 ? "s" : ""}`;
    validationColor = "#c45c5c";
  } else if (warningCount > 0) {
    validationText = `${warningCount} warning${warningCount !== 1 ? "s" : ""}`;
    validationColor = "#d4a84b";
  } else {
    validationText = "Valid";
    validationColor = "#3dbf84";
  }

  // ---- Derived details for nav cards ----
  const tabCount = tabs.length;
  const tabDetail = `${tabCount} tab${tabCount !== 1 ? "s" : ""}${dirty ? " · unsaved" : ""}`;

  const fleetDetail = connection.connected
    ? `Connected · ${connection.agentCount} agent${connection.agentCount !== 1 ? "s" : ""}`
    : "Not connected";

  const savedCount = state.savedPolicies?.length ?? 0;

  // ---- Live sentinel & findings data from providers ----
  const { sentinels } = useSentinels();
  const { findings } = useFindings();

  const sentinelStats = useMemo(() => {
    let active = 0;
    let paused = 0;
    let retired = 0;
    for (const s of sentinels) {
      if (s.status === "active") active++;
      else if (s.status === "paused") paused++;
      else if (s.status === "retired") retired++;
    }
    return { total: sentinels.length, active, paused, retired };
  }, [sentinels]);

  const findingsStats = useMemo(() => {
    let emerging = 0;
    let confirmed = 0;
    const severityCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      if (f.status === "emerging") emerging++;
      else if (f.status === "confirmed") confirmed++;
      if ((f.status === "emerging" || f.status === "confirmed") && f.severity in severityCounts) {
        severityCounts[f.severity]++;
      }
    }
    return { emerging, confirmed, total: findings.length, severityCounts };
  }, [findings]);

  return (
    <div className="h-full w-full flex flex-col bg-[#05060a] overflow-auto page-transition-enter">
      <div className="max-w-4xl w-full mx-auto px-6 py-6 flex flex-col gap-8">
        {/* ================================================================ */}
        {/* Policy Identity + Health Ring                                     */}
        {/* ================================================================ */}
        <div className="flex items-center gap-6">
          <HealthRing enabled={enabledCount} total={totalCount} />
          <div className="min-w-0">
            <h1 className="font-syne text-2xl font-bold text-[#ece7dc] tracking-tight truncate">
              {activePolicy.name}
            </h1>
            <div className="flex items-center gap-2 mt-1 flex-wrap text-xs font-mono">
              <span className="text-[#6f7f9a]">v{activePolicy.version}</span>
              <span className="text-[#2d3240]">&middot;</span>
              <span style={{ color: validationColor }}>{validationText}</span>
              <span className="text-[#2d3240]">&middot;</span>
              <span className="text-[#6f7f9a]">
                {enabledCount}/{totalCount} guards
              </span>
              {dirty && (
                <>
                  <span className="text-[#2d3240]">&middot;</span>
                  <span className="text-[#d4a84b]">unsaved</span>
                </>
              )}
            </div>
            {activePolicy.description && (
              <p className="text-[11px] text-[#6f7f9a]/60 mt-1.5 truncate max-w-lg">
                {activePolicy.description}
              </p>
            )}
          </div>
        </div>

        {/* ================================================================ */}
        {/* Sentinel & Findings Summary Cards                                */}
        {/* ================================================================ */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <SentinelSummaryCard {...sentinelStats} />
          <FindingsSummaryCard {...findingsStats} />
        </div>

        {/* ================================================================ */}
        {/* Quick Start Guide                                                */}
        {/* ================================================================ */}
        <QuickStartGuide
          fleetConnected={connection.connected}
          sentinelCount={connection.agentCount}
          findingsCount={enabledCount}
        />

        {sentinelStats.total === 0 && findingsStats.total === 0 && (
          <div className="mx-6 mt-4 rounded-lg border border-[#2d3240]/40 bg-[#131721]/30 px-4 py-3 flex items-center gap-3">
            <IconInfoCircle size={16} stroke={1.5} className="text-[#6f7f9a]/50 shrink-0" />
            <p className="text-[11px] text-[#6f7f9a]/60">
              Deploy a sentinel or connect to fleet to see live stats here.
            </p>
          </div>
        )}

        {/* ================================================================ */}
        {/* Guard Coverage Matrix                                             */}
        {/* ================================================================ */}
        <div>
          <h2 className="font-syne text-[10px] font-semibold text-[#d4a84b] uppercase tracking-wider mb-3">
            Guard Coverage
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-x-6 gap-y-5">
            {CATEGORY_ORDER.filter(
              (cat) => guardsByCategory[cat]?.length,
            ).map((cat) => (
              <div key={cat}>
                <span className="text-[9px] font-mono text-[#6f7f9a]/50 uppercase tracking-wider">
                  {CATEGORY_LABELS[cat] || cat}
                </span>
                <div className="mt-1.5 space-y-0.5">
                  {guardsByCategory[cat].map((g) => (
                    <GuardTile key={g.name} {...g} />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ================================================================ */}
        {/* Claude Code Hint                                                   */}
        {/* ================================================================ */}
        <ClaudeCodeHint hintId="home.audit" />

        {/* ================================================================ */}
        {/* Navigation Cards                                                  */}
        {/* ================================================================ */}
        <div>
          <h2 className="font-syne text-[10px] font-semibold text-[#d4a84b] uppercase tracking-wider mb-3">
            Navigate
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <NavCard
              icon={<IconRadar size={16} stroke={1.5} />}
              label="Sentinels"
              detail={`${sentinelStats.active} active sentinel${sentinelStats.active !== 1 ? "s" : ""}`}
              href="/sentinels"
            />
            <NavCard
              icon={<IconAlertTriangle size={16} stroke={1.5} />}
              label="Findings & Intel"
              detail={`${findingsStats.emerging} emerging · ${findingsStats.total} total findings & intel`}
              href="/findings"
              accent={findingsStats.emerging > 0 ? "text-[#d4a84b]" : undefined}
            />
            <NavCard
              icon={<IconFlask size={16} stroke={1.5} />}
              label="Lab"
              detail="Simulate and hunt threats"
              href="/lab"
            />
            <NavCard
              icon={<IconNetwork size={16} stroke={1.5} />}
              label="Swarms"
              detail="Trust network coordination"
              href="/swarms"
            />
            <NavCard
              icon={<IconPencil size={16} stroke={1.5} />}
              label="Editor"
              detail={tabDetail}
              href="/editor"
              accent={dirty ? "text-[#d4a84b]" : undefined}
            />
            <NavCard
              icon={<IconBooks size={16} stroke={1.5} />}
              label="Library"
              detail={`${savedCount} saved polic${savedCount !== 1 ? "ies" : "y"}`}
              href="/library"
            />
            <NavCard
              icon={<IconShieldCheck size={16} stroke={1.5} />}
              label="Compliance"
              detail="Framework coverage analysis"
              href="/compliance"
            />
            <NavCard
              icon={<IconGavel size={16} stroke={1.5} />}
              label="Approvals"
              detail={connection.connected ? "Live queue" : "Demo mode"}
              href="/approvals"
            />
            <NavCard
              icon={<IconFileAnalytics size={16} stroke={1.5} />}
              label="Audit"
              detail="Decision audit trail"
              href="/audit"
            />
            <NavCard
              icon={<IconCertificate size={16} stroke={1.5} />}
              label="Receipts"
              detail="Signed attestations"
              href="/receipts"
            />
            <NavCard
              icon={<IconServer size={16} stroke={1.5} />}
              label="Fleet"
              detail={fleetDetail}
              href="/fleet"
              accent={connection.connected ? "text-[#3dbf84]" : undefined}
            />
            <NavCard
              icon={<IconSitemap size={16} stroke={1.5} />}
              label="Topology"
              detail="Delegation & hierarchy graphs"
              href="/topology"
            />
          </div>
        </div>
      </div>
    </div>
  );
}
