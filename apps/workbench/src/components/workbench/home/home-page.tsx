import { useMemo } from "react";
import { Link } from "react-router-dom";
import {
  IconPencil,
  IconCrosshair,
  IconShieldCheck,
  IconGavel,
  IconServer,
  IconBooks,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { ClaudeCodeHint } from "@/components/workbench/shared/claude-code-hint";
import { useWorkbench, useMultiPolicy } from "@/lib/workbench/multi-policy-store";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
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
        {/* Active arc */}
        <circle
          cx="40"
          cy="40"
          r={radius}
          fill="none"
          stroke="#d4a84b"
          strokeWidth="3.5"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          className="transition-all duration-1000 ease-out"
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
        "flex items-center gap-2 px-3 py-2 rounded-md transition-all duration-200",
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
      className="group flex items-center gap-3.5 px-4 py-3.5 rounded-lg border border-[#2d3240]/40 bg-[#0b0d13]/40 hover:border-[#2d3240] hover:bg-[#0b0d13] transition-all duration-200"
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

  return (
    <div className="h-full w-full flex flex-col bg-[#05060a] overflow-auto page-transition-enter">
      <div className="max-w-4xl w-full mx-auto px-8 py-8 flex flex-col gap-8">
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
        {/* Guard Coverage Matrix                                             */}
        {/* ================================================================ */}
        <div>
          <h2 className="text-[10px] font-mono font-semibold text-[#d4a84b] uppercase tracking-[0.15em] mb-3">
            Guard Coverage
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-5">
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
          <h2 className="text-[10px] font-mono font-semibold text-[#d4a84b] uppercase tracking-[0.15em] mb-3">
            Navigate
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            <NavCard
              icon={<IconPencil size={16} stroke={1.5} />}
              label="Policy Editor"
              detail={tabDetail}
              href="/editor"
              accent={dirty ? "text-[#d4a84b]" : undefined}
            />
            <NavCard
              icon={<IconCrosshair size={16} stroke={1.5} />}
              label="Threat Lab"
              detail="Simulate attack scenarios"
              href="/simulator"
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
              icon={<IconServer size={16} stroke={1.5} />}
              label="Fleet"
              detail={fleetDetail}
              href="/fleet"
              accent={connection.connected ? "text-[#3dbf84]" : undefined}
            />
            <NavCard
              icon={<IconBooks size={16} stroke={1.5} />}
              label="Library"
              detail={`${savedCount} saved polic${savedCount !== 1 ? "ies" : "y"}`}
              href="/library"
            />
          </div>
        </div>
      </div>
    </div>
  );
}
