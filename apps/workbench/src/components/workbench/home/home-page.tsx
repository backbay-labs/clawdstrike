import { useMemo, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { motion, AnimatePresence } from "motion/react";
import {
  IconPencil,
  IconShieldCheck,
  IconGavel,
  IconRadar,
  IconAlertTriangle,
  IconFlask,
  IconServer,
  IconArrowRight,
  IconCheck,
  IconPlugConnected,
  IconActivity,
  IconShieldLock,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { ClaudeCodeHint } from "@/components/workbench/shared/claude-code-hint";
import { useWorkbenchState, usePolicyTabs } from "@/features/policy/hooks/use-policy-actions";
import { useFleetConnection } from "@/features/fleet/use-fleet-connection";
import { useSentinels } from "@/features/sentinels/stores/sentinel-store";
import { useFindings } from "@/features/findings/stores/finding-store";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import { SEVERITY_COLORS } from "@/lib/workbench/finding-constants";
import { type Posture, derivePosture, POSTURE_CONFIG } from "@/features/shared/posture-utils";
import type { GuardId } from "@/lib/workbench/types";

// ---------------------------------------------------------------------------
// Scan line — animated horizontal sweep across the viewport
// ---------------------------------------------------------------------------

function ScanLine({ posture }: { posture: Posture }) {
  if (posture === "offline") return null;
  const config = POSTURE_CONFIG[posture];
  return (
    <motion.div
      className="absolute left-0 right-0 h-px pointer-events-none z-10"
      style={{
        background: `linear-gradient(90deg, transparent 0%, ${config.color}40 20%, ${config.color}18 50%, ${config.color}40 80%, transparent 100%)`,
        boxShadow: `0 0 8px ${config.glow}`,
      }}
      animate={{ top: ["0%", "100%"] }}
      transition={{
        duration: posture === "critical" ? 4 : posture === "attention" ? 8 : 12,
        repeat: Infinity,
        ease: "linear",
      }}
    />
  );
}

// ---------------------------------------------------------------------------
// Posture Core — the hero visualization
// ---------------------------------------------------------------------------

function PostureCore({
  posture,
  enabledGuards,
  totalGuards,
}: {
  posture: Posture;
  enabledGuards: number;
  totalGuards: number;
}) {
  const config = POSTURE_CONFIG[posture];
  const pct = totalGuards > 0 ? enabledGuards / totalGuards : 0;

  // Guard arc segments
  const segments = useMemo(() => {
    const result: { angle: number; active: boolean }[] = [];
    const step = 360 / totalGuards;
    for (let idx = 0; idx < GUARD_REGISTRY.length; idx++) {
      result.push({ angle: step * idx, active: idx < enabledGuards });
    }
    return result;
  }, [enabledGuards, totalGuards]);

  return (
    <div className="relative flex items-center justify-center">
      {/* Outer glow */}
      <div
        className="absolute rounded-full"
        style={{
          width: 220,
          height: 220,
          background: `radial-gradient(circle, ${config.glow} 0%, transparent 70%)`,
        }}
      />

      {/* SVG rings */}
      <svg viewBox="0 0 200 200" className="w-[200px] h-[200px] -rotate-90" style={{ filter: `drop-shadow(0 0 12px ${config.glow})` }}>
        {/* Outer track */}
        <circle cx="100" cy="100" r="88" fill="none" stroke="#1a1d28" strokeWidth="1" />

        {/* Guard segment arcs */}
        {segments.map((seg, i) => {
          const r = 82;
          const segLen = (2 * Math.PI * r) / totalGuards;
          const gap = 3;
          const arcLen = segLen - gap;
          const offset = (2 * Math.PI * r) - (segLen * i);
          return (
            <motion.circle
              key={i}
              cx="100"
              cy="100"
              r={r}
              fill="none"
              stroke={seg.active ? config.ringStroke : "#1a1d28"}
              strokeWidth="3"
              strokeLinecap="round"
              strokeDasharray={`${arcLen} ${2 * Math.PI * r - arcLen}`}
              strokeDashoffset={offset}
              initial={{ opacity: 0 }}
              animate={{ opacity: seg.active ? 1 : 0.25 }}
              transition={{ delay: i * 0.05, duration: 0.4 }}
            />
          );
        })}

        {/* Inner ring — coverage arc */}
        <circle cx="100" cy="100" r="68" fill="none" stroke="#0e1018" strokeWidth="12" />
        <motion.circle
          cx="100"
          cy="100"
          r="68"
          fill="none"
          stroke={config.ringStroke}
          strokeWidth="2"
          strokeLinecap="round"
          strokeDasharray={2 * Math.PI * 68}
          initial={{ strokeDashoffset: 2 * Math.PI * 68 }}
          animate={{ strokeDashoffset: (2 * Math.PI * 68) * (1 - pct) }}
          transition={{ duration: 1.2, ease: "easeOut" }}
          style={{ filter: `drop-shadow(0 0 4px ${config.color}60)` }}
        />

        {/* Sweep tick marks */}
        {[0, 90, 180, 270].map((angle) => (
          <line
            key={angle}
            x1="100"
            y1="8"
            x2="100"
            y2="14"
            stroke="#2d3240"
            strokeWidth="1"
            transform={`rotate(${angle} 100 100)`}
          />
        ))}
      </svg>

      {/* Center content */}
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <motion.span
          className="text-[10px] font-mono font-bold tracking-[0.3em] leading-none"
          style={{ color: config.color }}
          animate={posture !== "offline" ? {
            opacity: [1, 0.5, 1],
          } : {}}
          transition={{
            duration: config.breathMs / 1000,
            repeat: Infinity,
            ease: "easeInOut",
          }}
        >
          {config.label}
        </motion.span>
        <span className="text-3xl font-syne font-black text-[#ece7dc] leading-none mt-2">
          {enabledGuards}
          <span className="text-lg text-[#6f7f9a] font-normal">/{totalGuards}</span>
        </span>
        <span className="text-[9px] font-mono text-[#6f7f9a]/60 mt-1">GUARDS ACTIVE</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Threat ticker — scrolling threat/finding feed
// ---------------------------------------------------------------------------

function ThreatTicker({
  findings,
}: {
  findings: Array<{ id: string; title: string; severity: string; status: string }>;
}) {
  const [visibleIdx, setVisibleIdx] = useState(0);
  const emergingFindings = findings.filter((f) => f.status === "emerging");

  useEffect(() => {
    if (emergingFindings.length <= 1) return;
    const iv = setInterval(() => {
      setVisibleIdx((prev) => (prev + 1) % emergingFindings.length);
    }, 4000);
    return () => clearInterval(iv);
  }, [emergingFindings.length]);

  if (emergingFindings.length === 0) return null;

  const current = emergingFindings[visibleIdx % emergingFindings.length];
  if (!current) return null;
  const sevColor = SEVERITY_COLORS[current.severity as keyof typeof SEVERITY_COLORS] ?? "#6f7f9a";

  return (
    <Link
      to="/findings"
      className="group flex items-center gap-3 px-4 py-2.5 rounded border border-[#c45c5c]/15 bg-[#c45c5c]/[0.03] hover:border-[#c45c5c]/30 transition-all"
    >
      <span className="w-1.5 h-1.5 rounded-full animate-pulse shrink-0" style={{ backgroundColor: sevColor }} />
      <AnimatePresence mode="wait">
        <motion.span
          key={current.id}
          className="text-[11px] font-mono text-[#ece7dc]/80 truncate flex-1"
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -6 }}
          transition={{ duration: 0.25 }}
        >
          <span className="font-bold uppercase text-[10px] mr-2" style={{ color: sevColor }}>
            {current.severity}
          </span>
          {current.title}
        </motion.span>
      </AnimatePresence>
      {emergingFindings.length > 1 && (
        <span className="text-[9px] font-mono text-[#6f7f9a]/50 shrink-0">
          {visibleIdx + 1}/{emergingFindings.length}
        </span>
      )}
      <IconArrowRight size={12} stroke={1.5} className="text-[#6f7f9a]/30 group-hover:text-[#c45c5c]/60 transition-colors shrink-0" />
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Stat cell — compact telemetry readout
// ---------------------------------------------------------------------------

function StatCell({
  label,
  value,
  sub,
  color,
  href,
  pulse,
  delay = 0,
}: {
  label: string;
  value: string | number;
  sub?: string;
  color?: string;
  href?: string;
  pulse?: boolean;
  delay?: number;
}) {
  const content = (
    <motion.div
      className={cn(
        "px-4 py-3 rounded border border-[#1a1d28] bg-[#0a0c12]/80 transition-all duration-150",
        href && "hover:border-[#2d3240] hover:bg-[#0e1018] cursor-pointer group",
      )}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: delay * 0.08, duration: 0.35 }}
    >
      <div className="text-[8px] font-mono text-[#6f7f9a]/50 uppercase tracking-[0.2em] mb-1">
        {label}
      </div>
      <div className="flex items-baseline gap-1.5">
        {pulse && <span className="w-1.5 h-1.5 rounded-full animate-pulse shrink-0" style={{ backgroundColor: color }} />}
        <span
          className="text-lg font-syne font-bold leading-none"
          style={{ color: color || "#ece7dc" }}
        >
          {value}
        </span>
        {sub && (
          <span className="text-[10px] font-mono text-[#6f7f9a]/60">{sub}</span>
        )}
      </div>
    </motion.div>
  );

  if (href) return <Link to={href}>{content}</Link>;
  return content;
}

// ---------------------------------------------------------------------------
// Guard matrix — refined coverage display
// ---------------------------------------------------------------------------

const CATEGORY_LABELS: Record<string, string> = {
  filesystem: "FS",
  network: "NET",
  content: "CONT",
  tools: "TOOL",
  detection: "DET",
  cua: "CUA",
};

function GuardMatrix({
  guards,
  posture,
}: {
  guards: { name: string; shortName: string; enabled: boolean; category: string }[];
  posture: Posture;
}) {
  const config = POSTURE_CONFIG[posture];

  return (
    <div className="grid grid-cols-13 gap-px">
      {guards.map((g, i) => (
        <motion.div
          key={g.shortName}
          className="relative group"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6 + i * 0.04 }}
        >
          <div
            className={cn(
              "w-full aspect-square rounded-sm flex items-center justify-center transition-all duration-300",
              g.enabled
                ? "bg-[#131721] border border-[#2d3240]/60"
                : "bg-[#0a0c12] border border-[#1a1d28]/40",
            )}
            title={`${g.name} — ${g.enabled ? "enabled" : "disabled"}`}
          >
            <div
              className={cn(
                "w-1.5 h-1.5 rounded-full transition-all",
                g.enabled && "animate-[pulse_4s_ease-in-out_infinite]",
              )}
              style={{
                backgroundColor: g.enabled ? config.ringStroke : "#1a1d28",
                boxShadow: g.enabled ? `0 0 4px ${config.color}40` : "none",
              }}
            />
          </div>
          {/* Tooltip */}
          <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1.5 px-2 py-1 rounded bg-[#1a1d28] border border-[#2d3240]/60 text-[9px] font-mono text-[#ece7dc] whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-20">
            {g.name}
            <span className="text-[#6f7f9a] ml-1.5">{CATEGORY_LABELS[g.category]}</span>
          </div>
        </motion.div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Action zone — primary actions
// ---------------------------------------------------------------------------

function ActionCard({
  icon,
  label,
  detail,
  href,
  accentColor,
  badge,
  delay = 0,
}: {
  icon: React.ReactNode;
  label: string;
  detail: string;
  href: string;
  accentColor: string;
  badge?: string | number;
  delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: delay * 0.06 + 0.3, duration: 0.35 }}
    >
      <Link
        to={href}
        className="group flex items-center gap-3 px-4 py-3 rounded border border-[#1a1d28] bg-[#0a0c12]/60 hover:border-[#2d3240] hover:bg-[#0e1018] transition-all duration-150"
      >
        <div
          className="w-8 h-8 rounded flex items-center justify-center shrink-0 transition-colors"
          style={{
            backgroundColor: `${accentColor}10`,
            color: accentColor,
          }}
        >
          {icon}
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs font-syne font-semibold text-[#ece7dc] group-hover:text-white transition-colors truncate">
            {label}
          </div>
          <div className="text-[10px] font-mono text-[#6f7f9a]/60 truncate">
            {detail}
          </div>
        </div>
        {badge !== undefined && badge !== 0 && (
          <span
            className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded-full shrink-0"
            style={{
              backgroundColor: `${accentColor}18`,
              color: accentColor,
            }}
          >
            {badge}
          </span>
        )}
        <IconArrowRight
          size={13}
          stroke={1.5}
          className="text-[#2d3240] group-hover:text-[#6f7f9a] transition-colors shrink-0"
        />
      </Link>
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Quick Start — compact onboarding strip
// ---------------------------------------------------------------------------

function QuickStartStrip({
  fleetConnected,
  sentinelCount,
  findingsCount,
}: {
  fleetConnected: boolean;
  sentinelCount: number;
  findingsCount: number;
}) {
  if (sentinelCount > 0 && findingsCount > 0 && fleetConnected) return null;

  const steps = [
    { label: "Connect Fleet", done: fleetConnected, href: "/settings" },
    { label: "Deploy Sentinel", done: sentinelCount > 0, href: "/sentinels/create" },
    { label: "Review Findings", done: findingsCount > 0, href: "/findings" },
  ];

  return (
    <motion.div
      className="flex items-center gap-2 px-3 py-2 rounded border border-[#d4a84b]/10 bg-[#d4a84b]/[0.02]"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: 1 }}
    >
      <span className="text-[8px] font-mono text-[#d4a84b]/60 uppercase tracking-widest shrink-0">
        Setup
      </span>
      <div className="flex items-center gap-1 flex-1 min-w-0">
        {steps.map((step, i) => (
          <Link
            key={step.label}
            to={step.href}
            className={cn(
              "flex items-center gap-1.5 px-2 py-1 rounded text-[10px] font-mono transition-all",
              step.done
                ? "text-[#3dbf84]/60"
                : "text-[#ece7dc]/60 hover:text-[#d4a84b] hover:bg-[#d4a84b]/[0.05]",
            )}
          >
            {step.done ? (
              <IconCheck size={10} stroke={2.5} className="text-[#3dbf84]/60" />
            ) : (
              <span className="text-[8px] font-bold text-[#d4a84b]/40">{i + 1}</span>
            )}
            <span className={step.done ? "line-through" : ""}>{step.label}</span>
          </Link>
        ))}
      </div>
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Home Page
// ---------------------------------------------------------------------------

export function HomePage() {
  const { state } = useWorkbenchState();
  const { tabs } = usePolicyTabs();
  const { connection } = useFleetConnection();
  const { activePolicy, validation, dirty } = state;

  const { sentinels } = useSentinels();
  const { findings } = useFindings();

  // ---- Guard analysis ----
  const { enabledCount, totalCount, guardList } = useMemo(() => {
    let enabled = 0;
    const list: { name: string; shortName: string; enabled: boolean; category: string }[] = [];

    for (const guard of GUARD_REGISTRY) {
      const cfg = activePolicy.guards[guard.id as GuardId];
      const isEnabled = !!(cfg && "enabled" in cfg && cfg.enabled);
      if (isEnabled) enabled++;
      list.push({
        name: guard.name,
        shortName: guard.id,
        enabled: isEnabled,
        category: guard.category,
      });
    }

    return { enabledCount: enabled, totalCount: GUARD_REGISTRY.length, guardList: list };
  }, [activePolicy]);

  // ---- Sentinel stats ----
  const sentinelStats = useMemo(() => {
    let active = 0, paused = 0;
    for (const s of sentinels) {
      if (s.status === "active") active++;
      else if (s.status === "paused") paused++;
    }
    return { total: sentinels.length, active, paused };
  }, [sentinels]);

  // ---- Findings stats ----
  const findingsStats = useMemo(() => {
    let emerging = 0, confirmed = 0, critical = 0;
    const severityCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      if (f.status === "emerging") emerging++;
      else if (f.status === "confirmed") confirmed++;
      if (f.severity === "critical" && (f.status === "emerging" || f.status === "confirmed")) critical++;
      if ((f.status === "emerging" || f.status === "confirmed") && f.severity in severityCounts) {
        severityCounts[f.severity]++;
      }
    }
    return { emerging, confirmed, critical, total: findings.length, severityCounts };
  }, [findings]);

  // ---- Posture ----
  const posture = derivePosture(
    connection.connected,
    findingsStats.critical,
    findingsStats.emerging,
    enabledCount,
  );

  // ---- Validation ----
  const errorCount = validation.errors.length;
  const validationColor = errorCount > 0 ? "#c45c5c" : "#3dbf84";

  return (
    <div className="h-full w-full flex flex-col bg-[#05060a] overflow-auto page-transition-enter relative">
      <ScanLine posture={posture} />

      <div className="w-full px-8 py-6 flex flex-col gap-6 relative z-10 max-w-6xl">

        {/* ================================================================ */}
        {/* Hero — Posture Core + Policy Identity                           */}
        {/* ================================================================ */}
        <div className="flex flex-col items-center pt-2 pb-2">
          <PostureCore
            posture={posture}
            enabledGuards={enabledCount}
            totalGuards={totalCount}
          />

          {/* Policy identity — below the ring */}
          <motion.div
            className="text-center mt-4"
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4, duration: 0.5 }}
          >
            <h1 className="font-syne text-lg font-bold text-[#ece7dc] tracking-tight">
              {activePolicy.name}
            </h1>
            <div className="flex items-center justify-center gap-2 mt-1 text-[10px] font-mono">
              <span className="text-[#6f7f9a]">v{activePolicy.version}</span>
              <span className="text-[#1a1d28]">/</span>
              <span style={{ color: validationColor }}>
                {errorCount > 0 ? `${errorCount} errors` : "valid"}
              </span>
              {dirty && (
                <>
                  <span className="text-[#1a1d28]">/</span>
                  <span className="text-[#d4a84b]">unsaved</span>
                </>
              )}
            </div>
          </motion.div>
        </div>

        {/* ================================================================ */}
        {/* Threat Ticker — emerging findings scroll                        */}
        {/* ================================================================ */}
        <ThreatTicker findings={findings as Array<{ id: string; title: string; severity: string; status: string }>} />

        {/* ================================================================ */}
        {/* Telemetry strip — key numbers at a glance                       */}
        {/* ================================================================ */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          <StatCell
            label="Sentinels"
            value={sentinelStats.active}
            sub={`/ ${sentinelStats.total}`}
            color={sentinelStats.active > 0 ? "#4ade80" : "#6f7f9a"}
            href="/sentinels"
            delay={0}
          />
          <StatCell
            label="Emerging"
            value={findingsStats.emerging}
            color={findingsStats.emerging > 0 ? "#d4a84b" : "#6f7f9a"}
            pulse={findingsStats.emerging > 0}
            href="/findings"
            delay={1}
          />
          <StatCell
            label="Fleet"
            value={connection.connected ? connection.agentCount : "—"}
            sub={connection.connected ? "agents" : ""}
            color={connection.connected ? "#4ade80" : "#6f7f9a"}
            href="/fleet"
            delay={2}
          />
          <StatCell
            label="Editor"
            value={tabs.length}
            sub={dirty ? "unsaved" : "tabs"}
            color={dirty ? "#d4a84b" : "#6f7f9a"}
            href="/editor"
            delay={3}
          />
        </div>

        {/* ================================================================ */}
        {/* Severity breakdown — horizontal bar                             */}
        {/* ================================================================ */}
        {findingsStats.total > 0 && (
          <motion.div
            className="flex items-center gap-2"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
          >
            <span className="text-[8px] font-mono text-[#6f7f9a]/40 uppercase tracking-widest shrink-0 w-12">
              Threat
            </span>
            <div className="flex-1 flex items-center h-2 rounded-full overflow-hidden bg-[#0e1018] border border-[#1a1d28]">
              {(["critical", "high", "medium", "low"] as const).map((sev) => {
                const count = findingsStats.severityCounts[sev] ?? 0;
                const pct = findingsStats.total > 0 ? (count / findingsStats.total) * 100 : 0;
                if (pct === 0) return null;
                return (
                  <motion.div
                    key={sev}
                    className="h-full"
                    style={{ backgroundColor: SEVERITY_COLORS[sev] }}
                    initial={{ width: 0 }}
                    animate={{ width: `${pct}%` }}
                    transition={{ delay: 0.7, duration: 0.6, ease: "easeOut" }}
                  />
                );
              })}
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {(["critical", "high", "medium", "low"] as const).map((sev) => {
                const count = findingsStats.severityCounts[sev] ?? 0;
                if (count === 0) return null;
                return (
                  <span key={sev} className="flex items-center gap-1">
                    <span className="w-1 h-1 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[sev] }} />
                    <span className="text-[8px] font-mono" style={{ color: SEVERITY_COLORS[sev] }}>{count}</span>
                  </span>
                );
              })}
            </div>
          </motion.div>
        )}

        {/* ================================================================ */}
        {/* Guard matrix — compact visual grid                              */}
        {/* ================================================================ */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6 }}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-[8px] font-mono text-[#6f7f9a]/40 uppercase tracking-[0.2em]">
              Guard Coverage
            </span>
            <Link
              to="/editor"
              className="text-[9px] font-mono text-[#6f7f9a]/30 hover:text-[#d4a84b] transition-colors"
            >
              Configure
            </Link>
          </div>
          <GuardMatrix guards={guardList} posture={posture} />
        </motion.div>

        {/* ================================================================ */}
        {/* Quick start — compact setup strip                               */}
        {/* ================================================================ */}
        <QuickStartStrip
          fleetConnected={connection.connected}
          sentinelCount={sentinelStats.total}
          findingsCount={findingsStats.total}
        />

        {/* ================================================================ */}
        {/* Action zones — curated primary actions                          */}
        {/* ================================================================ */}
        <div>
          <span className="text-[8px] font-mono text-[#6f7f9a]/40 uppercase tracking-[0.2em] mb-2 block">
            Operations
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <ActionCard
              icon={<IconRadar size={16} stroke={1.5} />}
              label="Sentinels"
              detail={`${sentinelStats.active} active · ${sentinelStats.paused} paused`}
              href="/sentinels"
              accentColor="#4ade80"
              badge={sentinelStats.active || undefined}
              delay={0}
            />
            <ActionCard
              icon={<IconAlertTriangle size={16} stroke={1.5} />}
              label="Findings"
              detail={`${findingsStats.emerging} emerging · ${findingsStats.confirmed} confirmed`}
              href="/findings"
              accentColor={findingsStats.critical > 0 ? "#ef4444" : "#d4a84b"}
              badge={findingsStats.emerging || undefined}
              delay={1}
            />
            <ActionCard
              icon={<IconFlask size={16} stroke={1.5} />}
              label="Lab"
              detail="Hunt · Simulate · Replay"
              href="/lab"
              accentColor="#7c9aef"
              delay={2}
            />
            <ActionCard
              icon={<IconPencil size={16} stroke={1.5} />}
              label="Editor"
              detail={`${tabs.length} tab${tabs.length !== 1 ? "s" : ""} open`}
              href="/editor"
              accentColor="#d4a84b"
              badge={dirty ? "!" : undefined}
              delay={3}
            />
            <ActionCard
              icon={<IconServer size={16} stroke={1.5} />}
              label="Fleet"
              detail={connection.connected ? `${connection.agentCount} agents connected` : "Not connected"}
              href="/fleet"
              accentColor={connection.connected ? "#4ade80" : "#6f7f9a"}
              delay={4}
            />
            <ActionCard
              icon={<IconShieldCheck size={16} stroke={1.5} />}
              label="Compliance"
              detail="Framework coverage"
              href="/compliance"
              accentColor="#8b7355"
              delay={5}
            />
            <ActionCard
              icon={<IconGavel size={16} stroke={1.5} />}
              label="Approvals"
              detail={connection.connected ? "Live queue" : "Demo mode"}
              href="/approvals"
              accentColor="#7b6b8b"
              delay={6}
            />
            <ActionCard
              icon={<IconActivity size={16} stroke={1.5} />}
              label="Audit & Receipts"
              detail="Decision trail · Signed attestations"
              href="/audit"
              accentColor="#6b9b8b"
              delay={7}
            />
          </div>
        </div>

        {/* ================================================================ */}
        {/* Claude Code Hint                                                 */}
        {/* ================================================================ */}
        <ClaudeCodeHint hintId="home.audit" />
      </div>
    </div>
  );
}
