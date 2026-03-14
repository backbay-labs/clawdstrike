import { useMemo, useState, useEffect, useRef, useId } from "react";
import { useLocation, Link } from "react-router-dom";
import {
  IconChevronsLeft,
  IconChevronsRight,
} from "@tabler/icons-react";
import {
  SigilSentinel,
  SigilFindings,
  SigilMission,
  SigilLab,
  SigilSwarms,
  SigilEditor,
  SigilLibrary,
  SigilCompliance,
  SigilApprovals,
  SigilAudit,
  SigilReceipts,
  SigilFleet,
  SigilTopology,
  SigilSettings,
  type SigilProps,
} from "./sidebar-icons";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { useOperator } from "@/lib/workbench/operator-store";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import { useSentinels } from "@/lib/workbench/sentinel-store";
import { useFindings } from "@/lib/workbench/finding-store";
import { cn } from "@/lib/utils";
import { SIGIL_SYMBOLS } from "@/components/workbench/settings/identity-settings";
import { fleetClient } from "@/lib/workbench/fleet-client";
import { DEMO_APPROVAL_REQUESTS } from "@/lib/workbench/approval-demo-data";

interface NavItem {
  readonly label: string;
  readonly icon: React.ComponentType<SigilProps>;
  readonly href: string;
  readonly badge?: boolean;
}

interface NavSection {
  readonly title: string;
  readonly accent: string; // muted tint for left bar + header text
  readonly items: readonly NavItem[];
}

const navSections: readonly NavSection[] = [
  {
    title: "Detect & Respond",
    accent: "#8b5555",
    items: [
      { label: "Sentinels", icon: SigilSentinel, href: "/sentinels" },
      { label: "Mission Control", icon: SigilMission, href: "/missions" },
      { label: "Findings & Intel", icon: SigilFindings, href: "/findings", badge: true },
      { label: "Lab", icon: SigilLab, href: "/lab" },
      { label: "Swarms", icon: SigilSwarms, href: "/swarms" },
    ],
  },
  {
    title: "Author & Test",
    accent: "#8b7355",
    items: [
      { label: "Editor", icon: SigilEditor, href: "/editor" },
      { label: "Library", icon: SigilLibrary, href: "/library" },
    ],
  },
  {
    title: "Platform",
    accent: "#7b6b8b",
    items: [
      { label: "Compliance", icon: SigilCompliance, href: "/compliance" },
      { label: "Approvals", icon: SigilApprovals, href: "/approvals", badge: true },
      { label: "Audit", icon: SigilAudit, href: "/audit" },
      { label: "Receipts", icon: SigilReceipts, href: "/receipts" },
      { label: "Fleet", icon: SigilFleet, href: "/fleet" },
      { label: "Topology", icon: SigilTopology, href: "/topology" },
    ],
  },
] as const;

type SystemPosture = "nominal" | "attention" | "critical" | "offline";

function derivePosture(
  activeSentinels: number,
  emergingFindings: number,
  criticalFindings: number,
  fleetOnline: boolean,
): SystemPosture {
  if (!fleetOnline && activeSentinels === 0) return "offline";
  if (criticalFindings > 0) return "critical";
  if (emergingFindings > 0) return "attention";
  return "nominal";
}

const POSTURE_RING: Record<SystemPosture, { color: string; glow: string; label: string }> = {
  nominal:   { color: "#4ade80", glow: "rgba(74,222,128,0.12)", label: "all clear" },
  attention: { color: "#d4a84b", glow: "rgba(212,168,75,0.15)", label: "attention" },
  critical:  { color: "#ef4444", glow: "rgba(239,68,68,0.18)",  label: "critical" },
  offline:   { color: "#6f7f9a", glow: "rgba(111,127,154,0.06)", label: "offline" },
};

const POSTURE_BREATH: Record<SystemPosture, number> = {
  nominal: 5000,
  attention: 2800,
  critical: 1600,
  offline: 0,
};

function SystemHeartbeat({
  collapsed,
  active,
  fleetOnline,
  pendingApprovals,
  emergingFindingsCount,
}: {
  collapsed: boolean;
  active: boolean;
  fleetOnline: boolean;
  pendingApprovals: number;
  emergingFindingsCount?: number;
}) {
  const uid = useId();
  const glowId = `hb-glow${uid}`;
  const sweepId = `hb-sweep${uid}`;
  const domeId = `hb-dome${uid}`;
  const glowUrl = `url(#${glowId})`;
  const sweepUrl = `url(#${sweepId})`;
  const domeUrl = `url(#${domeId})`;

  const { sentinels } = useSentinels();
    const findingsStore = useFindings();
  const findings = findingsStore.findings;

  const activeSentinels = sentinels.filter((s) => s.status === "active").length;
  const emergingFindings = emergingFindingsCount ?? findings.filter((f) => f.status === "emerging").length;
  const criticalFindings = findings.filter(
    (f) => f.status === "emerging" && f.severity === "critical",
  ).length;

  const posture = derivePosture(activeSentinels, emergingFindings, criticalFindings, fleetOnline);
  const ring = POSTURE_RING[posture];
  const breathMs = POSTURE_BREATH[posture];

    const segColors = [
    activeSentinels > 0 ? "#4ade80" : "#2d3240",                                      // sentinels
    criticalFindings > 0 ? "#ef4444" : emergingFindings > 0 ? "#d4a84b" : "#2d3240",  // findings
    pendingApprovals > 0 ? "#7c9aef" : "#2d3240",                                      // approvals
    fleetOnline ? "#4ade80" : "#ef4444",                                                // fleet
  ];

    const sweepSec = posture === "critical" ? 2 : posture === "attention" ? 4 : posture === "nominal" ? 8 : 0;

  const size = collapsed ? 28 : 36;

    const SR = 36;
  const CIRC = 2 * Math.PI * SR;
  const GAP = 8;
  const SEG = (CIRC - 4 * GAP) / 4;
  const STEP = SEG + GAP;
  const SWEEP_ARC = CIRC * 0.12;

  const anim = (name: string, delay?: string) =>
    breathMs > 0
      ? `${name} ${breathMs}ms ease-in-out ${delay ?? "0ms"} infinite`
      : "none";

  const tooltipLines = [
    `${activeSentinels} sentinel${activeSentinels !== 1 ? "s" : ""} active`,
    `${emergingFindings} emerging finding${emergingFindings !== 1 ? "s" : ""}`,
    `${pendingApprovals} pending approval${pendingApprovals !== 1 ? "s" : ""}`,
    `fleet ${fleetOnline ? "connected" : "offline"}`,
    `— ${ring.label} —`,
  ].join("\n");

  const sigil = (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      overflow="visible"
      aria-hidden="true"
      className="shrink-0"
      style={{ filter: `drop-shadow(0 0 8px ${ring.glow})` }}
    >
      <defs>
        <filter id={glowId} x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3" />
        </filter>
        <filter id={sweepId} x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="2.5" />
        </filter>
        <radialGradient id={domeId}>
          <stop offset="0%" stopColor="rgba(255,255,255,0.015)" />
          <stop offset="100%" stopColor="transparent" />
        </radialGradient>
      </defs>

            <circle
        cx={50} cy={50} r={46}
        fill="none"
        stroke={ring.color}
        strokeWidth={1.5}
        opacity={0.1}
        style={{ filter: glowUrl, animation: anim("hb-glow") }}
      />

            <circle
        cx={50} cy={50} r={44}
        fill="none"
        stroke={ring.color}
        strokeWidth={1}
        opacity={0.3}
        style={{ transformOrigin: "50px 50px", animation: anim("hb-ring") }}
      />

            <circle cx={50} cy={50} r={43} fill={domeUrl} />

            <g stroke={ring.color} strokeWidth={1.2} opacity={0.2}>
        <line x1={50} y1={2} x2={50} y2={7} />
        <line x1={98} y1={50} x2={93} y2={50} />
        <line x1={50} y1={98} x2={50} y2={93} />
        <line x1={2} y1={50} x2={7} y2={50} />
      </g>

            <g style={{ transform: "rotate(-90deg)", transformOrigin: "50px 50px" }}>
        {segColors.map((color, i) => (
          <circle
            key={i}
            cx={50} cy={50} r={SR}
            fill="none"
            stroke={color}
            strokeWidth={2.5}
            strokeLinecap="round"
            strokeDasharray={`${SEG} ${CIRC - SEG}`}
            strokeDashoffset={-i * STEP}
            opacity={color === "#2d3240" ? 0.15 : 0.65}
            style={{
              animation: color !== "#2d3240" ? anim("hb-seg") : "none",
              transition: "stroke 0.6s ease, opacity 0.6s ease",
            }}
          />
        ))}
      </g>

            {sweepSec > 0 && (
        <circle
          cx={50} cy={50} r={SR}
          fill="none"
          stroke={ring.color}
          strokeWidth={3.5}
          strokeLinecap="round"
          strokeDasharray={`${SWEEP_ARC} ${CIRC - SWEEP_ARC}`}
          opacity={0.35}
          style={{
            filter: sweepUrl,
            transformOrigin: "50px 50px",
            animation: `hb-sweep ${sweepSec}s linear infinite`,
          }}
        />
      )}

            <path
        d="M50 28 L68 50 L50 72 L32 50Z"
        fill={ring.color}
        opacity={0.06}
        style={{ filter: glowUrl }}
      />

            <path
        d="M50 28 L68 50 L50 72 L32 50Z"
        fill="none"
        stroke={ring.color}
        strokeWidth={1.5}
        strokeLinejoin="round"
        opacity={0.75}
        style={{ animation: anim("hb-diamond") }}
      />

            <g stroke={ring.color} strokeWidth={0.6} opacity={0.25} style={{ animation: anim("hb-facets") }}>
        <line x1={32} y1={50} x2={68} y2={50} />
        <line x1={50} y1={28} x2={41} y2={50} />
        <line x1={50} y1={28} x2={59} y2={50} />
        <line x1={50} y1={72} x2={41} y2={50} />
        <line x1={50} y1={72} x2={59} y2={50} />
      </g>

            <path
        d="M50 39 L56 50 L50 61 L44 50Z"
        fill={ring.color}
        opacity={0.1}
        style={{ animation: anim("hb-core", "150ms") }}
      />
    </svg>
  );

  const fleetChar = fleetOnline ? "○" : "●";

  return (
    <Link
      to="/home"
      title={tooltipLines}
      className={cn(
        "transition-all duration-200 group",
        collapsed
          ? cn(
              "flex flex-col items-center gap-1 mx-auto pt-1 pb-2",
              !active && "opacity-70 hover:opacity-100",
            )
          : cn(
              "flex items-center gap-3 mx-2 px-3 py-2 rounded-lg",
              active
                ? "bg-[#131721] shadow-[0_0_8px_rgba(212,168,75,0.08)]"
                : "hover:bg-[#131721]/40",
            ),
      )}
    >
      {sigil}
      {!collapsed && (
        <div className="flex flex-col min-w-0">
          <span className="text-[9px] font-mono tracking-[0.08em] text-[#6f7f9a]/70 group-hover:text-[#6f7f9a] transition-colors duration-200 tabular-nums select-none">
            <span className={cn(activeSentinels > 0 && "text-[#4ade80]/60")}>
              {activeSentinels}s
            </span>
            <span className="mx-[3px] text-[#2d3240]">·</span>
            <span className={cn(
              emergingFindings > 0 && "text-[#d4a84b]/70",
              posture === "critical" && "text-[#ef4444]/70",
            )}>
              {emergingFindings}f
            </span>
            <span className="mx-[3px] text-[#2d3240]">·</span>
            <span className={cn(pendingApprovals > 0 && "text-[#7c9aef]/60")}>
              {pendingApprovals}a
            </span>
            <span className="mx-[3px] text-[#2d3240]">·</span>
            <span className={cn(!fleetOnline && "text-[#ef4444]/40")}>
              {fleetChar}
            </span>
          </span>
        </div>
      )}
    </Link>
  );
}

export function DesktopSidebar() {
  const pathname = useLocation().pathname;
  const { state, dispatch } = useWorkbench();
  const collapsed = state.ui.sidebarCollapsed;
  const { currentOperator } = useOperator();
  const { connection } = useFleetConnection();
  const fleetConnected = connection.connected;
  const approvalsConnected = fleetConnected && connection.controlApiUrl.trim().length > 0;

  const [liveApprovalCount, setLiveApprovalCount] = useState<number | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = null;

    if (!approvalsConnected) {
      setLiveApprovalCount(null);
      return;
    }

    const fetchCount = async () => {
      try {
        const result = await fleetClient.fetchApprovals();
        if (result) {
          setLiveApprovalCount(result.requests.filter((r) => r.status === "pending").length);
        }
      } catch { /* stale count is acceptable */ }
    };

    fetchCount();
    pollRef.current = setInterval(fetchCount, 30_000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [approvalsConnected]);

  const isLiveBadge = approvalsConnected && liveApprovalCount !== null;
  const demoPendingCount = useMemo(
    () => DEMO_APPROVAL_REQUESTS.filter((r) => r.status === "pending").length,
    [],
  );
  const pendingApprovalCount = isLiveBadge
    ? liveApprovalCount
    : demoPendingCount;

  const { findings } = useFindings();
  const emergingFindingsCount = findings.filter((f) => f.status === "emerging").length;

  const getBadgeCount = (item: NavItem): number => {
    if (!item.badge) return 0;
    if (item.href === "/findings") return emergingFindingsCount;
    if (item.href === "/approvals") return pendingApprovalCount;
    return 0;
  };

  const isBadgeLive = (item: NavItem): boolean => {
    if (item.href === "/approvals") return isLiveBadge;
        return false;
  };

  const settingsActive = pathname === "/settings" || pathname.startsWith("/settings/");

  return (
    <aside
      aria-label="Main navigation"
      className={cn(
        "flex flex-col bg-[#0b0d13] border-r border-[#2d324060] shrink-0 h-full",
        "transition-[width] duration-300 ease-[cubic-bezier(0.4,0,0.2,1)]",
        collapsed ? "w-[52px]" : "w-[200px]",
      )}
    >
      <nav className="flex-1 py-3 flex flex-col overflow-y-auto">
        <SystemHeartbeat
          collapsed={collapsed}
          active={pathname === "/home" || pathname === "/"}
          fleetOnline={fleetConnected}
          pendingApprovals={pendingApprovalCount}
          emergingFindingsCount={emergingFindingsCount}
        />

                <div
          className="mx-3 mt-1.5 mb-0.5 h-px"
          style={{ background: "linear-gradient(to right, rgba(212,168,75,0.12), transparent 60%)" }}
        />

        {navSections.map((section, idx) => (
          <div key={section.title} className={cn("flex flex-col gap-px", idx === 0 ? "mt-2" : "mt-3")}>
                        {collapsed ? (
              <div
                className="mx-2 my-1.5 h-px"
                style={{ background: `linear-gradient(to right, ${section.accent}30, transparent 70%)` }}
              />
            ) : (
              <div className="flex items-center gap-2 mx-3 mb-1.5">
                <span
                  className="w-[2px] h-2.5 rounded-full shrink-0"
                  style={{
                    backgroundColor: section.accent,
                    boxShadow: `0 0 6px ${section.accent}40`,
                  }}
                />
                <span
                  className="text-[8px] font-semibold uppercase tracking-[0.14em] select-none whitespace-nowrap"
                  style={{ color: section.accent }}
                >
                  {section.title}
                </span>
                <span
                  className="h-px flex-1"
                  style={{ background: `linear-gradient(to right, ${section.accent}25, transparent)` }}
                />
              </div>
            )}

            {section.items.map((item) => {
              const active = pathname === item.href || pathname.startsWith(item.href + "/");
              const Icon = item.icon;
              const badgeCount = getBadgeCount(item);
              const showBadge = badgeCount > 0;
              const badgeLive = isBadgeLive(item);
              const tooltip = collapsed
                ? `${section.title}: ${item.label}`
                : undefined;

              return (
                <Link
                  key={item.href}
                  to={item.href}
                  title={tooltip}
                  className={cn(
                    "sidebar-link relative flex items-center gap-2.5 mx-2 rounded-lg",
                    "transition-all duration-150",
                    collapsed ? "justify-center px-0 py-1.5" : "px-3 py-[7px]",
                    active
                      ? "text-[#ece7dc]"
                      : "text-[#6f7f9a] hover:text-[#ece7dc]/80 hover:bg-[#131721]/30 hover:translate-x-px",
                  )}
                  style={active ? {
                    background: "linear-gradient(to right, rgba(19,23,33,0.9), rgba(19,23,33,0.3))",
                  } : undefined}
                >
                  {active && (
                    <span
                      className="sidebar-accent-bar absolute left-0 top-1.5 bottom-1.5 w-[2px] rounded-r-full bg-[#d4a84b]"
                      style={{ boxShadow: "0 0 8px rgba(212,168,75,0.3)" }}
                    />
                  )}
                  <span className="relative shrink-0">
                    <Icon
                      size={15}
                      stroke={1.4}
                      className={cn(
                        "transition-all duration-150",
                        active ? "text-[#d4a84b]" : "",
                      )}
                      style={active ? { filter: "drop-shadow(0 0 4px rgba(212,168,75,0.25))" } : undefined}
                    />
                    {showBadge && collapsed && (
                      <span
                        className={cn(
                          "absolute -right-1 -top-1 h-1.5 w-1.5 rounded-full animate-pulse",
                          badgeLive ? "bg-[#d4a84b]" : "bg-[#6f7f9a]",
                        )}
                      />
                    )}
                  </span>
                  {!collapsed && (
                    <>
                      <span className="text-[11.5px] font-medium tracking-[0.01em] truncate">
                        {item.label}
                      </span>
                      {showBadge && (
                        <span
                          className={cn(
                            "ml-auto flex h-[15px] min-w-[15px] items-center justify-center rounded-full px-1",
                            "text-[8px] font-mono font-medium tabular-nums border",
                            badgeLive
                              ? "border-[#d4a84b]/30 text-[#d4a84b]/70"
                              : "border-[#6f7f9a]/20 text-[#6f7f9a]/50",
                          )}
                        >
                          {badgeCount}
                        </span>
                      )}
                    </>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      <div className="shrink-0 px-2 pb-1">
        <Link
          to="/settings"
          title={collapsed ? "Settings" : undefined}
          className={cn(
            "sidebar-link relative flex items-center gap-2.5 rounded-lg",
            "transition-all duration-150",
            collapsed ? "justify-center px-0 py-1.5" : "px-3 py-[7px]",
            settingsActive
              ? "text-[#ece7dc]"
              : "text-[#6f7f9a] hover:text-[#ece7dc]/80 hover:bg-[#131721]/30 hover:translate-x-px",
          )}
          style={settingsActive ? {
            background: "linear-gradient(to right, rgba(19,23,33,0.9), rgba(19,23,33,0.3))",
          } : undefined}
        >
          {settingsActive && (
            <span
              className="sidebar-accent-bar absolute left-0 top-1.5 bottom-1.5 w-[2px] rounded-r-full bg-[#d4a84b]"
              style={{ boxShadow: "0 0 8px rgba(212,168,75,0.3)" }}
            />
          )}
          <SigilSettings
            size={15}
            stroke={1.4}
            className={cn(
              "shrink-0 transition-all duration-150",
              settingsActive ? "text-[#d4a84b]" : "",
            )}
            style={settingsActive ? { filter: "drop-shadow(0 0 4px rgba(212,168,75,0.25))" } : undefined}
          />
          {!collapsed && (
            <span className="text-[11.5px] font-medium tracking-[0.01em] truncate">
              Settings
            </span>
          )}
        </Link>
      </div>

      {currentOperator && (
        <div
          className={cn(
            "shrink-0 flex items-center text-[11px] text-[#6f7f9a] border-t border-[#2d324060]/50",
            collapsed ? "justify-center px-1 py-2" : "gap-2 px-3 py-2",
          )}
          title={currentOperator.displayName || currentOperator.fingerprint}
        >
          <span className="text-sm shrink-0">{SIGIL_SYMBOLS[currentOperator.sigil as keyof typeof SIGIL_SYMBOLS] ?? currentOperator.sigil}</span>
          {!collapsed && (
            <span className="truncate text-[11px]">
              {currentOperator.displayName || currentOperator.fingerprint.slice(0, 8)}
            </span>
          )}
        </div>
      )}

      <div className="shrink-0 border-t border-[#2d324060]/50 p-2">
        <button
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          onClick={() =>
            dispatch({ type: "SET_SIDEBAR_COLLAPSED", collapsed: !collapsed })
          }
          className={cn(
            "flex items-center justify-center w-full rounded-lg py-1.5 text-[#6f7f9a]/60 hover:text-[#6f7f9a] hover:bg-[#131721]/20 transition-all duration-150",
            collapsed ? "px-0" : "gap-1.5 px-2",
          )}
        >
          {collapsed ? (
            <IconChevronsRight size={13} stroke={1.4} />
          ) : (
            <>
              <IconChevronsLeft size={13} stroke={1.4} />
              <span className="text-[10px] font-medium tracking-[0.02em] uppercase">Collapse</span>
            </>
          )}
        </button>
      </div>
    </aside>
  );
}
