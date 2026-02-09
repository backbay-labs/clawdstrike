/**
 * NavRail - ModeRail-style navigation with Nexus orb, strikecell labs, and system status sigil.
 */
import { clsx } from "clsx";
import type { ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import type { AppId } from "../plugins/types";
import { useConnectionStatus } from "@/context/ConnectionContext";
import { dispatchCyberNexusCommand } from "@/features/cyber-nexus/events";
import type { StrikecellDomainId } from "@/features/cyber-nexus/types";
import { CyberNexusOrb } from "./CyberNexusOrb";

interface NavRailProps {
  activeAppId: AppId;
  onSelectApp: (appId: AppId) => void;
}

interface StrikecellNavItem {
  id: StrikecellDomainId;
  label: string;
  icon: StrikecellIcon;
}

type StrikecellIcon =
  | "overview"
  | "threat"
  | "attack"
  | "network"
  | "river"
  | "gateway"
  | "workflows"
  | "marketplace"
  | "events"
  | "policies";

const STRIKECELL_ITEMS: StrikecellNavItem[] = [
  { id: "security-overview", label: "Security Overview", icon: "overview" },
  { id: "threat-radar", label: "Threat Radar", icon: "threat" },
  { id: "attack-graph", label: "Attack Graph", icon: "attack" },
  { id: "network-map", label: "Network Map", icon: "network" },
  { id: "forensics-river", label: "Forensics River", icon: "river" },
  { id: "workflows", label: "Workflows", icon: "workflows" },
  { id: "marketplace", label: "Marketplace", icon: "marketplace" },
  { id: "events", label: "Event Stream", icon: "events" },
  { id: "policies", label: "Policies", icon: "policies" },
];

export function NavRail({ activeAppId, onSelectApp }: NavRailProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const connectionStatus = useConnectionStatus();
  const focusFromUrl = useMemoStrikecellFocus(location);

  return (
    <nav
      className="relative z-20 flex h-full w-[84px] shrink-0 flex-col border-r bg-[linear-gradient(180deg,rgba(9,11,18,0.98)_0%,rgba(4,6,10,0.99)_100%)] px-2 py-3"
      style={{ borderRightColor: "rgba(213, 173, 87, 0.3)" }}
    >
      <div className="nexus-rail-orb-divider flex flex-col items-center pb-2">
        <CyberNexusOrb />
        <div className="nexus-orb-ticks mt-2" aria-hidden="true">
          <span className="nexus-orb-tick nexus-orb-tick--outer" />
          <span className="nexus-orb-tick nexus-orb-tick--inner" />
        </div>
      </div>

      <div className="premium-panel premium-panel--rail mt-2 flex-1 overflow-hidden rounded-[18px] px-2 py-2">
        <div className="origin-label text-center text-[9px] tracking-[0.16em]">Strikecells</div>
        <div className="mt-1 text-center text-[9px] font-mono text-sdr-text-muted">labs</div>
        <div className="mt-2 flex h-[calc(100%-40px)] flex-col items-center gap-2 overflow-y-auto pb-1">
          {STRIKECELL_ITEMS.map((item) => (
            <RailButton
              key={item.id}
              icon={item.icon}
              label={item.label}
              active={focusFromUrl === item.id}
              onClick={() => focusStrikecell(navigate, location.pathname, item.id)}
            />
          ))}
        </div>
      </div>

      <div className="mt-2 flex justify-center">
        <RailButton
          icon="gateway"
          label="OpenClaw Fleet"
          active={activeAppId === "openclaw"}
          onClick={() => onSelectApp("openclaw")}
        />
      </div>

      <div className="mt-3 flex justify-center">
        <RailStatusSigil
          connectionStatus={connectionStatus}
          isSettingsActive={activeAppId === "settings"}
          onOpenSettings={() => onSelectApp("settings")}
        />
      </div>
    </nav>
  );
}

const NEXUS_FOCUS_STORAGE_KEY = "sdr:cyber-nexus:lastFocus";

function useMemoStrikecellFocus(location: { pathname: string; search: string }): StrikecellDomainId | null {
  if (!location.pathname.startsWith("/cyber-nexus")) return null;
  try {
    const params = new URLSearchParams(location.search);
    const fromUrl = params.get("focus") as StrikecellDomainId | null;
    if (fromUrl) return fromUrl;
    const stored = localStorage.getItem(NEXUS_FOCUS_STORAGE_KEY) as StrikecellDomainId | null;
    return stored;
  } catch {
    return null;
  }
}

function focusStrikecell(
  navigate: (path: string) => void,
  pathname: string,
  strikecellId: StrikecellDomainId
) {
  try {
    localStorage.setItem(NEXUS_FOCUS_STORAGE_KEY, strikecellId);
  } catch {
    // Ignore
  }

  if (pathname.startsWith("/cyber-nexus")) {
    dispatchCyberNexusCommand({ type: "focus-strikecell", strikecellId });
    navigate(`/cyber-nexus?focus=${encodeURIComponent(strikecellId)}`);
    return;
  }

  navigate(`/cyber-nexus?focus=${encodeURIComponent(strikecellId)}`);
}

function RailButton({
  icon,
  label,
  active,
  onClick,
}: {
  icon: StrikecellIcon;
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={label}
      aria-label={label}
      data-active={active}
      className="origin-sigil-tile origin-focus-ring"
    >
      <RailIcon icon={icon} />
    </button>
  );
}

function RailIcon({ icon }: { icon: StrikecellIcon }) {
  const paths: Record<StrikecellIcon, ReactNode> = {
    overview: (
      <path
        d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2zM9 22V12h6v10"
        stroke="currentColor"
        strokeWidth="1.8"
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    ),
    threat: (
      <path
        d="M22 12h-4l-3 9L9 3l-3 9H2"
        stroke="currentColor"
        strokeWidth="2"
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    ),
    attack: (
      <path
        d="M4 8h4M16 8h4M8 8a4 4 0 108 0 4 4 0 00-8 0M12 12v4M8 20h8"
        stroke="currentColor"
        strokeWidth="1.8"
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    ),
    network: (
      <>
        <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.8" fill="none" />
        <path d="M3 12h18M12 3v18" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
      </>
    ),
    river: (
      <path
        d="M2 8c2.5-3 5-3 7.5 0s5 3 7.5 0 5-3 7.5 0M2 16c2.5-3 5-3 7.5 0s5 3 7.5 0 5-3 7.5 0"
        stroke="currentColor"
        strokeWidth="1.8"
        fill="none"
        strokeLinecap="round"
      />
    ),
    gateway: (
      <>
        <rect x="3.5" y="5" width="17" height="14" rx="2" stroke="currentColor" strokeWidth="1.8" fill="none" />
        <path d="M7 9h10M7 12h5M7 15h7" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
      </>
    ),
    workflows: (
      <>
        <rect x="5" y="5" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.8" fill="none" />
        <rect x="14" y="5" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.8" fill="none" />
        <rect x="5" y="14" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.8" fill="none" />
        <path d="M10 7h4M7 10v4M16 10v4M10 16h4" stroke="currentColor" strokeWidth="1.8" />
      </>
    ),
    marketplace: (
      <path
        d="M12 2l8 6-8 6-8-6 8-6zm0 12l8 6-8 6-8-6 8-6z"
        stroke="currentColor"
        strokeWidth="1.8"
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    ),
    events: (
      <path
        d="M6 12h.01M12 12h.01M18 12h.01M6 17h12M6 7h12"
        stroke="currentColor"
        strokeWidth="2"
        fill="none"
        strokeLinecap="round"
      />
    ),
    policies: (
      <path
        d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"
        stroke="currentColor"
        strokeWidth="1.8"
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    ),
  };

  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      {paths[icon]}
    </svg>
  );
}

function RailStatusSigil({
  connectionStatus,
  isSettingsActive,
  onOpenSettings,
}: {
  connectionStatus: string;
  isSettingsActive: boolean;
  onOpenSettings: () => void;
}) {
  const label =
    connectionStatus === "connected"
      ? "Live"
      : connectionStatus === "connecting"
        ? "Sync"
        : "Offline";

  return (
    <button
      type="button"
      title="System status"
      aria-label={`System status ${label}`}
      onClick={onOpenSettings}
      data-active={isSettingsActive ? "true" : "false"}
      className="origin-focus-ring origin-status-sigil"
    >
      <span className="origin-status-sigil-core" aria-hidden="true">
        <span
          className={clsx(
            "origin-status-sigil-dot",
            connectionStatus === "connected"
              ? "bg-sdr-accent-green shadow-[0_0_8px_rgba(61,191,132,0.65)]"
              : connectionStatus === "connecting"
                ? "bg-sdr-accent-amber shadow-[0_0_8px_rgba(212,168,75,0.65)]"
                : "bg-sdr-accent-red shadow-[0_0_8px_rgba(196,92,92,0.55)]"
          )}
        />
      </span>
      <span className="origin-status-sigil-label">{label}</span>
    </button>
  );
}
