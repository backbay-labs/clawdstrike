import { useMemo } from "react";
import { useLocation, Link } from "react-router-dom";
import { SigilSettings } from "@/components/desktop/sidebar-icons";
import { SystemHeartbeat } from "@/components/desktop/desktop-sidebar";
import { useOperator } from "@/features/operator/stores/operator-store";
import { useFleetConnection } from "@/features/fleet/use-fleet-connection";
import { useFindings } from "@/features/findings/stores/finding-store";
import { SIGIL_SYMBOLS } from "@/components/workbench/settings/identity-settings";
import type { SigilType } from "@/lib/workbench/sentinel-manager";
import { useActivityBarStore } from "../stores/activity-bar-store";
import { ACTIVITY_BAR_ITEMS } from "../types";
import { ActivityBarItem } from "./activity-bar-item";
import { PresenceActivityPills } from "@/features/presence/components/presence-activity-pills";
import { cn } from "@/lib/utils";
import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";
import { useSpiritStore } from "@/features/spirit/stores/spirit-store";

// ---------------------------------------------------------------------------
// ActivityBar -- 48px vertical icon rail, far-left of the layout.
// ---------------------------------------------------------------------------

export function ActivityBar() {
  const activeItem = useActivityBarStore.use.activeItem();
  const actions = useActivityBarStore.use.actions();
  const { pathname } = useLocation();
  const { currentOperator } = useOperator();
  const { connection } = useFleetConnection();
  const fleetConnected = connection.connected;
  const { findings } = useFindings();
  const seamSummary = useObservatoryStore.use.seamSummary();
  const huntArtifactCount = seamSummary.artifactCount;
  const accentColor = useSpiritStore.use.accentColor();

  const emergingFindingsCount = useMemo(
    () => findings.filter((f) => f.status === "emerging").length,
    [findings],
  );

  const settingsActive =
    pathname === "/settings" || pathname.startsWith("/settings/");
  const heartbeatActive =
    pathname === "/home" || pathname === "/";

  return (
    <div
      role="toolbar"
      aria-label="Activity Bar"
      aria-orientation="vertical"
      className="w-[48px] shrink-0 flex flex-col bg-[#05060a] border-r border-[#1a1d28]/50 noise-overlay"
    >
      {/* SystemHeartbeat diamond (28px) */}
      <div className="pt-1 flex justify-center">
        <button
          type="button"
          role="tab"
          aria-selected={activeItem === "heartbeat"}
          aria-controls="sidebar-panel"
          id="activity-bar-tab-heartbeat"
          title="System Status"
          onClick={() => actions.toggleItem("heartbeat")}
          className="relative flex items-center justify-center"
        >
          {activeItem === "heartbeat" && (
            <span
              className="absolute left-0 rounded-r-full"
              style={{
                top: 8,
                bottom: 8,
                width: 2,
                backgroundColor: "#d4a84b",
                boxShadow: "0 0 8px rgba(212,168,75,0.3)",
              }}
            />
          )}
          <SystemHeartbeat
            collapsed={true}
            active={heartbeatActive}
            fleetOnline={fleetConnected}
            pendingApprovals={0}
            emergingFindingsCount={emergingFindingsCount}
          />
        </button>
      </div>

      {/* Gold gradient divider */}
      <div
        className="mx-3 mt-1.5 mb-0.5 h-px"
        style={{
          background:
            "linear-gradient(to right, rgba(212,168,75,0.12), transparent 60%)",
        }}
      />

      {/* Icon group (top) */}
      <div className="flex flex-col items-center gap-1 mt-1">
        {ACTIVITY_BAR_ITEMS.map((item) => (
          <ActivityBarItem
            key={item.id}
            id={item.id}
            icon={item.icon}
            tooltip={item.tooltip}
            active={item.id === activeItem}
            onClick={() => actions.toggleItem(item.id)}
            badge={item.id === "hunt" ? huntArtifactCount : undefined}
            orbColor={item.id === "hunt" ? (accentColor ?? undefined) : undefined}
          />
        ))}
      </div>

      {/* Analyst presence pills */}
      <div
        className="mx-3 mt-1 mb-0.5 h-px"
        style={{
          background:
            "linear-gradient(to right, rgba(111,127,154,0.12), transparent 60%)",
        }}
      />
      <PresenceActivityPills />

      {/* Flexible spacer */}
      <div className="flex-1" />

      {/* Settings icon (bottom) */}
      <div className="flex flex-col items-center">
        <Link
          to="/settings"
          role="tab"
          aria-selected={settingsActive}
          title="Settings"
          className={cn(
            "w-9 h-9 flex items-center justify-center relative",
            "transition-colors duration-150 ease-in-out",
            settingsActive
              ? "text-[#d4a84b] bg-[#131721]/60"
              : "text-[#6f7f9a] hover:text-[#ece7dc]/80",
          )}
        >
          {settingsActive && (
            <span
              className="absolute left-0 rounded-r-full"
              style={{
                top: 8,
                bottom: 8,
                width: 2,
                backgroundColor: "#d4a84b",
                boxShadow: "0 0 8px rgba(212,168,75,0.3)",
              }}
            />
          )}
          <SigilSettings
            size={18}
            stroke={1.4}
            style={
              settingsActive
                ? { filter: "drop-shadow(0 0 4px rgba(212,168,75,0.25))" }
                : undefined
            }
          />
        </Link>
      </div>

      {/* Operator identity sigil (16px) */}
      {currentOperator && (
        <div
          className="flex items-center justify-center border-t border-[#2d3240]/50 py-2"
          title={
            currentOperator.displayName || currentOperator.fingerprint
          }
        >
          <span className="text-sm text-[#6f7f9a] select-none">
            {SIGIL_SYMBOLS[currentOperator.sigil as SigilType] ??
              currentOperator.sigil}
          </span>
        </div>
      )}
    </div>
  );
}
