import { useDesktopOS } from "@backbay/glia-desktop";
import { useCallback } from "react";
import type { ConsoleStatus } from "../../../hooks/useConsoleStatus";
import {
  SIDEBAR_COLLAPSED_WIDTH,
  SIDEBAR_EXPANDED_WIDTH,
} from "../../../state/useShellPreferences";
import { StatusPulse } from "../StatusPulse";
import { NavRowButton } from "./NavItem";
import { SidebarHeader } from "./SidebarHeader";
import { SidebarSearch } from "./SidebarSearch";
import { useNavApps } from "./useNavApps";

export interface SidebarExpandedProps {
  onCmdK: () => void;
  /** Flip the collapsed flag (drives the width morph + label fade). */
  onToggleCollapse: () => void;
  status: ConsoleStatus;
  /** When true, the sidebar morphs down to a rail-like icon-only column. */
  collapsed?: boolean;
  /** Keyboard shortcut hint surfaced on the collapse/expand toggle. */
  toggleShortcut?: string;
}

const MORPH = "cubic-bezier(0.22,1,0.36,1)";

/**
 * Collapse-aware labeled sidebar. Animates its own width between the full
 * 248px and a rail-like 64px while labels fade + clip, so the open/close
 * transition morphs in place rather than hot-swapping to a separate component.
 * The collapsed state reads like the icon rail (centered icons + tooltips).
 */
export function SidebarExpanded({
  onCmdK,
  onToggleCollapse,
  status,
  collapsed = false,
  toggleShortcut,
}: SidebarExpandedProps) {
  const { processes } = useDesktopOS();
  const groups = useNavApps();

  const launch = useCallback((processId: string) => processes.launch(processId), [processes]);

  return (
    <nav
      aria-label="Primary navigation"
      className="cs-animated"
      style={{
        width: collapsed ? SIDEBAR_COLLAPSED_WIDTH : SIDEBAR_EXPANDED_WIDTH,
        flexShrink: 0,
        height: "100%",
        // Subtly lighten the glass when collapsed to match the standalone rail.
        background: collapsed
          ? "linear-gradient(180deg, rgba(11,13,16,0.96), rgba(7,8,10,0.96))"
          : "linear-gradient(180deg, rgba(11,13,16,0.97), rgba(7,8,10,0.97))",
        borderRight: "1px solid rgba(27,34,48,0.6)",
        display: "flex",
        flexDirection: "column",
        boxShadow: "inset -1px 0 0 rgba(214,177,90,0.05), 4px 0 32px rgba(0,0,0,0.5)",
        overflow: "hidden",
        transition: `width 0.22s ${MORPH}`,
      }}
    >
      <SidebarHeader
        collapsed={collapsed}
        onToggle={onToggleCollapse}
        toggleShortcut={toggleShortcut}
        version={status.build}
      />
      <SidebarSearch onCmdK={onCmdK} collapsed={collapsed} />

      <div
        style={{
          flex: 1,
          overflow: "hidden auto",
          padding: collapsed ? "4px 8px 10px" : "4px 10px 10px",
        }}
      >
        {groups.map((group) => (
          <div key={group.id} style={{ marginBottom: 12 }}>
            {/*
             * Group heading collapses to a thin centered divider when narrow —
             * the uppercase label has no room at 64px, so we morph between the
             * two cleanly (rail uses the same divider treatment).
             */}
            <div
              className="font-mono cs-animated"
              aria-hidden={collapsed || undefined}
              style={{
                padding: collapsed ? "8px 0 4px" : "8px 12px 4px",
                fontSize: 9.5,
                letterSpacing: "0.18em",
                textTransform: "uppercase",
                color: "rgba(154,167,181,0.42)",
                whiteSpace: "nowrap",
                overflow: "hidden",
                height: collapsed ? 9 : undefined,
                opacity: collapsed ? 0 : 1,
                transition: `opacity 0.16s ${MORPH}`,
              }}
            >
              {collapsed ? (
                <span
                  aria-hidden="true"
                  style={{
                    display: "block",
                    height: 1,
                    background: "rgba(27,34,48,0.6)",
                    margin: "4px 6px 0",
                    opacity: 1,
                  }}
                />
              ) : (
                group.label
              )}
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
              {group.apps.map((app) => (
                <NavRowButton
                  key={app.processId}
                  label={app.label}
                  Sigil={app.Sigil}
                  tone={app.tone}
                  active={app.active}
                  running={app.running}
                  onClick={() => launch(app.processId)}
                  collapsed={collapsed}
                />
              ))}
            </div>
          </div>
        ))}
      </div>

      <SidebarFooter status={status} collapsed={collapsed} />
    </nav>
  );
}

/**
 * System-pulse footer. Expanded: a 2×2 grid of labeled cards. Collapsed: the
 * cards fade out and a compact SSE + violations dot row takes their place so
 * live state (load-bearing in an EDR console) stays visible at 64px.
 */
function SidebarFooter({ status, collapsed }: { status: ConsoleStatus; collapsed: boolean }) {
  return (
    <div
      style={{
        position: "relative",
        padding: collapsed ? "8px 8px" : "10px 12px",
        borderTop: "1px solid rgba(27,34,48,0.6)",
      }}
    >
      {/* Expanded cards — present in the DOM so they can fade, removed from flow when collapsed. */}
      <div
        className="cs-animated"
        aria-hidden={collapsed || undefined}
        style={{
          display: collapsed ? "none" : "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 6,
          opacity: collapsed ? 0 : 1,
          transition: `opacity 0.16s ${MORPH}`,
        }}
      >
        <StatusPulse
          label="SSE"
          value={status.sseLive ? "● LIVE" : "◌ DOWN"}
          tone={status.sseLive ? "teal" : "crimson"}
          dense
        />
        <StatusPulse
          label="Violations"
          value={String(status.violations)}
          tone={status.violations > 0 ? "crimson" : "gold"}
          mono
          dense
        />
        <StatusPulse label="Uptime" value={status.uptime} tone="gold" mono dense />
        <StatusPulse label="Build" value={status.build} tone="gold" mono dense />
      </div>

      {/* Collapsed compact pulse: SSE dot + violations count. */}
      {collapsed && (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 8,
          }}
        >
          <span
            data-testid="sidebar-collapsed-sse"
            aria-label={status.sseLive ? "SSE live" : "SSE down"}
            title={status.sseLive ? "SSE LIVE" : "SSE DOWN"}
            className="cs-animated"
            style={{
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: status.sseLive ? "var(--teal)" : "var(--crimson)",
              boxShadow: status.sseLive ? "0 0 8px var(--teal)" : "0 0 8px var(--crimson)",
            }}
          />
          <span
            className="font-mono"
            data-testid="sidebar-collapsed-violations"
            title={`${status.violations} violations`}
            style={{
              fontSize: 11,
              fontWeight: 500,
              letterSpacing: "0.04em",
              color: status.violations > 0 ? "var(--crimson)" : "rgba(154,167,181,0.6)",
              fontFeatureSettings: '"tnum"',
            }}
          >
            {status.violations}
          </span>
        </div>
      )}
    </div>
  );
}
