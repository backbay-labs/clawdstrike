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
import { SidebarRailBody } from "./SidebarRailBody";
import { SidebarSearch } from "./SidebarSearch";
import { useNavApps } from "./useNavApps";

export interface SidebarExpandedProps {
  onCmdK: () => void;
  /** Flip the collapsed flag (drives the width morph + crossfade). */
  onToggleCollapse: () => void;
  status: ConsoleStatus;
  /** When true, the sidebar morphs down to the rail-like icon-only column. */
  collapsed?: boolean;
  /** Keyboard shortcut hint surfaced on the collapse/expand toggle. */
  toggleShortcut?: string;
}

const MORPH = "cubic-bezier(0.22,1,0.36,1)";

/**
 * Collapse-aware labeled sidebar. The nav animates its own width between the
 * full 248px and a rail-like 64px; the labeled rows and the polished icon rail
 * are kept as two stacked layers that crossfade, so the open/close transition
 * morphs in place rather than hot-swapping to a separate component. The
 * collapsed state renders the SAME {@link SidebarRailBody} as the standalone
 * rail variant, so it reads visually identical (gold active treatment, hairline
 * dividers, Settings footer, tooltips).
 */
export function SidebarExpanded({
  onCmdK,
  onToggleCollapse,
  status,
  collapsed = false,
  toggleShortcut,
}: SidebarExpandedProps) {
  return (
    <nav
      aria-label="Primary navigation"
      className="cs-animated"
      style={{
        position: "relative",
        width: collapsed ? SIDEBAR_COLLAPSED_WIDTH : SIDEBAR_EXPANDED_WIDTH,
        flexShrink: 0,
        height: "100%",
        // The glass subtly lightens when collapsed to match the standalone rail.
        background: collapsed
          ? "linear-gradient(180deg, rgba(11,13,16,0.96), rgba(7,8,10,0.96))"
          : "linear-gradient(180deg, rgba(11,13,16,0.97), rgba(7,8,10,0.97))",
        borderRight: "1px solid rgba(27,34,48,0.6)",
        boxShadow: "inset -1px 0 0 rgba(214,177,90,0.05), 4px 0 32px rgba(0,0,0,0.5)",
        overflow: "hidden",
        transition: `width 0.22s ${MORPH}, background 0.22s ${MORPH}`,
      }}
    >
      {/* Expanded layer — labeled rows, search, 2×2 footer. */}
      <Layer visible={!collapsed} testId="sidebar-layer-expanded">
        <ExpandedBody
          onCmdK={onCmdK}
          onToggleCollapse={onToggleCollapse}
          status={status}
          toggleShortcut={toggleShortcut}
        />
      </Layer>

      {/* Collapsed layer — the polished icon rail body + compact footer. */}
      <Layer visible={collapsed} testId="sidebar-layer-collapsed">
        <SidebarHeader collapsed onToggle={onToggleCollapse} toggleShortcut={toggleShortcut} />
        <SidebarRailBody />
        <CollapsedFooter status={status} />
      </Layer>
    </nav>
  );
}

/**
 * A full-height crossfade layer stacked inside the nav. The hidden layer fades
 * out, is removed from the a11y tree and pointer/focus flow, and (once faded)
 * becomes `visibility: hidden` so its controls are not tab-focusable.
 */
function Layer({
  visible,
  testId,
  children,
}: {
  visible: boolean;
  testId: string;
  children: React.ReactNode;
}) {
  return (
    <div
      data-testid={testId}
      aria-hidden={!visible || undefined}
      // `inert` (React 19) removes the hidden layer from focus + interaction.
      inert={!visible}
      className="cs-animated"
      style={{
        position: "absolute",
        inset: 0,
        display: "flex",
        flexDirection: "column",
        opacity: visible ? 1 : 0,
        // Exit is a touch faster than enter; both ease-out, no bounce.
        transition: visible
          ? `opacity 0.2s ${MORPH} 0.04s`
          : `opacity 0.14s ${MORPH}, visibility 0s linear 0.14s`,
        visibility: visible ? "visible" : "hidden",
        pointerEvents: visible ? undefined : "none",
      }}
    >
      {children}
    </div>
  );
}

interface ExpandedBodyProps {
  onCmdK: () => void;
  onToggleCollapse: () => void;
  status: ConsoleStatus;
  toggleShortcut?: string;
}

/** The full 248px labeled body: header, search, grouped rows, 2×2 pulse footer. */
function ExpandedBody({ onCmdK, onToggleCollapse, status, toggleShortcut }: ExpandedBodyProps) {
  const { processes } = useDesktopOS();
  const groups = useNavApps();
  const launch = useCallback((processId: string) => processes.launch(processId), [processes]);

  return (
    <>
      <SidebarHeader
        collapsed={false}
        onToggle={onToggleCollapse}
        toggleShortcut={toggleShortcut}
        version={status.build}
      />
      <SidebarSearch onCmdK={onCmdK} />

      <div style={{ flex: 1, overflow: "hidden auto", padding: "4px 10px 10px" }}>
        {groups.map((group) => (
          <div key={group.id} style={{ marginBottom: 12 }}>
            <div
              className="font-mono"
              style={{
                padding: "8px 12px 4px",
                fontSize: 9.5,
                letterSpacing: "0.18em",
                textTransform: "uppercase",
                color: "rgba(154,167,181,0.42)",
                whiteSpace: "nowrap",
              }}
            >
              {group.label}
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
                />
              ))}
            </div>
          </div>
        ))}
      </div>

      <div
        style={{
          padding: "10px 12px",
          borderTop: "1px solid rgba(27,34,48,0.6)",
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 6,
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
    </>
  );
}

/**
 * Compact 64px footer: an SSE health dot + violations count, so live state
 * (load-bearing in an EDR console) stays visible at rail width.
 */
function CollapsedFooter({ status }: { status: ConsoleStatus }) {
  return (
    <div
      style={{
        padding: "10px 8px",
        borderTop: "1px solid rgba(27,34,48,0.6)",
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
  );
}
