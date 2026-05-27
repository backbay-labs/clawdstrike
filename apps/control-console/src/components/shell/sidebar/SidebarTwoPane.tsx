import { useDesktopOS } from "@backbay/glia-desktop";
import { useCallback, useEffect, useState } from "react";
import type { ConsoleStatus } from "../../../hooks/useConsoleStatus";
import { type DesktopIconGroupId, PROCESS_ICONS } from "../../../state/processRegistry";
import { StatusPulse } from "../StatusPulse";
import { NavIconButton, NavRowButton } from "./NavItem";
import { SidebarHeader } from "./SidebarHeader";
import { useNavApps } from "./useNavApps";

export interface SidebarTwoPaneProps {
  status: ConsoleStatus;
}

const SETTINGS_PROCESS_ID = "settings";

const SECTION_SIGIL: Record<DesktopIconGroupId, React.ReactNode> = {
  core: PROCESS_ICONS["monitor"],
  "policy-ops": PROCESS_ICONS["policy"],
  advanced: PROCESS_ICONS["settings"],
};

/**
 * macOS-Finder-style two-pane sidebar: a 60px section rail on the left and a
 * 220px scrollable app list on the right. The active section is driven by the
 * focused app; clicking a section button overrides it.
 */
export function SidebarTwoPane({ status }: SidebarTwoPaneProps) {
  const { processes } = useDesktopOS();
  const groups = useNavApps();

  const launch = useCallback((processId: string) => processes.launch(processId), [processes]);

  // Derive the active group from the currently focused app.
  const getActiveGroup = (): DesktopIconGroupId => {
    for (const group of groups) {
      if (group.apps.some((app) => app.active)) return group.id;
    }
    return "core";
  };

  const [activeGroup, setActiveGroup] = useState<DesktopIconGroupId>(getActiveGroup);

  // Keep the active section in sync when the user launches an app from elsewhere
  // (e.g. command palette, taskbar). Mirror design lines 321-328.
  useEffect(() => {
    for (const group of groups) {
      if (group.apps.some((app) => app.active)) {
        setActiveGroup(group.id);
        return;
      }
    }
  }, [groups]);

  const currentGroup = groups.find((g) => g.id === activeGroup);
  const columnApps =
    currentGroup?.apps.filter((app) => app.processId !== SETTINGS_PROCESS_ID) ?? [];

  const settingsApp = groups
    .flatMap((g) => g.apps)
    .find((a) => a.processId === SETTINGS_PROCESS_ID);

  return (
    <nav aria-label="Primary navigation" style={{ display: "flex", height: "100%", flexShrink: 0 }}>
      {/* ── Section rail (60px) ── */}
      <div
        role="tablist"
        aria-label="Sections"
        style={{
          width: 60,
          flexShrink: 0,
          background: "linear-gradient(180deg, rgba(7,8,10,0.98), rgba(4,5,7,0.98))",
          borderRight: "1px solid rgba(27,34,48,0.6)",
          boxShadow: "inset -1px 0 0 rgba(214,177,90,0.04)",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <SidebarHeader collapsed />

        <div
          style={{
            flex: 1,
            padding: "10px 8px",
            display: "flex",
            flexDirection: "column",
            gap: 6,
          }}
        >
          {groups.map((group) => {
            const isActive = activeGroup === group.id;
            return (
              <SectionButton
                key={group.id}
                label={group.label}
                sigil={SECTION_SIGIL[group.id]}
                active={isActive}
                onClick={() => setActiveGroup(group.id)}
              />
            );
          })}
        </div>

        {settingsApp && (
          <div
            style={{
              padding: "10px 8px",
              borderTop: "1px solid rgba(27,34,48,0.6)",
            }}
          >
            <NavIconButton
              label={settingsApp.label}
              sigil={settingsApp.sigil}
              tone={settingsApp.tone}
              active={settingsApp.active}
              running={settingsApp.running}
              onClick={() => launch(settingsApp.processId)}
            />
          </div>
        )}
      </div>

      {/* ── App column (220px) ── */}
      <div
        style={{
          width: 220,
          flexShrink: 0,
          background: "linear-gradient(180deg, rgba(11,13,16,0.96), rgba(7,8,10,0.96))",
          borderRight: "1px solid rgba(27,34,48,0.6)",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {/* Section header */}
        <div style={{ padding: "14px 14px 8px" }}>
          <div
            className="font-mono"
            style={{
              fontSize: 9.5,
              letterSpacing: "0.18em",
              textTransform: "uppercase",
              color: "rgba(154,167,181,0.45)",
            }}
          >
            Section
          </div>
          <div
            className="font-display"
            style={{
              fontSize: 15,
              fontWeight: 500,
              letterSpacing: "0.02em",
              color: "var(--text)",
              marginTop: 2,
            }}
          >
            {currentGroup?.label ?? ""}
          </div>
        </div>

        {/* Scrollable app list */}
        <div
          style={{
            flex: 1,
            overflow: "auto",
            padding: "0 14px 10px",
            display: "flex",
            flexDirection: "column",
            gap: 1,
          }}
        >
          {columnApps.map((app) => (
            <NavRowButton
              key={app.processId}
              label={app.label}
              sigil={app.sigil}
              tone={app.tone}
              active={app.active}
              running={app.running}
              onClick={() => launch(app.processId)}
              compact
            />
          ))}
        </div>

        {/* Status footer — 2-up: SSE + Violations */}
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
            value={status.sseLive ? "● LIVE" : "◌"}
            tone={status.sseLive ? "teal" : "crimson"}
          />
          <StatusPulse
            label="Violations"
            value={String(status.violations)}
            tone={status.violations > 0 ? "crimson" : "gold"}
            mono
          />
        </div>
      </div>
    </nav>
  );
}

interface SectionButtonProps {
  label: string;
  sigil: React.ReactNode;
  active: boolean;
  onClick: () => void;
}

/**
 * 44×44 section selector in the rail. Active state: gold gradient fill +
 * inset border + 2px gold left bar (functional state indicator). Idle: muted
 * icon on transparent.
 */
function SectionButton({ label, sigil, active, onClick }: SectionButtonProps) {
  const [hover, setHover] = useState(false);
  const [focused, setFocused] = useState(false);
  const highlighted = hover || focused;

  return (
    <div style={{ position: "relative" }}>
      <button
        type="button"
        role="tab"
        aria-selected={active}
        aria-label={label}
        title={label}
        onClick={onClick}
        onMouseEnter={() => setHover(true)}
        onMouseLeave={() => setHover(false)}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        className="cs-nav-focus"
        style={{
          width: 44,
          height: 44,
          borderRadius: 10,
          border: "none",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: active
            ? "linear-gradient(180deg, rgba(214,177,90,0.2), rgba(214,177,90,0.05))"
            : highlighted
              ? "rgba(214,177,90,0.07)"
              : "transparent",
          color: active ? "var(--gold)" : highlighted ? "var(--gold)" : "rgba(154,167,181,0.7)",
          boxShadow: active ? "inset 0 0 0 1px rgba(214,177,90,0.3)" : "none",
          transition: "background 0.14s ease, color 0.14s ease, box-shadow 0.14s ease",
        }}
      >
        {sigil}
      </button>

      {/* 2px gold left bar — functional state indicator (VS Code / Linear convention) */}
      {active && (
        <span
          aria-hidden="true"
          style={{
            position: "absolute",
            left: -2,
            top: 8,
            bottom: 8,
            width: 2,
            background: "var(--gold)",
            borderRadius: 2,
            boxShadow: "0 0 8px var(--gold)",
          }}
        />
      )}
    </div>
  );
}
