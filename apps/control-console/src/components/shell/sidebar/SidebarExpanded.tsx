import { useDesktopOS } from "@backbay/glia-desktop";
import { useCallback } from "react";
import type { ConsoleStatus } from "../../../hooks/useConsoleStatus";
import { StatusPulse } from "../StatusPulse";
import { NavRowButton } from "./NavItem";
import { SidebarHeader } from "./SidebarHeader";
import { SidebarSearch } from "./SidebarSearch";
import { useNavApps } from "./useNavApps";

export interface SidebarExpandedProps {
  onCmdK: () => void;
  onCollapse: () => void;
  status: ConsoleStatus;
}

/** 248px labeled sidebar — grouped nav rows plus a system-pulse footer. */
export function SidebarExpanded({ onCmdK, onCollapse, status }: SidebarExpandedProps) {
  const { processes } = useDesktopOS();
  const groups = useNavApps();

  const launch = useCallback((processId: string) => processes.launch(processId), [processes]);

  return (
    <nav
      aria-label="Primary navigation"
      style={{
        width: 248,
        flexShrink: 0,
        height: "100%",
        background: "linear-gradient(180deg, rgba(11,13,16,0.97), rgba(7,8,10,0.97))",
        borderRight: "1px solid rgba(27,34,48,0.6)",
        display: "flex",
        flexDirection: "column",
        boxShadow: "inset -1px 0 0 rgba(214,177,90,0.05), 4px 0 32px rgba(0,0,0,0.5)",
      }}
    >
      <SidebarHeader collapsed={false} onToggle={onCollapse} />
      <SidebarSearch onCmdK={onCmdK} />

      <div style={{ flex: 1, overflow: "auto", padding: "4px 10px 10px" }}>
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
              }}
            >
              {group.label}
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
              {group.apps.map((app) => (
                <NavRowButton
                  key={app.processId}
                  label={app.label}
                  sigil={app.sigil}
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
        />
        <StatusPulse
          label="Violations"
          value={String(status.violations)}
          tone={status.violations > 0 ? "crimson" : "gold"}
          mono
        />
        <StatusPulse label="Uptime" value={status.uptime} tone="gold" mono />
        <StatusPulse label="Build" value={status.build} tone="gold" mono />
      </div>
    </nav>
  );
}
