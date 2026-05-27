import { useMemo } from "react";
import type { ConsoleStatus } from "../../hooks/useConsoleStatus";
import { desktopIconGroups, PROCESS_ICONS } from "../../state/processRegistry";
import { StatusPulse } from "./StatusPulse";
import { useNavApps } from "./sidebar/useNavApps";

export interface HeaderBarProps {
  variant: "rail" | "expanded" | "twopane";
  activeProcessId: string | undefined;
  status: ConsoleStatus;
  onCmdK: () => void;
}

/** Derive the group label for a given processId from desktopIconGroups. */
function useGroupLabel(processId: string | undefined): string | null {
  return useMemo(() => {
    if (!processId) return null;
    for (const group of desktopIconGroups) {
      if (group.icons.some((icon) => icon.processId === processId)) {
        return group.label;
      }
    }
    return null;
  }, [processId]);
}

/** The active app's display label from useNavApps (live process state). */
function useActiveAppLabel(
  activeProcessId: string | undefined,
): { label: string; sigil: React.ReactNode } | null {
  const groups = useNavApps();
  return useMemo(() => {
    if (!activeProcessId) return null;
    for (const group of groups) {
      const match = group.apps.find((app) => app.processId === activeProcessId);
      if (match) return { label: match.label, sigil: PROCESS_ICONS[activeProcessId] ?? null };
    }
    return null;
  }, [groups, activeProcessId]);
}

export function HeaderBar({ variant, activeProcessId, status, onCmdK }: HeaderBarProps) {
  const groupLabel = useGroupLabel(activeProcessId);
  const activeApp = useActiveAppLabel(activeProcessId);
  const showRailControls = variant === "rail";

  return (
    <div
      style={{
        height: 50,
        padding: "0 20px",
        display: "flex",
        alignItems: "center",
        gap: 16,
        borderBottom: "1px solid rgba(27,34,48,0.5)",
        background: "linear-gradient(180deg, rgba(11,13,16,0.55), rgba(11,13,16,0.2))",
        backdropFilter: "blur(12px)",
        WebkitBackdropFilter: "blur(12px)",
        flexShrink: 0,
        minWidth: 0,
      }}
    >
      {/* Breadcrumb */}
      <div
        aria-label="Location breadcrumb"
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          minWidth: 0,
          overflow: "hidden",
        }}
      >
        <span
          className="font-mono"
          style={{
            fontSize: 9.5,
            letterSpacing: "0.18em",
            textTransform: "uppercase",
            color: "rgba(154,167,181,0.45)",
            whiteSpace: "nowrap",
          }}
        >
          CLAWDSTRIKE
        </span>

        {activeApp && groupLabel && (
          <>
            <Separator />
            <span
              className="font-mono"
              style={{
                fontSize: 9.5,
                letterSpacing: "0.18em",
                textTransform: "uppercase",
                color: "rgba(154,167,181,0.55)",
                whiteSpace: "nowrap",
              }}
            >
              {groupLabel}
            </span>
            <Separator />
            <span
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                color: "var(--gold)",
                minWidth: 0,
                overflow: "hidden",
              }}
            >
              {activeApp.sigil && (
                <span
                  style={{
                    display: "flex",
                    alignItems: "center",
                    flexShrink: 0,
                    width: 13,
                    height: 13,
                    // Scale the sigil ReactNode (SVG) down to 13px
                    fontSize: 13,
                    lineHeight: 0,
                  }}
                  aria-hidden="true"
                >
                  <span
                    style={{
                      display: "inline-flex",
                      width: 13,
                      height: 13,
                      transformOrigin: "top left",
                      transform: "scale(0.65)",
                      color: "var(--gold)",
                    }}
                  >
                    {activeApp.sigil}
                  </span>
                </span>
              )}
              <span
                className="font-mono"
                style={{
                  fontSize: 10,
                  letterSpacing: "0.16em",
                  textTransform: "uppercase",
                  color: "var(--gold)",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                {activeApp.label}
              </span>
            </span>
          </>
        )}
      </div>

      {/* Flex spacer */}
      <div style={{ flex: 1 }} />

      {/* Rail-only right side: ⌘K pill + status chips */}
      {showRailControls && (
        <>
          <SearchPill onCmdK={onCmdK} />
          <div style={{ display: "flex", gap: 8 }}>
            <StatusPulse
              layout="chip"
              label="SSE"
              value={status.sseLive ? "LIVE" : "DOWN"}
              tone={status.sseLive ? "teal" : "crimson"}
              pulse={status.sseLive}
            />
            <StatusPulse
              layout="chip"
              label="Violations"
              value={String(status.violations)}
              tone={status.violations > 0 ? "crimson" : "gold"}
              mono
            />
            <StatusPulse layout="chip" label="Uptime" value={status.uptime} tone="gold" mono />
          </div>
        </>
      )}
    </div>
  );
}

function Separator() {
  return (
    <span aria-hidden="true" style={{ color: "rgba(154,167,181,0.3)", userSelect: "none" }}>
      /
    </span>
  );
}

interface SearchPillProps {
  onCmdK: () => void;
}

function SearchPill({ onCmdK }: SearchPillProps) {
  return (
    <button
      type="button"
      onClick={onCmdK}
      aria-label="Search apps (⌘K)"
      className="cs-nav-focus"
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "6px 10px",
        borderRadius: 8,
        border: "1px solid rgba(27,34,48,0.85)",
        background: "rgba(0,0,0,0.4)",
        cursor: "pointer",
        color: "rgba(154,167,181,0.55)",
        transition: "border-color 150ms ease, color 150ms ease",
      }}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLButtonElement).style.borderColor = "var(--gold-edge)";
        (e.currentTarget as HTMLButtonElement).style.color = "var(--gold)";
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(27,34,48,0.85)";
        (e.currentTarget as HTMLButtonElement).style.color = "rgba(154,167,181,0.55)";
      }}
    >
      {/* Search glyph */}
      <svg
        width="12"
        height="12"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        aria-hidden="true"
      >
        <circle cx="11" cy="11" r="7" />
        <path d="M21 21l-4.3-4.3" />
      </svg>
      <span
        className="font-mono"
        style={{ fontSize: 10.5, letterSpacing: "0.06em", whiteSpace: "nowrap" }}
      >
        Search
      </span>
      <span
        className="font-mono"
        style={{
          fontSize: 9,
          padding: "1px 5px",
          border: "1px solid rgba(27,34,48,0.9)",
          borderRadius: 3,
          background: "rgba(11,13,16,0.6)",
          whiteSpace: "nowrap",
        }}
      >
        ⌘K
      </span>
    </button>
  );
}
