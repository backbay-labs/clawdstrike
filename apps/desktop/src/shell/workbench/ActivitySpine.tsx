/**
 * ActivitySpine - 56px operator rail.
 *
 * Zones (top→bottom):
 *   A. Orb zone (10px top pad, 40px visible orb, 48px hit target)
 *   B. Shell zone (Wire, Hunt, Lab, Case — 40x40 hit targets, 18px icons, 8px gap)
 *   C. Status cluster (connection, inbox placeholder, profile)
 */
import { clsx } from "clsx";
import { useCallback, useRef, useState } from "react";
import { useConnectionStatus } from "@/context/ConnectionContext";
import { useShell, useWorkbenchDispatch } from "@/shell/workbench/WorkbenchStateProvider";
import type { ShellMode } from "@/shell/workbench/workbenchState";
import { OrbLensRotor } from "./OrbLensRotor";

interface ShellEntry {
  id: ShellMode;
  label: string;
  shortcut: string;
  icon: React.ReactNode;
}

/* ── Cyber-native shell icons (18px stroke set) ───────────────────── */

const SHELLS: readonly ShellEntry[] = [
  {
    id: "wire",
    label: "Wire",
    shortcut: "⌘1",
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M2 10h3l1.5-5 2 10 2-10 1.5 5H18" />
      </svg>
    ),
  },
  {
    id: "hunt",
    label: "Hunt",
    shortcut: "⌘2",
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <circle cx="10" cy="10" r="5" />
        <circle cx="10" cy="10" r="1.5" fill="currentColor" stroke="none" />
        <path d="M10 3v2M10 15v2M3 10h2M15 10h2" />
      </svg>
    ),
  },
  {
    id: "lab",
    label: "Lab",
    shortcut: "⌘3",
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M7.5 3v5l-4 9h13l-4-9V3" />
        <path d="M7.5 3h5" />
        <path d="M7 13h2.5" opacity="0.6" />
      </svg>
    ),
  },
  {
    id: "case",
    label: "Case",
    shortcut: "⌘4",
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M3 6a1.5 1.5 0 011.5-1.5h3L9 6h6.5A1.5 1.5 0 0117 7.5v7a1.5 1.5 0 01-1.5 1.5h-11A1.5 1.5 0 013 14.5V6z" />
        <path d="M7 10h6M7 13h3" opacity="0.5" />
      </svg>
    ),
  },
] as const;

export function ActivitySpine() {
  const shell = useShell();
  const dispatch = useWorkbenchDispatch();
  const connectionStatus = useConnectionStatus();
  const [hoveredShell, setHoveredShell] = useState<ShellMode | null>(null);
  const hoverTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showFlyout = useCallback((id: ShellMode) => {
    if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current);
    hoverTimerRef.current = setTimeout(() => setHoveredShell(id), 100);
  }, []);

  const hideFlyout = useCallback(() => {
    if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current);
    hoverTimerRef.current = null;
    setHoveredShell(null);
  }, []);

  return (
    <nav
      className="relative z-20 flex h-full w-[56px] shrink-0 flex-col items-center border-r bg-[linear-gradient(180deg,rgba(9,11,18,0.98)_0%,rgba(4,6,10,0.99)_100%)]"
      style={{ borderRightColor: "rgba(213, 173, 87, 0.25)" }}
      aria-label="Activity spine"
    >
      {/* A. Orb zone */}
      <div className="flex flex-col items-center pt-[10px] pb-0">
        <OrbLensRotor />
      </div>

      {/* Divider */}
      <div
        className="mx-auto h-px w-6"
        style={{ margin: "8px auto 10px", background: "linear-gradient(90deg, transparent, rgba(213,173,87,0.18), transparent)" }}
      />

      {/* B. Shell zone — starts ~72px from top */}
      <div className="flex flex-col items-center gap-2">
        {SHELLS.map((entry) => {
          const isActive = entry.id === shell;
          return (
            <div key={entry.id} className="relative">
              <button
                type="button"
                aria-label={`${entry.label} shell`}
                aria-current={isActive ? "page" : undefined}
                className={clsx(
                  "relative flex h-10 w-10 items-center justify-center rounded transition-colors duration-100",
                  isActive
                    ? "text-[rgba(213,173,87,0.9)]"
                    : "text-[rgba(182,183,193,0.45)] hover:text-[rgba(232,230,222,0.75)]",
                )}
                onClick={() => dispatch({ type: "SET_SHELL", payload: entry.id })}
                onMouseEnter={() => showFlyout(entry.id)}
                onMouseLeave={hideFlyout}
              >
                {/* 2px left rail active indicator */}
                {isActive && (
                  <span
                    className="absolute left-0 top-1.5 bottom-1.5 w-[2px] rounded-r-sm"
                    style={{ background: "rgba(213,173,87,0.8)" }}
                  />
                )}
                {entry.icon}
              </button>

              {/* Flyout label (anchored, not tooltip) */}
              {hoveredShell === entry.id && (
                <div
                  className="pointer-events-none absolute left-[52px] top-1/2 z-30 flex -translate-y-1/2 items-center gap-2 whitespace-nowrap rounded-md border px-2.5 py-1"
                  style={{
                    background: "rgba(9,12,19,0.95)",
                    borderColor: "rgba(213,173,87,0.25)",
                    boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
                  }}
                >
                  <span className="font-mono text-[11px] text-[rgba(232,230,222,0.9)]">{entry.label}</span>
                  <span className="font-mono text-[10px] text-[rgba(182,183,193,0.45)]">{entry.shortcut}</span>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* C. Status cluster */}
      <div className="flex flex-col items-center gap-3 pb-3">
        {/* Connection state */}
        <button
          type="button"
          title={`Connection: ${connectionStatus}`}
          aria-label={`Connection status: ${connectionStatus}`}
          className="flex h-6 w-6 items-center justify-center"
        >
          <span
            className={clsx(
              "h-[7px] w-[7px] rounded-full",
              connectionStatus === "connected" && "bg-[#3dbf84] shadow-[0_0_6px_rgba(61,191,132,0.6)]",
              connectionStatus === "connecting" && "bg-[#d4a84b] shadow-[0_0_6px_rgba(212,168,75,0.6)]",
              connectionStatus !== "connected" && connectionStatus !== "connecting" && "bg-[#c45c5c] shadow-[0_0_6px_rgba(196,92,92,0.5)]",
            )}
          />
        </button>
      </div>
    </nav>
  );
}

export default ActivitySpine;
