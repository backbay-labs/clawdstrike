// Ported from huntronomer NexusControlStrip.tsx
// Removed: ProfileMenu (not available in workbench), ConnectionStatus type inlined.

import * as React from "react";
import { ALL_LAYOUT_MODES, LAYOUT_METADATA } from "../layouts";
import type { NexusLayoutMode, Strikecell } from "../types";

type ConnectionStatus = "connected" | "connecting" | "error" | "disconnected";

interface NexusControlStripProps {
  connectionStatus: ConnectionStatus;
  layoutMode: NexusLayoutMode;
  activeStrikecell: Strikecell | null;
  brandSubline?: string;
  atlasLabel?: string;
  atlasCode?: string;
  atlasReason?: string;
  commandQuery: string;
  layoutDropdownOpen: boolean;
  onOpenSearch: () => void;
  onCommandQueryChange: (value: string) => void;
  onOpenCommandPalette: () => void;
  onToggleLayoutDropdown: () => void;
  onCloseLayoutDropdown: () => void;
  onSelectLayout: (mode: NexusLayoutMode) => void;
  onOpenOperations: () => void;
  onOpenConnectionSettings: () => void;
}

function statusText(status: ConnectionStatus) {
  switch (status) {
    case "connected":
      return "LIVE";
    case "connecting":
      return "SYNCING";
    case "error":
      return "ERROR";
    default:
      return "OFFLINE";
  }
}

function ControlButton({
  label,
  onClick,
  active,
}: {
  label: string;
  onClick: () => void;
  active?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        "origin-focus-ring premium-chip premium-chip--control nexus-control-chip px-3 py-[4px] text-[10px] font-mono uppercase tracking-[0.12em]",
        active ? "text-[color:var(--origin-gold)]" : "",
      ].join(" ")}
      data-active={active ? "true" : "false"}
    >
      {label}
    </button>
  );
}

function formatRunId(id: string | undefined) {
  if (!id) return "----";
  return id
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .slice(0, 4)
    .padEnd(4, "0");
}

export function NexusControlStrip({
  connectionStatus,
  layoutMode,
  activeStrikecell,
  brandSubline = "Observatory Atlas",
  atlasLabel = "Atlas",
  atlasCode = "NEX",
  atlasReason,
  commandQuery,
  layoutDropdownOpen,
  onOpenSearch,
  onCommandQueryChange,
  onOpenCommandPalette,
  onToggleLayoutDropdown,
  onCloseLayoutDropdown,
  onSelectLayout,
}: NexusControlStripProps) {
  const rootRef = React.useRef<HTMLElement | null>(null);
  const runId = formatRunId(activeStrikecell?.id);
  const manifestReason =
    atlasReason ??
    (activeStrikecell
      ? `${activeStrikecell.name} is the active atlas seam.`
      : "Atlas is waiting for a live strikecell focus.");

  React.useEffect(() => {
    if (!layoutDropdownOpen) return;
    const onPointer = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) onCloseLayoutDropdown();
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onCloseLayoutDropdown();
    };
    window.addEventListener("mousedown", onPointer);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onPointer);
      window.removeEventListener("keydown", onKey);
    };
  }, [layoutDropdownOpen, onCloseLayoutDropdown]);

  return (
    <header
      ref={rootRef}
      className="titlebar-drag nexus-command-rail relative z-40 mx-3 mt-3 overflow-visible"
    >
      <div className="titlebar-no-drag premium-panel premium-panel--allow-overflow premium-panel--dense flex min-h-[60px] items-center gap-3 rounded-[18px] border border-[rgba(212,168,75,0.14)] bg-[linear-gradient(180deg,rgba(7,10,16,0.9)_0%,rgba(4,6,10,0.96)_100%)] px-4 py-3 shadow-[0_18px_44px_rgba(0,0,0,0.34)] backdrop-blur-md">
        <div className="min-w-[188px]">
          <div className="origin-label text-[8px] tracking-[0.18em] text-[rgba(213,173,87,0.86)]">
            {atlasCode} {brandSubline}
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-[12px] font-mono uppercase tracking-[0.14em] text-sdr-text-primary">
              {atlasLabel}
            </span>
            <span className="text-[10px] font-mono uppercase tracking-[0.12em] text-sdr-text-muted">
              {statusText(connectionStatus)} {"\u00B7"} {runId}
            </span>
          </div>
        </div>

        <div className="h-7 w-px bg-[rgba(213,173,87,0.12)]" aria-hidden="true" />

        <div className="min-w-0 flex-1">
          <input
            value={commandQuery}
            onChange={(event) => {
              onCommandQueryChange(event.target.value);
              onOpenSearch();
            }}
            onFocus={onOpenSearch}
            placeholder="Search stations, nodes, paths... (Cmd+K)"
            className="premium-input nexus-command-input w-full rounded-full border border-[rgba(213,173,87,0.12)] bg-[rgba(6,9,14,0.74)] px-3 py-[7px] text-sm font-mono text-sdr-text-primary placeholder:text-sdr-text-muted outline-none"
          />
          <div className="mt-1 truncate text-[11px] text-sdr-text-muted">{manifestReason}</div>
        </div>

        <div className="ml-auto flex items-center gap-1.5">
          <div className="relative">
            <ControlButton
              label={LAYOUT_METADATA[layoutMode].icon + " Layout"}
              active={layoutDropdownOpen}
              onClick={onToggleLayoutDropdown}
            />
            {layoutDropdownOpen ? (
              <div className="nexus-layout-dropdown premium-panel premium-panel--dropdown absolute right-0 top-[calc(100%+8px)] z-[80] min-w-[240px] rounded-lg p-1.5">
                <div className="origin-label px-2 pt-1.5 pb-1 text-[10px] leading-[1.35]">
                  Layout Mode
                </div>
                <div className="premium-separator mb-1 h-px w-full" />
                {ALL_LAYOUT_MODES.map((mode) => (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => onSelectLayout(mode)}
                    className={[
                      "origin-focus-ring flex w-full items-center justify-between rounded px-2 py-1.5 text-left text-[11px] font-mono transition-all duration-150 ease-out",
                      mode === layoutMode
                        ? "bg-[rgba(213,173,87,0.12)] text-[color:var(--origin-gold)]"
                        : "text-sdr-text-secondary hover:bg-[rgba(213,173,87,0.08)] hover:text-sdr-text-primary",
                    ].join(" ")}
                  >
                    <span>{LAYOUT_METADATA[mode].name}</span>
                    <span className="text-[10px] text-sdr-text-muted">
                      {LAYOUT_METADATA[mode].shortcut}
                    </span>
                  </button>
                ))}
              </div>
            ) : null}
          </div>

          <ControlButton
            label="Cmd+K"
            onClick={onOpenCommandPalette}
          />
        </div>
      </div>
    </header>
  );
}
