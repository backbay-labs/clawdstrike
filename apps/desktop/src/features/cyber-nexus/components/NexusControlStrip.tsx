import type { ConnectionStatus } from "@/context/ConnectionContext";
import type { NexusLayoutMode, Strikecell } from "../types";
import { ALL_LAYOUT_MODES, LAYOUT_METADATA } from "../layouts";

interface NexusControlStripProps {
  connectionStatus: ConnectionStatus;
  layoutMode: NexusLayoutMode;
  activeStrikecell: Strikecell | null;
  commandQuery: string;
  layoutDropdownOpen: boolean;
  onOpenSearch: () => void;
  onCommandQueryChange: (value: string) => void;
  onOpenCommandPalette: () => void;
  onToggleLayoutDropdown: () => void;
  onSelectLayout: (mode: NexusLayoutMode) => void;
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

function statusToneClass(status: ConnectionStatus) {
  switch (status) {
    case "connected":
      return "bg-sdr-accent-green shadow-[0_0_8px_rgba(61,191,132,0.62)]";
    case "connecting":
      return "bg-sdr-accent-amber shadow-[0_0_8px_rgba(212,168,75,0.58)]";
    case "error":
      return "bg-sdr-accent-red shadow-[0_0_8px_rgba(196,92,92,0.48)]";
    default:
      return "bg-sdr-text-muted shadow-[0_0_8px_rgba(127,132,148,0.42)]";
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
  return id.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 4).padEnd(4, "0");
}

export function NexusControlStrip({
  connectionStatus,
  layoutMode,
  activeStrikecell,
  commandQuery,
  layoutDropdownOpen,
  onOpenSearch,
  onCommandQueryChange,
  onOpenCommandPalette,
  onToggleLayoutDropdown,
  onSelectLayout,
}: NexusControlStripProps) {
  const runId = formatRunId(activeStrikecell?.id);

  return (
    <header className="titlebar-drag nexus-command-rail relative z-40 ml-0 mr-3 mt-3 flex items-center gap-2.5 overflow-visible">
      <div className="titlebar-no-drag premium-panel premium-panel--allow-overflow premium-panel--dense premium-panel--identity nexus-title-plate nexus-title-plate--docked flex h-12 shrink-0 items-center gap-3 rounded-[16px] px-4">
        <span className="nexus-orb-bus-line" aria-hidden="true" />
        <span className="nexus-orb-dock-notch" aria-hidden="true" />
        <span className="origin-glyph-orb origin-glyph-orb--small nexus-plate-orb" aria-hidden="true" />
        <div className="flex flex-col">
          <span className="nexus-wordmark text-[15px] leading-none" aria-label="CLAWDSTRIKE">
            <span className="nexus-wordmark-main">CL</span>
            <span className="nexus-wordmark-a" aria-hidden="true">
              V
            </span>
            <span className="nexus-wordmark-main">WDSTRIKE</span>
          </span>
          <span className="origin-label nexus-wordmark-subline mt-1 text-[7px] tracking-[0.22em] text-sdr-text-muted">
            Swarm Nexus
          </span>
        </div>
        <span className="nexus-title-divider w-px" aria-hidden="true" />
        <span className="premium-chip nexus-title-chip px-2.5 py-[3px] text-[9px] font-mono uppercase tracking-[0.1em] text-sdr-text-secondary">
          {LAYOUT_METADATA[layoutMode].name}
        </span>
      </div>

      <div className="titlebar-no-drag premium-panel premium-panel--allow-overflow premium-panel--dense nexus-manifest-plate flex h-12 min-w-0 flex-[1.2] items-center gap-3 rounded-[16px] px-3.5">
        <div className="nexus-manifest-block min-w-[228px]">
          <div className="flex items-center gap-1.5">
            <span className="origin-label text-[8px] tracking-[0.14em] text-[color:rgba(213,173,87,0.86)]">
              Run {runId}
            </span>
            <span className="premium-separator premium-separator--v h-3 w-px" />
            <span className="origin-label text-[8px] tracking-[0.14em] text-sdr-text-muted">
              {activeStrikecell?.name ?? "Swarm Nexus"}
            </span>
          </div>
          <div className="mt-[2px] text-[10px] font-mono uppercase tracking-[0.12em] text-sdr-text-secondary">
            STATUS: {statusText(connectionStatus)}
          </div>
        </div>

        <span className="premium-separator premium-separator--v h-6 w-px" aria-hidden="true" />

        <div className="min-w-0 flex-1">
          <input
            value={commandQuery}
            onChange={(event) => {
              onCommandQueryChange(event.target.value);
              onOpenSearch();
            }}
            onFocus={onOpenSearch}
            placeholder="Search runs, receipts, tools… (⌘K)"
            className="premium-input nexus-command-input w-full px-3 py-[7px] text-sm text-sdr-text-primary placeholder:text-sdr-text-muted outline-none"
          />
        </div>

        <span className="premium-chip px-2 py-[4px] text-[9px] font-mono uppercase tracking-[0.12em] text-sdr-text-secondary">
          Cmd+K
        </span>
      </div>

      <div className="titlebar-no-drag premium-panel premium-panel--allow-overflow premium-panel--dense premium-panel--controls nexus-controls-plate flex h-12 shrink-0 items-center gap-1.5 rounded-[16px] px-3">
        <ControlButton label="⌘K" onClick={onOpenCommandPalette} />

        <div className="relative">
          <ControlButton
            label={LAYOUT_METADATA[layoutMode].icon + " Layout"}
            active={layoutDropdownOpen}
            onClick={onToggleLayoutDropdown}
          />
          {layoutDropdownOpen && (
            <div className="premium-panel premium-panel--dropdown absolute right-0 top-[calc(100%+8px)] z-[80] min-w-[220px] rounded-lg p-1.5">
              <div className="origin-label px-2 pt-1.5 pb-1 text-[10px] leading-[1.35]">Layout Mode</div>
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
                  <span className="text-[10px] text-sdr-text-muted">{LAYOUT_METADATA[mode].shortcut}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="premium-chip nexus-status-chip ml-0.5 flex items-center gap-1.5 px-2.5 py-[4px]">
          <span className={["h-2 w-2 rounded-full", statusToneClass(connectionStatus)].join(" ")} />
          <span className="text-[10px] font-mono uppercase tracking-[0.12em] text-sdr-text-secondary">
            {statusText(connectionStatus)}
          </span>
        </div>
      </div>
    </header>
  );
}
