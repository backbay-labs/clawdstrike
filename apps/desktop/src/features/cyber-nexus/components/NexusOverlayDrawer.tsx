import { useEffect } from "react";
import type { Strikecell } from "../types";

interface NexusOverlayDrawerProps {
  open: boolean;
  strikecell: Strikecell | null;
  onClose: () => void;
  onOpenFullView: (routeId: string) => void;
}

export function NexusOverlayDrawer({
  open,
  strikecell,
  onClose,
  onOpenFullView,
}: NexusOverlayDrawerProps) {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open || !strikecell) return null;

  return (
    <div className="absolute inset-0 z-50 bg-black/45 backdrop-blur-[2px]" onClick={onClose}>
      <aside
        className="origin-chrome-panel absolute right-0 top-0 h-full w-[420px] border-l border-[color:color-mix(in_srgb,var(--origin-panel-border)_70%,transparent)]"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-[color:color-mix(in_srgb,var(--origin-panel-border)_60%,transparent)] px-4 py-3">
          <div>
            <div className="origin-label text-[10px]">Quick Overlay</div>
            <h3 className="text-base font-semibold text-sdr-text-primary">{strikecell.name}</h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="origin-focus-ring origin-glass-button rounded px-2 py-1 text-xs font-mono"
          >
            Close
          </button>
        </div>

        <div className="h-[calc(100%-58px)] space-y-4 overflow-y-auto p-4">
          <p className="text-sm text-sdr-text-secondary">{strikecell.description}</p>

          <div className="grid grid-cols-2 gap-3">
            <div className="origin-card rounded-lg p-3">
              <div className="origin-label text-[10px]">Status</div>
              <div className="mt-1 text-sm uppercase text-sdr-text-primary">{strikecell.status}</div>
            </div>
            <div className="origin-card rounded-lg p-3">
              <div className="origin-label text-[10px]">Activity</div>
              <div className="mt-1 text-sm text-sdr-text-primary">{strikecell.activityCount}</div>
            </div>
          </div>

          <div className="origin-card rounded-lg p-3">
            <div className="origin-label mb-2 text-[10px]">Quick Actions</div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => onOpenFullView(strikecell.routeId)}
                className="origin-focus-ring origin-glass-button rounded px-3 py-1.5 text-xs font-mono text-[color:var(--origin-gold)]"
                data-active="true"
              >
                OPEN FULL VIEW
              </button>
              <button
                type="button"
                onClick={onClose}
                className="origin-focus-ring origin-glass-button rounded px-3 py-1.5 text-xs font-mono"
              >
                CLOSE PANEL
              </button>
            </div>
          </div>

          <div className="origin-card rounded-lg p-3">
            <div className="origin-label mb-2 text-[10px]">Node Snapshot</div>
            <div className="space-y-1.5">
              {strikecell.nodes.slice(0, 8).map((node) => (
                <div key={node.id} className="text-xs text-sdr-text-secondary">
                  <span className="text-sdr-text-primary">{node.label}</span>
                  <span className="font-mono text-sdr-text-muted"> · {node.kind}</span>
                </div>
              ))}
              {strikecell.nodes.length === 0 ? (
                <div className="text-xs text-sdr-text-muted">No live nodes available.</div>
              ) : null}
            </div>
          </div>
        </div>
      </aside>
    </div>
  );
}
