import type { Strikecell, StrikecellDomainId, StrikecellNode, StrikecellStatus } from "../types";

interface NexusDetailPanelProps {
  open: boolean;
  strikecells: Strikecell[];
  activeStrikecellId: StrikecellDomainId | null;
  selectedNodeIds: string[];
  focusedNodeId: string | null;
  onOpenFullView: (routeId: string) => void;
  onFocusNode: (nodeId: string | null) => void;
  onClearSelection: () => void;
  onClose: () => void;
}

function statusTone(status: StrikecellStatus): string {
  switch (status) {
    case "healthy":
      return "border-sdr-accent-green/45 text-sdr-accent-green";
    case "warning":
      return "border-sdr-accent-amber/45 text-sdr-accent-amber";
    case "critical":
      return "border-sdr-accent-red/45 text-sdr-accent-red";
    default:
      return "border-sdr-text-muted/45 text-sdr-text-muted";
  }
}

function findActive(strikecells: Strikecell[], activeStrikecellId: StrikecellDomainId | null): Strikecell | null {
  if (!activeStrikecellId) return null;
  return strikecells.find((strikecell) => strikecell.id === activeStrikecellId) ?? null;
}

function findFocusedNode(active: Strikecell | null, focusedNodeId: string | null): StrikecellNode | null {
  if (!active || !focusedNodeId) return null;
  return active.nodes.find((node) => node.id === focusedNodeId) ?? null;
}

export function NexusDetailPanel({
  open,
  strikecells,
  activeStrikecellId,
  selectedNodeIds,
  focusedNodeId,
  onOpenFullView,
  onFocusNode,
  onClearSelection,
  onClose,
}: NexusDetailPanelProps) {
  const active = findActive(strikecells, activeStrikecellId);
  const focused = findFocusedNode(active, focusedNodeId);

  return (
    <aside
      className={[
        "origin-chrome-panel absolute right-0 top-0 z-20 h-full w-[330px] border-l border-sdr-border-subtle transition-transform duration-200",
        open ? "translate-x-0" : "translate-x-full",
      ].join(" ")}
      aria-hidden={!open}
    >
      <div className="flex items-center justify-between border-b border-sdr-border-subtle px-4 py-3">
        <h2 className="origin-headline text-sm">Nexus Detail</h2>
        <button
          type="button"
          onClick={onClose}
          className="origin-focus-ring rounded border border-sdr-border px-2 py-1 text-xs font-mono text-sdr-text-secondary hover:text-sdr-text-primary"
        >
          Close
        </button>
      </div>

      {!active ? (
        <div className="p-4 text-sm text-sdr-text-muted">Select a strikecell to inspect details.</div>
      ) : (
        <div className="space-y-4 overflow-y-auto p-4">
          <div>
            <div className="origin-label mb-1 text-[10px]">Strikecell</div>
            <div className="text-lg font-semibold text-sdr-text-primary">{active.name}</div>
            <div className="mt-1 text-xs text-sdr-text-secondary">{active.description}</div>
            <span
              className={[
                "mt-2 inline-block rounded border px-2 py-0.5 text-[10px] font-mono uppercase",
                statusTone(active.status),
              ].join(" ")}
            >
              {active.status}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div className="origin-card rounded-lg p-2">
              <div className="origin-label text-[10px]">Activity</div>
              <div className="text-sm text-sdr-text-primary">{active.activityCount}</div>
            </div>
            <div className="origin-card rounded-lg p-2">
              <div className="origin-label text-[10px]">Nodes</div>
              <div className="text-sm text-sdr-text-primary">{active.nodeCount}</div>
            </div>
          </div>

          <div className="space-y-2">
            <div className="origin-label text-[10px]">Top Nodes</div>
            {active.nodes.slice(0, 8).map((node) => {
              const selected = focusedNodeId === node.id || selectedNodeIds.includes(node.id);
              return (
                <button
                  key={node.id}
                  type="button"
                  onClick={() => onFocusNode(selected ? null : node.id)}
                  className={[
                    "origin-focus-ring w-full rounded-md border px-2.5 py-2 text-left transition-colors",
                    selected
                      ? "border-sdr-accent-amber/45 bg-sdr-accent-amber/10"
                      : "border-sdr-border bg-sdr-bg-primary/65 hover:bg-sdr-bg-tertiary/70",
                  ].join(" ")}
                >
                  <div className="text-xs font-medium text-sdr-text-primary">{node.label}</div>
                  <div className="mt-0.5 text-[10px] font-mono text-sdr-text-muted">
                    {node.kind} · sev {node.severity.toFixed(2)} · act {node.activity.toFixed(2)}
                  </div>
                </button>
              );
            })}
            {active.nodes.length === 0 ? (
              <div className="text-xs text-sdr-text-muted">No active nodes for current source.</div>
            ) : null}
          </div>

          {focused ? (
            <div className="origin-card rounded-lg border border-sdr-accent-blue/30 p-3">
              <div className="origin-label text-[10px]">Focused Node</div>
              <div className="mt-1 text-sm text-sdr-text-primary">{focused.label}</div>
              <div className="mt-1 text-[10px] font-mono uppercase text-sdr-text-muted">{focused.kind}</div>
            </div>
          ) : null}

          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => onOpenFullView(active.routeId)}
              className="origin-focus-ring rounded border border-sdr-accent-amber/45 bg-sdr-accent-amber/10 px-3 py-1.5 text-xs font-mono text-sdr-accent-amber"
            >
              OPEN FULL VIEW
            </button>
            <button
              type="button"
              onClick={onClearSelection}
              className="origin-focus-ring rounded border border-sdr-border px-3 py-1.5 text-xs font-mono text-sdr-text-secondary hover:text-sdr-text-primary"
            >
              CLEAR
            </button>
          </div>
        </div>
      )}
    </aside>
  );
}
