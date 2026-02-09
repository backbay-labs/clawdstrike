import { clsx } from "clsx";

export interface NexusFeedItem {
  id: string;
  title: string;
  description: string;
  severity: "info" | "warning" | "critical";
  timestamp: string;
}

interface NexusActivityFeedProps {
  open: boolean;
  detailOpen: boolean;
  items: NexusFeedItem[];
  onClose: () => void;
}

function severityClass(severity: NexusFeedItem["severity"]): string {
  switch (severity) {
    case "critical":
      return "text-sdr-accent-red border-sdr-accent-red/35 bg-sdr-accent-red/10";
    case "warning":
      return "text-sdr-accent-amber border-sdr-accent-amber/35 bg-sdr-accent-amber/10";
    default:
      return "text-sdr-accent-blue border-sdr-accent-blue/35 bg-sdr-accent-blue/10";
  }
}

export function NexusActivityFeed({ open, detailOpen, items, onClose }: NexusActivityFeedProps) {
  return (
    <aside
      className={clsx(
        "origin-chrome-panel absolute inset-y-0 z-40 w-[370px] border-l border-sdr-border-subtle transition-transform duration-200",
        detailOpen ? "right-[330px]" : "right-0",
        open ? "translate-x-0" : "translate-x-full"
      )}
      aria-hidden={!open}
    >
      <div className="flex items-center justify-between border-b border-sdr-border-subtle px-4 py-3">
        <h3 className="origin-headline text-sm">Activity Feed</h3>
        <button
          type="button"
          onClick={onClose}
          className="origin-focus-ring rounded border border-sdr-border px-2 py-1 text-xs font-mono text-sdr-text-secondary hover:text-sdr-text-primary"
        >
          Close
        </button>
      </div>

      <div className="h-[calc(100%-54px)] space-y-2 overflow-y-auto p-3">
        {items.map((item) => (
          <div key={item.id} className="origin-card rounded-lg p-2.5">
            <div className="flex items-center justify-between gap-2">
              <div className="text-xs font-medium text-sdr-text-primary">{item.title}</div>
              <span
                className={`rounded border px-1.5 py-0.5 text-[9px] font-mono uppercase ${severityClass(item.severity)}`}
              >
                {item.severity}
              </span>
            </div>
            <div className="mt-1 text-[11px] text-sdr-text-secondary">{item.description}</div>
            <div className="mt-1.5 text-[10px] font-mono text-sdr-text-muted">{item.timestamp}</div>
          </div>
        ))}
        {items.length === 0 ? (
          <div className="px-1 py-2 text-xs text-sdr-text-muted">No recent activity.</div>
        ) : null}
      </div>
    </aside>
  );
}
