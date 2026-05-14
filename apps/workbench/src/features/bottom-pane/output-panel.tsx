import { IconTrash } from "@tabler/icons-react";
import { useBottomPaneStore } from "./bottom-pane-store";

function formatTimestamp(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function OutputPanel() {
  const outputEntries = useBottomPaneStore((state) => state.outputEntries);

  if (outputEntries.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-[12px] text-[#6f7f9a]">
        Command and terminal activity will appear here.
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center justify-between border-b border-[#202531] px-3 py-2">
        <div>
          <h3 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[#6f7f9a]">
            Output
          </h3>
          <p className="text-[11px] text-[#6f7f9a]">
            Recent command and terminal events
          </p>
        </div>

        <button
          type="button"
          className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-[11px] text-[#6f7f9a] transition-colors hover:bg-[#131721] hover:text-[#ece7dc]"
          onClick={() => useBottomPaneStore.getState().clearOutput()}
        >
          <IconTrash size={13} stroke={1.8} />
          Clear
        </button>
      </div>

      <div className="min-h-0 flex-1 overflow-auto px-3 py-2">
        <div className="space-y-2">
          {outputEntries.map((entry) => (
            <article
              key={entry.id}
              className="rounded-lg border border-[#202531] bg-[#0b0d13] px-3 py-2"
            >
              <div className="mb-1 flex items-center justify-between gap-3">
                <div className="flex min-w-0 items-center gap-2">
                  <span
                    className={
                      entry.level === "error"
                        ? "text-[10px] font-semibold uppercase tracking-[0.12em] text-[#ff8b8b]"
                        : "text-[10px] font-semibold uppercase tracking-[0.12em] text-[#79c4ff]"
                    }
                  >
                    {entry.level}
                  </span>
                  <span className="truncate text-[12px] text-[#ece7dc]">
                    {entry.title}
                  </span>
                </div>
                <span className="shrink-0 text-[10px] text-[#6f7f9a]">
                  {formatTimestamp(entry.timestamp)}
                </span>
              </div>

              {entry.detail ? (
                <p className="text-[11px] leading-5 text-[#9ca9bf]">
                  {entry.detail}
                </p>
              ) : null}
            </article>
          ))}
        </div>
      </div>
    </div>
  );
}
