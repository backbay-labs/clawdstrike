import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";
import { usePaneStore } from "@/features/panes/pane-store";

export function ProblemsPanel() {
  const tabs = usePolicyTabsStore((s) => s.tabs);
  const editStates = usePolicyEditStore((s) => s.editStates);

  const entries = tabs.flatMap((tab) => {
    const editState = editStates.get(tab.id);
    if (!editState) return [];
    const errors = editState.validation.errors.map((issue) => ({
      kind: "error" as const,
      message: issue.message,
      path: issue.path,
      tabId: tab.id,
      tabName: tab.name,
      filePath: tab.filePath,
    }));
    const warnings = editState.validation.warnings.map((issue) => ({
      kind: "warning" as const,
      message: issue.message,
      path: issue.path,
      tabId: tab.id,
      tabName: tab.name,
      filePath: tab.filePath,
    }));
    return [...errors, ...warnings];
  });

  if (entries.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-[12px] text-[#6f7f9a]">
        No validation problems across open tabs.
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto px-3 py-2">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[#6f7f9a]">
          Diagnostics
        </h3>
        <span className="text-[11px] text-[#6f7f9a]">
          {entries.length} issue{entries.length === 1 ? "" : "s"}
        </span>
      </div>
      <div className="space-y-2">
        {entries.map((entry, index) => (
          <button
            key={`${entry.tabId}-${entry.kind}-${index}`}
            type="button"
            className="w-full rounded-lg border border-[#202531] bg-[#0b0d13] px-3 py-2 text-left transition-colors hover:border-[#30384b] hover:bg-[#131721]"
            onClick={() => {
              usePolicyTabsStore.getState().switchTab(entry.tabId);
              if (entry.filePath) {
                usePaneStore.getState().openFile(entry.filePath);
              }
            }}
          >
            <div className="mb-1 flex items-center gap-2">
              <span
                className={
                  entry.kind === "error"
                    ? "text-[10px] font-semibold uppercase tracking-[0.12em] text-[#ff8b8b]"
                    : "text-[10px] font-semibold uppercase tracking-[0.12em] text-[#d4a84b]"
                }
              >
                {entry.kind}
              </span>
              <span className="text-[11px] text-[#ece7dc]/80">{entry.tabName}</span>
            </div>
            <p className="text-[12px] leading-5 text-[#cbd3e2]">{entry.message}</p>
          </button>
        ))}
      </div>
    </div>
  );
}
