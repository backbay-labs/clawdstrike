import { IconAlertTriangle, IconTerminal2, IconX, IconTerminal, IconLogs, IconFileAnalytics, IconLayoutColumns, IconTimeline } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useBottomPaneStore } from "./bottom-pane-store";
import { ProblemsPanel } from "./problems-panel";
import { TerminalPanel } from "./terminal-panel";
import { OutputPanel } from "./output-panel";
import { AuditTailPanel } from "./audit-tail-panel";
import { ForensicsTapePanel } from "@/features/forensics/components/ForensicsTapePanel";

export function BottomPane() {
  const activeTab = useBottomPaneStore((state) => state.activeTab);
  const splitTerminalIds = useBottomPaneStore((state) => state.splitTerminalIds);
  const isSplit = splitTerminalIds != null;

  return (
    <section data-testid="bottom-pane" className="flex h-full min-h-0 flex-col border-t border-[#202531] bg-[#07090f] spirit-field-stain-host">
      <header className="flex items-center justify-between border-b border-[#202531] px-3 py-2">
        <div className="flex items-center gap-1">
          <button
            type="button"
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors",
              activeTab === "terminal"
                ? "bg-[#131721] text-[#ece7dc]"
                : "text-[#6f7f9a] hover:bg-[#0f1219] hover:text-[#ece7dc]",
            )}
            onClick={() => useBottomPaneStore.getState().setActiveTab("terminal")}
          >
            <IconTerminal2 size={13} stroke={1.8} />
            Terminal
          </button>
          <button
            type="button"
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors",
              activeTab === "problems"
                ? "bg-[#131721] text-[#ece7dc]"
                : "text-[#6f7f9a] hover:bg-[#0f1219] hover:text-[#ece7dc]",
            )}
            onClick={() => useBottomPaneStore.getState().setActiveTab("problems")}
          >
            <IconAlertTriangle size={13} stroke={1.8} />
            Problems
          </button>
          <button
            type="button"
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors",
              activeTab === "output"
                ? "bg-[#131721] text-[#ece7dc]"
                : "text-[#6f7f9a] hover:bg-[#0f1219] hover:text-[#ece7dc]",
            )}
            onClick={() => useBottomPaneStore.getState().setActiveTab("output")}
          >
            <IconLogs size={13} stroke={1.8} />
            Output
          </button>
          <button
            type="button"
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors",
              activeTab === "audit"
                ? "bg-[#131721] text-[#ece7dc]"
                : "text-[#6f7f9a] hover:bg-[#0f1219] hover:text-[#ece7dc]",
            )}
            onClick={() => useBottomPaneStore.getState().setActiveTab("audit")}
          >
            <IconFileAnalytics size={13} stroke={1.8} />
            Audit
          </button>
          <button
            type="button"
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors",
              activeTab === "tape"
                ? "bg-[#131721] text-[#ece7dc]"
                : "text-[#6f7f9a] hover:bg-[#0f1219] hover:text-[#ece7dc]",
            )}
            onClick={() => useBottomPaneStore.getState().setActiveTab("tape")}
          >
            <IconTimeline size={13} stroke={1.8} />
            Tape
          </button>
        </div>

        <div className="flex items-center gap-1">
          {activeTab === "terminal" ? (
            <>
              <button
                type="button"
                className="rounded-md p-1.5 text-[#6f7f9a] transition-colors hover:bg-[#131721] hover:text-[#ece7dc]"
                onClick={() => void useBottomPaneStore.getState().splitTerminal()}
                aria-label={isSplit ? "Unsplit terminal" : "Split terminal"}
                title={isSplit ? "Unsplit terminal" : "Split terminal"}
              >
                <IconLayoutColumns size={14} stroke={1.8} />
              </button>
              <button
                type="button"
                className="rounded-md p-1.5 text-[#6f7f9a] transition-colors hover:bg-[#131721] hover:text-[#ece7dc]"
                onClick={() => void useBottomPaneStore.getState().newTerminal()}
                aria-label="New terminal session"
                title="New terminal session"
              >
                <IconTerminal size={14} stroke={1.8} />
              </button>
            </>
          ) : null}
          <button
            type="button"
            className="rounded-md p-1.5 text-[#6f7f9a] transition-colors hover:bg-[#131721] hover:text-[#ece7dc]"
            onClick={() => useBottomPaneStore.getState().toggleTab(activeTab)}
            aria-label="Close bottom pane"
          >
            <IconX size={14} stroke={1.8} />
          </button>
        </div>
      </header>

      <div className="min-h-0 flex-1">
        {activeTab === "terminal" ? (
          <TerminalPanel />
        ) : activeTab === "problems" ? (
          <ProblemsPanel />
        ) : activeTab === "audit" ? (
          <AuditTailPanel />
        ) : activeTab === "tape" ? (
          <ForensicsTapePanel />
        ) : (
          <OutputPanel />
        )}
      </div>
    </section>
  );
}
