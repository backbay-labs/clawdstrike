import { useState, useCallback } from "react";
import { PolicyTabBar } from "@/components/workbench/editor/policy-tab-bar";
import { SplitEditor, SplitModeToggle } from "@/components/workbench/editor/split-editor";
import {
  BulkOperationsDialog,
} from "@/components/workbench/editor/bulk-operations-dialog";
import { VersionHistoryPanel } from "@/components/workbench/editor/version-history-panel";
import { VersionDiffDialog } from "@/components/workbench/editor/version-diff-dialog";
import { useMultiPolicy } from "@/lib/workbench/multi-policy-store";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { useVersionHistory } from "@/lib/workbench/use-version-history";
import { useAutoVersion } from "@/lib/workbench/use-auto-version";
import type { PolicyVersion } from "@/lib/workbench/version-store";
import { IconWand, IconHistory } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { ClaudeCodeHint } from "@/components/workbench/shared/claude-code-hint";

export function PolicyEditor() {
  const { tabs, activeTab } = useMultiPolicy();
  const { state, dispatch } = useWorkbench();
  const [bulkOpen, setBulkOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [diffDialogOpen, setDiffDialogOpen] = useState(false);
  const [diffFromId, setDiffFromId] = useState<string | undefined>();
  const [diffToId, setDiffToId] = useState<string | undefined>();

  // Use the active tab's ID as the policyId for version tracking
  const policyId = activeTab?.id;
  const { versions } = useVersionHistory(policyId);

  // Auto-create versions on explicit save (dirty -> clean transition)
  useAutoVersion(policyId, state.yaml, state.activePolicy, state.dirty);

  // Rollback handler: load a version's policy into the editor
  const handleRollback = useCallback(
    (version: PolicyVersion) => {
      dispatch({ type: "SET_POLICY", policy: version.policy });
    },
    [dispatch],
  );

  // Compare handler: open diff dialog
  const handleCompare = useCallback(
    (fromId: string, toId: string) => {
      setDiffFromId(fromId);
      setDiffToId(toId);
      setDiffDialogOpen(true);
    },
    [],
  );

  return (
    <div className="h-full w-full flex flex-col">
      {/* Tab bar + toolbar */}
      <div className="flex items-center bg-[#0b0d13] border-b border-[#2d3240]">
        <div className="flex-1 min-w-0">
          <PolicyTabBar />
        </div>
        <div className="flex items-center gap-1 px-2 shrink-0">
          <SplitModeToggle />
          {tabs.length >= 2 && (
            <button
              type="button"
              onClick={() => setBulkOpen(true)}
              className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] border border-transparent hover:border-[#2d3240] rounded transition-colors"
              title="Bulk operations across policies"
            >
              <IconWand size={12} stroke={1.5} />
            </button>
          )}
          <button
            type="button"
            onClick={() => setHistoryOpen((prev) => !prev)}
            className={cn(
              "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors",
              historyOpen
                ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/30"
                : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240]",
            )}
            title="Toggle version history"
          >
            <IconHistory size={12} stroke={1.5} />
          </button>
        </div>
      </div>

      {/* Claude Code hint strip */}
      <ClaudeCodeHint
        hintId="editor.validate"
        className="mx-2 mt-1.5 mb-0.5"
      />

      {/* Editor content + optional version history sidebar */}
      <div className="flex-1 min-h-0 flex">
        <div className="flex-1 min-w-0">
          <SplitEditor />
        </div>

        {/* Version history panel (collapsible right sidebar) */}
        {historyOpen && (
          <div className="w-[280px] shrink-0">
            <VersionHistoryPanel
              policyId={policyId}
              currentYaml={state.yaml}
              currentPolicy={state.activePolicy}
              onRollback={handleRollback}
              onCompare={handleCompare}
            />
          </div>
        )}
      </div>

      {/* Bulk operations dialog */}
      <BulkOperationsDialog open={bulkOpen} onOpenChange={setBulkOpen} />

      {/* Version diff dialog */}
      <VersionDiffDialog
        open={diffDialogOpen}
        onOpenChange={setDiffDialogOpen}
        versions={versions}
        currentPolicy={state.activePolicy}
        currentYaml={state.yaml}
        initialFromId={diffFromId}
        initialToId={diffToId}
        onRollback={handleRollback}
      />
    </div>
  );
}
