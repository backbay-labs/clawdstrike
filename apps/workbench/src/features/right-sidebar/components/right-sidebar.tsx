import {
  IconChevronsRight,
  IconMessageCircle,
  IconPackage,
  IconBulb,
  IconHistory,
  IconSparkles,
} from "@tabler/icons-react";
import { useRightSidebarStore } from "../stores/right-sidebar-store";
import type { RightSidebarPanel } from "../types";
import { SpeakeasyPanel } from "@/components/workbench/speakeasy/speakeasy-panel";
import { EvidencePackPanel } from "@/components/workbench/editor/evidence-pack-panel";
import { ExplainabilityPanel } from "@/components/workbench/editor/explainability-panel";
import { VersionHistoryPanel } from "@/components/workbench/editor/version-history-panel";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";
import { useLabExecution } from "@/lib/workbench/detection-workflow/use-lab-execution";
import type { TabMeta } from "@/features/policy/stores/policy-tabs-store";
import type { Icon } from "@tabler/icons-react";
import { SpiritCompanionCanvas } from "@/features/spirit/components/spirit-companion-canvas";

// ---------------------------------------------------------------------------
// Tab strip configuration
// ---------------------------------------------------------------------------

const PANEL_TABS: ReadonlyArray<{
  id: RightSidebarPanel;
  icon: Icon;
  label: string;
}> = [
  { id: "speakeasy", icon: IconMessageCircle, label: "Speakeasy" },
  { id: "evidence", icon: IconPackage, label: "Evidence" },
  { id: "explain", icon: IconBulb, label: "Explain" },
  { id: "history", icon: IconHistory, label: "History" },
  { id: "spirit", icon: IconSparkles, label: "Spirit" },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function useActiveTabContext() {
  const tabs = usePolicyTabsStore((s) => s.tabs);
  const activeTabId = usePolicyTabsStore((s) => s.activeTabId);
  const editStates = usePolicyEditStore((s) => s.editStates);

  const activeMeta: TabMeta | undefined = tabs.find(
    (t) => t.id === activeTabId,
  );
  const editState = editStates.get(activeTabId);

  return {
    documentId: activeMeta?.documentId,
    fileType: activeMeta?.fileType,
    policyId: activeMeta?.documentId,
    currentYaml: editState?.yaml ?? "",
    currentPolicy: editState?.policy ?? null,
  };
}

function NoEditorPlaceholder({ panelName }: { panelName: string }) {
  return (
    <div className="flex flex-1 items-center justify-center p-4">
      <p className="text-center text-[12px] text-[#6f7f9a]">
        Open a detection file to see {panelName}
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Panel content renderers
// ---------------------------------------------------------------------------

function EvidenceContent() {
  const { documentId, fileType } = useActiveTabContext();
  if (!documentId) return <NoEditorPlaceholder panelName="Evidence Packs" />;
  return <EvidencePackPanel documentId={documentId} fileType={fileType} />;
}

function ExplainContent() {
  const { documentId, fileType } = useActiveTabContext();
  const { lastRun } = useLabExecution(documentId, fileType);

  if (!documentId)
    return <NoEditorPlaceholder panelName="Explainability Traces" />;

  const handleJumpToLine = (line: number) => {
    window.dispatchEvent(
      new CustomEvent("workbench:jump-to-line", { detail: { line } }),
    );
  };

  return (
    <ExplainabilityPanel
      documentId={documentId}
      lastRun={lastRun}
      onJumpToLine={handleJumpToLine}
    />
  );
}

function HistoryContent() {
  const { policyId, currentYaml, currentPolicy } = useActiveTabContext();

  if (!policyId)
    return <NoEditorPlaceholder panelName="Version History" />;

  if (!currentPolicy) {
    return (
      <div className="flex flex-1 items-center justify-center p-4">
        <p className="text-center text-[12px] text-[#6f7f9a]">
          Parsing policy…
        </p>
      </div>
    );
  }

  const handleRollback = (version: { yaml?: string }) => {
    if (version.yaml) {
      window.dispatchEvent(
        new CustomEvent("workbench:set-policy", {
          detail: { yaml: version.yaml },
        }),
      );
    }
  };

  const handleCompare = (_fromId: string, _toId: string) => {
    // Compare opens diff dialog -- no-op for now, will be wired in 07-03
  };

  return (
    <VersionHistoryPanel
      policyId={policyId}
      currentYaml={currentYaml}
      currentPolicy={currentPolicy}
      onRollback={handleRollback}
      onCompare={handleCompare}
    />
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function RightSidebar() {
  const width = useRightSidebarStore.use.width();
  const activePanel = useRightSidebarStore.use.activePanel();
  const actions = useRightSidebarStore.use.actions();

  const activePanelLabel =
    PANEL_TABS.find((t) => t.id === activePanel)?.label ?? "Speakeasy";

  return (
    <aside
      role="complementary"
      aria-label="Right Sidebar"
      className="shrink-0 flex flex-col bg-[#0b0d13] border-l border-[#1a1d28]/50"
      style={{ width }}
    >
      {/* Panel header */}
      <div className="flex h-8 shrink-0 items-center justify-between border-b border-[#2d3240]/40 px-4">
        <span className="font-display font-semibold text-[14px] text-[#ece7dc]">
          {activePanelLabel}
        </span>
        <button
          type="button"
          aria-label="Collapse right sidebar"
          className="rounded p-0.5 text-[#6f7f9a] transition-colors hover:text-[#ece7dc]"
          onClick={() => actions.hide()}
        >
          <IconChevronsRight size={14} stroke={1.8} />
        </button>
      </div>

      {/* Tab strip */}
      <div className="flex h-7 shrink-0 items-center gap-0 border-b border-[#2d3240]/40 bg-[#0b0d13]">
        {PANEL_TABS.map((tab) => {
          const isActive = tab.id === activePanel;
          const TabIcon = tab.icon;
          return (
            <button
              key={tab.id}
              type="button"
              aria-label={tab.label}
              title={tab.label}
              className={`flex h-full flex-1 items-center justify-center transition-colors ${
                isActive
                  ? "border-b-2 border-[#d4a84b] text-[#ece7dc]"
                  : "border-b-2 border-transparent text-[#6f7f9a] hover:text-[#ece7dc]/70"
              }`}
              onClick={() => actions.setActivePanel(tab.id)}
            >
              <TabIcon size={14} stroke={1.6} />
            </button>
          );
        })}
      </div>
      {/* Panel body */}
      {activePanel === "speakeasy" && (
        <SpeakeasyPanel
          inline
          isOpen
          room={null}
          onClose={() => actions.hide()}
        />
      )}
      {activePanel === "evidence" && <EvidenceContent />}
      {activePanel === "explain" && <ExplainContent />}
      {activePanel === "history" && <HistoryContent />}
      {activePanel === "spirit" && (
        <div className="flex flex-1 flex-col items-center justify-center gap-3">
          <SpiritCompanionCanvas />
          {/* Shown when no spirit bound (SpiritCompanionCanvas returns null) */}
        </div>
      )}
    </aside>
  );
}
