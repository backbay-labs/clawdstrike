import { useCallback } from "react";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { EditorVisualPanel } from "@/components/workbench/editor/editor-visual-panel";
import { YamlPreviewPanel } from "@/components/workbench/editor/yaml-preview-panel";
import { ViewContainer } from "@/components/plugins/view-container";
import { usePolicyTabsStore, type SplitMode } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";
import { useWorkbenchUIStore } from "@/features/policy/stores/workbench-ui-store";
import { useNativeValidation } from "@/features/policy/use-native-validation";
import { usePluginViewTabs } from "@/lib/plugins/plugin-view-tab-store";
import { getView } from "@/lib/plugins/view-registry";
import { getDescriptor } from "@/lib/workbench/file-type-registry";
import { getVisualPanel } from "@/lib/workbench/detection-workflow/visual-panels";
import { cn } from "@/lib/utils";
import {
  IconLayoutColumns,
  IconLayoutRows,
  IconLayoutSidebar,
} from "@tabler/icons-react";
import "@/components/workbench/editor/sigma-visual-panel";
import "@/components/workbench/editor/ocsf-visual-panel";
import "@/components/workbench/editor/yara-visual-panel";
import "@/components/workbench/editor/kql-visual-panel";
import "@/components/workbench/editor/eql-visual-panel";
import "@/components/workbench/editor/yaral-visual-panel";
import "@/components/workbench/editor/spl-visual-panel";

export function SplitModeToggle() {
  const tabs = usePolicyTabsStore((state) => state.tabs);
  const splitMode = usePolicyTabsStore((state) => state.splitMode);

  const cycleMode = useCallback(() => {
    const modes: SplitMode[] = ["none", "vertical", "horizontal"];
    const currentIndex = modes.indexOf(splitMode);
    const nextMode = modes[(currentIndex + 1) % modes.length];
    usePolicyTabsStore.getState().setSplitMode(nextMode);
  }, [splitMode]);

  if (tabs.length < 2) return null;

  const Icon =
    splitMode === "vertical"
      ? IconLayoutColumns
      : splitMode === "horizontal"
        ? IconLayoutRows
        : IconLayoutSidebar;

  const label =
    splitMode === "none"
      ? "Split view"
      : splitMode === "vertical"
        ? "Split: vertical"
        : "Split: horizontal";

  return (
    <button
      type="button"
      onClick={cycleMode}
      className={cn(
        "inline-flex items-center gap-1 rounded px-2 py-1 text-[9px] font-mono transition-colors",
        splitMode !== "none"
          ? "border border-[#d4a84b]/30 bg-[#d4a84b]/15 text-[#d4a84b]"
          : "border border-transparent text-[#6f7f9a] hover:border-[#2d3240] hover:text-[#ece7dc]",
      )}
      title={label}
    >
      <Icon size={12} stroke={1.5} />
      {splitMode !== "none" && <span className="hidden sm:inline">{label}</span>}
    </button>
  );
}

function PaneTabSelector({
  selectedTabId,
  excludeTabId,
  onSelect,
}: {
  selectedTabId: string | null;
  excludeTabId?: string;
  onSelect: (tabId: string) => void;
}) {
  const tabs = usePolicyTabsStore((state) => state.tabs);
  const pluginViewTabs = usePluginViewTabs();
  const availableTabs = excludeTabId
    ? tabs.filter((tab) => tab.id !== excludeTabId)
    : tabs;

  if (availableTabs.length === 0 && pluginViewTabs.length === 0) {
    return null;
  }

  return (
    <div className="flex items-center border-b border-[#2d3240] bg-[#0b0d13] px-2 py-1">
      <Select
        value={selectedTabId ?? undefined}
        onValueChange={(value) => {
          if (value) onSelect(value);
        }}
      >
        <SelectTrigger className="h-7 border-[#2d3240] bg-[#131721] text-[10px] font-mono text-[#ece7dc]">
          <SelectValue placeholder="Select tab..." />
        </SelectTrigger>
        <SelectContent className="border-[#2d3240] bg-[#131721]">
          {availableTabs.map((tab) => (
            <SelectItem
              key={tab.id}
              value={tab.id}
              className="text-[10px] font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
            >
              {tab.name}
              {tab.dirty ? " *" : ""}
            </SelectItem>
          ))}
          {pluginViewTabs.length > 0 && availableTabs.length > 0 && (
            <div className="my-1 h-px bg-[#2d3240]" />
          )}
          {pluginViewTabs.map((tab) => (
            <SelectItem
              key={`plugin:${tab.viewId}`}
              value={`plugin:${tab.viewId}`}
              className="text-[10px] font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
            >
              {tab.label} [Plugin]
              {tab.dirty ? " *" : ""}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

function EditorPane() {
  const activeTabId = usePolicyTabsStore((state) => state.activeTabId);
  const activeTab = usePolicyTabsStore((state) =>
    state.tabs.find((tab) => tab.id === state.activeTabId),
  );
  const editState = usePolicyEditStore((state) => state.editStates.get(activeTabId));
  const fileType = activeTab?.fileType;
  const yaml = editState?.yaml ?? "";

  useNativeValidation(
    yaml,
    fileType ?? "clawdstrike_policy",
    (action) => {
      usePolicyEditStore.getState().setNativeValidation(activeTabId, action.payload);
    },
  );

  const handleYamlChange = useCallback(
    (nextYaml: string) => {
      if (!activeTab) return;

      usePolicyEditStore.getState().setYaml(
        activeTabId,
        nextYaml,
        activeTab.fileType,
        activeTab.filePath,
        activeTab.name,
      );
      usePolicyTabsStore.getState().setDirty(activeTabId, true);
      useWorkbenchUIStore.getState().setEditorSyncDirection("yaml");
    },
    [activeTab, activeTabId],
  );

  const renderVisualPanel = () => {
    if (!fileType) {
      return <EditorVisualPanel />;
    }

    const Panel = getVisualPanel(fileType);
    if (!Panel) {
      return <EditorVisualPanel />;
    }

    const descriptor = getDescriptor(fileType);
    return (
      <Panel
        source={yaml}
        onSourceChange={handleYamlChange}
        readOnly={false}
        accentColor={descriptor.iconColor}
      />
    );
  };

  return (
    <ResizablePanelGroup direction="horizontal" className="h-full">
      <ResizablePanel defaultSize={55} minSize={30}>
        {renderVisualPanel()}
      </ResizablePanel>
      <ResizableHandle
        className="bg-[#2d3240] transition-colors hover:bg-[#d4a84b]/40 data-[resize-handle-active]:bg-[#d4a84b]"
        withHandle
      />
      <ResizablePanel defaultSize={45} minSize={25}>
        <YamlPreviewPanel fileType={activeTab?.fileType} />
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}

function SecondaryPanePreview({ tabId }: { tabId: string }) {
  const tab = usePolicyTabsStore((state) => state.tabs.find((entry) => entry.id === tabId));
  const editState = usePolicyEditStore((state) => state.editStates.get(tabId));

  if (!tab) {
    return (
      <div className="flex h-full items-center justify-center text-[11px] font-mono text-[#6f7f9a]/50">
        Select a policy to compare
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-[#2d3240] bg-[#131721] px-3 py-1.5">
        <span className="text-[10px] font-mono text-[#6f7f9a]">Preview:</span>
        <span className="truncate text-[11px] font-mono text-[#ece7dc]">{tab.name}</span>
        {tab.dirty && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-[#d4a84b]" />}
      </div>
      <div className="flex-1 overflow-auto">
        <pre className="whitespace-pre-wrap p-4 text-[11px] font-mono leading-relaxed text-[#ece7dc]/80">
          {editState?.yaml ?? ""}
        </pre>
      </div>
    </div>
  );
}

export function SplitEditor() {
  const splitMode = usePolicyTabsStore((state) => state.splitMode);
  const splitTabId = usePolicyTabsStore((state) => state.splitTabId);
  const activeTabId = usePolicyTabsStore((state) => state.activeTabId);

  const handleSetSplitTab = useCallback((tabId: string) => {
    usePolicyTabsStore.getState().setSplitTab(tabId);
  }, []);

  if (splitMode === "none") {
    return (
      <div className="h-full w-full">
        <EditorPane />
      </div>
    );
  }

  const direction = splitMode === "vertical" ? "horizontal" : "vertical";

  return (
    <div className="h-full w-full">
      <ResizablePanelGroup direction={direction} className="h-full">
        <ResizablePanel defaultSize={50} minSize={25}>
          <div className="flex h-full flex-col">
            <div className="border-b border-[#2d3240] bg-[#0b0d13] px-3 py-1 text-[10px] font-mono text-[#d4a84b]/70">
              Primary
            </div>
            <div className="min-h-0 flex-1">
              <EditorPane />
            </div>
          </div>
        </ResizablePanel>

        <ResizableHandle
          className="bg-[#2d3240] transition-colors hover:bg-[#d4a84b]/40 data-[resize-handle-active]:bg-[#d4a84b]"
          withHandle
        />

        <ResizablePanel defaultSize={50} minSize={25}>
          <div className="flex h-full flex-col">
            <PaneTabSelector
              selectedTabId={splitTabId}
              excludeTabId={activeTabId}
              onSelect={handleSetSplitTab}
            />
            <div className="min-h-0 flex-1">
              {splitTabId && splitTabId.startsWith("plugin:") ? (
                (() => {
                  const viewId = splitTabId.slice(7);
                  const registration = getView(viewId);
                  if (!registration) {
                    return (
                      <div className="flex h-full items-center justify-center text-[11px] font-mono text-[#6f7f9a]/50">
                        Plugin view not found
                      </div>
                    );
                  }

                  return (
                    <ViewContainer
                      registration={registration}
                      isActive={true}
                      slotType="editorTab"
                    />
                  );
                })()
              ) : splitTabId ? (
                <SecondaryPanePreview tabId={splitTabId} />
              ) : (
                <div className="flex h-full items-center justify-center text-[11px] font-mono text-[#6f7f9a]/50">
                  Select a tab above to compare
                </div>
              )}
            </div>
          </div>
        </ResizablePanel>
      </ResizablePanelGroup>
    </div>
  );
}
