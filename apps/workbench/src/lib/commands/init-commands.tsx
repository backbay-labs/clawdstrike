/**
 * InitCommands -- React component that registers all workbench commands.
 *
 * Must be rendered inside the workbench shell and a router context so that it
 * can access workbench, pane, and navigation state.
 *
 * Renders nothing (returns null). Re-registers commands when deps change so
 * closures are always fresh.
 */
import { useEffect, useRef, useCallback, useState } from "react";
import { useBottomPaneStore } from "@/features/bottom-pane/bottom-pane-store";
import { usePaneStore } from "@/features/panes/pane-store";
import { getAllPaneGroups } from "@/features/panes/pane-tree";
import { usePolicyTabsStore, pushRecentFile } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";
import { useWorkbenchUIStore } from "@/features/policy/stores/workbench-ui-store";
import { DEFAULT_POLICY } from "@/features/policy/stores/policy-store";
import { useActivityBarStore } from "@/features/activity-bar/stores/activity-bar-store";
import { useRightSidebarStore } from "@/features/right-sidebar/stores/right-sidebar-store";
import { commandRegistry } from "@/lib/command-registry";
import {
  isDesktop,
  openDetectionFile,
  saveDetectionFile,
} from "@/lib/tauri-bridge";
import { getDocumentIdentityStore } from "@/lib/workbench/detection-workflow/document-identity-store";
import {
  getPrimaryExtension,
  isPolicyFileType,
  sanitizeFilenameStem,
} from "@/lib/workbench/file-type-registry";
import {
  registerNavigateCommands,
  registerFileCommands,
  registerEditCommands,
  registerPolicyCommands,
  registerViewCommands,
  registerHuntronomerCommands,
} from "./index";
import { ShortcutHelpDialog } from "@/components/desktop/shortcut-help-dialog";

/**
 * Component that initializes all commands and manages the shortcut help dialog.
 * Placed inside DesktopLayout so it has access to router + workbench contexts.
 */
export function InitCommands() {
  const [helpOpen, setHelpOpen] = useState(false);

  const toggleHelp = useCallback(() => setHelpOpen((prev) => !prev), []);

  useEffect(
    () =>
      commandRegistry.subscribeExecutions((event) => {
        useBottomPaneStore.getState().appendOutput({
          level: event.status === "error" ? "error" : "info",
          title:
            event.status === "error"
              ? `${event.title} failed`
              : `${event.title} completed`,
          detail:
            event.status === "error"
              ? event.error
              : `${event.category} command in ${event.durationMs}ms`,
          commandId: event.commandId,
        });
      }),
    [],
  );

  // -- File command callbacks (ported from useWorkbench bridge) --

  const exportYaml = useCallback(() => {
    const activeTabId = usePolicyTabsStore.getState().activeTabId;
    const activeTab = usePolicyTabsStore.getState().tabs.find(t => t.id === activeTabId);
    const editState = usePolicyEditStore.getState().editStates.get(activeTabId);
    if (!activeTab || !editState) return;
    const blob = new Blob([editState.yaml], {
      type: activeTab.fileType === "ocsf_event" ? "application/json" : "text/plain",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const stem = sanitizeFilenameStem(activeTab.name || "untitled", "untitled");
    a.download = `${stem}${getPrimaryExtension(activeTab.fileType)}`;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  const copyYaml = useCallback(() => {
    const activeTabId = usePolicyTabsStore.getState().activeTabId;
    const editState = usePolicyEditStore.getState().editStates.get(activeTabId);
    if (!editState) return;
    navigator.clipboard.writeText(editState.yaml).catch(() => {});
  }, []);

  const openFile = useCallback(async () => {
    try {
      const result = await openDetectionFile();
      if (!result) return;
      usePolicyTabsStore.getState().openTabOrSwitch(
        result.path,
        result.fileType,
        result.content,
      );
      pushRecentFile(result.path);
    } catch (err) {
      console.error("[init-commands] Failed to open file:", err);
    }
  }, []);

  const saveFileAs = useCallback(async () => {
    const activeTabId = usePolicyTabsStore.getState().activeTabId;
    const activeTab = usePolicyTabsStore.getState().tabs.find(t => t.id === activeTabId);
    const editState = usePolicyEditStore.getState().editStates.get(activeTabId);
    if (!activeTab || !editState) return;
    try {
      if (!isDesktop()) {
        exportYaml();
        return;
      }
      const savedPath = await saveDetectionFile(
        editState.yaml,
        activeTab.fileType,
        null,
        activeTab.name,
      );
      if (!savedPath) return;
      getDocumentIdentityStore().register(savedPath, activeTab.documentId);
      usePolicyTabsStore.getState().setFilePath(activeTabId, savedPath);
      usePolicyEditStore.getState().markClean(activeTabId);
      usePolicyTabsStore.getState().setDirty(activeTabId, false);
      pushRecentFile(savedPath);
    } catch (err) {
      console.error("[init-commands] Failed to save file:", err);
    }
  }, [exportYaml]);

  const saveFile = useCallback(async () => {
    const activeTabId = usePolicyTabsStore.getState().activeTabId;
    const activeTab = usePolicyTabsStore.getState().tabs.find(t => t.id === activeTabId);
    const editState = usePolicyEditStore.getState().editStates.get(activeTabId);
    if (!activeTab || !editState) return;
    try {
      if (!isDesktop()) {
        exportYaml();
        return;
      }
      if (activeTab.filePath) {
        await saveDetectionFile(
          editState.yaml,
          activeTab.fileType,
          activeTab.filePath,
          activeTab.name,
        );
        usePolicyEditStore.getState().markClean(activeTabId);
        usePolicyTabsStore.getState().setDirty(activeTabId, false);
      } else {
        await saveFileAs();
      }
    } catch (err) {
      console.error("[init-commands] Failed to save file:", err);
    }
  }, [exportYaml, saveFileAs]);

  const undo = useCallback(() => {
    const id = usePolicyTabsStore.getState().activeTabId;
    usePolicyEditStore.getState().undo(id);
    usePolicyTabsStore.getState().setDirty(id, usePolicyEditStore.getState().isDirty(id));
  }, []);

  const redo = useCallback(() => {
    const id = usePolicyTabsStore.getState().activeTabId;
    usePolicyEditStore.getState().redo(id);
    usePolicyTabsStore.getState().setDirty(id, usePolicyEditStore.getState().isDirty(id));
  }, []);

  useEffect(() => {
    registerNavigateCommands();

    registerFileCommands({
      saveFile,
      saveFileAs,
      openFile,
      exportYaml,
      copyYaml,
    });

    registerEditCommands({
      undo,
      redo,
      getActiveTab: () => usePolicyTabsStore.getState().getActiveTab(),
    });

    registerPolicyCommands({
      getActiveTab: () => usePolicyTabsStore.getState().getActiveTab(),
      getActivePolicy: () => {
        const activeTabId = usePolicyTabsStore.getState().activeTabId;
        const editState = usePolicyEditStore.getState().editStates.get(activeTabId);
        return editState?.policy ?? DEFAULT_POLICY;
      },
      getYaml: () => {
        const activeTabId = usePolicyTabsStore.getState().activeTabId;
        const editState = usePolicyEditStore.getState().editStates.get(activeTabId);
        return editState?.yaml ?? "";
      },
      getDirty: () => {
        const activeTab = usePolicyTabsStore.getState().getActiveTab();
        return activeTab?.dirty ?? false;
      },
    });

    registerViewCommands({
      toggleShortcutHelp: toggleHelp,
      splitVertical: () =>
        usePaneStore.getState().splitPane(usePaneStore.getState().activePaneId, "vertical"),
      splitHorizontal: () =>
        usePaneStore.getState().splitPane(usePaneStore.getState().activePaneId, "horizontal"),
      closePane: () =>
        usePaneStore.getState().closePane(usePaneStore.getState().activePaneId),
      focusPane: (direction) => usePaneStore.getState().focusPane(direction),
      hasMultiplePanes: () => usePaneStore.getState().paneCount() > 1,
      toggleTerminal: () => useBottomPaneStore.getState().toggleTab("terminal"),
      toggleProblems: () => useBottomPaneStore.getState().toggleTab("problems"),
      toggleOutput: () => useBottomPaneStore.getState().toggleTab("output"),
      newTerminal: () => useBottomPaneStore.getState().newTerminal(),
      closeTerminal: () => {
        const { activeTerminalId } = useBottomPaneStore.getState();
        if (!activeTerminalId) return Promise.resolve();
        return useBottomPaneStore.getState().closeTerminal(activeTerminalId);
      },
      hasActiveTerminal: () => !!useBottomPaneStore.getState().activeTerminalId,
      toggleSidebar: () => useActivityBarStore.getState().actions.toggleSidebar(),
      showExplorer: () => useActivityBarStore.getState().actions.showPanel("explorer"),
      showSearch: () => useActivityBarStore.getState().actions.showPanel("search"),
      closeActiveTab: () => {
        const { root, activePaneId } = usePaneStore.getState();
        const allGroups = getAllPaneGroups(root);
        const activePane = allGroups.find((g) => g.id === activePaneId);
        if (activePane?.activeViewId) {
          usePaneStore.getState().closeView(activePaneId, activePane.activeViewId);
        }
      },
      toggleRightSidebar: () => useRightSidebarStore.getState().actions.toggle(),
      showSentinels: () => useActivityBarStore.getState().actions.showPanel("sentinels"),
      showFindings: () => useActivityBarStore.getState().actions.showPanel("findings"),
      showLibrary: () => useActivityBarStore.getState().actions.showPanel("library"),
      showFleet: () => useActivityBarStore.getState().actions.showPanel("fleet"),
      showCompliance: () => useActivityBarStore.getState().actions.showPanel("compliance"),
      showHeartbeat: () => useActivityBarStore.getState().actions.showPanel("heartbeat"),
      showObservatory: () => useActivityBarStore.getState().actions.showPanel("observatory"),
      toggleAudit: () => useBottomPaneStore.getState().toggleTab("audit"),
    });

    registerHuntronomerCommands();

    // No cleanup needed — commands are re-registered (overwritten) when deps change.
    // The registry uses a Map keyed by id, so re-registration is idempotent.
  }, [
    saveFile,
    saveFileAs,
    openFile,
    exportYaml,
    copyYaml,
    undo,
    redo,
    toggleHelp,
  ]);

  return <ShortcutHelpDialog open={helpOpen} onOpenChange={setHelpOpen} />;
}
