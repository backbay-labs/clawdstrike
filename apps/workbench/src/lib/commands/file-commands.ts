import { commandRegistry } from "@/lib/command-registry";
import type { Command } from "@/lib/command-registry";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";
import { usePaneStore } from "@/features/panes/pane-store";

export interface FileCommandDeps {
  saveFile: () => Promise<void>;
  saveFileAs: () => Promise<void>;
  openFile: () => Promise<void>;
  exportYaml: () => void;
  copyYaml: () => void;
}

export function registerFileCommands(deps: FileCommandDeps): void {
  const { saveFile, saveFileAs, openFile, exportYaml, copyYaml } = deps;

  const commands: Command[] = [
    {
      id: "file.save",
      title: "Save",
      category: "File",
      keybinding: "Meta+S",
      context: "editor",
      execute: async () => {
        // Check if there's an active file-first tab
        const activeTab = usePolicyTabsStore.getState().getActiveTab();
        if (activeTab?.id) {
          const editState = usePolicyEditStore.getState().getTabEditState(activeTab.id);
          if (editState) {
            try {
              const { saveDetectionFile } = await import("@/lib/tauri-bridge");
              const savedPath = await saveDetectionFile(
                editState.yaml,
                activeTab.fileType,
                activeTab.filePath,
                activeTab.name,
              );
              if (!savedPath) return;
              if (!activeTab.filePath) {
                usePolicyTabsStore.getState().setFilePath(activeTab.id, savedPath);
              }
              usePolicyEditStore.getState().markClean(activeTab.id);
              usePolicyTabsStore.getState().setDirty(activeTab.id, false);
              return;
            } catch (err) {
              console.error("[file.save] Save failed:", err);
              return;
            }
          }
        }
        // Fallback to legacy save
        await saveFile();
      },
    },
    {
      id: "file.saveAs",
      title: "Save As",
      category: "File",
      keybinding: "Meta+Shift+S",
      context: "editor",
      execute: async () => {
        const activeTab = usePolicyTabsStore.getState().getActiveTab();
        if (activeTab?.id) {
          const editState = usePolicyEditStore.getState().getTabEditState(activeTab.id);
          if (editState) {
            try {
              const { saveDetectionFile } = await import("@/lib/tauri-bridge");
              const savedPath = await saveDetectionFile(
                editState.yaml,
                activeTab.fileType,
                null, // force Save As dialog
                activeTab.name,
              );
              if (!savedPath) return;
              usePolicyTabsStore.getState().setFilePath(activeTab.id, savedPath);
              usePolicyEditStore.getState().markClean(activeTab.id);
              usePolicyTabsStore.getState().setDirty(activeTab.id, false);
              return;
            } catch (err) {
              console.error("[file.saveAs] Save failed:", err);
              return;
            }
          }
        }
        // Fallback to legacy save
        await saveFileAs();
      },
    },
    {
      id: "file.new",
      title: "New Policy",
      category: "File",
      keybinding: "Meta+N",
      execute: () => {
        const newTabId = usePolicyTabsStore.getState().newTab();
        if (newTabId) {
          usePaneStore.getState().openApp(`/file/__new__/${newTabId}`, "Untitled");
        }
      },
    },
    {
      id: "file.open",
      title: "Open Detection File",
      category: "File",
      keybinding: "Meta+O",
      execute: async () => {
        await openFile();
        // Open the file that was just loaded via the dialog
        const activeTab = usePolicyTabsStore.getState().getActiveTab();
        if (activeTab) {
          const route = activeTab.filePath
            ? `/file/${activeTab.filePath}`
            : `/file/__new__/${activeTab.id}`;
          usePaneStore.getState().openApp(route, activeTab.name || "File");
        }
      },
    },
    {
      id: "file.export",
      title: "Export Current Source",
      category: "File",
      keybinding: "Meta+E",
      context: "editor",
      execute: () => exportYaml(),
    },
    {
      id: "file.copySource",
      title: "Copy Current Source",
      category: "File",
      keybinding: "Meta+Shift+Y",
      context: "editor",
      execute: () => copyYaml(),
    },
  ];

  commandRegistry.registerAll(commands);
}
