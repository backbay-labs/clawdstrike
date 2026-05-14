import type React from "react";
import { commandRegistry } from "@/lib/command-registry";
import type { Command } from "@/lib/command-registry";
import type { TabMeta } from "@/features/policy/stores/policy-tabs-store";
import { openSearchPanel, searchKeymap, gotoLine } from "@codemirror/search";
import { getActiveEditorView } from "@/components/ui/yaml-editor";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePaneStore } from "@/features/panes/pane-store";

export interface EditCommandDeps {
  undo: () => void;
  redo: () => void;
  getActiveTab: () => TabMeta | undefined;
}

export function registerEditCommands(deps: EditCommandDeps): void {
  const { undo, redo, getActiveTab } = deps;

  const commands: Command[] = [
    {
      id: "edit.undo",
      title: "Undo",
      category: "Edit",
      keybinding: "Meta+Z",
      context: "editor",
      execute: () => undo(),
    },
    {
      id: "edit.redo",
      title: "Redo",
      category: "Edit",
      keybinding: "Meta+Shift+Z",
      context: "editor",
      execute: () => redo(),
    },
    {
      id: "edit.newTab",
      title: "New Tab",
      category: "Edit",
      keybinding: "Meta+T",
      context: "editor",
      execute: () => {
        const newTabId = usePolicyTabsStore.getState().newTab();
        if (newTabId) {
          usePaneStore.getState().openApp(`/file/__new__/${newTabId}`, "Untitled");
        }
      },
    },
    {
      id: "edit.closeTab",
      title: "Close Tab",
      category: "Edit",
      context: "editor",
      execute: () => {
        const tab = getActiveTab();
        if (!tab) return;
        if (tab.dirty) {
          const confirmed = window.confirm(
            `"${tab.name}" has unsaved changes. Close anyway?`,
          );
          if (!confirmed) return;
        }
        usePolicyTabsStore.getState().closeTab(tab.id);
      },
    },
    {
      id: "edit.find",
      title: "Find",
      category: "Edit",
      keybinding: "Meta+F",
      context: "editor",
      execute: () => {
        const view = getActiveEditorView();
        if (view) openSearchPanel(view);
      },
    },
    {
      id: "edit.replace",
      title: "Find and Replace",
      category: "Edit",
      keybinding: "Meta+H",
      context: "editor",
      execute: () => {
        const view = getActiveEditorView();
        if (!view) return;
        // Find the Mod-h command from searchKeymap which opens search with replace enabled
        const replaceCmd = searchKeymap.find(
          (k) => k.key === "Mod-h" || k.key === "Mod-H"
        );
        if (replaceCmd?.run) {
          replaceCmd.run(view);
        } else {
          // Fallback: open find-only panel
          openSearchPanel(view);
        }
      },
    },
    {
      id: "edit.goToLine",
      title: "Go to Line",
      category: "Edit",
      keybinding: "Meta+G",
      context: "editor",
      execute: () => {
        const view = getActiveEditorView();
        if (view) gotoLine(view);
      },
    },
  ];

  commandRegistry.registerAll(commands);
}
