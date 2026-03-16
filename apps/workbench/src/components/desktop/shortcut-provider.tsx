import { useMemo, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useKeyboardShortcuts, type ShortcutAction } from "@/lib/keyboard-shortcuts";
import { useWorkbench, useMultiPolicy } from "@/lib/workbench/multi-policy-store";
import { isDesktop } from "@/lib/tauri-bridge";
import { isPolicyFileType } from "@/lib/workbench/file-type-registry";
import { policyToYaml } from "@/lib/workbench/yaml-utils";
import { triggerNativeValidation } from "@/lib/workbench/use-native-validation";
import { ShortcutHelpDialog } from "./shortcut-help-dialog";

export const SHORTCUT_DEFINITIONS = [
  // File
  { key: "s", meta: true, shift: false, description: "Save current file", category: "File" },
  { key: "s", meta: true, shift: true, description: "Save As", category: "File" },
  { key: "n", meta: true, shift: false, description: "New policy", category: "File" },
  { key: "o", meta: true, shift: false, description: "Open detection file", category: "File" },
  { key: "e", meta: true, shift: false, description: "Export current source", category: "File" },
  // Tabs
  { key: "t", meta: true, shift: false, description: "New tab", category: "Tabs" },
  { key: "w", meta: true, shift: false, description: "Close tab", category: "Tabs" },
  // Edit
  { key: "z", meta: true, shift: false, description: "Undo", category: "Edit" },
  { key: "z", meta: true, shift: true, description: "Redo", category: "Edit" },
  { key: "b", meta: true, shift: false, description: "Toggle sidebar", category: "Edit" },
  // Policy
  { key: "v", meta: true, shift: true, description: "Validate current file", category: "Policy" },
  { key: "y", meta: true, shift: true, description: "Copy current source", category: "Policy" },
  // Navigate
  { key: "1", meta: true, shift: false, description: "Editor", category: "Navigate" },
  { key: "2", meta: true, shift: false, description: "Threat Lab", category: "Navigate" },
  { key: "3", meta: true, shift: false, description: "Compare", category: "Navigate" },
  { key: "4", meta: true, shift: false, description: "Compliance", category: "Navigate" },
  { key: "5", meta: true, shift: false, description: "Receipts", category: "Navigate" },
  { key: "6", meta: true, shift: false, description: "Library", category: "Navigate" },
  // Help
  { key: "/", meta: true, shift: false, description: "Show keyboard shortcuts", category: "Help" },
] as const;

const NAV_ROUTES = [
  "/editor",
  "/simulator",
  "/compare",
  "/compliance",
  "/receipts",
  "/library",
] as const;

/**
 * Registers all app-wide keyboard shortcuts.
 * Must be rendered inside both <WorkbenchProvider> and a router context.
 */
export function ShortcutProvider() {
  const {
    state,
    dispatch,
    exportYaml,
    copyYaml,
    openFile,
    saveFile,
    saveFileAs,
    newPolicy,
    undo,
    redo,
  } = useWorkbench();
  const { multiDispatch, activeTab } = useMultiPolicy();
  const navigate = useNavigate();
  const [helpOpen, setHelpOpen] = useState(false);

  const handleToggleSidebar = useCallback(() => {
    dispatch({
      type: "SET_SIDEBAR_COLLAPSED",
      collapsed: !state.ui.sidebarCollapsed,
    });
  }, [dispatch, state.ui.sidebarCollapsed]);

  const handleValidate = useCallback(() => {
    if (!activeTab) return;
    const source = isPolicyFileType(activeTab.fileType)
      ? policyToYaml(state.activePolicy)
      : state.yaml;
    const shouldSyncYaml = isPolicyFileType(activeTab.fileType)
      && (state.dirty || source !== state.yaml);

    if (shouldSyncYaml) {
      dispatch({ type: "SET_YAML", yaml: source });
    }

    if (isDesktop()) {
      void triggerNativeValidation(activeTab.fileType, source, dispatch);
    }

    navigate("/editor");
  }, [activeTab, state.activePolicy, state.yaml, state.dirty, dispatch, navigate]);

  const handleNewTab = useCallback(() => {
    multiDispatch({ type: "NEW_TAB" });
    navigate("/editor");
  }, [multiDispatch, navigate]);

  const handleCloseTab = useCallback(() => {
    if (!activeTab) return;
    if (activeTab.dirty) {
      const confirmed = window.confirm(`"${activeTab.name}" has unsaved changes. Close anyway?`);
      if (!confirmed) return;
    }
    multiDispatch({ type: "CLOSE_TAB", tabId: activeTab.id });
  }, [activeTab, multiDispatch]);

  const shortcuts: ShortcutAction[] = useMemo(
    () => [
      // File — shift:true entries must come before shift:false to match first
      { key: "s", meta: true, shift: true, description: "Save As", action: () => void saveFileAs() },
      { key: "s", meta: true, description: "Save current file", action: () => void saveFile() },
      { key: "n", meta: true, description: "New policy", action: () => { newPolicy(); navigate("/editor"); } },
      { key: "o", meta: true, description: "Open detection file", action: async () => { await openFile(); navigate("/editor"); } },
      { key: "e", meta: true, description: "Export current source", action: exportYaml },
      // Tabs
      { key: "t", meta: true, description: "New tab", action: handleNewTab },
      { key: "w", meta: true, description: "Close tab", action: handleCloseTab },
      // Edit — shift:true entries must come before shift:false for same key
      { key: "z", meta: true, shift: true, description: "Redo", action: redo },
      { key: "z", meta: true, description: "Undo", action: undo },
      { key: "b", meta: true, description: "Toggle sidebar", action: handleToggleSidebar },
      // Policy
      { key: "v", meta: true, shift: true, description: "Validate current file", action: handleValidate },
      { key: "y", meta: true, shift: true, description: "Copy current source", action: copyYaml },
      // Navigate (Cmd+1..6)
      ...NAV_ROUTES.map((route, i) => ({
        key: String(i + 1),
        meta: true,
        description: `Navigate to ${route.slice(1)}`,
        action: () => navigate(route),
      })),
      // Help — Cmd+/ (and Cmd+Shift+/ which produces "?" as e.key on many keyboards)
      { key: "/", meta: true, description: "Show keyboard shortcuts", action: () => setHelpOpen((prev) => !prev) },
      { key: "?", meta: true, shift: true, description: "Show keyboard shortcuts", action: () => setHelpOpen((prev) => !prev) },
    ],
    [
      saveFile,
      saveFileAs,
      newPolicy,
      openFile,
      exportYaml,
      handleNewTab,
      handleCloseTab,
      undo,
      redo,
      handleToggleSidebar,
      handleValidate,
      copyYaml,
      navigate,
    ],
  );

  useKeyboardShortcuts(shortcuts);

  return <ShortcutHelpDialog open={helpOpen} onOpenChange={setHelpOpen} />;
}
