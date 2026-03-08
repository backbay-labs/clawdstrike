/**
 * useShellShortcuts - Global keyboard shortcuts for shell navigation
 *
 * Shortcuts (v1 / legacy):
 * - Cmd+1-9: Navigate to view by index
 * - Cmd+,: Operations
 * - Cmd+K: Command palette
 * - Cmd+F: Focus search
 * - Cmd+N: New session
 * - Cmd+[/]: Previous/next view
 * - Esc: Close modal/panel
 *
 * Shortcuts (workbench v2, when isWorkbench=true):
 * - Cmd+1-7: Select lens by index
 * - Cmd+Shift+1-4: Switch shell (wire, hunt, lab, case)
 * - Cmd+Shift+B: Toggle sidebar
 * - Cmd+J: Toggle bottom panel
 * - Cmd+\: Toggle context inspector
 * - Cmd+W: Close active tab
 * - Ctrl+Tab: Next tab in active pane
 * - Ctrl+Shift+Tab: Previous tab in active pane
 */
import { useCallback, useEffect } from "react";
import type { AppId } from "../plugins/types";

// View mapping for quick number key navigation
const VIEW_KEYS: Record<string, AppId> = {
  "1": "nexus",
  "2": "operations",
  "3": "security-overview",
  "4": "threat-radar",
  "5": "attack-graph",
  "6": "network-map",
  "7": "marketplace",
  "8": "events",
  "9": "policies",
};

export interface ShellShortcutHandlers {
  onNewSession?: () => void;
  onOpenPalette?: () => void;
  onFocusSearch?: () => void;
  onSelectSessionByIndex?: (index: number) => void;
  onNextApp?: () => void;
  onPrevApp?: () => void;
  onSelectApp?: (appId: AppId) => void;
  onOpenSettings?: () => void;
  onCloseModal?: () => void;
  isWorkbench?: boolean;
  onSelectLens?: (index: number) => void;
  onSelectShell?: (index: number) => void;
  onToggleHuntDock?: () => void;
  onToggleSidebar?: () => void;
  onToggleBottomPanel?: () => void;
  onToggleInspector?: () => void;
  onCloseTab?: () => void;
  onNextTab?: () => void;
  onPrevTab?: () => void;
}

export function useShellShortcuts(handlers: ShellShortcutHandlers) {
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      // Don't capture if typing in input
      const target = e.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) {
        return;
      }

      const isMeta = e.metaKey || e.ctrlKey;
      const key = e.key.toLowerCase();

      // Escape: Close modal/panel
      if (key === "escape") {
        e.preventDefault();
        handlers.onCloseModal?.();
        return;
      }

      // Cmd+N: New session
      if (isMeta && key === "n") {
        e.preventDefault();
        handlers.onNewSession?.();
        return;
      }

      // Cmd+K: Open command palette
      if (isMeta && key === "k") {
        e.preventDefault();
        handlers.onOpenPalette?.();
        return;
      }

      // Cmd+F: Focus search
      if (isMeta && key === "f") {
        e.preventDefault();
        handlers.onFocusSearch?.();
        return;
      }

      // Cmd+,: Settings
      if (isMeta && key === ",") {
        e.preventDefault();
        handlers.onOpenSettings?.();
        return;
      }

      // Cmd+Shift+1-4: Switch shell (workbench v2)
      if (isMeta && e.shiftKey && ["1", "2", "3", "4"].includes(key)) {
        e.preventDefault();
        handlers.onSelectShell?.(parseInt(key, 10));
        return;
      }

      // Cmd+Shift+H: Toggle hunt dock (workbench v2)
      if (isMeta && e.shiftKey && key === "h") {
        e.preventDefault();
        handlers.onToggleHuntDock?.();
        return;
      }

      // Cmd+Shift+B: Toggle sidebar (workbench v2)
      if (isMeta && e.shiftKey && key === "b") {
        e.preventDefault();
        handlers.onToggleSidebar?.();
        return;
      }

      // Cmd+J: Toggle bottom panel (workbench v2)
      if (isMeta && key === "j") {
        e.preventDefault();
        handlers.onToggleBottomPanel?.();
        return;
      }

      // Cmd+\: Toggle inspector (workbench v2)
      if (isMeta && key === "\\") {
        e.preventDefault();
        handlers.onToggleInspector?.();
        return;
      }

      // Cmd+W: Close active tab (workbench v2)
      if (isMeta && key === "w") {
        e.preventDefault();
        handlers.onCloseTab?.();
        return;
      }

      // Ctrl+Tab / Ctrl+Shift+Tab: Next/prev tab in active pane
      if (e.ctrlKey && key === "tab") {
        e.preventDefault();
        if (e.shiftKey) {
          handlers.onPrevTab?.();
        } else {
          handlers.onNextTab?.();
        }
        return;
      }

      // Cmd+1-9: Select view by index (v1) or lens (v2)
      if (isMeta && !e.shiftKey && VIEW_KEYS[key]) {
        e.preventDefault();
        if (handlers.isWorkbench) {
          const index = parseInt(key, 10);
          if (index <= 7 && handlers.onSelectLens) {
            handlers.onSelectLens(index);
          }
          // In workbench mode, keys 8-9 have no lens mapping -- suppress legacy navigation
          return;
        }
        if (handlers.onSelectApp) {
          handlers.onSelectApp(VIEW_KEYS[key]);
        }
        return;
      }

      // Cmd+[: Previous app
      if (isMeta && key === "[") {
        e.preventDefault();
        handlers.onPrevApp?.();
        return;
      }

      // Cmd+]: Next app
      if (isMeta && key === "]") {
        e.preventDefault();
        handlers.onNextApp?.();
        return;
      }
    },
    [handlers],
  );

  useEffect(() => {
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);
}
