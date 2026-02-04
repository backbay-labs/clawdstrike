/**
 * useShellShortcuts - Global keyboard shortcuts for shell navigation
 *
 * Shortcuts:
 * - Cmd+1-6: Navigate to view by index
 * - Cmd+,: Settings
 * - Cmd+K: Command palette
 * - Cmd+F: Focus search
 * - Cmd+N: New session
 * - Cmd+[/]: Previous/next view
 * - Esc: Close modal/panel
 */
import { useEffect, useCallback } from "react";
import type { AppId } from "../plugins/types";

// View mapping for quick number key navigation
const VIEW_KEYS: Record<string, AppId> = {
  "1": "events",
  "2": "policies",
  "3": "policy-tester",
  "4": "swarm",
  "5": "marketplace",
  "6": "workflows",
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

      // Cmd+1-6: Select view by index
      if (isMeta && VIEW_KEYS[key] && handlers.onSelectApp) {
        e.preventDefault();
        handlers.onSelectApp(VIEW_KEYS[key]);
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
    [handlers]
  );

  useEffect(() => {
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);
}
