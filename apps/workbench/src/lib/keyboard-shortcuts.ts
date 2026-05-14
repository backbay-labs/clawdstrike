import { useEffect } from "react";

export interface ShortcutAction {
  key: string;
  meta: boolean;
  shift?: boolean;
  alt?: boolean;
  description: string;
  action: () => void;
}

/**
 * Hook that registers global keyboard shortcuts via a keydown listener.
 *
 * Matched shortcuts have their default browser behavior suppressed
 * (e.g. Cmd+S will not trigger the browser "Save Page" dialog).
 */
export function useKeyboardShortcuts(shortcuts: ShortcutAction[]): void {
  useEffect(() => {
    function handleKeydown(e: KeyboardEvent) {
      // Use metaKey on macOS, ctrlKey elsewhere
      const modifierPressed = e.metaKey || e.ctrlKey;

      for (const shortcut of shortcuts) {
        const keyMatches = e.key.toLowerCase() === shortcut.key.toLowerCase();
        const metaMatches = shortcut.meta ? modifierPressed : !modifierPressed;
        const shiftMatches = shortcut.shift ? e.shiftKey : !e.shiftKey;
        const altMatches = shortcut.alt ? e.altKey : !e.altKey;

        if (keyMatches && metaMatches && shiftMatches && altMatches) {
          e.preventDefault();
          e.stopPropagation();
          shortcut.action();
          return;
        }
      }
    }

    window.addEventListener("keydown", handleKeydown, { capture: true });
    return () => {
      window.removeEventListener("keydown", handleKeydown, { capture: true });
    };
  }, [shortcuts]);
}
