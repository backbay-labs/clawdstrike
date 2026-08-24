import { useEffect } from "react";

export interface Shortcut {
  key: string;
  /**
   * Primary modifier. Matches EITHER ⌘ (metaKey) or Ctrl (ctrlKey) so the
   * "⌘"-labeled shortcuts (⌘K, ⌘L, ⌘1–5, ⌘\\) fire on macOS via Cmd while
   * continuing to work via the physical Control key on Windows/Linux.
   */
  ctrl?: boolean;
  alt?: boolean;
  shift?: boolean;
  action: () => void;
  label: string;
}

export function useKeyboardShortcuts(shortcuts: Shortcut[]): void {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Skip when focus is on an editable element to avoid intercepting text input
      const target = e.target as HTMLElement | null;
      if (target) {
        const tag = target.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || target.isContentEditable) {
          return;
        }
      }

      // The primary modifier is satisfied by Cmd OR Ctrl (mac uses Cmd; the
      // labels say "⌘" but Ctrl must keep working on other platforms).
      const primaryModifier = e.metaKey || e.ctrlKey;

      for (const s of shortcuts) {
        if (
          e.key.toLowerCase() === s.key.toLowerCase() &&
          primaryModifier === !!s.ctrl &&
          !!e.altKey === !!s.alt &&
          !!e.shiftKey === !!s.shift
        ) {
          e.preventDefault();
          s.action();
          return;
        }
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [shortcuts]);
}
