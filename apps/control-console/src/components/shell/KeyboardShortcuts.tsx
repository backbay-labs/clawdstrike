import type { WindowId } from "@backbay/glia-desktop";
import { useDesktopOS } from "@backbay/glia-desktop";
import { useMemo } from "react";
import { type Shortcut, useKeyboardShortcuts } from "../../hooks/useKeyboardShortcuts";
import { pinnedAppIds } from "../../state/processRegistry";

export function KeyboardShortcuts({
  onToggleCommandPalette,
  onLock,
  onToggleSidebar,
}: {
  onToggleCommandPalette: () => void;
  onLock: () => void;
  /** Toggle the sidebar collapsed state (⌘\\ / Ctrl+\\, VS Code parity). */
  onToggleSidebar: () => void;
}) {
  const { processes, windows } = useDesktopOS();

  const shortcuts = useMemo<Shortcut[]>(
    () => [
      ...pinnedAppIds.slice(0, 5).map((id, i) => ({
        key: String(i + 1),
        ctrl: true,
        label: `Launch ${id}`,
        action: () => processes.launch(id),
      })),
      {
        key: "Escape",
        label: "Close focused window",
        action: () => {
          if (windows.focusedId) windows.close(windows.focusedId as WindowId);
        },
      },
      { key: "k", ctrl: true, label: "Command palette", action: onToggleCommandPalette },
      { key: "l", ctrl: true, label: "Lock screen", action: onLock },
      // ⌘\\ / Ctrl+\\ — toggle the sidebar (no conflict with ⌘1-5, ⌘K, ⌘L, Esc).
      { key: "\\", ctrl: true, label: "Toggle sidebar", action: onToggleSidebar },
    ],
    [processes, windows, onToggleCommandPalette, onLock, onToggleSidebar],
  );

  useKeyboardShortcuts(shortcuts);
  return null;
}
