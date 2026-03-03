import type { WindowId } from "@backbay/glia-desktop";
import { useDesktopOS } from "@backbay/glia-desktop";
import { useMemo } from "react";
import { type Shortcut, useKeyboardShortcuts } from "../../hooks/useKeyboardShortcuts";
import { pinnedAppIds } from "../../state/processRegistry";

export function KeyboardShortcuts({
  onToggleCommandPalette,
  onLock,
}: {
  onToggleCommandPalette: () => void;
  onLock: () => void;
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
    ],
    [processes, windows, onToggleCommandPalette, onLock],
  );

  useKeyboardShortcuts(shortcuts);
  return null;
}
