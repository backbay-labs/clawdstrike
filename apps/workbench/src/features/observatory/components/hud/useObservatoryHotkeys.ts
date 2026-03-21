import { useEffect } from "react";
import { useObservatoryStore } from "../../stores/observatory-store";
import type { HudPanelId } from "../../types";

const HOTKEY_MAP: Record<string, HudPanelId> = {
  e: "explainability",
  r: "replay",
  m: "mission",
  g: "ghost",
};

/**
 * useObservatoryHotkeys
 *
 * Binds E/R/M/G/Escape to panel registry actions.
 * Only fires when `enabled` is true (caller passes `paneIsActive` so hotkeys
 * are suppressed when the observatory tab is not the focused pane).
 *
 * Phase 30 HUD-14/HUD-15: keyboard-driven panel control.
 */
export function useObservatoryHotkeys(enabled: boolean): void {
  useEffect(() => {
    if (!enabled) return;

    function handleKeyDown(event: KeyboardEvent) {
      // Don't intercept when typing in input/textarea/contenteditable
      const target = event.target as HTMLElement | null;
      const tag = target?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || target?.isContentEditable) {
        return;
      }

      const key = event.key.toLowerCase();

      if (key === "escape") {
        useObservatoryStore.getState().actions.closePanel();
        return;
      }

      const panelId = HOTKEY_MAP[key];
      if (panelId) {
        useObservatoryStore.getState().actions.togglePanel(panelId);
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [enabled]);
}
