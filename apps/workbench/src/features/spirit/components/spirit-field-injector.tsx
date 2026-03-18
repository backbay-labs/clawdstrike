/**
 * SpiritFieldInjector — zero-render component that injects spirit CSS custom
 * properties into :root whenever spirit-store state changes.
 *
 * Renders null. Mounted once inside DesktopLayout.
 *
 * CSS vars injected:
 *   --spirit-accent              hex color or "transparent"
 *   --spirit-field-stain         hex+08 (5% alpha) or "transparent"
 *   --spirit-field-stain-strong  hex+14 (8% alpha) or "transparent"
 */
import { useEffect } from "react";
import { useSpiritStore } from "../stores/spirit-store";

export function SpiritFieldInjector() {
  const kind = useSpiritStore.use.kind();
  const accentColor = useSpiritStore.use.accentColor();

  useEffect(() => {
    const root = document.documentElement;
    if (kind === null || accentColor === null) {
      root.style.setProperty("--spirit-accent", "transparent");
      root.style.setProperty("--spirit-field-stain", "transparent");
      root.style.setProperty("--spirit-field-stain-strong", "transparent");
    } else {
      // Strip leading # for concatenation
      const hex = accentColor.replace("#", "");
      root.style.setProperty("--spirit-accent", accentColor);
      root.style.setProperty("--spirit-field-stain", `#${hex}08`);
      root.style.setProperty("--spirit-field-stain-strong", `#${hex}14`);
    }
  }, [kind, accentColor]);

  return null;
}
