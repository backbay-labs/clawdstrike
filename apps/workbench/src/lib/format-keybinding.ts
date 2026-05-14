const isMac =
  typeof navigator !== "undefined" && /Mac|iPod|iPhone|iPad/.test(navigator.platform);

/** Format a keybinding string like "Meta+Shift+S" for display. */
export function formatKeybinding(binding: string): string {
  const parts = binding.split("+");
  const formatted: string[] = [];
  for (const part of parts) {
    if (part === "Meta") formatted.push(isMac ? "\u2318" : "Ctrl");
    else if (part === "Shift") formatted.push(isMac ? "\u21e7" : "Shift");
    else if (part === "Alt") formatted.push(isMac ? "\u2325" : "Alt");
    else if (part === "ArrowLeft") formatted.push(isMac ? "\u2190" : "Left");
    else if (part === "ArrowRight") formatted.push(isMac ? "\u2192" : "Right");
    else if (part === "ArrowUp") formatted.push(isMac ? "\u2191" : "Up");
    else if (part === "ArrowDown") formatted.push(isMac ? "\u2193" : "Down");
    else {
      const displayKey = part === "/" ? "?" : part.toUpperCase();
      formatted.push(displayKey);
    }
  }
  return formatted.join(isMac ? "" : "+");
}
