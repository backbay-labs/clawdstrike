export const SHELL_OPEN_COMMAND_PALETTE_EVENT = "shell:open-command-palette";

export function dispatchShellOpenCommandPalette() {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new Event(SHELL_OPEN_COMMAND_PALETTE_EVENT));
}
