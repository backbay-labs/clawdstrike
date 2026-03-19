import { commandRegistry } from "@/lib/command-registry";
import type { Command } from "@/lib/command-registry";
import { usePaneStore } from "@/features/panes/pane-store";

/**
 * registerHuntronomerCommands — 5 Hunt-category commands for the command palette.
 *
 * All use usePaneStore.getState().openApp() to open views as pane tabs.
 * No keybindings initially — accessible via Cmd+K palette.
 * Category: "Hunt" — groups together in palette under Hunt header.
 */
export function registerHuntronomerCommands(): void {
  const commands: Command[] = [
    {
      id: "hunt.openHunt",
      title: "Open Hunt",
      category: "Hunt",
      execute: () => usePaneStore.getState().openApp("/hunt", "Hunt"),
    },
    {
      id: "hunt.openObservatory",
      title: "Open Observatory",
      category: "Hunt",
      execute: () => usePaneStore.getState().openApp("/observatory", "Observatory"),
    },
    {
      id: "hunt.openSpiritChamber",
      title: "Open Spirit Chamber",
      category: "Hunt",
      execute: () => usePaneStore.getState().openApp("/spirit-chamber", "Spirit Chamber"),
    },
    {
      id: "hunt.openNexus",
      title: "Open Nexus",
      category: "Hunt",
      execute: () => usePaneStore.getState().openApp("/nexus", "Nexus"),
    },
    {
      id: "hunt.bindSpirit",
      title: "Bind Spirit",
      category: "Hunt",
      execute: () => usePaneStore.getState().openApp("/spirit-chamber", "Spirit Chamber"),
    },
    {
      id: "observatory.probe",
      title: "Probe Active Station",
      category: "Hunt",
      execute: () => {
        window.dispatchEvent(new CustomEvent("observatory:probe"));
      },
    },
  ];

  commandRegistry.registerAll(commands);
}
