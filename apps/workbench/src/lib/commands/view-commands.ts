import type { PaneFocusDirection } from "@/features/panes/pane-types";
import { commandRegistry } from "@/lib/command-registry";
import type { Command } from "@/lib/command-registry";
import { useRightSidebarStore } from "@/features/right-sidebar/stores/right-sidebar-store";

export interface ViewCommandDeps {
  toggleShortcutHelp: () => void;
  splitVertical: () => void;
  splitHorizontal: () => void;
  closePane: () => void;
  focusPane: (direction: PaneFocusDirection) => void;
  hasMultiplePanes: () => boolean;
  toggleTerminal: () => void;
  toggleProblems: () => void;
  toggleOutput: () => void;
  newTerminal: () => Promise<void>;
  closeTerminal: () => Promise<void>;
  hasActiveTerminal: () => boolean;
  toggleSidebar: () => void;
  showExplorer: () => void;
  showSearch: () => void;
  closeActiveTab: () => void;
  toggleRightSidebar: () => void;
  showSentinels: () => void;
  showFindings: () => void;
  showLibrary: () => void;
  showFleet: () => void;
  showCompliance: () => void;
  showHeartbeat: () => void;
  showObservatory: () => void;
  toggleAudit: () => void;
}

export function registerViewCommands(deps: ViewCommandDeps): void {
  const commands: Command[] = [
    {
      id: "view.shortcuts",
      title: "Show Keyboard Shortcuts",
      category: "Help",
      keybinding: "Meta+/",
      context: "global",
      execute: () => deps.toggleShortcutHelp(),
    },
    {
      id: "view.splitVertical",
      title: "Split Pane Vertically",
      category: "View",
      keybinding: "Meta+\\",
      context: "pane",
      execute: () => deps.splitVertical(),
    },
    {
      id: "view.splitHorizontal",
      title: "Split Pane Horizontally",
      category: "View",
      keybinding: "Meta+Shift+\\",
      context: "pane",
      execute: () => deps.splitHorizontal(),
    },
    {
      id: "view.closePane",
      title: "Close Active Pane",
      category: "View",
      keybinding: "Meta+Shift+W",
      context: "pane",
      when: () => deps.hasMultiplePanes(),
      execute: () => deps.closePane(),
    },
    {
      id: "view.focusLeft",
      title: "Focus Left Pane",
      category: "View",
      keybinding: "Meta+Alt+ArrowLeft",
      context: "pane",
      when: () => deps.hasMultiplePanes(),
      execute: () => deps.focusPane("left"),
    },
    {
      id: "view.focusRight",
      title: "Focus Right Pane",
      category: "View",
      keybinding: "Meta+Alt+ArrowRight",
      context: "pane",
      when: () => deps.hasMultiplePanes(),
      execute: () => deps.focusPane("right"),
    },
    {
      id: "view.focusUp",
      title: "Focus Upper Pane",
      category: "View",
      keybinding: "Meta+Alt+ArrowUp",
      context: "pane",
      when: () => deps.hasMultiplePanes(),
      execute: () => deps.focusPane("up"),
    },
    {
      id: "view.focusDown",
      title: "Focus Lower Pane",
      category: "View",
      keybinding: "Meta+Alt+ArrowDown",
      context: "pane",
      when: () => deps.hasMultiplePanes(),
      execute: () => deps.focusPane("down"),
    },
    {
      id: "view.toggleTerminal",
      title: "Toggle Terminal Panel",
      category: "View",
      keybinding: "Meta+J",
      context: "global",
      execute: () => deps.toggleTerminal(),
    },
    {
      id: "view.toggleProblems",
      title: "Toggle Problems Panel",
      category: "View",
      keybinding: "Meta+Shift+M",
      context: "global",
      execute: () => deps.toggleProblems(),
    },
    {
      id: "view.toggleOutput",
      title: "Toggle Output Panel",
      category: "View",
      context: "global",
      execute: () => deps.toggleOutput(),
    },
    {
      id: "terminal.new",
      title: "New Terminal Session",
      category: "View",
      keybinding: "Meta+Shift+`",
      context: "global",
      execute: () => deps.newTerminal(),
    },
    {
      id: "terminal.close",
      title: "Close Active Terminal Session",
      category: "View",
      context: "terminal",
      when: () => deps.hasActiveTerminal(),
      execute: () => deps.closeTerminal(),
    },
    {
      id: "sidebar.toggle",
      title: "Toggle Sidebar",
      category: "View",
      keybinding: "Meta+B",
      context: "global",
      execute: () => deps.toggleSidebar(),
    },
    {
      id: "sidebar.explorer",
      title: "Show Explorer",
      category: "Sidebar",
      keybinding: "Meta+Shift+E",
      context: "global",
      execute: () => deps.showExplorer(),
    },
    {
      id: "sidebar.search",
      title: "Search in Files",
      category: "Sidebar",
      keybinding: "Meta+Shift+F",
      context: "global",
      execute: () => deps.showSearch(),
    },
    {
      id: "tab.close",
      title: "Close Active Tab",
      category: "View",
      keybinding: "Meta+W",
      context: "pane",
      execute: () => deps.closeActiveTab(),
    },
    {
      id: "sidebar.toggleRight",
      title: "Toggle Right Sidebar",
      category: "View",
      keybinding: "Meta+Shift+B",
      context: "global",
      execute: () => deps.toggleRightSidebar(),
    },
    {
      id: "sidebar.sentinels",
      title: "Show Sentinels",
      category: "Sidebar",
      context: "global",
      execute: () => deps.showSentinels(),
    },
    {
      id: "sidebar.findings",
      title: "Show Findings",
      category: "Sidebar",
      context: "global",
      execute: () => deps.showFindings(),
    },
    {
      id: "sidebar.library",
      title: "Show Library",
      category: "Sidebar",
      context: "global",
      execute: () => deps.showLibrary(),
    },
    {
      id: "sidebar.fleet",
      title: "Show Fleet",
      category: "Sidebar",
      context: "global",
      execute: () => deps.showFleet(),
    },
    {
      id: "sidebar.compliance",
      title: "Show Compliance",
      category: "Sidebar",
      context: "global",
      execute: () => deps.showCompliance(),
    },
    {
      id: "sidebar.heartbeat",
      title: "Show System Status",
      category: "Sidebar",
      context: "global",
      execute: () => deps.showHeartbeat(),
    },
    {
      id: "observatory.minimap",
      title: "Show Observatory Minimap",
      category: "Observatory",
      context: "global",
      execute: () => deps.showObservatory(),
    },
    {
      id: "view.toggleAudit",
      title: "Toggle Audit Panel",
      category: "View",
      context: "global",
      execute: () => deps.toggleAudit(),
    },
    {
      id: "rightSidebar.evidence",
      title: "Show Evidence Packs",
      category: "View",
      context: "global",
      execute: () => {
        const store = useRightSidebarStore.getState();
        store.actions.setActivePanel("evidence");
        store.actions.show();
      },
    },
    {
      id: "rightSidebar.explain",
      title: "Show Explainability Traces",
      category: "View",
      context: "global",
      execute: () => {
        const store = useRightSidebarStore.getState();
        store.actions.setActivePanel("explain");
        store.actions.show();
      },
    },
    {
      id: "rightSidebar.history",
      title: "Show Version History",
      category: "View",
      context: "global",
      execute: () => {
        const store = useRightSidebarStore.getState();
        store.actions.setActivePanel("history");
        store.actions.show();
      },
    },
  ];

  commandRegistry.registerAll(commands);
}
