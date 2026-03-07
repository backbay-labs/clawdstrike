import type { PaletteCommand } from "@/shell/components/CommandPalette";
import type { WorkspacePaneId } from "@/features/workspace/state/workspaceShellState";

export const WORKSPACE_OPEN_FOLDER_EVENT = "huntronomer:workspace:open-folder";
export const WORKSPACE_SAVE_ACTIVE_FILE_EVENT = "huntronomer:workspace:save-active-file";

export type WorkspaceCommandScope =
  | "global"
  | "wire"
  | "huntboard"
  | "vault"
  | "replay"
  | "cases"
  | "profile"
  | "workspace"
  | "settings";

export interface WorkspaceCommandContext {
  activeScope: WorkspaceCommandScope;
  workspaceRootId?: string;
  activeSurfaceRoute: string;
  activeObject?: { type: string; id: string };
  selectedObjectIds: string[];
  focusedPane?: WorkspacePaneId;
  connectivity: {
    daemon: "connected" | "degraded" | "offline";
    openclaw: "connected" | "degraded" | "offline";
  };
}

export type WorkspaceCommandResult =
  | { kind: "navigate"; to: string }
  | { kind: "invoke"; action: string; payload?: Record<string, unknown> }
  | { kind: "open-panel"; panel: string; payload?: Record<string, unknown> }
  | { kind: "toast"; level: "info" | "warning" | "error"; message: string }
  | { kind: "noop" };

export interface WorkspaceShellCommand {
  id: string;
  title: string;
  description?: string;
  keywords?: string[];
  group: string;
  scope: WorkspaceCommandScope | WorkspaceCommandScope[];
  shortcut?: string;
  when?: (context: WorkspaceCommandContext) => boolean;
  run: (context: WorkspaceCommandContext) => WorkspaceCommandResult | Promise<WorkspaceCommandResult>;
}

const workspaceCommands: WorkspaceShellCommand[] = [
  {
    id: "workspace.open",
    title: "Open Workspace",
    description: "Navigate to the workspace surface",
    keywords: ["workspace", "shell", "authoring"],
    group: "Workspace",
    scope: "global",
    shortcut: "Cmd+Shift+W",
    run: () => ({ kind: "navigate", to: "/workspace" }),
  },
  {
    id: "workspace.open-folder",
    title: "Open Folder",
    description: "Choose a candidate folder and register it as a trusted root",
    keywords: ["workspace", "folder", "trust", "root"],
    group: "Workspace",
    scope: ["global", "workspace"],
    run: () => ({ kind: "invoke", action: WORKSPACE_OPEN_FOLDER_EVENT }),
  },
  {
    id: "workspace.quick-open",
    title: "Quick Open File",
    description: "Search for a path inside the active trusted root",
    keywords: ["workspace", "file", "quick", "path"],
    group: "Workspace",
    scope: "workspace",
    shortcut: "Cmd+P",
    when: (context) => Boolean(context.workspaceRootId),
    run: () => ({ kind: "open-panel", panel: "workspace-search", payload: { mode: "paths" } }),
  },
  {
    id: "workspace.search",
    title: "Search In Workspace",
    description: "Open content search for the active root",
    keywords: ["workspace", "search", "rg"],
    group: "Workspace",
    scope: "workspace",
    shortcut: "Cmd+Shift+F",
    when: (context) => Boolean(context.workspaceRootId),
    run: () => ({ kind: "navigate", to: "/workspace/search" }),
  },
  {
    id: "workspace.terminal",
    title: "Open Workspace Terminal",
    description: "Show the PTY-backed terminal panel for the active root",
    keywords: ["workspace", "terminal", "shell"],
    group: "Workspace",
    scope: "workspace",
    shortcut: "Ctrl+`",
    when: (context) => Boolean(context.workspaceRootId),
    run: () => ({ kind: "navigate", to: "/workspace/terminal" }),
  },
  {
    id: "workspace.git-status",
    title: "Open Git Status",
    description: "Navigate to the workspace git status panel",
    keywords: ["workspace", "git", "status"],
    group: "Workspace",
    scope: "workspace",
    when: (context) => Boolean(context.workspaceRootId),
    run: () => ({ kind: "navigate", to: "/workspace/git" }),
  },
  {
    id: "workspace.save-file",
    title: "Save Active File",
    description: "Persist the active workspace file through the backend service",
    keywords: ["workspace", "save", "file"],
    group: "Workspace",
    scope: "workspace",
    shortcut: "Cmd+S",
    when: (context) => context.activeScope === "workspace" && context.focusedPane === "main",
    run: () => ({ kind: "invoke", action: WORKSPACE_SAVE_ACTIVE_FILE_EVENT }),
  },
];

export function getWorkspaceShellCommands() {
  return workspaceCommands;
}

export function getEligibleWorkspaceCommands(context: WorkspaceCommandContext) {
  return workspaceCommands.filter((command) => {
    const scopes = Array.isArray(command.scope) ? command.scope : [command.scope];
    if (!scopes.includes("global") && !scopes.includes(context.activeScope)) {
      return false;
    }

    return command.when ? command.when(context) : true;
  });
}

export function createWorkspacePaletteCommands(
  context: WorkspaceCommandContext,
  onRun: (result: WorkspaceCommandResult, command: WorkspaceShellCommand) => void,
): PaletteCommand[] {
  return getEligibleWorkspaceCommands(context).map((command) => ({
    id: command.id,
    group: command.group,
    title: command.title,
    description: command.description,
    shortcut: command.shortcut,
    action: async () => {
      const result = await command.run(context);
      onRun(result, command);
    },
  }));
}
