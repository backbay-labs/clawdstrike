import type { ReactNode } from "react";
import { WorkspaceShellScreen } from "./WorkspaceShellScreen";

export type WorkspaceShellRoutePath =
  | "/workspace"
  | "/workspace/tree"
  | "/workspace/search"
  | "/workspace/git"
  | "/workspace/terminal"
  | "/workspace/file/:fileId";

export interface WorkspaceShellRouteDefinition {
  id: string;
  path: WorkspaceShellRoutePath;
  title: string;
  description: string;
  element: ReactNode;
}

export function getWorkspaceShellRoutes(): WorkspaceShellRouteDefinition[] {
  return [
    {
      id: "workspace-home",
      path: "/workspace",
      title: "Workspace",
      description: "Workspace overview with trusted roots and active panes",
      element: <WorkspaceShellScreen section="workspace" />,
    },
    {
      id: "workspace-tree",
      path: "/workspace/tree",
      title: "Workspace Tree",
      description: "Tree-focused workspace view",
      element: <WorkspaceShellScreen section="tree" />,
    },
    {
      id: "workspace-search",
      path: "/workspace/search",
      title: "Workspace Search",
      description: "Search-focused workspace view",
      element: <WorkspaceShellScreen section="search" />,
    },
    {
      id: "workspace-git",
      path: "/workspace/git",
      title: "Workspace Git",
      description: "Git-focused workspace view",
      element: <WorkspaceShellScreen section="git" />,
    },
    {
      id: "workspace-terminal",
      path: "/workspace/terminal",
      title: "Workspace Terminal",
      description: "Terminal-focused workspace view",
      element: <WorkspaceShellScreen section="terminal" />,
    },
    {
      id: "workspace-file",
      path: "/workspace/file/:fileId",
      title: "Workspace File",
      description: "Single-file workspace view",
      element: <WorkspaceShellScreen section="file" />,
    },
  ];
}
