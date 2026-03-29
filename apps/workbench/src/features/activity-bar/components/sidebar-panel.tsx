import { useState, useEffect, useMemo } from "react";
import { useActivityBarStore } from "../stores/activity-bar-store";
import {
  ExplorerPanel,
  type ExplorerRootState,
} from "@/components/workbench/explorer/explorer-panel";
import { useProjectStore } from "@/features/project/stores/project-store";
import {
  canonicalizeWorkspaceConsumerPath,
  resolveWorkspaceConsumerRoot,
} from "@/features/project/stores/project-store";
import type { DetectionProject, ProjectFile } from "@/features/project/stores/project-store";
import { usePaneStore, getActivePaneRoute } from "@/features/panes/pane-store";
import { useWorkbenchState } from "@/features/policy/hooks/use-policy-actions";
import { HeartbeatPanel } from "../panels/heartbeat-panel";
import { SentinelPanel } from "../panels/sentinel-panel";
import { FindingsPanel } from "../panels/findings-panel";
import { LibraryPanel } from "../panels/library-panel";
import { FleetPanel } from "../panels/fleet-panel";
import { CompliancePanel } from "../panels/compliance-panel";
import { SearchPanelConnected } from "@/features/search/components/search-panel";
import { AnalystRosterPanel } from "@/features/presence/components/analyst-roster-panel";
import { ObservatoryMinimapPanel } from "@/features/observatory/panels/observatory-minimap-panel";
import type { ActivityBarItemId } from "../types";
import {
  joinWorkspacePath,
  relativeWorkspacePath,
} from "@/lib/workbench/path-utils";
import { revealWorkspaceEntryNative } from "@/lib/tauri-commands";

function getExplorerFileKey(rootId: string, relativePath: string): string {
  return `${rootId}::${relativePath}`;
}

// ---------------------------------------------------------------------------
// SidebarPanel -- Container that renders active panel content.
// Reads activeItem from the activity-bar store and switches panel view.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Explorer panel wiring -- connects ExplorerPanel to project store
// ---------------------------------------------------------------------------

function ExplorerPanelConnected() {
  const project = useProjectStore.use.project();
  const projectsById = useProjectStore.use.projectsById();
  const rootsById = useProjectStore.use.rootsById();
  const orderedRootIds = useProjectStore.use.orderedRootIds();
  const defaultRootId = useProjectStore.use.defaultRootId();
  const rootStatusById = useProjectStore.use.rootStatusById();
  const rootErrorById = useProjectStore.use.rootErrorById();
  const rootMutationById = useProjectStore.use.rootMutationById();
  const loading = useProjectStore.use.loading();
  const filter = useProjectStore.use.filter();
  const formatFilter = useProjectStore.use.formatFilter();
  const fileStatuses = useProjectStore.use.fileStatuses();
  const actions = useProjectStore.use.actions();
  const { openFileByPath } = useWorkbenchState();

  const workspaceRootPaths = useMemo(
    () =>
      orderedRootIds
        .map((rootId) => rootsById.get(rootId)?.displayPath ?? null)
        .filter((rootPath): rootPath is string => rootPath != null),
    [orderedRootIds, rootsById],
  );

  const workspaceConsumerState = useMemo(
    () => ({
      project,
      defaultRootId,
      orderedRootIds,
      rootsById,
      rootStatusById,
      projectRoots: workspaceRootPaths,
    }),
    [defaultRootId, orderedRootIds, project, rootStatusById, rootsById, workspaceRootPaths],
  );

  const projects = useMemo(() => {
    return orderedRootIds
      .map((rootId) => projectsById.get(rootId))
      .filter((p): p is DetectionProject => p != null);
  }, [orderedRootIds, projectsById]);

  const resolveRoot = (rootIdOrPath: string | null | undefined) =>
    resolveWorkspaceConsumerRoot(workspaceConsumerState, rootIdOrPath);

  const rootStates = useMemo(() => {
    const states = new Map<string, ExplorerRootState>();
    for (const project of projects) {
      const rootId = project.rootId;
      const root = rootsById.get(project.rootId);
      if (!root) continue;
      states.set(rootId, {
        status: rootStatusById.get(rootId) ?? "idle",
        error: rootErrorById.get(rootId) ?? null,
        mutation: rootMutationById.get(rootId) ?? null,
        isDefault: rootId === defaultRootId,
        label: root.label,
        kind: root.kind,
        provenance: root.provenance,
      });
    }
    return states;
  }, [defaultRootId, projects, rootErrorById, rootMutationById, rootStatusById, rootsById]);

  // Derive active file's relative path from pane store for tree highlighting.
  const paneRoot = usePaneStore((s) => s.root);
  const activePaneId = usePaneStore((s) => s.activePaneId);

  const activeFileKey = useMemo(() => {
    const route = getActivePaneRoute(paneRoot, activePaneId);
    if (!route.startsWith("/file/")) return null;
    const canonicalPath = canonicalizeWorkspaceConsumerPath(
      workspaceConsumerState,
      route.slice("/file/".length),
    );
    const root = resolveWorkspaceConsumerRoot(workspaceConsumerState, canonicalPath);
    return root
      ? getExplorerFileKey(
          root.rootId,
          relativeWorkspacePath(root.displayPath, canonicalPath),
        )
      : null;
  }, [activePaneId, paneRoot, workspaceConsumerState]);

  // Show loading indicator briefly while bootstrap resolves the initial roots.
  const [timedOut, setTimedOut] = useState(false);
  useEffect(() => {
    if (!loading) return;
    setTimedOut(false);
    const timer = setTimeout(() => setTimedOut(true), 5_000);
    return () => clearTimeout(timer);
  }, [loading]);

  if (loading && !timedOut && workspaceRootPaths.length === 0 && projects.length === 0) {
    return (
      <div className="h-full flex flex-col">
        <div className="h-[36px] shrink-0 flex items-center border-b border-[#202531] px-3">
          <span className="font-mono text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
            Explorer
          </span>
        </div>
        <div className="flex-1 flex items-center justify-center">
          <span className="text-[11px] font-mono text-[#6f7f9a]/50 animate-pulse">
            Loading workspace...
          </span>
        </div>
      </div>
    );
  }

  return (
    <ExplorerPanel
      projects={projects}
      rootStates={rootStates}
      activeFileKey={activeFileKey}
      onToggleDir={(rootId, dirPath) => {
        actions.toggleDirForRoot(rootId, dirPath);
      }}
      onOpenFile={async (rootId, file) => {
        const root = resolveRoot(rootId);
        if (!root) return;
        const absPath = joinWorkspacePath(root.displayPath, file.path);
        if (file.fileType === "swarm_bundle") {
          usePaneStore.getState().openApp(
            `/swarm-board/${encodeURIComponent(absPath)}`,
            file.name.replace(/\.swarm$/, ""),
          );
        } else {
          await openFileByPath(absPath);
          usePaneStore.getState().openFile(absPath, file.name);
        }
      }}
      onExpandAll={actions.expandAll}
      onCollapseAll={actions.collapseAll}
      onRefresh={async () => {
        await Promise.all(orderedRootIds.map((rootId) => actions.loadRoot(rootId)));
      }}
      filter={filter}
      onFilterChange={actions.setFilter}
      formatFilter={formatFilter}
      onFormatFilterChange={actions.setFormatFilter}
      fileStatuses={fileStatuses}
      onAddFolder={async () => {
        const { isDesktop } = await import("@/lib/tauri-bridge");
        if (!isDesktop()) return;
        const { open } = await import("@tauri-apps/plugin-dialog");
        const selected = await open({ directory: true, multiple: false, title: "Add Folder to Workspace" });
        if (selected && typeof selected === "string") {
          // addRoot internally triggers loadRoot (fire-and-forget).
          const storeActions = useProjectStore.getState().actions;
          await storeActions.addRoot(selected);
        }
      }}
      onRemoveRoot={(rootId) => {
        actions.removeRoot(rootId);
      }}
      onCreateFile={async (parentPath, fileName) => {
        const savedPath = await actions.createFile(parentPath, fileName, "clawdstrike_policy");
        if (savedPath) {
          actions.setFileStatus(savedPath, { modified: true });
          await openFileByPath(savedPath);
          usePaneStore.getState().openFile(savedPath, fileName);
        }
      }}
      onRenameFile={async (rootId, file, newName) => {
        const root = resolveRoot(rootId);
        if (!root) return;
        await actions.renameFile(joinWorkspacePath(root.displayPath, file.path), newName);
      }}
      onDeleteFile={async (rootId, file) => {
        const root = resolveRoot(rootId);
        if (!root) return;
        await actions.deleteFile(joinWorkspacePath(root.displayPath, file.path));
      }}
      onRevealInFinder={async (rootId, absPath) => {
        const root = resolveRoot(rootId);
        if (!root) return;
        const canonicalPath = canonicalizeWorkspaceConsumerPath(workspaceConsumerState, absPath);
        const relativePath = relativeWorkspacePath(root.displayPath, canonicalPath);
        await revealWorkspaceEntryNative(root.rootId, relativePath);
      }}
      onCreateFolder={async (parentPath, folderName) => {
        await actions.createDirectory(parentPath, folderName);
      }}
      onCollapseChildren={(rootId, dirPath) => {
        // Collapse dirPath and all its descendant dirs within the root
        const project = projectsById.get(rootId);
        if (!project) return;
        const toCollapse: string[] = [dirPath];
        function collectChildren(files: ProjectFile[]) {
          for (const f of files) {
            if (f.isDirectory && f.path.startsWith(dirPath + "/")) {
              toCollapse.push(f.path);
              if (f.children) collectChildren(f.children);
            }
          }
        }
        collectChildren(project.files);
        for (const p of toCollapse) {
          if (project.expandedDirs.has(p)) {
            actions.toggleDirForRoot(rootId, p);
          }
        }
      }}
      onRefreshRoot={async (rootId) => {
        await actions.loadRoot(rootId);
      }}
    />
  );
}

// ---------------------------------------------------------------------------
// Panel renderer -- switches on active activity bar item
// ---------------------------------------------------------------------------

function renderPanel(activeItem: ActivityBarItemId) {
  switch (activeItem) {
    case "heartbeat":
      return <HeartbeatPanel />;
    case "hunt":
      return <FindingsPanel />;
    case "sentinels":
      return <SentinelPanel />;
    case "findings":
      return <FindingsPanel />;
    case "explorer":
      return <ExplorerPanelConnected />;
    case "search":
      return <SearchPanelConnected />;
    case "library":
      return <LibraryPanel />;
    case "fleet":
      return <FleetPanel />;
    case "compliance":
      return <CompliancePanel />;
    case "people":
      return <AnalystRosterPanel />;
    case "observatory":
      return <ObservatoryMinimapPanel />;
  }
}

// ---------------------------------------------------------------------------
// Main SidebarPanel component
// ---------------------------------------------------------------------------

export function SidebarPanel() {
  const activeItem = useActivityBarStore.use.activeItem();
  const sidebarVisible = useActivityBarStore.use.sidebarVisible();
  const sidebarWidth = useActivityBarStore.use.sidebarWidth();

  return (
    <div
      role="tabpanel"
      id="sidebar-panel"
      aria-labelledby={`activity-bar-tab-${activeItem}`}
      className="shrink-0 bg-[#0b0d13] overflow-hidden transition-[width] duration-[250ms] ease-[cubic-bezier(0.25,0.1,0.25,1)] spirit-field-stain-host"
      style={{ width: sidebarVisible ? sidebarWidth : 0 }}
    >
      {sidebarVisible && (
        <div className="h-full flex flex-col" style={{ width: sidebarWidth }}>
          {renderPanel(activeItem)}
        </div>
      )}
    </div>
  );
}
