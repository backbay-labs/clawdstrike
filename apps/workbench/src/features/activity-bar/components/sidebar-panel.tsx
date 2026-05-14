import { useState, useEffect } from "react";
import { useActivityBarStore } from "../stores/activity-bar-store";
import { ExplorerPanel } from "@/components/workbench/explorer/explorer-panel";
import { useProjectStore } from "@/features/project/stores/project-store";
import { getProjectFileStatusKey } from "@/features/project/stores/project-store";
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
import { useMemo } from "react";
import {
  joinWorkspacePath,
  relativeWorkspacePath,
  resolveWorkspaceRootPath,
} from "@/lib/workbench/path-utils";

// ---------------------------------------------------------------------------
// SidebarPanel -- Container that renders active panel content.
// Reads activeItem from the activity-bar store and switches panel view.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Explorer panel wiring -- connects ExplorerPanel to project store
// ---------------------------------------------------------------------------

function ExplorerPanelConnected() {
  const projectRoots = useProjectStore.use.projectRoots();
  const projectsMap = useProjectStore.use.projects();
  const loading = useProjectStore.use.loading();
  const filter = useProjectStore.use.filter();
  const formatFilter = useProjectStore.use.formatFilter();
  const fileStatuses = useProjectStore.use.fileStatuses();
  const actions = useProjectStore.use.actions();
  const { openFileByPath } = useWorkbenchState();

  // Build ordered projects array from roots.
  // When loading is true, roots may exist but projects Map is not yet populated,
  // so we include an empty array during loading to avoid flashing "No project open".
  const projects = useMemo(() => {
    return projectRoots
      .map((root) => projectsMap.get(root))
      .filter((p): p is DetectionProject => p != null);
  }, [projectRoots, projectsMap]);

  // Derive active file's relative path from pane store for tree highlighting.
  const paneRoot = usePaneStore((s) => s.root);
  const activePaneId = usePaneStore((s) => s.activePaneId);

  const activeFileKey = useMemo(() => {
    const route = getActivePaneRoute(paneRoot, activePaneId);
    if (!route.startsWith("/file/")) return null;
    const absPath = route.slice("/file/".length);
    const rootPath = resolveWorkspaceRootPath(projectRoots, absPath);
    return rootPath
      ? getProjectFileStatusKey(rootPath, relativeWorkspacePath(rootPath, absPath))
      : null;
  }, [paneRoot, activePaneId, projectRoots]);

  // Show loading indicator briefly while bootstrap scans directories.
  // 5s timeout prevents indefinite "Loading..." if bootstrap hangs or fails.
  const [timedOut, setTimedOut] = useState(false);
  useEffect(() => {
    if (!loading) return;
    setTimedOut(false);
    const timer = setTimeout(() => setTimedOut(true), 5000);
    return () => clearTimeout(timer);
  }, [loading]);

  if (loading && !timedOut && projects.length === 0) {
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
      activeFileKey={activeFileKey}
      onToggleDir={(rootPath, dirPath) => {
        actions.toggleDirForRoot(rootPath, dirPath);
      }}
      onOpenFile={async (rootPath, file) => {
        const absPath = joinWorkspacePath(rootPath, file.path);
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
        for (const root of projectRoots) {
          await actions.loadRoot(root);
        }
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
          storeActions.addRoot(selected);
        }
      }}
      onRemoveRoot={(rootPath) => {
        actions.removeRoot(rootPath);
      }}
      onCreateFile={async (parentPath, fileName) => {
        const savedPath = await actions.createFile(parentPath, fileName, "clawdstrike_policy");
        if (savedPath) {
          actions.setFileStatus(savedPath, { modified: true });
          await openFileByPath(savedPath);
          usePaneStore.getState().openFile(savedPath, fileName);
        }
      }}
      onRenameFile={async (rootPath, file, newName) => {
        await actions.renameFile(joinWorkspacePath(rootPath, file.path), newName);
      }}
      onDeleteFile={async (rootPath, file) => {
        await actions.deleteFile(joinWorkspacePath(rootPath, file.path));
      }}
      onRevealInFinder={async (absPath) => {
        const { revealInFinder } = await import("@/lib/tauri-bridge");
        await revealInFinder(absPath);
      }}
      onCreateFolder={async (parentPath, folderName) => {
        const { createDirectory } = await import("@/lib/tauri-bridge");
        const fullPath = joinWorkspacePath(parentPath, folderName);
        const ok = await createDirectory(fullPath);
        if (ok) {
          // Re-scan the root that contains this folder
          const root = resolveWorkspaceRootPath(projectRoots, parentPath);
          if (root) await actions.loadRoot(root);
        }
      }}
      onCollapseChildren={(rootPath, dirPath) => {
        // Collapse dirPath and all its descendant dirs within the root
        const project = projectsMap.get(rootPath);
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
            actions.toggleDirForRoot(rootPath, p);
          }
        }
      }}
      onRefreshRoot={async (rootPath) => {
        await actions.loadRoot(rootPath);
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
