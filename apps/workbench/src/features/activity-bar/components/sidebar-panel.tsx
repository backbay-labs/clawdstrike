import { useActivityBarStore } from "../stores/activity-bar-store";
import { ExplorerPanel } from "@/components/workbench/explorer/explorer-panel";
import { useProjectStore } from "@/features/project/stores/project-store";
import { usePaneStore } from "@/features/panes/pane-store";
import { HeartbeatPanel } from "../panels/heartbeat-panel";
import { SentinelPanel } from "../panels/sentinel-panel";
import { FindingsPanel } from "../panels/findings-panel";
import { LibraryPanel } from "../panels/library-panel";
import { FleetPanel } from "../panels/fleet-panel";
import { CompliancePanel } from "../panels/compliance-panel";
import { SearchPanelConnected } from "@/features/search/components/search-panel";
import { ObservatoryMinimapPanel } from "@/features/observatory/panels/observatory-minimap-panel";
import type { ActivityBarItemId } from "../types";

// ---------------------------------------------------------------------------
// SidebarPanel -- Container that renders active panel content.
// Reads activeItem from the activity-bar store and switches panel view.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Explorer panel wiring -- connects ExplorerPanel to project store
// ---------------------------------------------------------------------------

function ExplorerPanelConnected() {
  const project = useProjectStore.use.project();
  const filter = useProjectStore.use.filter();
  const formatFilter = useProjectStore.use.formatFilter();
  const fileStatuses = useProjectStore.use.fileStatuses();
  const actions = useProjectStore.use.actions();

  return (
    <ExplorerPanel
      project={project}
      onToggleDir={actions.toggleDir}
      onOpenFile={(file) => {
        usePaneStore.getState().openApp("/editor", file.name);
      }}
      onExpandAll={actions.expandAll}
      onCollapseAll={actions.collapseAll}
      filter={filter}
      onFilterChange={actions.setFilter}
      formatFilter={formatFilter}
      onFormatFilterChange={actions.setFormatFilter}
      fileStatuses={fileStatuses}
      onCreateFile={async (parentPath, fileName) => {
        const savedPath = await actions.createFile(parentPath, fileName, "clawdstrike_policy");
        if (savedPath) {
          // Compute relative path for status key.
          const project = useProjectStore.getState().project;
          const relPath = project && savedPath.startsWith(project.rootPath)
            ? savedPath.slice(project.rootPath.length).replace(/^\//, "")
            : fileName;
          actions.setFileStatus(relPath, { modified: true });
          usePaneStore.getState().openApp("/editor", fileName);
        }
      }}
      onRenameFile={async (file, newName) => {
        await actions.renameFile(file.path, newName);
      }}
      onDeleteFile={async (file) => {
        await actions.deleteFile(file.path);
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
