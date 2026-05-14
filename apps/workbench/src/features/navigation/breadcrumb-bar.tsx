import { IconChevronRight } from "@tabler/icons-react";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { useProjectStore } from "@/features/project/stores/project-store";
import { useActivityBarStore } from "@/features/activity-bar/stores/activity-bar-store";
import { relativeWorkspacePath } from "@/lib/workbench/path-utils";

/**
 * BreadcrumbBar -- compact path-segment navigation rendered above the editor.
 *
 * Shows: Project > folder > ... > file.yaml
 * Clicking a folder segment expands it in the Explorer sidebar.
 * Only renders for /file/ routes.
 */
export function BreadcrumbBar({ route }: { route: string }) {
  const tabs = usePolicyTabsStore((s) => s.tabs);
  const project = useProjectStore((s) => s.project);
  const projectRoots = useProjectStore((s) => s.projectRoots);

  // Show breadcrumbs for file routes (not app routes like /home, /guards, etc.)
  if (!route.startsWith("/file/")) return null;

  const filePath = route.slice("/file/".length);

  // Handle __new__ routes: show "Untitled" breadcrumb
  if (filePath.startsWith("__new__/")) {
    const tabId = filePath.split("/")[1];
    const activeTab = tabs.find((t) => t.id === tabId);
    return (
      <div className="flex h-[24px] items-center gap-0 border-b border-[#1a1d27] bg-[#0b0d13] pl-4">
        <span className="flex items-center">
          <button type="button" className="rounded px-1.5 font-mono text-[10px] text-[#ece7dc]">
            {activeTab?.name ?? "Untitled"}
          </button>
        </span>
      </div>
    );
  }

  // Derive relative path by stripping the matching project root prefix.
  // E.g., "/Users/connor/.clawdstrike/workspace/policies/strict.yaml"
  // becomes "policies/strict.yaml" when rootPath is "/Users/connor/.clawdstrike/workspace".
  let relPath = filePath;
  for (const root of projectRoots) {
    const candidate = relativeWorkspacePath(root, filePath);
    if (candidate !== filePath) {
      relPath = candidate;
      break;
    }
  }
  if (relPath === filePath && project?.rootPath) {
    relPath = relativeWorkspacePath(project.rootPath, filePath);
  }

  const segments = relPath.split("/").filter(Boolean);

  // Build breadcrumb segments: [projectName, ...folders, fileName]
  const projectName = project?.name ?? segments[0] ?? "Project";
  const folderSegments = segments.slice(0, -1);
  const fileName = segments[segments.length - 1];

  const crumbs: Array<{
    label: string;
    type: "project" | "folder" | "file";
    folderPath?: string;
  }> = [{ label: projectName, type: "project" }];

  for (let i = 0; i < folderSegments.length; i++) {
    crumbs.push({
      label: folderSegments[i],
      type: "folder",
      folderPath: folderSegments.slice(0, i + 1).join("/"),
    });
  }

  if (fileName) {
    crumbs.push({ label: fileName, type: "file" });
  }

  const handleCrumbClick = (crumb: (typeof crumbs)[number]) => {
    if (crumb.type === "folder" && crumb.folderPath) {
      // Expand the folder in the Explorer
      const projectActions = useProjectStore.getState().actions;
      const expandedDirs =
        useProjectStore.getState().project?.expandedDirs ?? new Set<string>();

      // Ensure the folder is expanded (not toggled closed)
      if (!expandedDirs.has(crumb.folderPath)) {
        projectActions.toggleDir(crumb.folderPath);
      }

      // Ensure Explorer sidebar is visible
      const abStore = useActivityBarStore.getState();
      if (!abStore.sidebarVisible || abStore.activeItem !== "explorer") {
        abStore.actions.showPanel("explorer");
      }
    }
    // project and file clicks are no-ops
  };

  return (
    <div className="flex h-[24px] items-center gap-0 border-b border-[#1a1d27] bg-[#0b0d13] pl-4">
      {crumbs.map((crumb, i) => (
        <span key={`${crumb.type}-${i}`} className="flex items-center">
          {i > 0 && (
            <IconChevronRight
              size={10}
              className="mx-0.5 shrink-0 text-[#6f7f9a]/40"
            />
          )}
          <button
            type="button"
            onClick={() => handleCrumbClick(crumb)}
            className={`rounded px-1.5 font-mono text-[10px] transition-colors ${
              crumb.type === "file"
                ? "text-[#ece7dc]"
                : "text-[#6f7f9a] hover:bg-[#131721] hover:text-[#ece7dc]"
            }`}
          >
            {crumb.label}
          </button>
        </span>
      ))}
    </div>
  );
}
