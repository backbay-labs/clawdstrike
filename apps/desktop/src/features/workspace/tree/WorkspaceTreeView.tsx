import { clsx } from "clsx";
import type { WorkspaceEntry } from "@/services/workspace";

interface WorkspaceTreeViewProps {
  entries: WorkspaceEntry[];
  expandedPaths: string[];
  selectedPath?: string;
  onToggleDirectory: (relativePath: string) => void;
  onSelectEntry: (entry: WorkspaceEntry) => void;
}

interface WorkspaceTreeNodeProps {
  depth: number;
  entry: WorkspaceEntry;
  expandedPaths: Set<string>;
  selectedPath?: string;
  onToggleDirectory: (relativePath: string) => void;
  onSelectEntry: (entry: WorkspaceEntry) => void;
}

export function WorkspaceTreeView({
  entries,
  expandedPaths,
  selectedPath,
  onToggleDirectory,
  onSelectEntry,
}: WorkspaceTreeViewProps) {
  const expanded = new Set(expandedPaths);

  return (
    <div className="space-y-1" role="tree" aria-label="Workspace tree">
      {entries.map((entry) => (
        <WorkspaceTreeNode
          key={entry.relativePath || entry.name}
          depth={0}
          entry={entry}
          expandedPaths={expanded}
          selectedPath={selectedPath}
          onToggleDirectory={onToggleDirectory}
          onSelectEntry={onSelectEntry}
        />
      ))}
    </div>
  );
}

function WorkspaceTreeNode({
  depth,
  entry,
  expandedPaths,
  selectedPath,
  onToggleDirectory,
  onSelectEntry,
}: WorkspaceTreeNodeProps) {
  const isDirectory = entry.kind === "directory";
  const isExpanded = isDirectory && expandedPaths.has(entry.relativePath);
  const isSelected = selectedPath === entry.relativePath;

  return (
    <div>
      <button
        type="button"
        role="treeitem"
        aria-expanded={isDirectory ? isExpanded : undefined}
        onClick={() => {
          if (isDirectory) {
            onToggleDirectory(entry.relativePath);
          }
          onSelectEntry(entry);
        }}
        className={clsx(
          "flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left text-sm transition-colors",
          isSelected
            ? "bg-sdr-bg-secondary/80 text-sdr-text-primary"
            : "text-sdr-text-secondary hover:bg-sdr-bg-secondary/50 hover:text-sdr-text-primary",
        )}
        style={{ paddingLeft: `${depth * 14 + 8}px` }}
      >
        <span className="inline-flex w-4 justify-center text-sdr-text-muted">
          {isDirectory ? (isExpanded ? "▾" : "▸") : "·"}
        </span>
        <span className="inline-flex w-4 justify-center">{isDirectory ? "📁" : "📄"}</span>
        <span className="truncate">{entry.name}</span>
      </button>

      {isDirectory && isExpanded && entry.children?.length ? (
        <div role="group" className="mt-1 space-y-1">
          {entry.children.map((child) => (
            <WorkspaceTreeNode
              key={child.relativePath}
              depth={depth + 1}
              entry={child}
              expandedPaths={expandedPaths}
              selectedPath={selectedPath}
              onToggleDirectory={onToggleDirectory}
              onSelectEntry={onSelectEntry}
            />
          ))}
        </div>
      ) : null}
    </div>
  );
}
