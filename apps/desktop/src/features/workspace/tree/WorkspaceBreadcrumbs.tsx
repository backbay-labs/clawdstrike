import type { WorkspaceEntry } from "@/services/workspace";

interface WorkspaceBreadcrumbsProps {
  rootName?: string;
  activePath?: string;
  onSelectPath?: (relativePath: string) => void;
}

interface BreadcrumbSegment {
  id: string;
  label: string;
  relativePath: string;
}

function buildSegments(rootName?: string, activePath?: string): BreadcrumbSegment[] {
  const base = {
    id: "root",
    label: rootName ?? "Workspace",
    relativePath: "",
  };

  if (!activePath) return [base];

  const parts = activePath.split("/").filter(Boolean);
  const segments = parts.map((part, index) => ({
    id: `${part}-${index}`,
    label: part,
    relativePath: parts.slice(0, index + 1).join("/"),
  }));

  return [base, ...segments];
}

export function findWorkspaceEntryByPath(
  entries: WorkspaceEntry[],
  relativePath?: string,
): WorkspaceEntry | undefined {
  if (!relativePath) return undefined;

  for (const entry of entries) {
    if (entry.relativePath === relativePath) return entry;
    if (entry.children?.length) {
      const nested: WorkspaceEntry | undefined = findWorkspaceEntryByPath(
        entry.children,
        relativePath,
      );
      if (nested) return nested;
    }
  }

  return undefined;
}

export function WorkspaceBreadcrumbs({
  rootName,
  activePath,
  onSelectPath,
}: WorkspaceBreadcrumbsProps) {
  const segments = buildSegments(rootName, activePath);

  return (
    <nav aria-label="Workspace breadcrumbs" className="flex min-w-0 items-center gap-1 text-xs">
      {segments.map((segment, index) => {
        const isLast = index === segments.length - 1;
        return (
          <div key={segment.id} className="flex min-w-0 items-center gap-1">
            <button
              type="button"
              onClick={() => onSelectPath?.(segment.relativePath)}
              className={isLast ? "text-sdr-text-primary" : "text-sdr-text-muted hover:text-sdr-text-primary"}
            >
              <span className="truncate">{segment.label}</span>
            </button>
            {!isLast ? <span className="text-sdr-text-muted">/</span> : null}
          </div>
        );
      })}
    </nav>
  );
}
