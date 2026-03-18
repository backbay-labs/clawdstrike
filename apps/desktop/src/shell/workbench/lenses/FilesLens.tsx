import { useCallback, useEffect, useMemo, useState } from "react";
import { useShell } from "@/shell/workbench/WorkbenchStateProvider";
import { WorkspaceTreeView } from "@/features/workspace/tree/WorkspaceTreeView";
import { getWorkspaceShellSnapshot } from "@/services/workspace";
import type { WorkspaceEntry, WorkspaceShellSnapshot } from "@/services/workspace";
import type { LensProps } from "./SharedRows";
import { ActionRow, DataRow, EmptyState, LensRegistrySection } from "./SharedRows";
import { FolderIcon, PlusIcon } from "./LensIcons";
import { ARTIFACT_KIND_ICONS } from "./LensIcons";
import type { DragPayload } from "../DragDropContext";
import type { LensSectionDirective } from "../anticipation/types";

type FilesMode = "assets" | "files" | "mounts";
type FilesSectionId = "hunt-files" | "current-shell" | "workspace" | "mounts";
type FilesLensDirective = LensSectionDirective;

interface SectionDescriptor {
  id: FilesSectionId;
  title: string;
  preview: string;
  promotedReason?: string;
  defaultExpanded: boolean;
  render: () => React.ReactNode;
}

const FILES_MODE_LABELS: Record<FilesMode, string> = {
  assets: "assets",
  files: "files",
  mounts: "mounts",
};

function getPreferredMode(preferredView?: string | null): FilesMode | null {
  if (preferredView === "assets" || preferredView === "files" || preferredView === "mounts") {
    return preferredView;
  }
  return null;
}

function getVisibleSectionIds(mode: FilesMode): FilesSectionId[] {
  if (mode === "files") {
    return ["workspace"];
  }

  if (mode === "mounts") {
    return ["mounts"];
  }

  return ["hunt-files", "current-shell"];
}

export function FilesLens({
  activeHunt,
  huntStore,
  onOpenPath,
  directive,
}: LensProps & {
  onOpenPath?: (relativePath: string) => void;
  directive?: FilesLensDirective | null;
}) {
  const shell = useShell();
  const preferredMode = getPreferredMode(directive?.preferredView);
  const [mode, setMode] = useState<FilesMode>(preferredMode ?? "assets");
  const [hasManualModeOverride, setHasManualModeOverride] = useState(false);

  const huntFiles = activeHunt
    ? activeHunt.artifactIds
        .map((id) => huntStore.artifacts[id])
        .filter((artifact) => artifact?.kind === "file")
    : [];

  const currentShellRows = useMemo(() => {
    if (shell === "lab") {
      return [
        { label: "Run scratch space", meta: "Latest outputs" },
        { label: "Sandbox handoff", meta: "Mount candidates" },
        { label: "Experiment traces", meta: "Working artifacts" },
      ];
    }

    if (shell === "case") {
      return [
        { label: "Case exhibits", meta: "Report-bound files" },
        { label: "Supporting evidence", meta: "Attach and cite" },
        { label: "Delivery bundle", meta: "Ready to export" },
      ];
    }

    if (shell === "wire") {
      return [
        { label: "Signal captures", meta: "Fresh intake" },
        { label: "Scope packets", meta: "Watch inputs" },
        { label: "Escalation bundle", meta: "Promote to hunt" },
      ];
    }

    return [
      { label: "Notes", meta: "Narrative attachments" },
      { label: "Receipts", meta: "Proof packets" },
      { label: "Evidence", meta: "Current hunt files" },
      { label: "Queries", meta: "Reusable pivots" },
    ];
  }, [shell]);

  const descriptors = useMemo(() => {
    const defs: SectionDescriptor[] = [
      {
        id: "hunt-files",
        title: activeHunt ? `${activeHunt.title} files` : "Current hunt files",
        preview: activeHunt
          ? huntFiles.length > 0
            ? `${huntFiles.length} ${huntFiles.length === 1 ? "file" : "files"} already attached to this hunt.`
            : "No hunt files yet. Drop one here or promote a workspace file."
          : "Open or create a hunt to attach files as working evidence.",
        promotedReason: directive?.reasonsBySectionId["hunt-files"],
        defaultExpanded: mode === "assets" && Boolean(activeHunt),
        render: () => (
          <>
            {activeHunt ? (
              huntFiles.length > 0 ? (
                huntFiles.map((artifact) => {
                  const IconComp = ARTIFACT_KIND_ICONS[artifact.kind];
                  const payload: DragPayload = {
                    kind: "artifact",
                    artifactId: artifact.id,
                    sourceHuntId: activeHunt.id,
                    artifact,
                  };
                  return (
                    <DataRow
                      key={artifact.id}
                      icon={<IconComp />}
                      label={artifact.title}
                      meta={artifact.sourceUri.split("/").pop()}
                      onClick={() => onOpenPath?.(artifact.sourceUri)}
                      dragPayload={payload}
                      hoverTargetType="file"
                    />
                  );
                })
              ) : (
                <EmptyState text="Drag files here or open a workspace artifact below" />
              )
            ) : (
              <EmptyState text="No active hunt selected" />
            )}
          </>
        ),
      },
      {
        id: "current-shell",
        title: `Current ${shell}`,
        preview: `The ${shell} shell keeps its likely attachment surfaces here.`,
        promotedReason: directive?.reasonsBySectionId["current-shell"],
        defaultExpanded: mode === "assets",
        render: () => (
          <>
            {currentShellRows.map((row) => (
              <DataRow key={row.label} icon={<FolderIcon />} label={row.label} meta={row.meta} />
            ))}
          </>
        ),
      },
      {
        id: "workspace",
        title: "Workspace",
        preview: "Browse the live workspace tree and open files in place.",
        promotedReason: directive?.reasonsBySectionId.workspace,
        defaultExpanded: mode === "files",
        render: () => <RawFileTree onOpenPath={onOpenPath} />,
      },
      {
        id: "mounts",
        title: "Mounts",
        preview: "Attach directories, evidence bundles, and external file surfaces here.",
        promotedReason: directive?.reasonsBySectionId.mounts,
        defaultExpanded: mode === "mounts",
        render: () => (
          <>
            <EmptyState text="No mounts attached" />
            <ActionRow label="Mount directory" icon={<PlusIcon />} />
            <ActionRow label="Attach evidence bundle" icon={<PlusIcon />} />
          </>
        ),
      },
    ];

    const hidden = new Set(directive?.hiddenSectionIds ?? []);
    const visibleIds = new Set(getVisibleSectionIds(mode));
    const visible = defs.filter((section) => visibleIds.has(section.id) && !hidden.has(section.id));
    const order = directive?.sectionOrder ?? visible.map((section) => section.id);
    const rank = new Map(order.map((id, index) => [id, index]));

    return visible.sort(
      (a, b) => (rank.get(a.id) ?? Number.MAX_SAFE_INTEGER) - (rank.get(b.id) ?? Number.MAX_SAFE_INTEGER),
    );
  }, [activeHunt, currentShellRows, directive, huntFiles, mode, onOpenPath]);

  const [manualExpanded, setManualExpanded] = useState<Record<FilesSectionId, boolean>>({
    "hunt-files": Boolean(activeHunt) && mode === "assets",
    "current-shell": mode === "assets",
    workspace: mode === "files",
    mounts: mode === "mounts",
  });

  useEffect(() => {
    if (hasManualModeOverride) {
      return;
    }

    if (preferredMode) {
      setMode(preferredMode);
    }
  }, [hasManualModeOverride, preferredMode]);

  useEffect(() => {
    setManualExpanded((prev) => ({
      ...prev,
      "hunt-files": prev["hunt-files"] || (mode === "assets" && Boolean(activeHunt)),
      "current-shell": prev["current-shell"] || mode === "assets",
      workspace: prev.workspace || mode === "files",
      mounts: prev.mounts || mode === "mounts",
    }));
  }, [activeHunt, mode]);

  useEffect(() => {
    if (!directive) return;
    setManualExpanded((prev) => {
      const next = { ...prev };
      for (const id of directive.expandedSectionIds) {
        if (id === "hunt-files" || id === "current-shell" || id === "workspace" || id === "mounts") {
          next[id] = true;
        }
      }
      return next;
    });
  }, [directive]);

  const promoted = new Set(directive?.promotedSectionIds ?? []);

  return (
    <div className="flex flex-col">
      <div
        className="flex h-8 shrink-0 items-center gap-0 border-b px-[10px]"
        style={{ borderBottomColor: "rgba(213,173,87,0.08)" }}
      >
        {(["assets", "files", "mounts"] as FilesMode[]).map((nextMode) => (
          <button
            key={nextMode}
            type="button"
            className={`px-2 py-1 font-mono text-[10px] uppercase tracking-[0.1em] transition-colors ${
              mode === nextMode
                ? "text-[rgba(213,173,87,0.85)]"
                : "text-[rgba(182,183,193,0.35)] hover:text-[rgba(182,183,193,0.6)]"
            }`}
            onClick={() => {
              setHasManualModeOverride(true);
              setMode(nextMode);
            }}
          >
            {FILES_MODE_LABELS[nextMode]}
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto py-1">
        {descriptors.map((section) => {
          const expanded = manualExpanded[section.id] ?? section.defaultExpanded;
          return (
            <LensRegistrySection
              key={section.id}
              title={section.title}
              preview={section.preview}
              promoted={promoted.has(section.id)}
              expanded={expanded}
              onToggle={() => {
                setManualExpanded((prev) => ({
                  ...prev,
                  [section.id]: !expanded,
                }));
              }}
            >
              {section.render()}
            </LensRegistrySection>
          );
        })}
      </div>
    </div>
  );
}

function RawFileTree({ onOpenPath }: { onOpenPath?: (relativePath: string) => void }) {
  const [snapshot, setSnapshot] = useState<WorkspaceShellSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedPaths, setExpandedPaths] = useState<string[]>([]);
  const [selectedPath, setSelectedPath] = useState<string | undefined>();

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getWorkspaceShellSnapshot()
      .then((result) => {
        if (!cancelled) setSnapshot(result);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleToggleDirectory = useCallback((relativePath: string) => {
    setExpandedPaths((prev) =>
      prev.includes(relativePath)
        ? prev.filter((path) => path !== relativePath)
        : [...prev, relativePath],
    );
  }, []);

  const handleSelectEntry = useCallback(
    (entry: WorkspaceEntry) => {
      setSelectedPath(entry.relativePath);
      if (entry.kind === "file" && onOpenPath) {
        onOpenPath(entry.relativePath);
      }
    },
    [onOpenPath],
  );

  if (loading) {
    return (
      <div className="px-[10px] py-2 text-[12px] text-[rgba(182,183,193,0.35)]">Loading...</div>
    );
  }

  if (!snapshot || snapshot.roots.length === 0) {
    return (
      <div className="px-[10px] py-2 text-[12px] text-[rgba(182,183,193,0.35)]">
        No workspace root registered
      </div>
    );
  }

  if (snapshot.tree.length === 0) {
    return (
      <div className="px-[10px] py-2 text-[12px] text-[rgba(182,183,193,0.35)]">
        Workspace is empty
      </div>
    );
  }

  return (
    <div className="px-1 py-1">
      <WorkspaceTreeView
        entries={snapshot.tree}
        expandedPaths={expandedPaths}
        selectedPath={selectedPath}
        onToggleDirectory={handleToggleDirectory}
        onSelectEntry={handleSelectEntry}
      />
    </div>
  );
}
