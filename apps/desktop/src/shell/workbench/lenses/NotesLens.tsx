import { useEffect, useMemo, useState } from "react";
import type { LensProps } from "./SharedRows";
import { ActionRow, DataRow, EmptyState } from "./SharedRows";
import { PlusIcon, TemplateIcon, DocIcon } from "./LensIcons";
import { ARTIFACT_KIND_ICONS } from "./LensIcons";
import type { DragPayload } from "../DragDropContext";
import type { LensSectionDirective } from "../anticipation/types";

type NotesSectionId = "hunt-notes" | "current-shell" | "quick-actions" | "templates";

interface SectionDescriptor {
  id: NotesSectionId;
  title: string;
  preview: string;
  promotedReason?: string;
  defaultExpanded: boolean;
  render: () => React.ReactNode;
}

export function NotesLens({
  shell,
  activeHunt,
  huntStore,
  directive,
}: LensProps & { shell: string; directive?: LensSectionDirective | null }) {
  const huntNotes = activeHunt
    ? activeHunt.artifactIds
        .map((id) => huntStore.artifacts[id])
        .filter((artifact) => artifact?.kind === "note")
    : [];

  const currentShellRows = useMemo(() => {
    if (shell === "case") {
      return [
        { label: "Case citations", meta: "Proof surface" },
        { label: "Related findings", meta: "Narrative link" },
      ];
    }

    if (shell === "hunt") {
      return [
        { label: "Current hunt narrative", meta: "Live summary" },
        { label: "Evidence annotations", meta: "Drag to cite" },
      ];
    }

    if (shell === "lab") {
      return [
        { label: "Run notebook", meta: "Inputs + outcomes" },
        { label: "Experiment notes", meta: "Working log" },
      ];
    }

    return [
      { label: "Signal triage note", meta: "Escalation path" },
      { label: "Working context", meta: "Recent pivots" },
    ];
  }, [shell]);

  const descriptors = useMemo(() => {
    const defs: SectionDescriptor[] = [
      {
        id: "hunt-notes",
        title: activeHunt ? `${activeHunt.title} notes` : "Current hunt notes",
        preview: activeHunt
          ? huntNotes.length > 0
            ? `${huntNotes.length} ${huntNotes.length === 1 ? "note" : "notes"} already linked.`
            : "No notes yet. Drag proof here or start a scratchpad."
          : "Open or create a hunt to keep notes attached to the work.",
        promotedReason: directive?.reasonsBySectionId["hunt-notes"],
        defaultExpanded: Boolean(activeHunt),
        render: () => (
          <>
            {activeHunt ? (
              huntNotes.length > 0 ? (
                huntNotes.map((artifact) => {
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
                      dragPayload={payload}
                    />
                  );
                })
              ) : (
                <EmptyState text="Drag notes here or use Quick Actions below" />
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
        preview: `The ${shell} shell can promote citations and working notes here.`,
        promotedReason: directive?.reasonsBySectionId["current-shell"],
        defaultExpanded: shell === "case",
        render: () => (
          <>
            {currentShellRows.map((row) => (
              <DataRow key={row.label} icon={<DocIcon />} label={row.label} meta={row.meta} />
            ))}
          </>
        ),
      },
      {
        id: "quick-actions",
        title: "Quick actions",
        preview: "Scratchpads and template starts stay one move away.",
        promotedReason: directive?.reasonsBySectionId["quick-actions"],
        defaultExpanded: true,
        render: () => (
          <>
            <ActionRow label="New scratchpad" shortcut="⌘N" icon={<PlusIcon />} />
            <ActionRow label="New from template" shortcut="T" icon={<TemplateIcon />} />
          </>
        ),
      },
      {
        id: "templates",
        title: "Templates",
        preview: "Fast note shapes for citations, field notes, and tracking.",
        promotedReason: directive?.reasonsBySectionId.templates,
        defaultExpanded: shell === "case",
        render: () => (
          <>
            <DataRow icon={<DocIcon />} label="Field note" meta="Working note" />
            <DataRow icon={<DocIcon />} label="IOC tracker" meta="Evidence matrix" />
            <DataRow icon={<DocIcon />} label="Case citation stub" meta="Report seed" />
          </>
        ),
      },
    ];

    const hidden = new Set(directive?.hiddenSectionIds ?? []);
    const visible = defs.filter((section) => !hidden.has(section.id));
    const order = directive?.sectionOrder ?? visible.map((section) => section.id);
    const rank = new Map(order.map((id, index) => [id, index]));

    return visible.sort(
      (a, b) =>
        (rank.get(a.id) ?? Number.MAX_SAFE_INTEGER)
        - (rank.get(b.id) ?? Number.MAX_SAFE_INTEGER),
    );
  }, [activeHunt, currentShellRows, directive, huntNotes, shell]);

  const [manualExpanded, setManualExpanded] = useState<Record<NotesSectionId, boolean>>({
    "hunt-notes": Boolean(activeHunt),
    "current-shell": shell === "case",
    "quick-actions": true,
    templates: shell === "case",
  });

  useEffect(() => {
    setManualExpanded((prev) => ({
      ...prev,
      "hunt-notes": prev["hunt-notes"] || Boolean(activeHunt),
    }));
  }, [activeHunt]);

  useEffect(() => {
    if (shell !== "case") return;
    setManualExpanded((prev) => ({
      ...prev,
      "current-shell": true,
      templates: true,
    }));
  }, [shell]);

  useEffect(() => {
    if (!directive) return;
    setManualExpanded((prev) => {
      const next = { ...prev };
      for (const id of directive.expandedSectionIds) {
        if (
          id === "hunt-notes"
          || id === "current-shell"
          || id === "quick-actions"
          || id === "templates"
        ) {
          next[id] = true;
        }
      }
      return next;
    });
  }, [directive]);

  const promoted = new Set(directive?.promotedSectionIds ?? []);

  return (
    <div className="flex flex-col py-1">
      {descriptors.map((section) => {
        const expanded = manualExpanded[section.id] ?? section.defaultExpanded;
        return (
          <NotesRegistrySection
            key={section.id}
            title={section.title}
            preview={section.preview}
            reason={section.promotedReason}
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
          </NotesRegistrySection>
        );
      })}
    </div>
  );
}

function NotesRegistrySection({
  title,
  preview,
  reason,
  promoted,
  expanded,
  onToggle,
  children,
}: {
  title: string;
  preview: string;
  reason?: string;
  promoted: boolean;
  expanded: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}) {
  return (
    <div
      className="mx-[8px] my-1 overflow-hidden rounded-[8px]"
      style={{
        border: promoted
          ? "1px solid rgba(213,173,87,0.18)"
          : "1px solid rgba(213,173,87,0.06)",
        background: promoted
          ? "rgba(213,173,87,0.045)"
          : "rgba(255,255,255,0.01)",
      }}
    >
      <button
        type="button"
        className="flex w-full items-center justify-between px-[10px] py-[6px] text-left"
        onClick={onToggle}
      >
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-[rgba(182,183,193,0.4)]">
          {title}
        </span>
        <span
          className="font-mono text-[10px]"
          style={{ color: promoted ? "rgba(213,173,87,0.8)" : "rgba(182,183,193,0.35)" }}
        >
          {expanded ? "−" : "+"}
        </span>
      </button>

      {reason && (
        <div className="px-[10px] pb-[4px] font-mono text-[10px] text-[rgba(213,173,87,0.72)]">
          {reason}
        </div>
      )}

      {!expanded && (
        <div className="px-[10px] pb-[8px] text-[12px] text-[rgba(182,183,193,0.42)]">
          {preview}
        </div>
      )}

      {expanded && <div className="pb-[6px]">{children}</div>}
    </div>
  );
}
