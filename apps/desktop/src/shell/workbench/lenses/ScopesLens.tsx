import { useEffect, useMemo, useState } from "react";
import type { LensProps } from "./SharedRows";
import { ActionRow, DataRow, EmptyState } from "./SharedRows";
import { ScopeIcon, FeedIcon, PlusIcon } from "./LensIcons";
import { ARTIFACT_KIND_ICONS } from "./LensIcons";
import type { DragPayload } from "../DragDropContext";
import type { LensSectionDirective } from "../anticipation/types";

type ScopesSectionId = "hunt-scopes" | "watchlists" | "feeds" | "quick-actions";

interface SectionDescriptor {
  id: ScopesSectionId;
  title: string;
  preview: string;
  promotedReason?: string;
  defaultExpanded: boolean;
  render: () => React.ReactNode;
}

export function ScopesLens({
  activeHunt,
  huntStore,
  directive,
}: LensProps & { directive?: LensSectionDirective | null }) {
  const huntEntities = activeHunt
    ? activeHunt.artifactIds
        .map((id) => huntStore.artifacts[id])
        .filter((a) => a?.kind === "entity")
    : [];

  const descriptors = useMemo(() => {
    const defs: SectionDescriptor[] = [
      {
        id: "hunt-scopes",
        title: activeHunt ? `${activeHunt.title} scopes` : "Current hunt scopes",
        preview: activeHunt
          ? huntEntities.length > 0
            ? `${huntEntities.length} ${huntEntities.length === 1 ? "entity" : "entities"} already in scope.`
            : "Drag entities here to turn the current hunt into a live watch surface."
          : "Open a hunt to pivot from live entities into watchlists and feeds.",
        promotedReason: directive?.reasonsBySectionId["hunt-scopes"],
        defaultExpanded: Boolean(activeHunt),
        render: () => (
          <>
            {activeHunt ? (
              huntEntities.length > 0 ? (
                huntEntities.map((artifact) => {
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
                      hoverTargetType="entity"
                    />
                  );
                })
              ) : (
                <EmptyState text="Drag entities here or use Quick Actions below" />
              )
            ) : (
              <EmptyState text="No active hunt selected" />
            )}
          </>
        ),
      },
      {
        id: "watchlists",
        title: "Watchlists",
        preview: "Persistent scopes and threat collections should sit one move away from the hunt.",
        promotedReason: directive?.reasonsBySectionId.watchlists,
        defaultExpanded: true,
        render: () => (
          <>
            <DataRow icon={<ScopeIcon />} label="Default watchlist" badge={12} hoverTargetType="entity" />
            <DataRow icon={<ScopeIcon />} label="MITRE ATT&CK" badge={42} hoverTargetType="entity" />
          </>
        ),
      },
      {
        id: "feeds",
        title: "Feeds",
        preview: "Upstream sources stay visible when the operator is still in triage mode.",
        promotedReason: directive?.reasonsBySectionId.feeds,
        defaultExpanded: false,
        render: () => <DataRow icon={<FeedIcon />} label="Custom feeds" meta="3 sources" />,
      },
      {
        id: "quick-actions",
        title: "Quick actions",
        preview: "Follow a technique or create a new watchlist without leaving the lens.",
        promotedReason: directive?.reasonsBySectionId["quick-actions"],
        defaultExpanded: true,
        render: () => (
          <>
            <ActionRow label="Follow technique" icon={<PlusIcon />} />
            <ActionRow label="Create watchlist" icon={<PlusIcon />} />
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
  }, [activeHunt, directive, huntEntities]);

  const [manualExpanded, setManualExpanded] = useState<Record<ScopesSectionId, boolean>>({
    "hunt-scopes": Boolean(activeHunt),
    watchlists: true,
    feeds: false,
    "quick-actions": true,
  });

  useEffect(() => {
    setManualExpanded((prev) => ({
      ...prev,
      "hunt-scopes": prev["hunt-scopes"] || Boolean(activeHunt),
    }));
  }, [activeHunt]);

  useEffect(() => {
    if (!directive) return;
    setManualExpanded((prev) => {
      const next = { ...prev };
      for (const id of directive.expandedSectionIds) {
        if (id === "hunt-scopes" || id === "watchlists" || id === "feeds" || id === "quick-actions") {
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
          <ScopesRegistrySection
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
          </ScopesRegistrySection>
        );
      })}
    </div>
  );
}

function ScopesRegistrySection({
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
