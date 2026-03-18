import { useEffect, useMemo, useState } from "react";
import type { LensProps } from "./SharedRows";
import { ActionRow, DataRow, EmptyState, LensRegistrySection } from "./SharedRows";
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
  );
}
