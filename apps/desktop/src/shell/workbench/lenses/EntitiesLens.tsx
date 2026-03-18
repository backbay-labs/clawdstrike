import { useEffect, useMemo, useState } from "react";
import type { LensProps } from "./SharedRows";
import { ActionRow, DataRow, EmptyState, LensRegistrySection } from "./SharedRows";
import { ReticleIcon, PlusIcon } from "./LensIcons";
import { ARTIFACT_KIND_ICONS } from "./LensIcons";
import type { DragPayload } from "../DragDropContext";
import type { LensSectionDirective } from "../anticipation/types";

type EntitiesSectionId = "hunt-entities" | "hosts" | "identities" | "quick-actions";

interface SectionDescriptor {
  id: EntitiesSectionId;
  title: string;
  preview: string;
  promotedReason?: string;
  defaultExpanded: boolean;
  render: () => React.ReactNode;
}

export function EntitiesLens({
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
        id: "hunt-entities",
        title: activeHunt ? `${activeHunt.title} entities` : "Current hunt entities",
        preview: activeHunt
          ? huntEntities.length > 0
            ? `${huntEntities.length} ${huntEntities.length === 1 ? "entity" : "entities"} ready.`
            : "No entities yet. Drag one here to seed the hunt."
          : "Open or create a hunt to collect entities.",
        promotedReason: directive?.reasonsBySectionId["hunt-entities"],
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
        id: "hosts",
        title: "Hosts",
        preview: "Infrastructure pivots and hosts appear here first.",
        promotedReason: directive?.reasonsBySectionId.hosts,
        defaultExpanded: false,
        render: () => <EmptyState text="No hosts discovered" />,
      },
      {
        id: "identities",
        title: "Identities",
        preview: "Watchable identities and principals appear here.",
        promotedReason: directive?.reasonsBySectionId.identities,
        defaultExpanded: false,
        render: () => <EmptyState text="No identities loaded" />,
      },
      {
        id: "quick-actions",
        title: "Quick actions",
        preview: "Run discovery or import a list without leaving the lens.",
        promotedReason: directive?.reasonsBySectionId["quick-actions"],
        defaultExpanded: true,
        render: () => (
          <>
            <ActionRow label="Run a hunt to discover entities" icon={<ReticleIcon />} />
            <ActionRow label="Import entity list" icon={<PlusIcon />} />
          </>
        ),
      },
    ];

    const hidden = new Set(directive?.hiddenSectionIds ?? []);
    const visible = defs.filter((section) => !hidden.has(section.id));
    const order = directive?.sectionOrder ?? visible.map((section) => section.id);
    const rank = new Map(order.map((id, index) => [id, index]));

    return visible.sort(
      (a, b) => (rank.get(a.id) ?? Number.MAX_SAFE_INTEGER) - (rank.get(b.id) ?? Number.MAX_SAFE_INTEGER),
    );
  }, [activeHunt, huntEntities, directive, huntStore.artifacts]);

  const [manualExpanded, setManualExpanded] = useState<Record<EntitiesSectionId, boolean>>({
    "hunt-entities": Boolean(activeHunt),
    hosts: false,
    identities: false,
    "quick-actions": true,
  });

  useEffect(() => {
    if (!directive) return;
    setManualExpanded((prev) => {
      const next = { ...prev };
      for (const id of directive.expandedSectionIds) {
        if (id === "hunt-entities" || id === "hosts" || id === "identities" || id === "quick-actions") {
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
