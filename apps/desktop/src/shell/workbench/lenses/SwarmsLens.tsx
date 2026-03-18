import { useEffect, useMemo, useState } from "react";
import type { LensProps } from "./SharedRows";
import { ActionRow, EmptyState, LensRegistrySection } from "./SharedRows";
import { PlusIcon, TemplateIcon } from "./LensIcons";
import type { LensSectionDirective } from "../anticipation/types";

type SwarmsSectionId = "hunt-swarms" | "live-runs" | "quick-actions";

interface SectionDescriptor {
  id: SwarmsSectionId;
  title: string;
  preview: string;
  promotedReason?: string;
  defaultExpanded: boolean;
  render: () => React.ReactNode;
}

export function SwarmsLens({
  activeHunt,
  directive,
}: LensProps & { directive?: LensSectionDirective | null }) {
  const descriptors = useMemo(() => {
    const defs: SectionDescriptor[] = [
      {
        id: "hunt-swarms",
        title: activeHunt ? `${activeHunt.title} swarms` : "Current hunt swarms",
        preview: activeHunt
          ? "Launch coordinated swarm work from the hunt when the problem needs automation."
          : "Open a hunt before coordinating swarm work around shared evidence.",
        promotedReason: directive?.reasonsBySectionId["hunt-swarms"],
        defaultExpanded: Boolean(activeHunt),
        render: () => (
          <>
            {activeHunt ? (
              <EmptyState text="Launch a swarm from Quick Actions below" />
            ) : (
              <EmptyState text="No active hunt selected" />
            )}
          </>
        ),
      },
      {
        id: "live-runs",
        title: "Live runs",
        preview: "Active swarm runs should bubble up as soon as automation is underway.",
        promotedReason: directive?.reasonsBySectionId["live-runs"],
        defaultExpanded: true,
        render: () => <EmptyState text="No active swarms" />,
      },
      {
        id: "quick-actions",
        title: "Quick actions",
        preview: "Create or reuse a swarm profile without leaving the current shell.",
        promotedReason: directive?.reasonsBySectionId["quick-actions"],
        defaultExpanded: true,
        render: () => (
          <>
            <ActionRow label="Create swarm profile" icon={<PlusIcon />} />
            <ActionRow label="Browse templates" icon={<TemplateIcon />} />
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
  }, [activeHunt, directive]);

  const [manualExpanded, setManualExpanded] = useState<Record<SwarmsSectionId, boolean>>({
    "hunt-swarms": Boolean(activeHunt),
    "live-runs": true,
    "quick-actions": true,
  });

  useEffect(() => {
    setManualExpanded((prev) => ({
      ...prev,
      "hunt-swarms": prev["hunt-swarms"] || Boolean(activeHunt),
    }));
  }, [activeHunt]);

  useEffect(() => {
    if (!directive) return;
    setManualExpanded((prev) => {
      const next = { ...prev };
      for (const id of directive.expandedSectionIds) {
        if (id === "hunt-swarms" || id === "live-runs" || id === "quick-actions") {
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
