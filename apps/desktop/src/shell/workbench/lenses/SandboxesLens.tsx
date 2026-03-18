import { useEffect, useMemo, useState } from "react";
import type { LensProps } from "./SharedRows";
import { ActionRow, EmptyState, LensRegistrySection } from "./SharedRows";
import { TerminalIcon, TemplateIcon, PlusIcon } from "./LensIcons";
import type { LensSectionDirective } from "../anticipation/types";

type SandboxesSectionId = "hunt-sandboxes" | "live" | "quick-actions";

interface SectionDescriptor {
  id: SandboxesSectionId;
  title: string;
  preview: string;
  promotedReason?: string;
  defaultExpanded: boolean;
  render: () => React.ReactNode;
}

export function SandboxesLens({
  activeHunt,
  directive,
}: LensProps & { directive?: LensSectionDirective | null }) {
  const descriptors = useMemo(() => {
    const defs: SectionDescriptor[] = [
      {
        id: "hunt-sandboxes",
        title: activeHunt ? `${activeHunt.title} sandboxes` : "Current hunt sandboxes",
        preview: activeHunt
          ? "Spin up a sandbox from this hunt to keep inputs and evidence in one place."
          : "Open a hunt before staging sandbox work around case artifacts.",
        promotedReason: directive?.reasonsBySectionId["hunt-sandboxes"],
        defaultExpanded: Boolean(activeHunt),
        render: () => (
          <>
            {activeHunt ? (
              <EmptyState text="Spin up a sandbox from Quick Actions below" />
            ) : (
              <EmptyState text="No active hunt selected" />
            )}
          </>
        ),
      },
      {
        id: "live",
        title: "Live",
        preview: "Running sandboxes and mounted evidence should promote here first.",
        promotedReason: directive?.reasonsBySectionId.live,
        defaultExpanded: true,
        render: () => <EmptyState text="No active sandboxes" />,
      },
      {
        id: "quick-actions",
        title: "Quick actions",
        preview: "Start the likely sandbox without leaving the current flow.",
        promotedReason: directive?.reasonsBySectionId["quick-actions"],
        defaultExpanded: true,
        render: () => (
          <>
            <ActionRow label="Start Linux sandbox" icon={<TerminalIcon />} />
            <ActionRow label="Start Windows sandbox" icon={<TerminalIcon />} />
            <ActionRow label="Load template" icon={<TemplateIcon />} />
            <ActionRow label="Attach evidence bundle" icon={<PlusIcon />} />
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

  const [manualExpanded, setManualExpanded] = useState<Record<SandboxesSectionId, boolean>>({
    "hunt-sandboxes": Boolean(activeHunt),
    live: true,
    "quick-actions": true,
  });

  useEffect(() => {
    setManualExpanded((prev) => ({
      ...prev,
      "hunt-sandboxes": prev["hunt-sandboxes"] || Boolean(activeHunt),
    }));
  }, [activeHunt]);

  useEffect(() => {
    if (!directive) return;
    setManualExpanded((prev) => {
      const next = { ...prev };
      for (const id of directive.expandedSectionIds) {
        if (id === "hunt-sandboxes" || id === "live" || id === "quick-actions") {
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
