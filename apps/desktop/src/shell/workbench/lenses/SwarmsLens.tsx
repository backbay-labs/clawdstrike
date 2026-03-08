import { useEffect, useMemo, useState } from "react";
import type { LensProps } from "./SharedRows";
import { ActionRow, EmptyState } from "./SharedRows";
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
          <SwarmsRegistrySection
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
          </SwarmsRegistrySection>
        );
      })}
    </div>
  );
}

function SwarmsRegistrySection({
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
