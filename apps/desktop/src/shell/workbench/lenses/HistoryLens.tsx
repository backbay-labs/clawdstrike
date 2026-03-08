import { useEffect, useMemo, useState } from "react";
import type { LensProps } from "./SharedRows";
import { DataRow, EmptyState } from "./SharedRows";
import { RunIcon } from "./LensIcons";
import type { LensSectionDirective } from "../anticipation/types";

const RUN_STATUS_META: Record<string, string> = {
  running: "running",
  completed: "done",
  failed: "failed",
  cancelled: "cancelled",
};

type HistorySectionId = "hunt-runs" | "current-session" | "today";

interface SectionDescriptor {
  id: HistorySectionId;
  title: string;
  preview: string;
  promotedReason?: string;
  defaultExpanded: boolean;
  render: () => React.ReactNode;
}

export function HistoryLens({
  activeHunt,
  huntStore,
  directive,
}: LensProps & { directive?: LensSectionDirective | null }) {
  const runs = activeHunt
    ? activeHunt.runIds
        .map((id) => huntStore.runs[id])
        .filter(Boolean)
    : [];

  const descriptors = useMemo(() => {
    const defs: SectionDescriptor[] = [
      {
        id: "hunt-runs",
        title: activeHunt ? `${activeHunt.title} runs` : "Current hunt runs",
        preview: activeHunt
          ? runs.length > 0
            ? `${runs.length} ${runs.length === 1 ? "run" : "runs"} captured in this hunt.`
            : "Start a run to begin building hunt history."
          : "Open a hunt to pin runs and outcomes to the current casework.",
        promotedReason: directive?.reasonsBySectionId["hunt-runs"],
        defaultExpanded: Boolean(activeHunt),
        render: () => (
          <>
            {activeHunt ? (
              runs.length > 0 ? (
                runs.map((run) => (
                  <DataRow
                    key={run.id}
                    icon={<RunIcon />}
                    label={run.label}
                    meta={RUN_STATUS_META[run.status]}
                    badge={run.artifactIds.length || undefined}
                  />
                ))
              ) : (
                <EmptyState text="Start a run to populate history" />
              )
            ) : (
              <EmptyState text="No active hunt selected" />
            )}
          </>
        ),
      },
      {
        id: "current-session",
        title: "Current session",
        preview: "Fresh pivots, opens, and run completions should bubble up here first.",
        promotedReason: directive?.reasonsBySectionId["current-session"],
        defaultExpanded: true,
        render: () => <EmptyState text="No recent activity" />,
      },
      {
        id: "today",
        title: "Today",
        preview: "Longer-lived history stays one section lower once the session cools down.",
        promotedReason: directive?.reasonsBySectionId.today,
        defaultExpanded: false,
        render: () => <EmptyState text="No history yet" />,
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
  }, [activeHunt, directive, runs]);

  const [manualExpanded, setManualExpanded] = useState<Record<HistorySectionId, boolean>>({
    "hunt-runs": Boolean(activeHunt),
    "current-session": true,
    today: false,
  });

  useEffect(() => {
    setManualExpanded((prev) => ({
      ...prev,
      "hunt-runs": prev["hunt-runs"] || Boolean(activeHunt),
    }));
  }, [activeHunt]);

  useEffect(() => {
    if (!directive) return;
    setManualExpanded((prev) => {
      const next = { ...prev };
      for (const id of directive.expandedSectionIds) {
        if (id === "hunt-runs" || id === "current-session" || id === "today") {
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
          <HistoryRegistrySection
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
          </HistoryRegistrySection>
        );
      })}
    </div>
  );
}

function HistoryRegistrySection({
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
