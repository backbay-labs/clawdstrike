import { useEffect, useMemo, useState } from "react";
import type { LensProps } from "./SharedRows";
import { DataRow, EmptyState, LensRegistrySection } from "./SharedRows";
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
