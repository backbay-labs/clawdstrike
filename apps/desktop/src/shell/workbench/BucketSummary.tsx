/**
 * BucketSummary — Expandable hunt context bar (replaces thin BucketContextBar).
 *
 * Collapsed (28px): color dot, title, artifact count, chevron toggle.
 * Expanded (~96px): + artifact breakdown + active run indicator.
 * Acts as a drop target — glows gold when artifacts are dragged over.
 */
import type { Hunt, HuntStore } from "./huntTypes";
import { groupArtifactsByKind, formatArtifactBreakdown } from "./huntTypes";
import { useDropTarget } from "./DragDropContext";

export interface BucketSummaryProps {
  hunt: Hunt;
  huntStore: HuntStore;
  collapsed: boolean;
  onToggleCollapse: () => void;
}

export function BucketSummary({ hunt, huntStore, collapsed, onToggleCollapse }: BucketSummaryProps) {
  const { dropTargetProps, isOver, canDrop } = useDropTarget(hunt.id);
  const isDropHighlight = isOver && canDrop;

  const counts = groupArtifactsByKind(hunt.artifactIds, huntStore.artifacts);
  const breakdown = formatArtifactBreakdown(counts);

  // Find active run (if any)
  const activeRun = hunt.runIds
    .map((id) => huntStore.runs[id])
    .find((r) => r?.status === "running") ?? null;

  // Case title (if promoted)
  const caseTitle = hunt.caseId ? huntStore.cases[hunt.caseId]?.title ?? null : null;

  return (
    <div
      className={`shrink-0 border-b ${isDropHighlight ? "bucket-summary--drop-target" : ""}`}
      style={{
        borderBottomColor: "rgba(213,173,87,0.08)",
        background: isDropHighlight ? "rgba(213,173,87,0.06)" : "rgba(213,173,87,0.03)",
        transition: "background 150ms ease, border-color 150ms ease",
      }}
      {...dropTargetProps}
    >
      {/* Row 1: Always visible — dot, title, count, toggle */}
      <div className="flex h-7 items-center gap-2 px-[10px]">
        <span
          className="inline-block h-[7px] w-[7px] shrink-0 rounded-full"
          style={{ background: hunt.color }}
        />
        <span className="flex-1 truncate font-mono text-[11px] text-[rgba(232,230,222,0.7)]">
          {hunt.title}
        </span>
        {collapsed && (
          <span className="font-mono text-[10px] text-[rgba(182,183,193,0.4)]">
            {hunt.artifactIds.length}
          </span>
        )}
        {!collapsed && (
          <span
            className="rounded-sm px-1 py-0.5 font-mono text-[9px] uppercase tracking-[0.08em]"
            style={{
              background: "rgba(213,173,87,0.1)",
              color: "rgba(213,173,87,0.7)",
            }}
          >
            {hunt.status}
          </span>
        )}
        <button
          type="button"
          className="flex h-5 w-5 items-center justify-center rounded text-[rgba(182,183,193,0.4)] transition-colors hover:text-[rgba(232,230,222,0.7)]"
          onClick={onToggleCollapse}
          aria-label={collapsed ? "Expand bucket summary" : "Collapse bucket summary"}
        >
          <svg
            viewBox="0 0 10 10"
            width="10"
            height="10"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
            style={{
              transform: collapsed ? "rotate(0deg)" : "rotate(180deg)",
              transition: "transform 150ms ease",
            }}
          >
            <path d="M2 4l3 3 3-3" />
          </svg>
        </button>
      </div>

      {/* Rows 2-3: Expanded details */}
      {!collapsed && (
        <div className="flex flex-col gap-0.5 px-[10px] pb-[6px]">
          {/* Row 2: Artifact breakdown */}
          <div className="font-mono text-[10px] text-[rgba(182,183,193,0.45)]">
            {breakdown || "No artifacts yet"}
          </div>

          {/* Row 3: Active run or case */}
          <div className="flex items-center gap-1.5 font-mono text-[10px]">
            {activeRun ? (
              <>
                <span
                  className="inline-block h-[5px] w-[5px] rounded-full"
                  style={{
                    background: "#3dbf84",
                    boxShadow: "0 0 4px rgba(61,191,132,0.5)",
                    animation: "pulse 2s ease-in-out infinite",
                  }}
                />
                <span className="text-[rgba(61,191,132,0.8)]">{activeRun.label}</span>
              </>
            ) : caseTitle ? (
              <span className="text-[rgba(182,183,193,0.4)]">Case: {caseTitle}</span>
            ) : (
              <span className="text-[rgba(182,183,193,0.3)]">No active run</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
