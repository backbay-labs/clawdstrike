/**
 * SmartBucketHeader — enhanced bucket header with semantic drop zones.
 *
 * Normal state: renders like BucketSummary (collapsed 28px / expanded ~96px).
 * When dragging over: transforms into a semantic drop target showing
 * context-aware drop-role pills (Target, Evidence, Watch, Cite, etc.).
 */
import { useState } from "react";
import type { CSSProperties, HTMLAttributes } from "react";
import type { Hunt, HuntStore, ArtifactKind } from "../huntTypes";
import { groupArtifactsByKind, formatArtifactBreakdown } from "../huntTypes";
import type { DropRole, DropSemantic } from "./types";
import { SemanticDropZone } from "./SemanticDropZone";

export interface SmartBucketHeaderProps {
  hunt: Hunt;
  huntStore: HuntStore;
  collapsed: boolean;
  onToggleCollapse: () => void;
  isDragOver: boolean;
  draggedKind: ArtifactKind | null;
  dropRoles: DropRole[];
  defaultDropRole: DropRole | null;
  selectedSemantic?: DropSemantic | null;
  dropTargetProps?: HTMLAttributes<HTMLDivElement>;
  onSemanticDrop: (semantic: DropSemantic) => void;
  onSemanticPreview?: (semantic: DropSemantic) => void;
}

// ── Component ───────────────────────────────────────────────────

export function SmartBucketHeader({
  hunt,
  huntStore,
  collapsed,
  onToggleCollapse,
  isDragOver,
  draggedKind,
  dropRoles,
  defaultDropRole,
  selectedSemantic,
  dropTargetProps,
  onSemanticDrop,
  onSemanticPreview,
}: SmartBucketHeaderProps) {
  const [hovered, setHovered] = useState(false);

  const counts = groupArtifactsByKind(hunt.artifactIds, huntStore.artifacts);
  const breakdown = formatArtifactBreakdown(counts);

  const activeRun =
    hunt.runIds
      .map((id) => huntStore.runs[id])
      .find((r) => r?.status === "running") ?? null;

  const caseTitle =
    hunt.caseId ? (huntStore.cases[hunt.caseId]?.title ?? null) : null;

  const showDropZones = isDragOver && draggedKind !== null && dropRoles.length > 0;

  const containerStyle: CSSProperties = {
    borderBottomWidth: 1,
    borderBottomStyle: "solid",
    borderBottomColor: showDropZones
      ? "rgba(213,173,87,0.3)"
      : "rgba(213,173,87,0.08)",
    background: showDropZones
      ? "rgba(213,173,87,0.06)"
      : "rgba(213,173,87,0.03)",
    transition: "background 150ms ease, border-color 150ms ease",
  };

  return (
    <div
      className="shrink-0"
      style={containerStyle}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      {...dropTargetProps}
    >
      {/* Row 1: dot + title + count + chevron */}
      <div className="flex h-7 items-center gap-2 px-[10px]">
        <span
          className="inline-block h-[7px] w-[7px] shrink-0 rounded-full"
          style={{ background: hunt.color }}
        />
        <span
          className="flex-1 truncate font-mono"
          style={{ fontSize: 13, color: "rgba(232,230,222,0.85)" }}
        >
          {hunt.title}
        </span>
        {collapsed && !showDropZones && (
          <span
            className="font-mono"
            style={{ fontSize: 10, color: "rgba(182,183,193,0.4)" }}
          >
            {hunt.artifactIds.length}
          </span>
        )}
        {!collapsed && !showDropZones && (
          <span
            className="rounded-sm px-1 py-0.5 font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.08em",
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

      {/* Semantic drop pills — appear when dragging over */}
      {showDropZones && (
        <div className="px-[10px] pb-[6px]" style={{ paddingTop: 2 }}>
          <SemanticDropZone
            roles={dropRoles}
            defaultRole={defaultDropRole}
            selectedSemantic={selectedSemantic}
            visible={true}
            onDrop={onSemanticDrop}
            onPreview={onSemanticPreview}
          />
        </div>
      )}

      {/* Expanded details — only when not showing drop zones */}
      {!collapsed && !showDropZones && (
        <div className="flex flex-col gap-0.5 px-[10px] pb-[6px]">
          {/* Artifact breakdown */}
          <div
            className="font-mono"
            style={{ fontSize: 10, color: "rgba(182,183,193,0.4)" }}
          >
            {breakdown || "No artifacts yet"}
          </div>

          {/* Active run or case */}
          <div className="flex items-center gap-1.5 font-mono" style={{ fontSize: 10 }}>
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
                <span style={{ color: "rgba(61,191,132,0.8)" }}>{activeRun.label}</span>
              </>
            ) : caseTitle ? (
              <span style={{ color: "rgba(182,183,193,0.4)" }}>Case: {caseTitle}</span>
            ) : (
              <span style={{ color: "rgba(182,183,193,0.3)" }}>No active run</span>
            )}
          </div>

          <div
            className="font-mono"
            style={{ fontSize: 9, color: "rgba(213,173,87,0.55)", lineHeight: 1.35 }}
          >
            Drag rows marked DRAG here or onto hunt pills to attach them.
          </div>
        </div>
      )}

      {/* Quick actions — hover only, not during drag */}
      {hovered && !showDropZones && (
        <div
          className="flex items-center gap-2 px-[10px] pb-[4px]"
          style={{ transition: "opacity 150ms ease" }}
        >
          <QuickActionButton label="Expand" onClick={onToggleCollapse} />
          <QuickActionButton label="Add to case" />
          <QuickActionButton label="Share" />
        </div>
      )}
    </div>
  );
}

// ── Quick Action Button ─────────────────────────────────────────

function QuickActionButton({
  label,
  onClick,
}: {
  label: string;
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      className="font-mono"
      style={{
        fontSize: 9,
        color: "rgba(182,183,193,0.4)",
        background: "transparent",
        border: "none",
        cursor: "pointer",
        padding: "1px 4px",
        borderRadius: 3,
        transition: "color 100ms ease",
      }}
      onClick={onClick}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLButtonElement).style.color = "rgba(232,230,222,0.7)";
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLButtonElement).style.color = "rgba(182,183,193,0.4)";
      }}
    >
      {label}
    </button>
  );
}
