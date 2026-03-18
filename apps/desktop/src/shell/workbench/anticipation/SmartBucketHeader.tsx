/**
 * SmartBucketHeader — enhanced bucket header with semantic drop zones.
 *
 * Normal state: renders like BucketSummary (collapsed 28px / expanded ~96px).
 * When dragging over: transforms into a semantic drop target showing
 * context-aware drop-role pills (Target, Evidence, Watch, Cite, etc.).
 */
import { useEffect, useRef, useState } from "react";
import type { CSSProperties, HTMLAttributes } from "react";
import type { Hunt, HuntStore, ArtifactKind } from "../huntTypes";
import { groupArtifactsByKind, formatArtifactBreakdown } from "../huntTypes";
import { buildHuntObservatorySeamSummary } from "../observatorySeam";
import type { DropRole, DropSemantic } from "./types";
import { SemanticDropZone } from "./SemanticDropZone";
import { getHuntSpiritMeta } from "../spirit";
import {
  requestSpiritChamber,
  SpiritGlyph,
} from "../spirit/components";
import {
  getSpiritReleaseCueTimestamp,
  SPIRIT_SURFACE_AFTERMATH_MS,
  SPIRIT_SURFACE_RECEIVE_MS,
  type SpiritSurfaceReceiveState,
} from "../spirit-ritual/release";

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
  const [releaseReceiveState, setReleaseReceiveState] = useState<SpiritSurfaceReceiveState>("idle");
  const receiveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const aftermathTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastReleaseCueRef = useRef<number | null>(null);

  const counts = groupArtifactsByKind(hunt.artifactIds, huntStore.artifacts);
  const breakdown = formatArtifactBreakdown(counts);

  const activeRun =
    hunt.runIds
      .map((id) => huntStore.runs[id])
      .find((r) => r?.status === "running") ?? null;

  const caseTitle =
    hunt.caseId ? (huntStore.cases[hunt.caseId]?.title ?? null) : null;
  const seamSummary = buildHuntObservatorySeamSummary(hunt, huntStore);
  const spiritMeta = getHuntSpiritMeta(hunt.spirit?.kind);
  const spiritAccent = spiritMeta?.accentColor ?? hunt.color;
  const spiritReleaseCueAt = getSpiritReleaseCueTimestamp(hunt.spirit);
  const isReceivingRelease = releaseReceiveState === "receiving";
  const isReleaseAftermath = releaseReceiveState === "aftermath";
  const isReleaseLive = releaseReceiveState !== "idle";

  const showDropZones = isDragOver && draggedKind !== null && dropRoles.length > 0;

  useEffect(() => {
    if (!spiritReleaseCueAt) return undefined;
    if (lastReleaseCueRef.current === null) {
      lastReleaseCueRef.current = spiritReleaseCueAt;
      return undefined;
    }
    if (spiritReleaseCueAt <= lastReleaseCueRef.current) return undefined;
    lastReleaseCueRef.current = spiritReleaseCueAt;
    setReleaseReceiveState("receiving");
    if (receiveTimerRef.current) clearTimeout(receiveTimerRef.current);
    if (aftermathTimerRef.current) clearTimeout(aftermathTimerRef.current);
    receiveTimerRef.current = setTimeout(() => {
      setReleaseReceiveState("aftermath");
      receiveTimerRef.current = null;
    }, SPIRIT_SURFACE_RECEIVE_MS);
    aftermathTimerRef.current = setTimeout(() => {
      setReleaseReceiveState("idle");
      aftermathTimerRef.current = null;
    }, SPIRIT_SURFACE_RECEIVE_MS + SPIRIT_SURFACE_AFTERMATH_MS);
    return () => {
      if (receiveTimerRef.current) {
        clearTimeout(receiveTimerRef.current);
        receiveTimerRef.current = null;
      }
      if (aftermathTimerRef.current) {
        clearTimeout(aftermathTimerRef.current);
        aftermathTimerRef.current = null;
      }
    };
  }, [spiritReleaseCueAt]);

  const containerStyle: CSSProperties = {
    position: "relative",
    borderBottomWidth: 1,
    borderBottomStyle: "solid",
    borderBottomColor: showDropZones
      ? "rgba(213,173,87,0.3)"
      : isReceivingRelease
        ? `${spiritAccent}44`
      : isReleaseAftermath
        ? `${spiritAccent}30`
      : "rgba(213,173,87,0.08)",
    background: showDropZones
      ? "rgba(213,173,87,0.06)"
      : isReceivingRelease
        ? `${spiritAccent}10`
      : isReleaseAftermath
        ? `${spiritAccent}0b`
      : "rgba(213,173,87,0.03)",
    boxShadow: isReceivingRelease
      ? `inset 0 1px 0 ${spiritAccent}18, 0 0 18px ${spiritAccent}12`
      : isReleaseAftermath
        ? `inset 0 1px 0 ${spiritAccent}12, 0 0 14px ${spiritAccent}0e`
        : undefined,
    transition: "background 150ms ease, border-color 150ms ease, box-shadow 180ms ease",
  };

  return (
    <div
      className="shrink-0"
      style={containerStyle}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      {...dropTargetProps}
    >
      <div
        aria-hidden="true"
        data-testid={isReceivingRelease ? "smart-bucket-spirit-receive" : undefined}
        style={{
          position: "absolute",
          inset: 6,
          borderRadius: collapsed ? 10 : 14,
          border: `1px solid ${spiritAccent}34`,
          background: `radial-gradient(circle at 24% 20%, ${spiritAccent}20, transparent 68%)`,
          opacity: isReceivingRelease ? 0.9 : isReleaseAftermath ? 0.44 : 0,
          transform: isReceivingRelease ? "scale(1.015)" : isReleaseAftermath ? "scale(1.008)" : "scale(0.985)",
          transition: "opacity 180ms ease, transform 760ms cubic-bezier(0.18, 0.82, 0.28, 1)",
          pointerEvents: "none",
        }}
      />
      <div
        aria-hidden="true"
        data-testid={isReleaseAftermath ? "smart-bucket-spirit-aftermath" : undefined}
        style={{
          position: "absolute",
          inset: collapsed ? 10 : 8,
          borderRadius: collapsed ? 12 : 16,
          border: `1px solid ${spiritAccent}1f`,
          opacity: isReleaseAftermath ? 0.52 : 0,
          transform: isReleaseAftermath ? "scale(1.018)" : "scale(0.99)",
          transition: "opacity 220ms ease, transform 920ms cubic-bezier(0.18, 0.82, 0.28, 1)",
          pointerEvents: "none",
        }}
      />

      {/* Row 1: dot + title + count + chevron */}
      <div className="flex h-7 items-center gap-2 px-[10px]">
        <button
          type="button"
          data-testid="smart-bucket-spirit-open"
          aria-label="Configure spirit"
          title="Configure spirit"
          className="flex h-5 w-5 items-center justify-center rounded-[6px] transition-colors"
          style={{
            background: hovered ? "rgba(232,230,222,0.04)" : "transparent",
            border: "none",
            padding: 0,
            cursor: "pointer",
          }}
          onClick={(event) => {
            event.stopPropagation();
            requestSpiritChamber({ huntId: hunt.id, source: "smart-bucket" });
          }}
        >
          <SpiritGlyph hunt={hunt} size={16} glow={showDropZones || hovered || isReleaseLive} />
        </button>
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
        <div className="flex flex-col gap-1 px-[10px] pb-[6px]">
          {seamSummary.stations.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {seamSummary.stations.slice(0, 3).map((station, index) => (
                <span
                  key={station.stationId}
                  className="rounded-full border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.08em]"
                  style={{
                    borderColor:
                      index === 0 ? "rgba(213,173,87,0.22)" : "rgba(232,230,222,0.08)",
                    color:
                      index === 0 ? "rgba(244,225,177,0.82)" : "rgba(182,183,193,0.56)",
                    background:
                      index === 0 ? "rgba(213,173,87,0.08)" : "rgba(232,230,222,0.03)",
                  }}
                >
                  {station.code} {station.count}
                </span>
              ))}
            </div>
          ) : (
            <div
              className="font-mono"
              style={{ fontSize: 10, color: "rgba(182,183,193,0.36)" }}
            >
              {breakdown || "No artifacts yet"}
            </div>
          )}

          <div className="font-mono" style={{ fontSize: 10, color: "rgba(182,183,193,0.42)" }}>
            {(activeRun?.label ?? caseTitle ?? breakdown) || "No active run"}
          </div>
        </div>
      )}
    </div>
  );
}
