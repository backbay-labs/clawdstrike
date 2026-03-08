/** Shared row primitives for sidebar lenses */
import { useRef, useState, useEffect, useCallback } from "react";
import { useHoverAnticipation, ProximalAffordance, useSidebarWakeAnchor } from "../anticipation";
import type { Hunt, HuntStore } from "../huntTypes";
import type { DragPayload } from "../DragDropContext";
import { useDragSource } from "../DragDropContext";

export interface LensProps {
  activeHunt: Hunt | null;
  huntStore: HuntStore;
}

export function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="flex h-5 items-center px-[10px] font-mono text-[10px] uppercase tracking-[0.12em] text-[rgba(182,183,193,0.4)]"
      role="heading"
      aria-level={3}
    >
      {children}
    </div>
  );
}

export function ActionRow({
  icon,
  label,
  shortcut,
  onClick,
  muted,
}: {
  icon?: React.ReactNode;
  label: string;
  shortcut?: string;
  onClick?: () => void;
  muted?: boolean;
}) {
  return (
    <button
      type="button"
      className="group flex h-[28px] w-full items-center gap-2 px-[10px] text-left transition-colors hover:bg-[rgba(213,173,87,0.04)]"
      onClick={onClick}
    >
      {icon && (
        <span className="flex h-4 w-4 shrink-0 items-center justify-center text-[rgba(182,183,193,0.4)]">
          {icon}
        </span>
      )}
      <span
        className={`flex-1 truncate text-[13px] ${muted ? "text-[rgba(182,183,193,0.4)]" : "text-[rgba(232,230,222,0.7)]"}`}
      >
        {label}
      </span>
      {shortcut && (
        <span className="font-mono text-[10px] text-[rgba(182,183,193,0.3)]">{shortcut}</span>
      )}
    </button>
  );
}

export function DataRow({
  icon,
  label,
  meta,
  badge,
  onClick,
  dragPayload,
  hoverTargetType,
}: {
  icon?: React.ReactNode;
  label: string;
  meta?: string;
  badge?: string | number;
  onClick?: () => void;
  dragPayload?: DragPayload | null;
  hoverTargetType?: string; // e.g. "entity", "file", "receipt" — enables proximal affordance
}) {
  const { dragSourceProps, isDragging } = useDragSource(dragPayload ?? null);
  const isDraggable = Boolean(dragPayload);

  const rowRef = useRef<HTMLButtonElement>(null);
  const { hoverIntent, onHoverStart, onHoverEnd, isActivated } = useHoverAnticipation();
  const { setAnchorFromElement, clearAnchor } = useSidebarWakeAnchor();

  const [affordancePos, setAffordancePos] = useState<{ x: number; y: number } | null>(null);
  const wakeAnchorId = dragPayload
    ? `artifact-row:${dragPayload.artifactId}`
    : `row:${hoverTargetType ?? "generic"}:${label}`;

  const publishWakeAnchor = useCallback((source: "hover" | "drag") => {
    if (!rowRef.current) return;
    setAnchorFromElement({
      id: wakeAnchorId,
      kind: "row",
      element: rowRef.current,
      label,
      objectType: hoverTargetType ?? dragPayload?.artifact.kind ?? null,
      source,
    });
  }, [dragPayload?.artifact.kind, hoverTargetType, label, setAnchorFromElement, wakeAnchorId]);

  useEffect(() => {
    if (isActivated && hoverTargetType && rowRef.current) {
      const rect = rowRef.current.getBoundingClientRect();
      setAffordancePos({ x: rect.right + 4, y: rect.top + rect.height / 2 });
    } else {
      setAffordancePos(null);
    }
  }, [isActivated, hoverTargetType]);

  const handleMouseEnter = useCallback(() => {
    publishWakeAnchor("hover");
    if (hoverTargetType) {
      onHoverStart(label, hoverTargetType);
    }
  }, [hoverTargetType, label, onHoverStart, publishWakeAnchor]);

  const handleMouseLeave = useCallback(() => {
    clearAnchor(wakeAnchorId);
    if (hoverTargetType) {
      onHoverEnd();
    }
  }, [clearAnchor, hoverTargetType, onHoverEnd, wakeAnchorId]);

  return (
    <>
      <button
        ref={rowRef}
        type="button"
        className="group flex h-[30px] w-full items-center gap-2 px-[10px] text-left transition-colors hover:bg-[rgba(213,173,87,0.04)]"
        onClick={onClick}
        onMouseEnter={handleMouseEnter}
        onMouseMove={() => publishWakeAnchor("hover")}
        onMouseLeave={handleMouseLeave}
        onPointerDownCapture={() => publishWakeAnchor("drag")}
        title={isDraggable ? "Drag into a hunt, smart bucket, or stage shelf" : undefined}
        {...(dragPayload ? dragSourceProps : {})}
        style={dragPayload ? dragSourceProps.style : undefined}
      >
        {icon && (
          <span className="flex h-4 w-4 shrink-0 items-center justify-center text-[rgba(182,183,193,0.35)]">
            {icon}
          </span>
        )}
        <span className="flex-1 truncate text-[13px] text-[rgba(232,230,222,0.7)]">{label}</span>
        {meta && <span className="text-[11px] text-[rgba(182,183,193,0.35)]">{meta}</span>}
        {badge != null && (
          <span className="min-w-[18px] rounded-full bg-[rgba(213,173,87,0.12)] px-1.5 text-center font-mono text-[10px] text-[rgba(213,173,87,0.7)]">
            {badge}
          </span>
        )}
        {isDraggable && <DragCue active={isDragging} />}
      </button>
      {isActivated && hoverTargetType && hoverIntent && affordancePos && (
        <ProximalAffordance
          actions={hoverIntent.subtargets}
          position={affordancePos}
          visible={true}
          onAction={(actionId) => {
            if (actionId === "open" && onClick) onClick();
            onHoverEnd();
          }}
          onMouseLeave={onHoverEnd}
        />
      )}
    </>
  );
}

export function ReasonRow({
  icon,
  label,
  reason,
  meta,
  onClick,
  dragPayload,
}: {
  icon?: React.ReactNode;
  label: string;
  reason: string;
  meta?: string;
  onClick?: () => void;
  dragPayload?: DragPayload | null;
}) {
  const { dragSourceProps, isDragging } = useDragSource(dragPayload ?? null);
  const isDraggable = Boolean(dragPayload);
  const rowRef = useRef<HTMLButtonElement>(null);
  const { setAnchorFromElement, clearAnchor } = useSidebarWakeAnchor();
  const wakeAnchorId = dragPayload
    ? `reason-row:${dragPayload.artifactId}`
    : `reason:${label}`;
  const publishWakeAnchor = useCallback((source: "hover" | "drag") => {
    if (!rowRef.current) return;
    setAnchorFromElement({
      id: wakeAnchorId,
      kind: "row",
      element: rowRef.current,
      label,
      objectType: dragPayload?.artifact.kind ?? null,
      source,
    });
  }, [dragPayload?.artifact.kind, label, setAnchorFromElement, wakeAnchorId]);

  return (
    <button
      ref={rowRef}
      type="button"
      className="group flex h-[30px] w-full items-center gap-2 px-[10px] text-left transition-colors hover:bg-[rgba(213,173,87,0.04)]"
      onClick={onClick}
      onMouseEnter={() => publishWakeAnchor("hover")}
      onMouseMove={() => publishWakeAnchor("hover")}
      onMouseLeave={() => clearAnchor(wakeAnchorId)}
      onPointerDownCapture={() => publishWakeAnchor("drag")}
      title={isDraggable ? "Drag into a hunt, smart bucket, or stage shelf" : undefined}
      {...(dragPayload ? dragSourceProps : {})}
      style={dragPayload ? dragSourceProps.style : undefined}
    >
      {icon && (
        <span className="flex h-4 w-4 shrink-0 items-center justify-center text-[rgba(182,183,193,0.35)]">
          {icon}
        </span>
      )}
      <span className="flex-1 truncate text-[13px] text-[rgba(232,230,222,0.7)]">{label}</span>
      {meta && <span className="text-[11px] text-[rgba(182,183,193,0.35)]">{meta}</span>}
      <span
        className="shrink-0 font-mono text-[9px] italic text-[rgba(182,183,193,0.35)]"
        style={{ background: "rgba(213,173,87,0.05)", borderRadius: 3, padding: "1px 5px" }}
      >
        {reason}
      </span>
      {isDraggable && <DragCue active={isDragging} />}
    </button>
  );
}

function DragCue({ active }: { active: boolean }) {
  return (
    <span
      className="shrink-0 rounded-sm border px-1.5 py-[1px] font-mono text-[9px] uppercase tracking-[0.08em]"
      style={{
        borderColor: active ? "rgba(213,173,87,0.35)" : "rgba(213,173,87,0.16)",
        background: active ? "rgba(213,173,87,0.14)" : "rgba(213,173,87,0.05)",
        color: active ? "rgba(232,230,222,0.92)" : "rgba(213,173,87,0.72)",
      }}
    >
      drag
    </span>
  );
}

export function CollapsibleSection({
  title,
  children,
  count,
  forceVisible,
}: {
  title: string;
  children: React.ReactNode;
  count: number;
  forceVisible?: boolean;
}) {
  if (count === 0 && !forceVisible) return null;
  return (
    <>
      <SectionHeader>{title}</SectionHeader>
      {children}
    </>
  );
}

export function EmptyState({ text }: { text: string }) {
  return (
    <div className="px-[10px] py-1">
      <span className="text-[12px] text-[rgba(182,183,193,0.35)]">{text}</span>
    </div>
  );
}
