/**
 * NoteNode — sticky note aesthetic.
 *
 * Warm background tint, slight rotation, no hard borders.
 * Feels handwritten and analog, not digital.
 */

import { memo, useState, useCallback, useRef, useEffect } from "react";
import { NodeResizer, type NodeProps } from "@xyflow/react";
import { IconPencil, IconCheck } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useSwarmBoard } from "@/features/swarm/stores/swarm-board-store";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";
import { useZoomTier } from "../hooks/use-zoom-tier";

function NoteNodeInner({ id, data, selected }: NodeProps) {
  const d = data as SwarmBoardNodeData;
  const tier = useZoomTier();
  const { updateNode } = useSwarmBoard();

  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(d.content ?? "");
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  // Track cancel intent so onBlur doesn't save after Escape
  const cancellingRef = useRef(false);

  // Respond to external editing trigger (e.g., double-click from page)
  useEffect(() => {
    if (d.editing && !editing) {
      setDraft(d.content ?? "");
      setEditing(true);
      // Clear the flag so it doesn't re-trigger
      updateNode(id, { editing: false });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [d.editing, d.content, id, updateNode]);

  // Focus the textarea when entering edit mode
  useEffect(() => {
    if (editing && textareaRef.current) {
      textareaRef.current.focus();
      textareaRef.current.setSelectionRange(draft.length, draft.length);
    }
    // draft.length is intentionally omitted — we only want to focus on editing toggle
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editing]);

  const handleSave = useCallback(() => {
    if (cancellingRef.current) {
      cancellingRef.current = false;
      return;
    }
    updateNode(id, { content: draft });
    setEditing(false);
  }, [id, draft, updateNode]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      // Save on Cmd/Ctrl+Enter
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        handleSave();
      }
      // Cancel on Escape — set flag before blur fires
      if (e.key === "Escape") {
        cancellingRef.current = true;
        setDraft(d.content ?? "");
        setEditing(false);
      }
    },
    [handleSave, d.content],
  );

  // ---------------------------------------------------------------------------
  // Dot tier — warm-tinted square
  // ---------------------------------------------------------------------------
  if (tier === "dot") {
    return (
      <div
        className="rounded"
        style={{
          backgroundColor: "#12100c",
          width: "100%",
          height: "100%",
          minWidth: 20,
          minHeight: 20,
          borderLeft: "2px solid #a08a60",
        }}
      />
    );
  }

  // ---------------------------------------------------------------------------
  // Chip tier — first ~20 chars of content truncated, warm background
  // ---------------------------------------------------------------------------
  if (tier === "chip") {
    const preview = (d.content ?? d.title ?? "Note").slice(0, 20);
    return (
      <div
        className="rounded px-2 flex items-center"
        style={{
          backgroundColor: "#12100c",
          minWidth: 60,
          minHeight: 22,
        }}
      >
        <span className="text-[7px] font-mono text-[#a08a60] truncate">
          {preview}
        </span>
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Compact tier — show content but hide edit controls
  // Full tier — unchanged
  // ---------------------------------------------------------------------------

  return (
    <div
      className={cn(
        // Soft edges, no hard border — sticky note vibes
        "rounded transition-all duration-150 overflow-hidden",
        selected && "ring-1 ring-[#c49a3c]/15",
      )}
      style={{
        backgroundColor: '#12100c',
        width: "100%",
        height: "100%",
        minWidth: tier === "compact" ? 120 : 180,
        minHeight: tier === "compact" ? 50 : 90,
        // The slight rotation that says "a human placed this here"
        transform: 'rotate(-1.2deg)',
        // Warm tint overlay — amber, not blue-gray like everything else
        boxShadow: selected
          ? '0 2px 12px rgba(196,154,60,0.08)'
          : '0 1px 6px rgba(0,0,0,0.3)',
      }}
    >
      {tier === "full" && (
        <NodeResizer
          minWidth={180}
          minHeight={90}
          isVisible={selected}
          lineClassName="!border-[#c49a3c]/25"
          handleClassName="!w-1.5 !h-1.5 !bg-[#c49a3c] !border-[#12100c]"
        />
      )}

      {/* Top accent — warm amber strip instead of a full header */}
      <div
        className="flex items-center justify-between px-3 pt-2.5 pb-1"
      >
        <span className="text-[10px] font-medium text-[#a08a60] truncate flex-1">
          {d.title || "Note"}
        </span>
        {tier === "full" && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              if (editing) {
                handleSave();
              } else {
                setDraft(d.content ?? "");
                setEditing(true);
              }
            }}
            className="shrink-0 p-0.5 text-[#a08a60]/50 hover:text-[#a08a60] transition-colors"
            title={editing ? "Save" : "Edit"}
            aria-label={editing ? "Save note" : "Edit note"}
          >
            {editing ? <IconCheck size={11} stroke={2} /> : <IconPencil size={11} stroke={1.5} />}
          </button>
        )}
      </div>

      {/* Body — generous padding, warm text */}
      <div className="px-3 pb-3 pt-1">
        {tier === "full" && editing ? (
          <textarea
            ref={textareaRef}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={handleKeyDown}
            onBlur={handleSave}
            className="w-full bg-transparent text-[11px] text-[#d4cabb] leading-[1.7] resize-none outline-none placeholder-[#3d3528] min-h-[50px]"
            placeholder="Type your notes here..."
            // Prevent React Flow from capturing drag events on the textarea
            onMouseDown={(e) => e.stopPropagation()}
          />
        ) : (
          <div
            className={cn(
              "text-[11px] text-[#9a8e78] leading-[1.7] whitespace-pre-wrap",
              tier === "full" && "cursor-text",
              tier === "compact" && "line-clamp-2",
            )}
            onClick={tier === "full" ? (e) => {
              e.stopPropagation();
              setDraft(d.content ?? "");
              setEditing(true);
            } : undefined}
          >
            {d.content || (
              <span className="text-[#3d3528] italic">Click to add notes...</span>
            )}
          </div>
        )}
      </div>

      {/* Helper hint when editing — very quiet, full tier only */}
      {tier === "full" && editing && (
        <div className="px-3 pb-2">
          <span className="text-[7px] text-[#3d3528]">
            Ctrl+Enter to save / Esc to cancel
          </span>
        </div>
      )}
    </div>
  );
}

export const NoteNode = memo(NoteNodeInner);
