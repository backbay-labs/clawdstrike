/**
 * NoteNode — editable sticky note with gold-tinted background.
 */

import { memo, useState, useCallback, useRef, useEffect } from "react";
import { NodeResizer, type NodeProps } from "@xyflow/react";
import { IconNote, IconPencil, IconCheck } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useSwarmBoard } from "@/lib/workbench/swarm-board-store";
import type { SwarmBoardNodeData } from "@/lib/workbench/swarm-board-types";

function NoteNodeInner({ id, data, selected }: NodeProps) {
  const d = data as SwarmBoardNodeData;
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
  }, [d.editing]);

  // Focus the textarea when entering edit mode
  useEffect(() => {
    if (editing && textareaRef.current) {
      textareaRef.current.focus();
      textareaRef.current.setSelectionRange(draft.length, draft.length);
    }
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

  return (
    <div
      className={cn(
        "rounded-lg transition-all duration-200 overflow-hidden",
        selected
          ? "shadow-[0_0_0_1px_rgba(212,168,75,0.25)]"
          : "shadow-[0_2px_8px_rgba(0,0,0,0.4)]",
        !selected && "hover:bg-[#0f1219]",
      )}
      style={{
        backgroundColor: selected ? "#11141c" : "#0c0e14",
        width: "100%",
        height: "100%",
        minWidth: 200,
        minHeight: 100,
        // Subtle gold tint via gradient overlay
        backgroundImage:
          "linear-gradient(135deg, rgba(212,168,75,0.04) 0%, rgba(12,14,20,0) 60%)",
      }}
    >
      <NodeResizer
        minWidth={200}
        minHeight={100}
        isVisible={selected}
        lineClassName="!border-[#d4a84b]/40"
        handleClassName="!w-2 !h-2 !bg-[#d4a84b] !border-[#0b0d13]"
      />

      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-[#d4a84b15]">
        <IconNote size={13} stroke={1.5} className="text-[#d4a84b80] shrink-0" />
        <span className="text-[11px] font-medium text-[#d4a84b] truncate flex-1">
          {d.title || "Note"}
        </span>
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
          className="shrink-0 p-0.5 rounded hover:bg-[#d4a84b15] text-[#d4a84b80] hover:text-[#d4a84b] transition-colors"
          title={editing ? "Save" : "Edit"}
        >
          {editing ? <IconCheck size={12} stroke={2} /> : <IconPencil size={12} stroke={1.5} />}
        </button>
      </div>

      {/* Body */}
      <div className="px-3 py-2.5">
        {editing ? (
          <textarea
            ref={textareaRef}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={handleKeyDown}
            onBlur={handleSave}
            className="w-full bg-transparent text-[11px] text-[#ece7dc] leading-[1.6] resize-none outline-none placeholder-[#3d4250] min-h-[60px]"
            placeholder="Type your notes here..."
            // Prevent React Flow from capturing drag events on the textarea
            onMouseDown={(e) => e.stopPropagation()}
          />
        ) : (
          <div
            className="text-[11px] text-[#8a96ab] leading-[1.6] whitespace-pre-wrap cursor-text"
            onClick={(e) => {
              e.stopPropagation();
              setDraft(d.content ?? "");
              setEditing(true);
            }}
          >
            {d.content || (
              <span className="text-[#3d4250] italic">Click to add notes...</span>
            )}
          </div>
        )}
      </div>

      {/* Helper hint when editing */}
      {editing && (
        <div className="px-3 pb-1.5">
          <span className="text-[8px] text-[#3d4250]">
            Ctrl+Enter to save / Escape to cancel
          </span>
        </div>
      )}
    </div>
  );
}

export const NoteNode = memo(NoteNodeInner);
