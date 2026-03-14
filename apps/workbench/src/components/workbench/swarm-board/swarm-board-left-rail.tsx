/**
 * SwarmBoardLeftRail — workspace explorer panel (Section 9).
 *
 * Provides a collapsible left rail with:
 * - Active sessions list
 * - Hunts/investigations
 * - Recent artifacts
 * - Branch overview
 *
 * Phase 1: static list derived from board state.
 * Phase 2+: live data from PTY backend + git integration.
 */

import { useState, useCallback, useRef, useEffect } from "react";
import {
  IconChevronLeft,
  IconChevronRight,
  IconTerminal2,
  IconTarget,
  IconFile,
  IconGitBranch,
  IconCircleFilled,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useSwarmBoard } from "@/lib/workbench/swarm-board-store";
import type { SwarmBoardNodeData, SessionStatus } from "@/lib/workbench/swarm-board-types";

// ---------------------------------------------------------------------------
// Status dot color
// ---------------------------------------------------------------------------

const STATUS_DOT_COLOR: Record<SessionStatus, string> = {
  idle: "#6f7f9a",
  running: "#3dbf84",
  blocked: "#d4a84b",
  completed: "#6f7f9a",
  failed: "#e74c3c",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SwarmBoardLeftRail() {
  const [collapsed, setCollapsed] = useState(false);
  const { state, selectNode } = useSwarmBoard();

  const toggle = useCallback(() => setCollapsed((c) => !c), []);

  // Derive lists from board state
  const sessions = state.nodes.filter(
    (n) => (n.data as SwarmBoardNodeData).nodeType === "agentSession",
  );
  const artifacts = state.nodes.filter(
    (n) => (n.data as SwarmBoardNodeData).nodeType === "artifact",
  );

  // Unique branches from session nodes
  const branches = Array.from(
    new Set(
      sessions
        .map((n) => (n.data as SwarmBoardNodeData).branch)
        .filter(Boolean) as string[],
    ),
  );

  // Unique hunt IDs
  const hunts = Array.from(
    new Set(
      state.nodes
        .map((n) => (n.data as SwarmBoardNodeData).huntId)
        .filter(Boolean) as string[],
    ),
  );

  if (collapsed) {
    return (
      <div
        className="flex flex-col items-center py-3 shrink-0"
        style={{ backgroundColor: "#070910", width: 36, borderRight: "1px solid #1a1f2e" }}
      >
        <button
          onClick={toggle}
          className="p-1 rounded hover:bg-[#ffffff06] text-[#3d4250] hover:text-[#6f7f9a] transition-colors"
          title="Expand panel"
        >
          <IconChevronRight size={13} stroke={1.5} />
        </button>
        <div className="mt-4 flex flex-col gap-2 items-center">
          <IconTerminal2 size={12} stroke={1.5} className="text-[#1e2230]" />
          <span className="text-[9px] text-[#3d4250] font-mono tabular-nums">{sessions.length}</span>
        </div>
      </div>
    );
  }

  return (
    <div
      className="flex flex-col shrink-0 overflow-y-auto"
      style={{ backgroundColor: "#070910", width: 220, borderRight: "1px solid #1a1f2e" }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2.5 shrink-0" style={{ borderBottom: "1px solid #1a1f2e" }}>
        <span className="text-[8px] font-mono text-[#3d4250] uppercase tracking-[0.2em]">
          Explorer
        </span>
        <button
          onClick={toggle}
          className="p-0.5 rounded hover:bg-[#ffffff06] text-[#3d4250] hover:text-[#6f7f9a] transition-colors"
          title="Collapse panel"
        >
          <IconChevronLeft size={13} stroke={1.5} />
        </button>
      </div>

      {/* Sessions */}
      <RailSection icon={IconTerminal2} title="Sessions" count={sessions.length}>
        {sessions.length === 0 ? (
          <span className="text-[10px] text-[#1e2230] font-mono px-3 py-1 block">
            spawn a session to begin...
          </span>
        ) : (
          sessions.map((node) => {
            const d = node.data as SwarmBoardNodeData;
            const isSelected = state.selectedNodeId === node.id;
            return (
              <button
                key={node.id}
                onClick={() => selectNode(node.id)}
                className={cn(
                  "w-full flex items-center gap-2 px-3 py-1.5 text-left transition-colors",
                  isSelected
                    ? "bg-[#d4a84b08]"
                    : "hover:bg-[#ffffff04]",
                )}
              >
                <IconCircleFilled
                  size={5}
                  style={{ color: STATUS_DOT_COLOR[d.status ?? "idle"] }}
                  className="shrink-0"
                />
                <span className={cn(
                  "text-[11px] truncate flex-1",
                  isSelected ? "text-[#ece7dc]" : "text-[#6f7f9a]",
                )}>
                  {d.title}
                </span>
                {d.sessionId ? (
                  d.branch && (
                    <span className="text-[9px] text-[#1e2230] font-mono truncate max-w-[55px] text-right">
                      {d.branch.length > 10 ? d.branch.slice(0, 8) + "..." : d.branch}
                    </span>
                  )
                ) : (
                  <span className="text-[9px] text-[#1e223080] font-mono">
                    demo
                  </span>
                )}
              </button>
            );
          })
        )}
      </RailSection>

      {/* Hunts */}
      <RailSection icon={IconTarget} title="Hunts" count={hunts.length}>
        {hunts.length === 0 ? (
          <span className="text-[10px] text-[#1e2230] font-mono px-3 py-1 block">
            No active hunts
          </span>
        ) : (
          hunts.map((huntId) => (
            <div
              key={huntId}
              className="flex items-center gap-2 px-3 py-1.5"
            >
              <IconTarget size={10} stroke={1.5} className="text-[#d4a84b60] shrink-0" />
              <span className="text-[10px] text-[#6f7f9a] font-mono truncate">
                {huntId}
              </span>
            </div>
          ))
        )}
      </RailSection>

      {/* Recent Artifacts */}
      <RailSection icon={IconFile} title="Artifacts" count={artifacts.length}>
        {artifacts.length === 0 ? (
          <span className="text-[10px] text-[#1e2230] font-mono px-3 py-1 block">
            No artifacts
          </span>
        ) : (
          artifacts.map((node) => {
            const d = node.data as SwarmBoardNodeData;
            return (
              <button
                key={node.id}
                onClick={() => selectNode(node.id)}
                className={cn(
                  "w-full flex items-center gap-2 px-3 py-1.5 text-left transition-colors",
                  state.selectedNodeId === node.id
                    ? "bg-[#3dbf8408]"
                    : "hover:bg-[#ffffff04]",
                )}
              >
                <IconFile size={10} stroke={1.5} className="text-[#3dbf8460] shrink-0" />
                <span className="text-[10px] text-[#6f7f9a] font-mono truncate">
                  {d.filePath ?? d.title}
                </span>
              </button>
            );
          })
        )}
      </RailSection>

      {/* Branches */}
      <RailSection icon={IconGitBranch} title="Branches" count={branches.length}>
        {branches.length === 0 ? (
          <span className="text-[10px] text-[#1e2230] font-mono px-3 py-1 block">
            No branches
          </span>
        ) : (
          branches.map((branch) => (
            <div
              key={branch}
              className="flex items-center gap-2 px-3 py-1.5"
            >
              <IconGitBranch size={10} stroke={1.5} className="text-[#5b8def60] shrink-0" />
              <span className="text-[10px] text-[#6f7f9a] font-mono truncate">
                {branch}
              </span>
            </div>
          ))
        )}
      </RailSection>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Section helper
// ---------------------------------------------------------------------------

function RailSection({
  icon: Icon,
  title,
  count,
  children,
}: {
  icon: typeof IconTerminal2;
  title: string;
  count: number;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(true);
  const contentRef = useRef<HTMLDivElement>(null);
  const [contentHeight, setContentHeight] = useState<number | undefined>(undefined);

  useEffect(() => {
    if (contentRef.current) {
      setContentHeight(contentRef.current.scrollHeight);
    }
  }, [children]);

  return (
    <div style={{ borderBottom: "1px solid #0f1119" }}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1.5 px-3 py-2 w-full text-left hover:bg-[#ffffff03] transition-colors"
      >
        <Icon size={10} stroke={1.5} className="text-[#1e2230] shrink-0" />
        <span className="text-[8px] font-mono uppercase tracking-[0.2em] text-[#3d4250] flex-1">
          {title}
        </span>
        <span className="text-[9px] text-[#1e2230] font-mono tabular-nums">{count}</span>
      </button>
      <div
        style={{
          height: open ? contentHeight : 0,
          overflow: "hidden",
          transition: "height 0.2s ease",
        }}
      >
        <div ref={contentRef} className="pb-1">
          {children}
        </div>
      </div>
    </div>
  );
}
