/**
 * DiffComparison -- side-by-side comparison of diff nodes.
 *
 * Shows file count, added/removed line counts, and truncated file list.
 * No diffContent preview (too wide for comparison columns).
 */

import type { Node } from "@xyflow/react";
import { IconGitCommit } from "@tabler/icons-react";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";
import { ComparisonColumns } from "./comparison-columns";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_VISIBLE_FILES = 5;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface DiffComparisonProps {
  nodes: Node<SwarmBoardNodeData>[];
  onClose: () => void;
}

export function DiffComparison({ nodes, onClose }: DiffComparisonProps) {
  return (
    <ComparisonColumns
      nodes={nodes}
      typeLabel="diff"
      typeIcon={IconGitCommit}
      typeColor="#7c5cbf"
      onClose={onClose}
      renderNode={(node) => {
        const d = node.data as SwarmBoardNodeData;
        const summary = d.diffSummary;
        const files = summary?.files ?? [];
        const visibleFiles = files.slice(0, MAX_VISIBLE_FILES);
        const overflow = files.length - MAX_VISIBLE_FILES;

        return (
          <div className="flex flex-col gap-1">
            {/* Stats row */}
            <div className="flex items-center gap-3 text-[10px] font-mono">
              <span className="text-[#5c6a80]">
                {files.length} file{files.length !== 1 ? "s" : ""}
              </span>
              {summary && (
                <span>
                  <span style={{ color: "#38a876" }}>+{summary.added}</span>
                  {" / "}
                  <span style={{ color: "#cc5555" }}>-{summary.removed}</span>
                </span>
              )}
            </div>

            {/* File list */}
            {visibleFiles.length > 0 && (
              <div className="flex flex-col gap-0.5">
                {visibleFiles.map((f) => (
                  <div key={f} className="text-[9px] font-mono text-[#5c6a80] truncate">
                    {f}
                  </div>
                ))}
                {overflow > 0 && (
                  <div className="text-[9px] font-mono text-[#2a2f3a]">
                    and {overflow} more...
                  </div>
                )}
              </div>
            )}
          </div>
        );
      }}
    />
  );
}
