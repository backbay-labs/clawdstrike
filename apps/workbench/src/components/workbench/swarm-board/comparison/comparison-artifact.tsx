/**
 * ArtifactComparison -- side-by-side comparison of artifact nodes.
 *
 * Shows file path, file type badge, artifact kind (if detection workflow),
 * format, and publish state.
 */

import type { Node } from "@xyflow/react";
import { IconFile } from "@tabler/icons-react";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";
import { ComparisonColumns } from "./comparison-columns";

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface ArtifactComparisonProps {
  nodes: Node<SwarmBoardNodeData>[];
  onClose: () => void;
}

export function ArtifactComparison({ nodes, onClose }: ArtifactComparisonProps) {
  return (
    <ComparisonColumns
      nodes={nodes}
      typeLabel="artifact"
      typeIcon={IconFile}
      typeColor="#38a876"
      onClose={onClose}
      renderNode={(node) => {
        const d = node.data as SwarmBoardNodeData;
        return (
          <div className="flex flex-col gap-1">
            {/* File path */}
            {d.filePath && (
              <div className="text-[9px] font-mono text-[#5c6a80] truncate">
                {d.filePath}
              </div>
            )}

            {/* Badges row */}
            <div className="flex items-center gap-2 flex-wrap">
              {/* File type */}
              {d.fileType && (
                <span className="text-[9px] font-mono px-1 py-0.5 rounded-sm bg-[#14181f] text-[#5c6a80]">
                  {d.fileType}
                </span>
              )}

              {/* Artifact kind */}
              {d.artifactKind && (
                <span className="text-[9px] font-mono px-1 py-0.5 rounded-sm bg-[#14181f] text-[#c49a3c]">
                  {d.artifactKind}
                </span>
              )}

              {/* Format */}
              {d.format && (
                <span className="text-[9px] font-mono px-1 py-0.5 rounded-sm bg-[#14181f] text-[#5c6a80]">
                  {String(d.format)}
                </span>
              )}
            </div>

            {/* Publish state */}
            {d.publishState && (
              <div className="text-[8px] font-mono text-[#2a2f3a]">
                publish: {d.publishState}
              </div>
            )}
          </div>
        );
      }}
    />
  );
}
