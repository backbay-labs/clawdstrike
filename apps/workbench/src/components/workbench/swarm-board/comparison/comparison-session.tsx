/**
 * SessionComparison -- side-by-side comparison of agentSession nodes.
 *
 * Renders ComparisonColumns with a 2-column grid showing key metrics
 * per session: status, model, branch, risk, policy, receipts, etc.
 */

import type { Node } from "@xyflow/react";
import { IconTerminal2 } from "@tabler/icons-react";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";
import { ComparisonColumns } from "./comparison-columns";

// ---------------------------------------------------------------------------
// Risk color mapping
// ---------------------------------------------------------------------------

const RISK_COLORS: Record<string, string> = {
  low: "#38a876",
  medium: "#c49a3c",
  high: "#cc5555",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface SessionComparisonProps {
  nodes: Node<SwarmBoardNodeData>[];
  onClose: () => void;
}

export function SessionComparison({ nodes, onClose }: SessionComparisonProps) {
  return (
    <ComparisonColumns
      nodes={nodes}
      typeLabel="session"
      typeIcon={IconTerminal2}
      typeColor="#c49a3c"
      onClose={onClose}
      renderNode={(node) => {
        const d = node.data as SwarmBoardNodeData;
        return (
          <div className="grid grid-cols-2 gap-x-3 gap-y-1">
            <MetricCell label="Status" value={d.status} />
            <MetricCell label="Risk" value={d.risk} color={d.risk ? RISK_COLORS[d.risk] : undefined} />
            <MetricCell label="Model" value={d.agentModel} />
            <MetricCell label="Policy" value={d.policyMode} />
            <MetricCell label="Branch" value={d.branch} />
            <MetricCell label="Receipts" value={d.receiptCount != null ? String(d.receiptCount) : undefined} />
            <MetricCell label="Files changed" value={d.changedFilesCount != null ? String(d.changedFilesCount) : undefined} />
            <MetricCell label="Blocked" value={d.blockedActionCount != null ? String(d.blockedActionCount) : undefined} />
            <MetricCell label="Tool events" value={d.toolBoundaryEvents != null ? String(d.toolBoundaryEvents) : undefined} />
            <MetricCell label="Confidence" value={d.confidence != null ? `${d.confidence}%` : undefined} />
          </div>
        );
      }}
    />
  );
}

// ---------------------------------------------------------------------------
// Metric cell
// ---------------------------------------------------------------------------

function MetricCell({
  label,
  value,
  color,
}: {
  label: string;
  value?: string;
  color?: string;
}) {
  return (
    <div>
      <div className="text-[10px] text-[#2a2f3a] uppercase font-mono" style={{ letterSpacing: "0.08em" }}>
        {label}
      </div>
      <div
        className="text-[11px] font-mono truncate"
        style={{ color: color ?? "#ece7dc" }}
      >
        {value ?? "--"}
      </div>
    </div>
  );
}
