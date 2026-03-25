/**
 * ReceiptComparison -- side-by-side comparison of receipt nodes with
 * posture analytics integration.
 *
 * Renders PostureSummaryBar + GuardHeatmapTable in the header extra,
 * then ComparisonColumns with per-receipt verdict, guard results, and
 * signature status.
 */

import { useMemo } from "react";
import type { Node } from "@xyflow/react";
import { IconCertificate } from "@tabler/icons-react";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";
import {
  summarizeReceiptPosture,
  summarizeGuardPolicyHeatmap,
} from "@/features/swarm/stores/swarm-board-store";
import { ComparisonColumns } from "./comparison-columns";
import { PostureSummaryBar, GuardHeatmapTable } from "./comparison-posture";

// ---------------------------------------------------------------------------
// Verdict badge colors
// ---------------------------------------------------------------------------

const VERDICT_COLORS: Record<string, string> = {
  allow: "#38a876",
  warn: "#c49a3c",
  deny: "#cc5555",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface ReceiptComparisonProps {
  nodes: Node<SwarmBoardNodeData>[];
  onClose: () => void;
}

export function ReceiptComparison({ nodes, onClose }: ReceiptComparisonProps) {
  const posture = useMemo(() => summarizeReceiptPosture(nodes), [nodes]);
  const heatmap = useMemo(() => summarizeGuardPolicyHeatmap(nodes), [nodes]);

  const headerExtra = (
    <div>
      <PostureSummaryBar posture={posture} />
      <GuardHeatmapTable heatmap={heatmap} />
    </div>
  );

  return (
    <ComparisonColumns
      nodes={nodes}
      typeLabel="receipt"
      typeIcon={IconCertificate}
      typeColor="#7c5cbf"
      onClose={onClose}
      headerExtra={headerExtra}
      renderNode={(node) => {
        const d = node.data as SwarmBoardNodeData;
        const verdict = d.verdict ?? "allow";
        const guards = d.guardResults ?? [];
        const sigStatus =
          d.signatureVerified === true
            ? "verified"
            : d.signatureVerified === false
              ? "unverified"
              : "unchecked";

        return (
          <div className="flex flex-col gap-1.5">
            {/* Verdict badge */}
            <div className="flex items-center gap-2">
              <span
                className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded-sm"
                style={{
                  backgroundColor: `${VERDICT_COLORS[verdict]}18`,
                  color: VERDICT_COLORS[verdict],
                }}
              >
                {verdict}
              </span>
              <span className="text-[9px] font-mono text-[#2a2f3a]">
                sig: {sigStatus}
              </span>
            </div>

            {/* Guard results table */}
            {guards.length > 0 && (
              <table className="w-full text-[9px] font-mono">
                <thead>
                  <tr className="text-[#2a2f3a] uppercase" style={{ letterSpacing: "0.1em" }}>
                    <th className="text-left font-normal py-0.5">Guard</th>
                    <th className="text-right font-normal py-0.5">Status</th>
                    <th className="text-right font-normal py-0.5">Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {guards.map((g, i) => (
                    <tr key={`${g.guard}-${i}`} className="text-[#5c6a80]">
                      <td className="text-left py-0.5 text-[#ece7dc] truncate max-w-[120px]">
                        {g.guard}
                      </td>
                      <td
                        className="text-right py-0.5"
                        style={{ color: g.allowed ? "#38a876" : "#cc5555" }}
                      >
                        {g.allowed ? "allow" : "deny"}
                      </td>
                      <td className="text-right py-0.5">
                        {g.duration_ms != null ? `${g.duration_ms}ms` : "--"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {/* Created timestamp */}
            {d.createdAt != null && (
              <div className="text-[8px] font-mono text-[#2a2f3a]">
                {new Date(d.createdAt).toISOString().replace("T", " ").slice(0, 19)}
              </div>
            )}
          </div>
        );
      }}
    />
  );
}
