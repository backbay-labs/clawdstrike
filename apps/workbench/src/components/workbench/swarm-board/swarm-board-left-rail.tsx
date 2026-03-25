/**
 * SwarmBoardLeftRail — minimal workspace explorer panel.
 *
 * Design: terminal-listing aesthetic. Section headers are barely-there
 * single-character abbreviations with thin divider lines. Session items
 * are monospace rows with a status dot, name, and branch — no cards,
 * no padding excess.
 */

import { useState, useCallback, useRef, useEffect, useMemo } from "react";
import { IconCircleFilled } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import {
  useSwarmBoard,
  summarizeGuardPolicyHeatmap,
  type GuardPolicySummary,
} from "@/features/swarm/stores/swarm-board-store";
import type { SwarmBoardNodeData, SessionStatus } from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COLLAPSED_WIDTH = 28;
const EXPANDED_WIDTH = 200;
const BRANCH_TRUNCATE_LENGTH = 10;
const BRANCH_DISPLAY_LENGTH = 8;

const STATUS_DOT_COLOR: Record<SessionStatus, string> = {
  idle: "#3d4250",
  running: "#3dbf84",
  blocked: "#d4a84b",
  completed: "#3d4250",
  failed: "#e74c3c",
  evaluating: "#d4a84b",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SwarmBoardLeftRail() {
  const [collapsed, setCollapsed] = useState(false);
  const { state, selectNode } = useSwarmBoard();

  const toggle = useCallback(() => setCollapsed((c) => !c), []);

  const sessions = useMemo(
    () =>
      state.nodes.filter(
        (n) => (n.data as SwarmBoardNodeData).nodeType === "agentSession",
      ),
    [state.nodes],
  );
  const artifacts = useMemo(
    () =>
      state.nodes.filter(
        (n) => (n.data as SwarmBoardNodeData).nodeType === "artifact",
      ),
    [state.nodes],
  );

  const branches = useMemo(
    () =>
      Array.from(
        new Set(
          sessions
            .map((n) => (n.data as SwarmBoardNodeData).branch)
            .filter(Boolean) as string[],
        ),
      ),
    [sessions],
  );

  const hunts = useMemo(
    () =>
      Array.from(
        new Set(
          state.nodes
            .map((n) => (n.data as SwarmBoardNodeData).huntId)
            .filter(Boolean) as string[],
        ),
      ),
    [state.nodes],
  );

  const policyHeatmap = useMemo(
    () => summarizeGuardPolicyHeatmap(state.nodes),
    [state.nodes],
  );

  const topPolicyGuards = useMemo(
    () => policyHeatmap.guards.slice(0, 5),
    [policyHeatmap.guards],
  );

  const policySummaryText = useMemo(
    () =>
      [
        `${policyHeatmap.receiptsWithGuards}r`,
        `${policyHeatmap.totalEvaluations}e`,
        `${policyHeatmap.denyCount}d`,
      ].join(" "),
    [policyHeatmap],
  );

  if (collapsed) {
    return (
      <div
        className="flex flex-col items-center pt-2 shrink-0"
        style={{ backgroundColor: "#070910", width: COLLAPSED_WIDTH, borderRight: "1px solid #0f1119" }}
      >
        <button
          onClick={toggle}
          className="text-[#3d4250] hover:text-[#6f7f9a] transition-colors leading-none text-[11px]"
          title="Expand panel"
          aria-label="Expand explorer panel"
        >
          &#x203a;
        </button>
        <span className="text-[9px] text-[#1e2230] font-mono tabular-nums mt-3">{sessions.length}</span>
        {policyHeatmap.uniqueGuards > 0 && (
          <span className="text-[8px] text-[#38221d] font-mono tabular-nums mt-1">
            {policyHeatmap.denyCount}d
          </span>
        )}
      </div>
    );
  }

  return (
    <div
      className="flex flex-col shrink-0 overflow-y-auto"
      style={{ backgroundColor: "#070910", width: EXPANDED_WIDTH, borderRight: "1px solid #0f1119" }}
    >
      {/* Header — minimal */}
      <div className="flex items-center justify-between px-2 py-1.5 shrink-0" style={{ borderBottom: "1px solid #0f1119" }}>
        <span className="text-[8px] font-mono text-[#1e2230] uppercase tracking-[0.2em]">
          explorer
        </span>
        <button
          onClick={toggle}
          className="text-[#3d4250] hover:text-[#6f7f9a] transition-colors leading-none text-[11px]"
          title="Collapse panel"
          aria-label="Collapse explorer panel"
        >
          &#x2039;
        </button>
      </div>

      {/* Sessions */}
      <RailSection label="S" title="Sessions" count={sessions.length}>
        {sessions.length === 0 ? (
          <span className="text-[9px] text-[#1e2230] font-mono px-2 py-0.5 block">
            no sessions
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
                  "w-full flex items-center gap-1.5 px-2 py-[3px] text-left font-mono transition-colors",
                  isSelected
                    ? "bg-[#d4a84b08] text-[#ece7dc]"
                    : "text-[#6f7f9a] hover:bg-[#ffffff04]",
                )}
                aria-label={`Select session: ${d.title}`}
              >
                <IconCircleFilled
                  size={4}
                  style={{ color: STATUS_DOT_COLOR[d.status ?? "idle"] }}
                  className="shrink-0"
                />
                <span className="text-[10px] truncate flex-1">
                  {d.title}
                </span>
                {d.branch && (
                  <span className="text-[8px] text-[#1e2230] truncate max-w-[50px] text-right tabular-nums">
                    {d.branch.length > BRANCH_TRUNCATE_LENGTH
                      ? d.branch.slice(0, BRANCH_DISPLAY_LENGTH) + ".."
                      : d.branch}
                  </span>
                )}
              </button>
            );
          })
        )}
      </RailSection>

      {/* Hunts */}
      {hunts.length > 0 && (
        <RailSection label="H" title="Hunts" count={hunts.length}>
          {hunts.map((huntId) => (
            <div key={huntId} className="flex items-center gap-1.5 px-2 py-[3px] font-mono">
              <span className="text-[10px] text-[#6f7f9a] truncate">
                {huntId}
              </span>
            </div>
          ))}
        </RailSection>
      )}

      {/* Artifacts */}
      {artifacts.length > 0 && (
        <RailSection label="A" title="Artifacts" count={artifacts.length}>
          {artifacts.map((node) => {
            const d = node.data as SwarmBoardNodeData;
            return (
              <button
                key={node.id}
                onClick={() => selectNode(node.id)}
                className={cn(
                  "w-full flex items-center gap-1.5 px-2 py-[3px] text-left font-mono transition-colors",
                  state.selectedNodeId === node.id
                    ? "bg-[#3dbf8408] text-[#ece7dc]"
                    : "text-[#6f7f9a] hover:bg-[#ffffff04]",
                )}
                aria-label={`Select artifact: ${d.filePath ?? d.title}`}
              >
                <span className="text-[10px] truncate">
                  {d.filePath ?? d.title}
                </span>
              </button>
            );
          })}
        </RailSection>
      )}

      {/* Policy */}
      {policyHeatmap.uniqueGuards > 0 && (
        <RailSection label="P" title="Policy" count={policyHeatmap.uniqueGuards}>
          <div className="px-2 py-1 font-mono text-[8px] text-[#3d4250]">
            <div className="flex items-center justify-between gap-2">
              <span>{policySummaryText}</span>
              <span>{policyHeatmap.allowCount}a {policyHeatmap.warnCount}w</span>
            </div>
          </div>
          {topPolicyGuards.map((guard) => (
            <PolicyRow key={guard.guard} summary={guard} />
          ))}
        </RailSection>
      )}

      {/* Branches */}
      {branches.length > 0 && (
        <RailSection label="B" title="Branches" count={branches.length}>
          {branches.map((branch) => (
            <div key={branch} className="flex items-center gap-1.5 px-2 py-[3px] font-mono">
              <span className="text-[10px] text-[#6f7f9a] truncate">
                {branch}
              </span>
            </div>
          ))}
        </RailSection>
      )}
    </div>
  );
}

function PolicyRow({ summary }: { summary: GuardPolicySummary }) {
  return (
    <div className="px-2 py-1 font-mono" data-testid={`policy-row-${summary.guard}`}>
      <div className="flex items-center gap-2">
        <span className="text-[10px] text-[#c3cfdf] truncate flex-1">{summary.guard}</span>
        <span className="text-[8px] text-[#1e2230] tabular-nums">{summary.totalEvaluations}</span>
      </div>
      <div className="mt-1 flex items-center gap-2">
        <RatioBar summary={summary} />
        <span className="text-[8px] tabular-nums whitespace-nowrap">
          <span className="text-[#e74c3c]">{summary.denyCount}d</span>{" "}
          <span className="text-[#d4a84b]">{summary.warnCount}w</span>{" "}
          <span className="text-[#3dbf84]">{summary.allowCount}a</span>
        </span>
      </div>
      <div className="mt-0.5 text-[8px] text-[#3d4250] tabular-nums">
        {summary.receiptCount}r {formatLatency(summary)}
      </div>
    </div>
  );
}

function RatioBar({ summary }: { summary: GuardPolicySummary }) {
  const segments = [
    { key: "deny", ratio: summary.denyRatio, color: "#6d231d" },
    { key: "warn", ratio: summary.warnRatio, color: "#70521f" },
    { key: "allow", ratio: summary.allowRatio, color: "#184634" },
  ].filter((segment) => segment.ratio > 0);

  return (
    <div className="flex h-[4px] flex-1 overflow-hidden rounded-full bg-[#0f1119]">
      {segments.map((segment) => (
        <span
          key={segment.key}
          style={{
            width: `${Math.max(segment.ratio * 100, 8)}%`,
            backgroundColor: segment.color,
          }}
        />
      ))}
    </div>
  );
}

function formatLatency(summary: GuardPolicySummary): string {
  if (summary.averageLatencyMs == null || summary.maxLatencyMs == null) {
    return "lat n/a";
  }

  return `avg ${Math.round(summary.averageLatencyMs)}ms max ${summary.maxLatencyMs}ms`;
}

// ---------------------------------------------------------------------------
// Section — barely-there label + thin divider, collapsible
// ---------------------------------------------------------------------------

function RailSection({
  label,
  title,
  count,
  children,
}: {
  label: string;
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
    <div style={{ borderBottom: "1px solid #0a0c12" }}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1 px-2 py-1 w-full text-left"
        aria-label={`${open ? "Collapse" : "Expand"} ${title} section`}
        title={title}
      >
        <span className="text-[8px] font-mono text-[#1e2230] w-3 shrink-0 uppercase">
          {label}
        </span>
        <span className="flex-1 h-px bg-[#0f1119]" />
        <span className="text-[8px] text-[#1e2230] font-mono tabular-nums ml-1">{count}</span>
      </button>
      <div
        style={{
          height: open ? contentHeight : 0,
          overflow: "hidden",
          transition: "height 0.15s ease",
        }}
      >
        <div ref={contentRef} className="pb-0.5">
          {children}
        </div>
      </div>
    </div>
  );
}
