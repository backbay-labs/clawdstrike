/**
 * LabRunHistoryPanel — Displays past lab runs for the current document.
 *
 * Shows a list of runs with timestamp, summary, and file type. Supports
 * inspecting individual run results and deleting old runs.
 */

import { useState } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { LabRun } from "@/lib/workbench/detection-workflow/shared-types";
import { FILE_TYPE_REGISTRY, type FileType } from "@/lib/workbench/file-type-registry";
import {
  IconCircleCheck,
  IconCircleX,
  IconClock,
  IconTrash,
  IconChevronDown,
  IconChevronRight,
  IconFlask,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";

interface LabRunHistoryPanelProps {
  runs: LabRun[];
  onDeleteRun: (runId: string) => void;
}

export function LabRunHistoryPanel({
  runs,
  onDeleteRun,
}: LabRunHistoryPanelProps) {
  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);

  if (runs.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full px-6 text-[#6f7f9a]">
        <div className="w-14 h-14 rounded-2xl bg-[#131721] border border-[#2d3240]/60 flex items-center justify-center mb-4">
          <IconFlask size={22} stroke={1.2} className="empty-state-icon text-[#6f7f9a]" />
        </div>
        <span className="text-[13px] font-medium text-[#6f7f9a]">
          No lab runs yet
        </span>
        <span className="text-[11px] mt-1.5 text-[#6f7f9a]/60 text-center leading-relaxed">
          Execute a lab run to see results here.
          <br />
          History persists across sessions.
        </span>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-4 py-3 border-b border-[#2d3240] shrink-0">
        <div className="flex items-center gap-2">
          <h2 className="font-syne font-bold text-sm text-[#ece7dc]">
            Run History
          </h2>
          <span className="text-[9px] font-mono text-[#6f7f9a]/60">
            {runs.length} run{runs.length !== 1 ? "s" : ""}
          </span>
        </div>
      </div>

      <ScrollArea className="flex-1 overflow-y-auto">
        <div className="p-3 space-y-1">
          {runs.map((run) => {
            const isExpanded = expandedRunId === run.id;
            const allPassed = run.summary.failed === 0 && run.summary.totalCases > 0;
            const descriptor = FILE_TYPE_REGISTRY[run.fileType as FileType];

            return (
              <div
                key={run.id}
                className={cn(
                  "rounded-lg border transition-colors",
                  isExpanded
                    ? "border-[#2d3240] bg-[#131721]"
                    : "border-transparent hover:border-[#2d3240]/40 hover:bg-[#131721]/30",
                )}
              >
                {/* Run summary row */}
                <button
                  onClick={() => setExpandedRunId(isExpanded ? null : run.id)}
                  className="w-full flex items-center gap-2 px-3 py-2.5 text-left"
                >
                  {isExpanded ? (
                    <IconChevronDown size={10} stroke={2} className="text-[#6f7f9a] shrink-0" />
                  ) : (
                    <IconChevronRight size={10} stroke={2} className="text-[#6f7f9a] shrink-0" />
                  )}

                  {/* Status icon */}
                  {allPassed ? (
                    <IconCircleCheck size={13} stroke={1.5} className="text-[#3dbf84] shrink-0" />
                  ) : (
                    <IconCircleX size={13} stroke={1.5} className="text-[#c45c5c] shrink-0" />
                  )}

                  {/* Summary text */}
                  <div className="flex-1 min-w-0">
                    <span
                      className={cn(
                        "text-[11px] font-mono",
                        allPassed ? "text-[#3dbf84]" : "text-[#c45c5c]",
                      )}
                    >
                      {run.summary.passed}/{run.summary.totalCases} passed
                    </span>
                    {run.summary.matched > 0 && (
                      <span className="text-[10px] font-mono text-[#d4a84b]/70 ml-2">
                        {run.summary.matched} matched
                      </span>
                    )}
                  </div>

                  {/* File type badge */}
                  {descriptor && (
                    <span
                      className="text-[8px] font-mono uppercase px-1.5 py-0 border rounded shrink-0"
                      style={{
                        color: descriptor.iconColor,
                        borderColor: `${descriptor.iconColor}33`,
                        backgroundColor: `${descriptor.iconColor}15`,
                      }}
                    >
                      {descriptor.shortLabel}
                    </span>
                  )}

                  {/* Timestamp */}
                  <span className="text-[9px] font-mono text-[#6f7f9a]/50 shrink-0">
                    {formatRunTimestamp(run.completedAt)}
                  </span>
                </button>

                {/* Expanded details */}
                {isExpanded && (
                  <div className="px-3 pb-3 space-y-2">
                    {/* Stats grid */}
                    <div className="grid grid-cols-3 gap-2">
                      <StatBox label="Passed" value={run.summary.passed} color="#3dbf84" />
                      <StatBox label="Failed" value={run.summary.failed} color="#c45c5c" />
                      <StatBox label="Total" value={run.summary.totalCases} color="#6f7f9a" />
                    </div>

                    {/* Detailed metrics */}
                    <div className="flex items-center gap-3 text-[9px] font-mono text-[#6f7f9a]">
                      <span>Matched: {run.summary.matched}</span>
                      <span>Missed: {run.summary.missed}</span>
                      <span>FP: {run.summary.falsePositives}</span>
                      <span className="uppercase">Engine: {run.summary.engine}</span>
                    </div>

                    {/* Timing */}
                    <div className="flex items-center gap-1.5 text-[9px] font-mono text-[#6f7f9a]/60">
                      <IconClock size={9} stroke={1.5} />
                      <span>{new Date(run.startedAt).toLocaleString()}</span>
                    </div>

                    {/* Case results (truncated) */}
                    {run.results.length > 0 && (
                      <div className="space-y-0.5 max-h-40 overflow-y-auto">
                        <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]/50 block mb-1">
                          Cases
                        </span>
                        {run.results.slice(0, 10).map((caseResult) => (
                          <div
                            key={caseResult.caseId}
                            className="flex items-center gap-2 px-2 py-1 rounded bg-[#0b0d13]/50"
                          >
                            {caseResult.status === "pass" ? (
                              <IconCircleCheck size={10} stroke={1.5} className="text-[#3dbf84] shrink-0" />
                            ) : (
                              <IconCircleX size={10} stroke={1.5} className="text-[#c45c5c] shrink-0" />
                            )}
                            <span className="text-[10px] font-mono text-[#6f7f9a] truncate flex-1">
                              {caseResult.caseId.slice(0, 12)}
                            </span>
                            <span className="text-[9px] font-mono text-[#6f7f9a]/50 shrink-0">
                              expected: {caseResult.expected}
                            </span>
                            <span className="text-[9px] font-mono text-[#6f7f9a]/50 shrink-0">
                              actual: {caseResult.actual}
                            </span>
                          </div>
                        ))}
                        {run.results.length > 10 && (
                          <span className="text-[9px] font-mono text-[#6f7f9a]/40 block text-center mt-1">
                            +{run.results.length - 10} more cases
                          </span>
                        )}
                      </div>
                    )}

                    {/* Delete button */}
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onDeleteRun(run.id);
                      }}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[10px] font-mono text-[#c45c5c]/60 hover:text-[#c45c5c] hover:bg-[#c45c5c]/10 transition-colors"
                    >
                      <IconTrash size={11} stroke={1.5} />
                      Delete run
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </ScrollArea>
    </div>
  );
}

function StatBox({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="flex flex-col items-center px-2 py-2 rounded-lg border border-[#2d3240] bg-[#0b0d13]">
      <span className="text-sm font-mono font-bold" style={{ color }}>
        {value}
      </span>
      <span className="text-[8px] font-mono uppercase tracking-wider text-[#6f7f9a] mt-0.5">
        {label}
      </span>
    </div>
  );
}

function formatRunTimestamp(isoString: string): string {
  const date = new Date(isoString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;

  return date.toLocaleDateString();
}
