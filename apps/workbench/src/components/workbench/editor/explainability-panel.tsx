/**
 * Explainability Panel — displays structured explainability traces
 * from the latest lab run, with grouping, comparison deltas, and
 * jump-to-source support.
 *
 * Follows the same visual patterns as ResultsPanel and EvidencePackPanel:
 * - bg-[#0b0d13] with border-l
 * - 10px font-mono headers with tabler icons
 * - ScrollArea body
 * - Collapsible sections
 */

import { useState, useMemo } from "react";
import {
  IconBulb,
  IconChevronDown,
  IconChevronRight,
  IconTarget,
  IconAlertTriangle,
  IconEye,
  IconShieldCheck,
  IconArrowUp,
  IconArrowDown,
  IconMinus,
  IconFileCode,
} from "@tabler/icons-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { VerdictBadge } from "@/components/workbench/shared/verdict-badge";
import { cn } from "@/lib/utils";
import type { LabRun } from "@/lib/workbench/detection-workflow/shared-types";
import type { ExplainabilityTrace } from "@/lib/workbench/detection-workflow/shared-types";
import {
  extractTraces,
  compareRuns,
  groupTracesByOutcome,
  getSourceLineRange,
  type EnrichedTrace,
  type RunComparisonDelta,
  type TraceGroups,
} from "@/lib/workbench/detection-workflow/explainability";

// ---- Props ----

export interface ExplainabilityPanelProps {
  documentId: string | undefined;
  lastRun: LabRun | null;
  baselineRun?: LabRun | null;
  onJumpToLine?: (line: number) => void;
}

// ---- Collapsible Section ----

function CollapsibleSection({
  title,
  count,
  color,
  defaultOpen = false,
  children,
}: {
  title: string;
  count: number;
  color: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);

  if (count === 0) return null;

  return (
    <div className="mb-3">
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        className="flex items-center gap-1.5 w-full text-left py-1 group"
      >
        {open ? (
          <IconChevronDown size={12} stroke={1.5} className="text-[#6f7f9a] shrink-0" />
        ) : (
          <IconChevronRight size={12} stroke={1.5} className="text-[#6f7f9a] shrink-0" />
        )}
        <span className="text-[10px] font-mono uppercase tracking-wider" style={{ color }}>
          {title}
        </span>
        <span
          className="ml-auto text-[9px] font-mono px-1.5 py-0.5 rounded-full border"
          style={{ color, borderColor: `${color}30`, backgroundColor: `${color}10` }}
        >
          {count}
        </span>
      </button>
      {open && <div className="mt-1.5 space-y-1.5 pl-4">{children}</div>}
    </div>
  );
}

// ---- Source Line Link ----

function SourceLineLink({
  trace,
  onJumpToLine,
}: {
  trace: ExplainabilityTrace;
  onJumpToLine?: (line: number) => void;
}) {
  const range = getSourceLineRange(trace);
  if (!range || !onJumpToLine) return null;

  const label =
    range.start === range.end
      ? `L${range.start}`
      : `L${range.start}-${range.end}`;

  return (
    <button
      type="button"
      onClick={() => onJumpToLine(range.start)}
      className="inline-flex items-center gap-0.5 text-[9px] font-mono text-[#7c9aef] hover:text-[#9bb4f5] transition-colors"
      title={`Jump to line ${range.start}`}
    >
      <IconFileCode size={10} stroke={1.5} />
      {label}
    </button>
  );
}

// ---- Trace Renderers ----

function SigmaMatchTrace({
  enriched,
  onJumpToLine,
}: {
  enriched: EnrichedTrace;
  onJumpToLine?: (line: number) => void;
}) {
  const trace = enriched.trace;
  if (trace.kind !== "sigma_match") return null;

  return (
    <div className="rounded border border-[#2d3240] bg-[#131721] p-2">
      <div className="flex items-center gap-1.5 mb-1">
        <IconTarget size={11} stroke={1.5} className="text-[#d4a84b] shrink-0" />
        <span className="text-[10px] font-mono text-[#ece7dc] truncate">
          Sigma Match
        </span>
        <SourceLineLink trace={trace} onJumpToLine={onJumpToLine} />
      </div>

      {/* Matched selectors */}
      {trace.matchedSelectors.length > 0 && (
        <div className="mb-1">
          <span className="text-[9px] font-mono text-[#6f7f9a] uppercase">Selectors:</span>
          <div className="flex flex-wrap gap-1 mt-0.5">
            {trace.matchedSelectors.map((sel, i) => (
              <span
                key={`${sel.name}-${i}`}
                className="text-[9px] font-mono px-1 py-0.5 rounded bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/20"
              >
                {sel.name}
                {sel.fields.length > 0 && (
                  <span className="text-[#6f7f9a] ml-0.5">
                    ({sel.fields.join(", ")})
                  </span>
                )}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Matched fields */}
      {trace.matchedFields.length > 0 && (
        <div className="mb-1">
          <span className="text-[9px] font-mono text-[#6f7f9a] uppercase">Fields:</span>
          <div className="mt-0.5 space-y-0.5">
            {trace.matchedFields.map((f, i) => (
              <div key={`${f.path}-${i}`} className="flex items-center gap-1 text-[9px] font-mono">
                <span className="text-[#6f7f9a]">{f.path}:</span>
                <span className="text-[#ece7dc] truncate">{f.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Technique hints */}
      {trace.techniqueHints.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1">
          {trace.techniqueHints.map((t, i) => (
            <span
              key={`${t}-${i}`}
              className="text-[8px] font-mono px-1 py-0.5 rounded bg-[#7c9aef]/10 text-[#7c9aef] border border-[#7c9aef]/20"
            >
              {t}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function YaraMatchTrace({
  enriched,
  onJumpToLine,
}: {
  enriched: EnrichedTrace;
  onJumpToLine?: (line: number) => void;
}) {
  const trace = enriched.trace;
  if (trace.kind !== "yara_match") return null;

  return (
    <div className="rounded border border-[#2d3240] bg-[#131721] p-2">
      <div className="flex items-center gap-1.5 mb-1">
        <IconEye size={11} stroke={1.5} className="text-[#c45c5c] shrink-0" />
        <span className="text-[10px] font-mono text-[#ece7dc] truncate">
          YARA Match
        </span>
        <SourceLineLink trace={trace} onJumpToLine={onJumpToLine} />
      </div>

      {/* Matched strings */}
      {trace.matchedStrings.length > 0 && (
        <div className="mb-1">
          <span className="text-[9px] font-mono text-[#6f7f9a] uppercase">Strings:</span>
          <div className="mt-0.5 space-y-0.5">
            {trace.matchedStrings.map((s, i) => (
              <div key={`${s.name}-${i}`} className="flex items-center gap-1.5 text-[9px] font-mono">
                <span className="text-[#c45c5c]">{s.name}</span>
                <span className="text-[#6f7f9a]">
                  @{s.offset} ({s.length}b)
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Condition summary */}
      {trace.conditionSummary && (
        <div className="text-[9px] font-mono text-[#6f7f9a] mt-1">
          <span className="text-[#6f7f9a]/70 uppercase">Condition: </span>
          <span className="text-[#ece7dc]">{trace.conditionSummary}</span>
        </div>
      )}
    </div>
  );
}

function OcsfValidationTrace({
  enriched,
  onJumpToLine,
}: {
  enriched: EnrichedTrace;
  onJumpToLine?: (line: number) => void;
}) {
  const trace = enriched.trace;
  if (trace.kind !== "ocsf_validation") return null;

  return (
    <div className="rounded border border-[#2d3240] bg-[#131721] p-2">
      <div className="flex items-center gap-1.5 mb-1">
        <IconAlertTriangle size={11} stroke={1.5} className="text-[#d4a84b] shrink-0" />
        <span className="text-[10px] font-mono text-[#ece7dc] truncate">
          OCSF Validation
        </span>
        <SourceLineLink trace={trace} onJumpToLine={onJumpToLine} />
      </div>

      {/* Class UID */}
      {trace.classUid != null && (
        <div className="text-[9px] font-mono text-[#6f7f9a] mb-1">
          Class UID: <span className="text-[#ece7dc]">{trace.classUid}</span>
        </div>
      )}

      {/* Missing fields */}
      {trace.missingFields.length > 0 && (
        <div className="mb-1">
          <span className="text-[9px] font-mono text-[#c45c5c] uppercase">Missing:</span>
          <div className="flex flex-wrap gap-1 mt-0.5">
            {trace.missingFields.map((f, i) => (
              <span
                key={`${f}-${i}`}
                className="text-[8px] font-mono px-1 py-0.5 rounded bg-[#c45c5c]/10 text-[#c45c5c] border border-[#c45c5c]/20"
              >
                {f}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Invalid fields */}
      {trace.invalidFields.length > 0 && (
        <div>
          <span className="text-[9px] font-mono text-[#d4a84b] uppercase">Invalid:</span>
          <div className="flex flex-wrap gap-1 mt-0.5">
            {trace.invalidFields.map((f, i) => (
              <span
                key={`${f}-${i}`}
                className="text-[8px] font-mono px-1 py-0.5 rounded bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/20"
              >
                {f}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function PolicyEvaluationTrace({
  enriched,
}: {
  enriched: EnrichedTrace;
}) {
  const trace = enriched.trace;
  if (trace.kind !== "policy_evaluation") return null;

  return (
    <div className="rounded border border-[#2d3240] bg-[#131721] p-2">
      <div className="flex items-center gap-1.5 mb-1">
        <IconShieldCheck size={11} stroke={1.5} className="text-[#3dbf84] shrink-0" />
        <span className="text-[10px] font-mono text-[#ece7dc] truncate">
          Policy Evaluation
        </span>
      </div>

      {/* Guard results */}
      {trace.guardResults.length > 0 && (
        <div className="space-y-1 mt-1">
          {trace.guardResults.map((gr, i) => (
            <div key={`${gr.guardId}-${i}`} className="flex items-center gap-1.5">
              <VerdictBadge verdict={gr.verdict} />
              <span className="text-[9px] font-mono text-[#ece7dc] truncate flex-1">
                {gr.guardName}
              </span>
              <span
                className={cn(
                  "text-[8px] font-mono uppercase shrink-0",
                  gr.verdict === "allow" && "text-[#3dbf84]",
                  gr.verdict === "deny" && "text-[#c45c5c]",
                  gr.verdict === "warn" && "text-[#d4a84b]",
                )}
              >
                {gr.verdict}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function TraceEntry({
  enriched,
  onJumpToLine,
}: {
  enriched: EnrichedTrace;
  onJumpToLine?: (line: number) => void;
}) {
  const { trace } = enriched;

  switch (trace.kind) {
    case "sigma_match":
      return <SigmaMatchTrace enriched={enriched} onJumpToLine={onJumpToLine} />;
    case "yara_match":
      return <YaraMatchTrace enriched={enriched} onJumpToLine={onJumpToLine} />;
    case "ocsf_validation":
      return <OcsfValidationTrace enriched={enriched} onJumpToLine={onJumpToLine} />;
    case "policy_evaluation":
      return <PolicyEvaluationTrace enriched={enriched} />;
    default:
      return null;
  }
}

// ---- Comparison Delta ----

function ComparisonDelta({ delta }: { delta: RunComparisonDelta }) {
  const hasDelta =
    delta.casesFlipped.length > 0 ||
    delta.newMatches.length > 0 ||
    delta.newFalsePositives.length > 0 ||
    delta.techniquesAdded.length > 0 ||
    delta.techniquesLost.length > 0;

  if (!hasDelta) {
    return (
      <div className="rounded border border-[#2d3240] bg-[#131721] p-2 mb-3">
        <span className="text-[10px] font-mono text-[#6f7f9a]">
          No changes from baseline
        </span>
      </div>
    );
  }

  return (
    <div className="rounded border border-[#2d3240] bg-[#131721] p-2 mb-3 space-y-2">
      <div className="flex items-center gap-1.5 mb-1">
        <IconBulb size={11} stroke={1.5} className="text-[#d4a84b] shrink-0" />
        <span className="text-[10px] font-mono text-[#ece7dc] uppercase tracking-wider">
          Comparison Delta
        </span>
      </div>

      {/* Summary delta row */}
      <div className="flex flex-wrap gap-3">
        <DeltaStat label="Passed" value={delta.summaryDelta.passedDelta} />
        <DeltaStat label="Failed" value={delta.summaryDelta.failedDelta} invert />
        <DeltaStat label="Matched" value={delta.summaryDelta.matchedDelta} />
        <DeltaStat label="Missed" value={delta.summaryDelta.missedDelta} invert />
        <DeltaStat label="FP" value={delta.summaryDelta.falsePositivesDelta} invert />
      </div>

      {/* Cases flipped */}
      {delta.casesFlipped.length > 0 && (
        <div>
          <span className="text-[9px] font-mono text-[#6f7f9a] uppercase">
            Flipped ({delta.casesFlipped.length}):
          </span>
          <div className="mt-0.5 space-y-0.5">
            {delta.casesFlipped.map((c) => (
              <div key={c.caseId} className="flex items-center gap-1 text-[9px] font-mono">
                <span className="text-[#6f7f9a] truncate">{c.caseId.slice(0, 8)}</span>
                <span className={c.previousStatus === "pass" ? "text-[#3dbf84]" : "text-[#c45c5c]"}>
                  {c.previousStatus}
                </span>
                <span className="text-[#6f7f9a]">&rarr;</span>
                <span className={c.currentStatus === "pass" ? "text-[#3dbf84]" : "text-[#c45c5c]"}>
                  {c.currentStatus}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Techniques delta */}
      {delta.techniquesAdded.length > 0 && (
        <div className="flex flex-wrap gap-1">
          <span className="text-[9px] font-mono text-[#3dbf84] uppercase">+Techniques:</span>
          {delta.techniquesAdded.map((t) => (
            <span
              key={t}
              className="text-[8px] font-mono px-1 py-0.5 rounded bg-[#3dbf84]/10 text-[#3dbf84] border border-[#3dbf84]/20"
            >
              {t}
            </span>
          ))}
        </div>
      )}
      {delta.techniquesLost.length > 0 && (
        <div className="flex flex-wrap gap-1">
          <span className="text-[9px] font-mono text-[#c45c5c] uppercase">-Techniques:</span>
          {delta.techniquesLost.map((t) => (
            <span
              key={t}
              className="text-[8px] font-mono px-1 py-0.5 rounded bg-[#c45c5c]/10 text-[#c45c5c] border border-[#c45c5c]/20"
            >
              {t}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function DeltaStat({
  label,
  value,
  invert = false,
}: {
  label: string;
  value: number;
  invert?: boolean;
}) {
  const isPositive = invert ? value < 0 : value > 0;
  const isNegative = invert ? value > 0 : value < 0;

  return (
    <div className="text-center">
      <span className="text-[8px] font-mono text-[#6f7f9a]/60 block">{label}</span>
      <span
        className={cn(
          "text-[10px] font-mono flex items-center justify-center gap-0.5",
          isPositive && "text-[#3dbf84]",
          isNegative && "text-[#c45c5c]",
          !isPositive && !isNegative && "text-[#6f7f9a]",
        )}
      >
        {value > 0 && <IconArrowUp size={8} stroke={2} />}
        {value < 0 && <IconArrowDown size={8} stroke={2} />}
        {value === 0 && <IconMinus size={8} stroke={2} />}
        {Math.abs(value)}
      </span>
    </div>
  );
}

// ---- Summary Bar ----

function SummaryBar({ groups }: { groups: TraceGroups }) {
  const total =
    groups.matches.length +
    groups.misses.length +
    groups.falsePositives.length +
    groups.passes.length +
    groups.failures.length;

  return (
    <div className="flex items-center gap-3 px-3 py-2 bg-[#131721] rounded border border-[#2d3240] mb-3">
      <div className="text-center">
        <span className="text-[8px] font-mono text-[#6f7f9a]/60 block">Total</span>
        <span className="text-[11px] font-mono text-[#ece7dc]">{total}</span>
      </div>
      <div className="text-center">
        <span className="text-[8px] font-mono text-[#6f7f9a]/60 block">Matches</span>
        <span className="text-[11px] font-mono text-[#3dbf84]">{groups.matches.length}</span>
      </div>
      <div className="text-center">
        <span className="text-[8px] font-mono text-[#6f7f9a]/60 block">Misses</span>
        <span className="text-[11px] font-mono text-[#c45c5c]">{groups.misses.length}</span>
      </div>
      <div className="text-center">
        <span className="text-[8px] font-mono text-[#6f7f9a]/60 block">FP</span>
        <span className="text-[11px] font-mono text-[#d4a84b]">{groups.falsePositives.length}</span>
      </div>
    </div>
  );
}

// ---- Main Panel ----

export function ExplainabilityPanel({
  documentId,
  lastRun,
  baselineRun,
  onJumpToLine,
}: ExplainabilityPanelProps) {
  const enrichedTraces = useMemo(
    () => (lastRun ? extractTraces(lastRun) : []),
    [lastRun],
  );

  const groups = useMemo(
    () => groupTracesByOutcome(enrichedTraces),
    [enrichedTraces],
  );

  const delta = useMemo(
    () =>
      lastRun && baselineRun ? compareRuns(lastRun, baselineRun) : null,
    [lastRun, baselineRun],
  );

  // Empty state: no document
  if (!documentId) {
    return (
      <div className="h-full flex flex-col bg-[#0b0d13] border-l border-[#2d3240]">
        <div className="px-4 py-3 border-b border-[#2d3240] shrink-0">
          <div className="flex items-center gap-2">
            <IconBulb size={13} stroke={1.5} className="text-[#d4a84b]" />
            <h2 className="font-syne font-bold text-sm text-[#ece7dc]">
              Explain
            </h2>
          </div>
        </div>
        <div className="flex-1 flex items-center justify-center px-6">
          <span className="text-[11px] text-[#6f7f9a] text-center">
            Open a document to view explainability traces
          </span>
        </div>
      </div>
    );
  }

  // Empty state: no run
  if (!lastRun) {
    return (
      <div className="h-full flex flex-col bg-[#0b0d13] border-l border-[#2d3240]">
        <div className="px-4 py-3 border-b border-[#2d3240] shrink-0">
          <div className="flex items-center gap-2">
            <IconBulb size={13} stroke={1.5} className="text-[#d4a84b]" />
            <h2 className="font-syne font-bold text-sm text-[#ece7dc]">
              Explain
            </h2>
          </div>
        </div>
        <div className="flex-1 flex flex-col items-center justify-center px-6">
          <div className="w-14 h-14 rounded-2xl bg-[#131721] border border-[#2d3240]/60 flex items-center justify-center mb-4">
            <IconBulb size={22} stroke={1.2} className="text-[#6f7f9a]" />
          </div>
          <span className="text-[13px] font-medium text-[#6f7f9a]">
            No lab run yet
          </span>
          <span className="text-[11px] mt-1.5 text-[#6f7f9a]/60 text-center leading-relaxed">
            Execute a lab run to see
            <br />
            explainability traces
          </span>
        </div>
      </div>
    );
  }

  // Empty traces
  if (enrichedTraces.length === 0) {
    return (
      <div className="h-full flex flex-col bg-[#0b0d13] border-l border-[#2d3240]">
        <div className="px-4 py-3 border-b border-[#2d3240] shrink-0">
          <div className="flex items-center gap-2">
            <IconBulb size={13} stroke={1.5} className="text-[#d4a84b]" />
            <h2 className="font-syne font-bold text-sm text-[#ece7dc]">
              Explain
            </h2>
          </div>
        </div>
        <div className="flex-1 flex flex-col items-center justify-center px-6">
          <span className="text-[13px] font-medium text-[#6f7f9a]">
            No traces in this run
          </span>
          <span className="text-[11px] mt-1.5 text-[#6f7f9a]/60 text-center leading-relaxed">
            The last lab run produced no
            <br />
            explainability traces
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col bg-[#0b0d13] border-l border-[#2d3240]">
      {/* Header */}
      <div className="px-4 py-3 border-b border-[#2d3240] shrink-0">
        <div className="flex items-center gap-2">
          <IconBulb size={13} stroke={1.5} className="text-[#d4a84b]" />
          <h2 className="font-syne font-bold text-sm text-[#ece7dc]">
            Explain
          </h2>
          <span className="text-[9px] font-mono text-[#6f7f9a]/60 ml-auto">
            {enrichedTraces.length} trace{enrichedTraces.length !== 1 ? "s" : ""}
          </span>
        </div>
      </div>

      <ScrollArea className="flex-1 overflow-y-auto">
        <div className="p-4">
          {/* Comparison delta */}
          {delta && <ComparisonDelta delta={delta} />}

          {/* Summary bar */}
          <SummaryBar groups={groups} />

          {/* Grouped traces */}
          <CollapsibleSection
            title="Matches"
            count={groups.matches.length}
            color="#3dbf84"
            defaultOpen
          >
            {groups.matches.map((t) => (
              <TraceEntry key={t.trace.id} enriched={t} onJumpToLine={onJumpToLine} />
            ))}
          </CollapsibleSection>

          <CollapsibleSection
            title="Misses"
            count={groups.misses.length}
            color="#c45c5c"
            defaultOpen
          >
            {groups.misses.map((t) => (
              <TraceEntry key={t.trace.id} enriched={t} onJumpToLine={onJumpToLine} />
            ))}
          </CollapsibleSection>

          <CollapsibleSection
            title="False Positives"
            count={groups.falsePositives.length}
            color="#d4a84b"
            defaultOpen
          >
            {groups.falsePositives.map((t) => (
              <TraceEntry key={t.trace.id} enriched={t} onJumpToLine={onJumpToLine} />
            ))}
          </CollapsibleSection>

          <CollapsibleSection
            title="Passes"
            count={groups.passes.length}
            color="#3dbf84"
          >
            {groups.passes.map((t) => (
              <TraceEntry key={t.trace.id} enriched={t} onJumpToLine={onJumpToLine} />
            ))}
          </CollapsibleSection>

          <CollapsibleSection
            title="Failures"
            count={groups.failures.length}
            color="#c45c5c"
          >
            {groups.failures.map((t) => (
              <TraceEntry key={t.trace.id} enriched={t} onJumpToLine={onJumpToLine} />
            ))}
          </CollapsibleSection>
        </div>
      </ScrollArea>
    </div>
  );
}
