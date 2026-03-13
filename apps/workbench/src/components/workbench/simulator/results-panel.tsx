import { useState, useMemo } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Accordion,
  AccordionItem,
  AccordionTrigger,
  AccordionContent,
} from "@/components/ui/accordion";
import { VerdictBadge } from "@/components/workbench/shared/verdict-badge";
import { cn } from "@/lib/utils";
import type { SimulationResult, SimulationEngine, TestScenario } from "@/lib/workbench/types";
import { IconCheck, IconX, IconClock, IconShieldCheck, IconShieldOff, IconAlertTriangle } from "@tabler/icons-react";
import { EvaluationPath } from "./evaluation-path";

// ---------------------------------------------------------------------------
// Verdict display config
// ---------------------------------------------------------------------------

const VERDICT_DISPLAY: Record<string, {
  label: string;
  sublabel: string;
  ringClass: string;
  textClass: string;
  bgClass: string;
  borderClass: string;
  Icon: typeof IconShieldCheck;
}> = {
  allow: {
    label: "ACCESS GRANTED",
    sublabel: "All guards passed — action permitted",
    ringClass: "verdict-ring-allow",
    textClass: "text-[#3dbf84]",
    bgClass: "bg-[#3dbf84]/5",
    borderClass: "border-[#3dbf84]/20",
    Icon: IconShieldCheck,
  },
  deny: {
    label: "THREAT BLOCKED",
    sublabel: "One or more guards denied — action rejected",
    ringClass: "verdict-ring-deny",
    textClass: "text-[#c45c5c]",
    bgClass: "bg-[#c45c5c]/5",
    borderClass: "border-[#c45c5c]/20",
    Icon: IconShieldOff,
  },
  warn: {
    label: "ANOMALY DETECTED",
    sublabel: "Guards flagged suspicious behavior — action cautioned",
    ringClass: "verdict-ring-warn",
    textClass: "text-[#d4a84b]",
    bgClass: "bg-[#d4a84b]/5",
    borderClass: "border-[#d4a84b]/20",
    Icon: IconAlertTriangle,
  },
};

// ---------------------------------------------------------------------------
// Engine badge styles
// ---------------------------------------------------------------------------

const ENGINE_BADGE_STYLES: Record<SimulationEngine, { label: string; className: string }> = {
  native: {
    label: "Rust",
    className: "bg-[#3dbf84]/10 text-[#3dbf84] border-[#3dbf84]/20",
  },
  client: {
    label: "JS",
    className: "bg-[#6f7f9a]/10 text-[#6f7f9a] border-[#6f7f9a]/30",
  },
  stubbed: {
    label: "Stub",
    className: "bg-[#d4a84b]/10 text-[#d4a84b] border-[#d4a84b]/20",
  },
};

function EngineBadge({ engine }: { engine?: SimulationEngine }) {
  if (!engine) return null;
  const style = ENGINE_BADGE_STYLES[engine];
  return (
    <span
      className={cn(
        "inline-flex items-center px-1.5 py-0 text-[8px] font-mono uppercase border rounded select-none shrink-0",
        style.className,
      )}
    >
      {style.label}
    </span>
  );
}

/** Determine the dominant engine used across all guard results. */
function detectOverallEngine(results: SimulationResult): {
  label: string;
  isNative: boolean;
} {
  const engines = new Set(results.guardResults.map((r) => r.engine).filter(Boolean));
  if (engines.size === 0) return { label: "Unknown", isNative: false };
  if (engines.has("native") && engines.size === 1) return { label: "Rust Engine", isNative: true };
  if (!engines.has("native")) return { label: "Client (Rust unavailable)", isNative: false };
  return { label: "Mixed (Rust + Client)", isNative: false };
}

/** Compute confidence as ratio of evaluated guards vs total available. */
function computeConfidence(result: SimulationResult): number {
  // 13 total built-in guards
  const totalGuards = 13;
  const evaluated = result.guardResults.length;
  return Math.min(Math.round((evaluated / totalGuards) * 100), 100);
}

/** Compute time to verdict from evaluation path. */
function computeTimeToVerdict(result: SimulationResult): string | null {
  if (!result.evaluationPath || result.evaluationPath.length === 0) return null;
  const totalMs = Object.values(
    result.evaluationPath.reduce<Record<string, number>>((acc, s) => {
      if (!(s.stage in acc)) acc[s.stage] = s.stage_duration_ms;
      return acc;
    }, {}),
  ).reduce((a, b) => a + b, 0);
  if (totalMs < 0.001) return "<1us";
  if (totalMs < 1) return `${(totalMs * 1000).toFixed(0)}us`;
  if (totalMs < 1000) return `${totalMs.toFixed(2)}ms`;
  return `${(totalMs / 1000).toFixed(2)}s`;
}

/** Map guard verdict to a severity classification for display. */
function guardSeverityLabel(verdict: string): { label: string; className: string } {
  switch (verdict) {
    case "deny":
      return { label: "BLOCK", className: "text-[#c45c5c]" };
    case "warn":
      return { label: "WARN", className: "text-[#d4a84b]" };
    case "allow":
      return { label: "PASS", className: "text-[#3dbf84]" };
    default:
      return { label: "SKIP", className: "text-[#6f7f9a]" };
  }
}

interface ResultsPanelProps {
  results: SimulationResult[];
  scenarios: TestScenario[];
  compact?: boolean;
  simulating?: boolean;
}

export function ResultsPanel({ results, scenarios, compact, simulating }: ResultsPanelProps) {
  const [expandedIdx, setExpandedIdx] = useState<number>(0);

  if (results.length === 0) {
    return (
      <div className={cn("flex flex-col items-center justify-center text-[#6f7f9a]", compact ? "p-4" : "h-full px-6")}>
        <div className="w-14 h-14 rounded-2xl bg-[#131721] border border-[#2d3240]/60 flex items-center justify-center mb-4">
          <IconClock size={22} stroke={1.2} className="empty-state-icon text-[#6f7f9a]" />
        </div>
        <span className="text-[13px] font-medium text-[#6f7f9a]">Awaiting probe results</span>
        <span className="text-[11px] mt-1.5 text-[#6f7f9a]/60 text-center leading-relaxed">
          Execute a probe to evaluate your<br />policy against the detection pipeline
        </span>
      </div>
    );
  }

  const latest = results[0];
  const latestScenario = scenarios.find((s) => s.id === latest.scenarioId);
  const passedExpectation =
    latestScenario?.expectedVerdict != null
      ? latestScenario.expectedVerdict === latest.overallVerdict
      : null;

  const verdictDisplay = VERDICT_DISPLAY[latest.overallVerdict] ?? VERDICT_DISPLAY.deny;
  const confidence = computeConfidence(latest);
  const timeToVerdict = computeTimeToVerdict(latest);

  return (
    <>
      {/* Header */}
      <div className="px-4 py-3 border-b border-[#2d3240] shrink-0">
        <div className="flex items-center gap-2">
          <h2 className="font-syne font-bold text-sm text-[#ece7dc]">
            Results
          </h2>
          {simulating && (
            <span className="text-[9px] font-mono text-[#d4a84b]/70 animate-pulse">
              evaluating...
            </span>
          )}
        </div>
      </div>

      <ScrollArea className="flex-1 overflow-y-auto">
        <div className="p-4">
          {/* Latest result: large verdict */}
          <div className="mb-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-[#6f7f9a] truncate">
                {latestScenario?.name ?? latest.scenarioId}
              </span>
              {passedExpectation != null && (
                <span
                  className={cn(
                    "flex items-center gap-1 text-[10px] font-mono uppercase",
                    passedExpectation ? "text-[#3dbf84]" : "text-[#c45c5c]",
                  )}
                >
                  {passedExpectation ? (
                    <IconCheck size={12} stroke={2} />
                  ) : (
                    <IconX size={12} stroke={2} />
                  )}
                  {passedExpectation ? "PASS" : "FAIL"}
                </span>
              )}
            </div>

            {/* Large verdict badge with pulsing ring */}
            <div
              className={cn(
                "rounded-lg p-5 text-center border",
                verdictDisplay.bgClass,
                verdictDisplay.borderClass,
                verdictDisplay.ringClass,
              )}
            >
              <verdictDisplay.Icon
                size={20}
                stroke={1.5}
                className={cn("mx-auto mb-2", verdictDisplay.textClass)}
              />
              <span
                className={cn(
                  "text-xl font-syne font-extrabold uppercase tracking-wider block verdict-alert-text",
                  verdictDisplay.textClass,
                )}
              >
                {verdictDisplay.label}
              </span>
              <p className="text-[9px] text-[#6f7f9a]/70 mt-1">
                {verdictDisplay.sublabel}
              </p>

              {/* Metrics row */}
              <div className="flex items-center justify-center gap-4 mt-3 pt-2 border-t border-[#2d3240]/30">
                <div className="text-center">
                  <span className="text-[10px] font-mono text-[#6f7f9a]/50 block">Guards</span>
                  <span className="text-[12px] font-mono text-[#ece7dc]">
                    {latest.guardResults.length}
                  </span>
                </div>
                <div className="text-center">
                  <span className="text-[10px] font-mono text-[#6f7f9a]/50 block">Confidence</span>
                  <span className={cn(
                    "text-[12px] font-mono",
                    confidence >= 80 ? "text-[#3dbf84]" : confidence >= 50 ? "text-[#d4a84b]" : "text-[#c45c5c]",
                  )}>
                    {confidence}%
                  </span>
                </div>
                {timeToVerdict && (
                  <div className="text-center">
                    <span className="text-[10px] font-mono text-[#6f7f9a]/50 block">Verdict</span>
                    <span className="text-[12px] font-mono text-[#d4a84b]">
                      {timeToVerdict}
                    </span>
                  </div>
                )}
              </div>

              {/* Overall engine indicator */}
              {(() => {
                const { label, isNative } = detectOverallEngine(latest);
                return (
                  <p
                    className={cn(
                      "text-[9px] font-mono mt-2",
                      isNative ? "text-[#3dbf84]/70" : "text-[#6f7f9a]/70",
                    )}
                  >
                    Evaluated by: {label}
                  </p>
                );
              })()}
            </div>
          </div>

          {/* Evaluation pipeline (native engine only) */}
          {latest.evaluationPath && latest.evaluationPath.length > 0 && (
            <EvaluationPath steps={latest.evaluationPath} />
          )}

          {/* Guard-by-guard breakdown */}
          <div className="mb-4">
            <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
              Detection Pipeline Results
            </h3>
            <Accordion>
              {latest.guardResults.map((gr, i) => {
                const severity = guardSeverityLabel(gr.verdict);
                return (
                  <AccordionItem key={`${gr.guardId}-${i}`} className="border-[#2d3240]">
                    <AccordionTrigger className="py-2 px-0 hover:no-underline">
                      <div className="flex items-center gap-2 flex-1 min-w-0">
                        <VerdictBadge verdict={gr.verdict} />
                        <span className="text-xs text-[#ece7dc] truncate">
                          {gr.guardName}
                        </span>
                        <span className={cn("text-[8px] font-mono uppercase shrink-0", severity.className)}>
                          {severity.label}
                        </span>
                        <EngineBadge engine={gr.engine} />
                      </div>
                    </AccordionTrigger>
                    <AccordionContent>
                      <div className="pb-2 space-y-2">
                        <p className="text-xs text-[#6f7f9a]">{gr.message}</p>
                        {gr.evidence && Object.keys(gr.evidence).length > 0 && (
                          <pre className="text-[10px] font-mono bg-[#131721] border border-[#2d3240] rounded p-2 overflow-x-auto text-[#6f7f9a] max-h-32 overflow-y-auto">
                            {JSON.stringify(gr.evidence, null, 2)}
                          </pre>
                        )}
                      </div>
                    </AccordionContent>
                  </AccordionItem>
                );
              })}
            </Accordion>
          </div>

          {/* History */}
          {results.length > 1 && (
            <div>
              <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
                Execution History
              </h3>
              <div className="space-y-1">
                {results.slice(1).map((r, i) => {
                  const sc = scenarios.find((s) => s.id === r.scenarioId);
                  const isExpanded = expandedIdx === i + 1;
                  return (
                    <button
                      key={`${r.scenarioId}-${r.executedAt}`}
                      onClick={() => setExpandedIdx(isExpanded ? -1 : i + 1)}
                      className={cn(
                        "w-full flex items-center gap-2 px-2 py-1.5 rounded text-left transition-colors",
                        isExpanded
                          ? "bg-[#131721]"
                          : "hover:bg-[#131721]/50",
                      )}
                    >
                      <VerdictBadge verdict={r.overallVerdict} />
                      <span className="text-[11px] text-[#6f7f9a] truncate flex-1">
                        {sc?.name ?? r.scenarioId}
                      </span>
                      <span className="text-[9px] text-[#6f7f9a]/50 shrink-0 font-mono">
                        {new Date(r.executedAt).toLocaleTimeString()}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </ScrollArea>
    </>
  );
}
