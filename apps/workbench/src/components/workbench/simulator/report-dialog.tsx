import { useMemo, useCallback } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/components/ui/toast";
import { cn } from "@/lib/utils";
import type { BatchTestReport } from "@/lib/workbench/report-generator";
import { reportToJson, downloadReport } from "@/lib/workbench/report-generator";
import {
  IconDownload,
  IconCopy,
  IconCheck,
  IconX,
  IconAlertTriangle,
  IconShieldCheck,
} from "@tabler/icons-react";


function computePostureGrade(passRate: number): {
  grade: string;
  color: string;
  label: string;
} {
  if (passRate >= 0.95) return { grade: "A", color: "#3dbf84", label: "Excellent" };
  if (passRate >= 0.85) return { grade: "B", color: "#6fb87d", label: "Good" };
  if (passRate >= 0.70) return { grade: "C", color: "#d4a84b", label: "Acceptable" };
  if (passRate >= 0.50) return { grade: "D", color: "#e07c4f", label: "Needs Work" };
  return { grade: "F", color: "#c45c5c", label: "Critical" };
}

function generateRecommendations(report: BatchTestReport): string[] {
  const recs: string[] = [];
  const failedScenarios = report.scenarios.filter((s) => !s.passed);

  // Group by action type
  const failedByAction = new Map<string, number>();
  for (const s of failedScenarios) {
    failedByAction.set(s.action_type, (failedByAction.get(s.action_type) ?? 0) + 1);
  }

  for (const [action, count] of failedByAction.entries()) {
    switch (action) {
      case "file_access":
      case "file_write":
        recs.push(`Review forbidden_path and path_allowlist guards — ${count} file operation(s) failed`);
        break;
      case "network_egress":
        recs.push(`Review egress_allowlist configuration — ${count} network probe(s) failed`);
        break;
      case "shell_command":
        recs.push(`Review shell_command guard forbidden patterns — ${count} shell probe(s) failed`);
        break;
      case "mcp_tool_call":
        recs.push(`Review mcp_tool guard allow/block lists — ${count} tool invocation(s) failed`);
        break;
      case "user_input":
        recs.push(`Review prompt_injection and jailbreak guard thresholds — ${count} input probe(s) failed`);
        break;
      case "patch_apply":
        recs.push(`Review patch_integrity limits — ${count} patch operation(s) failed`);
        break;
      default:
        recs.push(`Review guard configuration for ${action} — ${count} probe(s) failed`);
    }
  }

  // Check disabled guards
  const disabledGuards = report.policy_config.enabled_guards.filter((g) => !g.enabled);
  if (disabledGuards.length > 3) {
    recs.push(`Enable additional guards — ${disabledGuards.length} guards are currently disabled`);
  }

  // Low compliance
  for (const fw of Object.values(report.compliance)) {
    if (fw.score < 50) {
      recs.push(`Improve ${fw.framework_name} compliance — currently at ${fw.score}%`);
    }
  }

  if (recs.length === 0) {
    recs.push("Policy configuration appears well-tuned for the current test suite");
  }

  return recs;
}


function StatCard({
  label,
  value,
  color,
}: {
  label: string;
  value: string | number;
  color: string;
}) {
  return (
    <div className="flex flex-col items-center px-4 py-3 rounded-lg border border-[#2d3240] bg-[#0b0d13]">
      <span className="text-xl font-mono font-bold" style={{ color }}>
        {value}
      </span>
      <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mt-1">
        {label}
      </span>
    </div>
  );
}

function PostureGradeBadge({ passRate }: { passRate: number }) {
  const { grade, color, label } = computePostureGrade(passRate);
  return (
    <div className="flex flex-col items-center px-6 py-4 rounded-lg border border-[#2d3240] bg-[#0b0d13]">
      <span
        className="text-4xl grade-badge"
        style={{ color }}
      >
        {grade}
      </span>
      <span className="text-[10px] font-mono uppercase tracking-wider mt-1" style={{ color }}>
        {label}
      </span>
      <span className="text-[9px] font-mono text-[#6f7f9a]/60 mt-0.5">
        Security Posture
      </span>
    </div>
  );
}

/** CSS-only coverage radar using conic-gradient. */
function CoverageRadar({ compliance }: { compliance: Record<string, { score: number; framework_name: string }> }) {
  const entries = Object.values(compliance);
  if (entries.length === 0) return null;

  const segments = entries.map((fw, i) => {
    const angle = (360 / entries.length);
    const startAngle = i * angle;
    const endAngle = startAngle + angle;
    const score = fw.score / 100;
    // Map score to a color
    const color = score >= 0.8 ? "#3dbf84" : score >= 0.5 ? "#d4a84b" : "#c45c5c";
    return { startAngle, endAngle, score, color, name: fw.framework_name };
  });

  // Build conic-gradient from segments
  const gradientStops = segments.flatMap((seg) => {
    const coverageAngle = seg.startAngle + (seg.endAngle - seg.startAngle) * seg.score;
    return [
      `${seg.color}30 ${seg.startAngle}deg`,
      `${seg.color}30 ${coverageAngle}deg`,
      `#131721 ${coverageAngle}deg`,
      `#131721 ${seg.endAngle}deg`,
    ];
  });

  return (
    <div className="flex items-center gap-4">
      <div
        className="w-20 h-20 rounded-full border border-[#2d3240] shrink-0 relative"
        style={{
          background: `conic-gradient(from 0deg, ${gradientStops.join(", ")})`,
        }}
      >
        {/* Center circle */}
        <div className="absolute inset-[25%] rounded-full bg-[#05060a] border border-[#2d3240]/50" />
        {/* Inner ring */}
        <div className="absolute inset-[12%] rounded-full border border-[#2d3240]/30" />
      </div>
      <div className="space-y-1.5">
        {segments.map((seg) => (
          <div key={seg.name} className="flex items-center gap-2">
            <span
              className="w-2 h-2 rounded-full shrink-0"
              style={{ backgroundColor: seg.color }}
            />
            <span className="text-[10px] text-[#6f7f9a]">{seg.name}</span>
            <span
              className="text-[10px] font-mono ml-auto"
              style={{ color: seg.color }}
            >
              {Math.round(seg.score * 100)}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function VerdictDot({ verdict }: { verdict: string }) {
  const color =
    verdict === "allow"
      ? "#3dbf84"
      : verdict === "deny"
        ? "#c45c5c"
        : "#d4a84b";
  return (
    <span
      className="inline-block w-2 h-2 rounded-full shrink-0"
      style={{ backgroundColor: color }}
    />
  );
}

function PassFailBadge({ passed }: { passed: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-mono uppercase border rounded select-none shrink-0",
        passed
          ? "bg-[#3dbf84]/10 text-[#3dbf84] border-[#3dbf84]/20"
          : "bg-[#c45c5c]/10 text-[#c45c5c] border-[#c45c5c]/20",
      )}
    >
      {passed ? (
        <IconCheck size={10} stroke={2} />
      ) : (
        <IconX size={10} stroke={2} />
      )}
      {passed ? "PASS" : "FAIL"}
    </span>
  );
}

function ComplianceBar({
  label,
  score,
  metCount,
  totalCount,
}: {
  label: string;
  score: number;
  metCount: number;
  totalCount: number;
}) {
  const color =
    score > 80 ? "#3dbf84" : score >= 50 ? "#d4a84b" : "#c45c5c";
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-[#ece7dc] w-16 shrink-0 font-medium">
        {label}
      </span>
      <div className="flex-1 h-2 rounded-full bg-[#2d3240] overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${score}%`, backgroundColor: color }}
        />
      </div>
      <span
        className="text-xs font-mono w-12 text-right shrink-0"
        style={{ color }}
      >
        {score}%
      </span>
      <span className="text-[10px] text-[#6f7f9a] w-10 text-right shrink-0">
        {metCount}/{totalCount}
      </span>
    </div>
  );
}


interface ReportDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  report: BatchTestReport | null;
  policyName: string;
}

export function ReportDialog({
  open,
  onOpenChange,
  report,
  policyName,
}: ReportDialogProps) {
  const { toast } = useToast();

  const handleDownload = useCallback(() => {
    if (!report) return;
    downloadReport(report, policyName);
    toast({
      type: "success",
      title: "Report downloaded",
      description: `${policyName}_test_report.json saved`,
    });
  }, [report, policyName, toast]);

  const handleCopy = useCallback(() => {
    if (!report) return;
    const json = reportToJson(report);
    navigator.clipboard.writeText(json).then(() => {
      toast({
        type: "success",
        title: "Copied to clipboard",
        description: "Report JSON copied",
      });
    }).catch(() => {
      toast({
        type: "error",
        title: "Copy failed",
        description: "Could not write to clipboard",
      });
    });
  }, [report, toast]);

  const passRatePercent = useMemo(() => {
    if (!report) return "0";
    return `${Math.round(report.summary.pass_rate * 100)}`;
  }, [report]);

  const passRateColor = useMemo(() => {
    if (!report) return "#6f7f9a";
    const pct = report.summary.pass_rate * 100;
    if (pct >= 90) return "#3dbf84";
    if (pct >= 70) return "#d4a84b";
    return "#c45c5c";
  }, [report]);

  const recommendations = useMemo(() => {
    if (!report) return [];
    return generateRecommendations(report);
  }, [report]);

  if (!report) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl max-h-[85vh] bg-[#05060a] border-[#2d3240] text-[#ece7dc] flex flex-col p-0 overflow-hidden">
        <DialogHeader className="px-6 pt-5 pb-0 shrink-0">
          <DialogTitle className="font-syne font-bold text-base text-[#ece7dc]">
            ClawdStrike Policy Test Report
          </DialogTitle>
          <DialogDescription className="text-xs text-[#6f7f9a]">
            {report.policy.name} &middot; Generated{" "}
            {new Date(report.generated_at).toLocaleString()}
          </DialogDescription>
        </DialogHeader>

        <ScrollArea className="flex-1 overflow-y-auto px-6 py-4">
          <div className="space-y-6">
            {/* Security Posture Grade + Summary */}
            <section>
              <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-3">
                Security Posture
              </h3>
              <div className="grid grid-cols-[auto_1fr] gap-4">
                <PostureGradeBadge passRate={report.summary.pass_rate} />
                <div className="grid grid-cols-4 gap-2">
                  <StatCard
                    label="Total"
                    value={report.summary.total}
                    color="#ece7dc"
                  />
                  <StatCard
                    label="Passed"
                    value={report.summary.passed}
                    color="#3dbf84"
                  />
                  <StatCard
                    label="Failed"
                    value={report.summary.failed}
                    color="#c45c5c"
                  />
                  <StatCard
                    label="Pass Rate"
                    value={`${passRatePercent}%`}
                    color={passRateColor}
                  />
                </div>
              </div>
            </section>

            {/* Coverage Radar + Compliance */}
            <section>
              <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-3">
                Compliance Coverage
              </h3>
              <div className="p-4 border border-[#2d3240] rounded-lg bg-[#0b0d13]">
                <CoverageRadar compliance={report.compliance} />
                <div className="mt-4 space-y-3 pt-3 border-t border-[#2d3240]/50">
                  {Object.values(report.compliance).map((fw) => (
                    <ComplianceBar
                      key={fw.framework}
                      label={fw.framework_name}
                      score={fw.score}
                      metCount={fw.met_count}
                      totalCount={fw.total_requirements}
                    />
                  ))}
                </div>
              </div>
            </section>

            {/* Recommended Actions */}
            <section>
              <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#d4a84b] mb-3 flex items-center gap-1.5">
                <IconShieldCheck size={12} stroke={1.5} />
                Recommended Actions
              </h3>
              <div className="space-y-1.5 p-4 border border-[#2d3240] rounded-lg bg-[#0b0d13]">
                {recommendations.map((rec, i) => (
                  <div key={i} className="flex items-start gap-2 text-[11px]">
                    <span className="text-[#d4a84b] font-mono shrink-0 mt-0.5">{i + 1}.</span>
                    <span className="text-[#6f7f9a]">{rec}</span>
                  </div>
                ))}
              </div>
            </section>

            {/* Scenario results table */}
            <section>
              <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-3">
                Scenario Results
              </h3>
              <div className="border border-[#2d3240] rounded-lg overflow-hidden">
                {/* Table header */}
                <div className="grid grid-cols-[1fr_100px_80px_80px_60px] gap-2 px-3 py-2 bg-[#0b0d13] border-b border-[#2d3240] text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
                  <span>Scenario</span>
                  <span>Action</span>
                  <span>Expected</span>
                  <span>Actual</span>
                  <span className="text-right">Result</span>
                </div>

                {/* Table rows */}
                {report.scenarios.map((s) => (
                  <div
                    key={s.scenario_id}
                    className={cn(
                      "grid grid-cols-[1fr_100px_80px_80px_60px] gap-2 px-3 py-2 border-b border-[#2d3240] last:border-b-0 text-xs items-center",
                      !s.passed && "bg-[#c45c5c]/5",
                    )}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <VerdictDot verdict={s.actual_verdict} />
                      <span className="truncate text-[#ece7dc]">{s.name}</span>
                    </div>
                    <span className="text-[#6f7f9a] font-mono text-[11px] truncate">
                      {s.action_type}
                    </span>
                    <span className="text-[#6f7f9a] font-mono text-[11px]">
                      {s.expected_verdict ?? "--"}
                    </span>
                    <span
                      className={cn(
                        "font-mono text-[11px] uppercase",
                        s.actual_verdict === "allow" && "text-[#3dbf84]",
                        s.actual_verdict === "deny" && "text-[#c45c5c]",
                        s.actual_verdict === "warn" && "text-[#d4a84b]",
                      )}
                    >
                      {s.actual_verdict}
                    </span>
                    <div className="flex justify-end">
                      <PassFailBadge passed={s.passed} />
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* Guard configuration */}
            <section>
              <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-3">
                Guard Configuration
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {report.policy_config.enabled_guards.map((g) => (
                  <span
                    key={g.guard_id}
                    className={cn(
                      "inline-flex items-center gap-1.5 px-2 py-1 text-[11px] font-mono border rounded-md select-none",
                      g.enabled
                        ? "bg-[#3dbf84]/10 text-[#3dbf84] border-[#3dbf84]/20"
                        : "bg-[#131721] text-[#6f7f9a]/50 border-[#2d3240]",
                    )}
                  >
                    <span
                      className={cn(
                        "w-1.5 h-1.5 rounded-full shrink-0",
                        g.enabled ? "bg-[#3dbf84]" : "bg-[#6f7f9a]/30",
                      )}
                    />
                    {g.guard_id}
                  </span>
                ))}
              </div>
              {report.policy_config.base_ruleset && (
                <p className="text-[11px] text-[#6f7f9a] mt-2">
                  Extends:{" "}
                  <span className="font-mono text-[#d4a84b]">
                    {report.policy_config.base_ruleset}
                  </span>
                </p>
              )}
            </section>

            {/* Failed scenarios detail */}
            {report.scenarios.some((s) => !s.passed) && (
              <section>
                <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#c45c5c] mb-3 flex items-center gap-1.5">
                  <IconAlertTriangle size={12} stroke={1.5} />
                  Failed Scenarios
                </h3>
                <div className="space-y-2">
                  {report.scenarios
                    .filter((s) => !s.passed)
                    .map((s) => (
                      <div
                        key={s.scenario_id}
                        className="p-3 border border-[#c45c5c]/20 rounded-lg bg-[#c45c5c]/5"
                      >
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-xs font-medium text-[#ece7dc]">
                            {s.name}
                          </span>
                          <span className="text-[10px] font-mono text-[#6f7f9a]">
                            Expected{" "}
                            <span className="text-[#d4a84b]">
                              {s.expected_verdict}
                            </span>{" "}
                            got{" "}
                            <span
                              className={cn(
                                s.actual_verdict === "allow" && "text-[#3dbf84]",
                                s.actual_verdict === "deny" && "text-[#c45c5c]",
                                s.actual_verdict === "warn" && "text-[#d4a84b]",
                              )}
                            >
                              {s.actual_verdict}
                            </span>
                          </span>
                        </div>
                        <p className="text-[11px] text-[#6f7f9a] mb-2">
                          {s.description}
                        </p>
                        <div className="space-y-1">
                          {s.guard_results.map((gr, i) => (
                            <div
                              key={`${gr.guard_id}-${i}`}
                              className="flex items-center gap-2 text-[11px]"
                            >
                              <VerdictDot verdict={gr.verdict} />
                              <span className="font-mono text-[#6f7f9a]">
                                {gr.guard_name}
                              </span>
                              <span className="text-[#6f7f9a]/60 truncate">
                                {gr.message}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                </div>
              </section>
            )}
          </div>
        </ScrollArea>

        <DialogFooter className="px-6 py-3 border-t border-[#2d3240] bg-[#0b0d13] shrink-0 -mx-0 -mb-0 rounded-b-xl flex-row gap-2 sm:justify-end">
          <Button
            variant="outline"
            size="sm"
            onClick={handleCopy}
            className="border-[#2d3240] text-[#ece7dc] hover:bg-[#131721]"
          >
            <IconCopy size={14} stroke={1.5} data-icon="inline-start" />
            Copy to Clipboard
          </Button>
          <Button
            size="sm"
            onClick={handleDownload}
            className="bg-[#d4a84b] text-[#05060a] hover:bg-[#d4a84b]/80"
          >
            <IconDownload size={14} stroke={1.5} data-icon="inline-start" />
            Download JSON
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
