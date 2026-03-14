import { useState, useCallback, useMemo } from "react";
import type { TestScenario, SimulationResult, TestActionType, Verdict, GuardSimResult, EvaluationPathStep, PostureReport, PostureBudget } from "@/lib/workbench/types";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { useToast } from "@/components/ui/toast";
import { simulatePolicy } from "@/lib/workbench/simulation-engine";
import { PRE_BUILT_SCENARIOS } from "@/lib/workbench/pre-built-scenarios";
import { policyToYaml } from "@/lib/workbench/yaml-utils";
import { isDesktop } from "@/lib/tauri-bridge";
import { emitAuditEvent } from "@/lib/workbench/local-audit";
import {
  simulateActionNative,
  simulateWithPostureNative,
  type TauriSimulationResponse,
  type TauriPostureSimulationResponse,
} from "@/lib/tauri-commands";
import {
  verdictFromNativeGuardResult,
  verdictFromNativeSimulation,
} from "@/lib/workbench/native-simulation";
import { generateBatchReport, downloadReport, type BatchTestReport } from "@/lib/workbench/report-generator";
import { generateScenariosFromPolicy } from "@/lib/workbench/scenario-generator";
import { analyzeCoverage, type CoverageReport } from "@/lib/workbench/coverage-analyzer";
import { ScenarioList } from "./scenario-list";
import { ScenarioBuilder } from "./scenario-builder";
import { ResultsPanel } from "./results-panel";
import { PosturePanel } from "./posture-panel";
import { ReportDialog } from "./report-dialog";
import { ObservePanel } from "./observe-panel";
import { ThreatMatrix } from "./threat-matrix";
import { TrustprintLab } from "./trustprint-lab";
import {
  IconFileReport,
  IconDownload,
  IconCrosshair,
  IconTestPipe,
  IconEye,
  IconGrid3x3,
  IconShieldCheck,
  IconCircle,
  IconFingerprint,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { ClaudeCodeHint } from "@/components/workbench/shared/claude-code-hint";


type SimulatorTab = "scenarios" | "trustprint-lab" | "observe" | "coverage";

// Helpers to map between the workbench TestScenario format and the Rust
// simulate_action command's flat parameter format.

/** Map workbench TestActionType to the Rust action_type string. */
function toRustActionType(at: TestActionType): string | null {
  const map: Record<TestActionType, string> = {
    file_access: "file_access",
    file_write: "file_write",
    network_egress: "network",
    shell_command: "shell",
    mcp_tool_call: "mcp_tool",
    patch_apply: "patch",
    user_input: "", // not supported by the Rust engine
  };
  return map[at] || null;
}

/** Extract the target string the Rust command expects from the scenario payload. */
function extractTarget(at: TestActionType, payload: Record<string, unknown>): string {
  switch (at) {
    case "file_access":
    case "file_write":
    case "patch_apply":
      return (payload.path as string) ?? "";
    case "network_egress": {
      const host = (payload.host as string) ?? "";
      const port = payload.port != null ? Number(payload.port) : 443;
      return port !== 443 ? `${host}:${port}` : host;
    }
    case "shell_command":
      return (payload.command as string) ?? "";
    case "mcp_tool_call":
      return (payload.tool as string) ?? "";
    case "user_input":
      return (payload.text as string) ?? "";
    default:
      return "";
  }
}

/** Extract optional content string for Rust commands that accept it. */
function extractContent(at: TestActionType, payload: Record<string, unknown>): string | undefined {
  switch (at) {
    case "file_write":
    case "patch_apply":
      return (payload.content as string) || undefined;
    case "mcp_tool_call": {
      const args = payload.args;
      if (args && typeof args === "object") return JSON.stringify(args);
      if (typeof args === "string") return args;
      return undefined;
    }
    default:
      return undefined;
  }
}

/** Convert a Rust SimulationResponse into a workbench SimulationResult. */
function fromRustSimulation(
  scenarioId: string,
  resp: TauriSimulationResponse,
): SimulationResult {
  const guardResults: GuardSimResult[] = resp.results.map((r) => ({
    guardId: r.guard as GuardSimResult["guardId"],
    guardName: r.guard,
    verdict: verdictFromNativeGuardResult(r),
    message: r.message,
    evidence: r.details ? (r.details as Record<string, unknown>) : undefined,
    engine: "native" as const,
  }));

  const evaluationPath: EvaluationPathStep[] | undefined =
    resp.evaluation_path && resp.evaluation_path.length > 0
      ? resp.evaluation_path.map((step) => ({
          guard: step.guard,
          stage: step.stage,
          stage_duration_ms: step.stage_duration_ms,
          result: step.result,
        }))
      : undefined;

  return {
    scenarioId,
    overallVerdict: verdictFromNativeSimulation(resp),
    guardResults,
    executedAt: new Date().toISOString(),
    evaluationPath,
  };
}

/** Convert a posture-aware Rust response into a workbench SimulationResult + PostureReport + state JSON. */
function fromRustPostureSimulation(
  scenarioId: string,
  resp: TauriPostureSimulationResponse,
): { result: SimulationResult; posture: PostureReport | null; postureStateJson: string | null } {
  const guardResults: GuardSimResult[] = resp.results.map((r) => ({
    guardId: r.guard as GuardSimResult["guardId"],
    guardName: r.guard,
    verdict: verdictFromNativeGuardResult(r),
    message: r.message,
    evidence: r.details ? (r.details as Record<string, unknown>) : undefined,
    engine: "native" as const,
  }));

  const result: SimulationResult = {
    scenarioId,
    overallVerdict: verdictFromNativeSimulation(resp),
    guardResults,
    executedAt: new Date().toISOString(),
  };

  let posture: PostureReport | null = null;
  if (resp.posture) {
    posture = {
      budgets: resp.posture.budgets.map((b) => ({
        name: b.name,
        limit: b.limit,
        consumed: b.consumed,
        remaining: b.remaining,
      })),
      violations: resp.posture.violations,
      state: resp.posture.state,
      stateBefore: resp.posture.state_before,
      transitioned: resp.posture.transitioned,
    };
  }

  return { result, posture, postureStateJson: resp.posture_state_json ?? null };
}

/** Merge a new PostureReport into cumulative tracking (max of consumed values). */
function mergeCumulativePosture(
  existing: PostureReport | null,
  incoming: PostureReport,
): PostureReport {
  if (!existing) return incoming;

  const budgetMap = new Map<string, PostureBudget>();
  for (const b of existing.budgets) {
    budgetMap.set(b.name, b);
  }
  for (const b of incoming.budgets) {
    const prev = budgetMap.get(b.name);
    if (!prev || b.consumed >= prev.consumed) {
      budgetMap.set(b.name, b);
    }
  }

  return {
    budgets: Array.from(budgetMap.values()),
    violations: incoming.violations,
    state: incoming.state,
    stateBefore: incoming.stateBefore,
    transitioned: incoming.transitioned,
  };
}


function computeThreatLevel(results: SimulationResult[], scenarios: TestScenario[]): {
  color: string;
  label: string;
} {
  if (results.length === 0) return { color: "#6f7f9a", label: "UNKNOWN" };

  const resultMap = new Map(results.map((r) => [r.scenarioId, r]));
  let passed = 0;
  let total = 0;

  for (const s of scenarios) {
    const result = resultMap.get(s.id);
    if (!result || !s.expectedVerdict) continue;
    total++;
    if (s.expectedVerdict === result.overallVerdict) passed++;
  }

  if (total === 0) return { color: "#6f7f9a", label: "UNKNOWN" };
  const rate = passed / total;
  if (rate >= 0.9) return { color: "#3dbf84", label: "SECURE" };
  if (rate >= 0.7) return { color: "#d4a84b", label: "MODERATE" };
  return { color: "#c45c5c", label: "AT RISK" };
}


function SimulatorHeader({
  activeTab,
  onTabChange,
  threatLevel,
  engineConnected,
}: {
  activeTab: SimulatorTab;
  onTabChange: (tab: SimulatorTab) => void;
  threatLevel: { color: string; label: string };
  engineConnected: boolean;
}) {
  const tabs: { id: SimulatorTab; label: string; icon: typeof IconTestPipe }[] = [
    { id: "scenarios", label: "Scenarios", icon: IconTestPipe },
    { id: "trustprint-lab", label: "Trustprint", icon: IconFingerprint },
    { id: "observe", label: "Observe", icon: IconEye },
    { id: "coverage", label: "Coverage", icon: IconGrid3x3 },
  ];

  return (
    <div className="flex items-center justify-between px-1 py-0 border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
      {/* Tabs */}
      <div className="flex items-center">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={cn(
                "flex items-center gap-1.5 px-4 py-3 text-xs font-medium transition-all duration-150 border-b-2 -mb-px",
                isActive
                  ? "text-[#d4a84b] border-[#d4a84b]"
                  : "text-[#6f7f9a] border-transparent hover:text-[#ece7dc] hover:border-[#2d3240]",
              )}
            >
              <Icon size={14} stroke={1.5} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Right side: status indicators */}
      <div className="flex items-center gap-3 pr-3">
        {/* Engine connection status */}
        <div
          className="flex items-center gap-1.5"
          title={
            engineConnected
              ? "Rust engine available"
              : "Rust engine unavailable — using JS fallback"
          }
        >
          <IconCircle
            size={6}
            stroke={0}
            fill={engineConnected ? "#3dbf84" : "#6f7f9a"}
            className={engineConnected ? "animate-pulse" : ""}
          />
          <span
            className={cn(
              "text-[9px] font-mono uppercase tracking-wider",
              engineConnected ? "text-[#3dbf84]/70" : "text-[#6f7f9a]/50",
            )}
          >
            {engineConnected ? "Rust" : "JS"}
          </span>
        </div>

        {/* Threat level badge */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-[#2d3240] bg-[#131721]">
          <IconShieldCheck size={13} stroke={1.5} style={{ color: threatLevel.color }} />
          <span
            className="text-[10px] font-mono font-semibold uppercase tracking-wider"
            style={{ color: threatLevel.color }}
          >
            {threatLevel.label}
          </span>
        </div>
      </div>
    </div>
  );
}


export function SimulatorLayout() {
  const { state } = useWorkbench();
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState<SimulatorTab>("scenarios");
  const [scenarios, setScenarios] = useState<TestScenario[]>(PRE_BUILT_SCENARIOS);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editingScenario, setEditingScenario] = useState<TestScenario | null>(null);
  const [results, setResults] = useState<SimulationResult[]>([]);
  const [isCreating, setIsCreating] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [cumulativePosture, setCumulativePosture] = useState<PostureReport | null>(null);
  const [postureStateJson, setPostureStateJson] = useState<string | null>(null);
  const [reportDialogOpen, setReportDialogOpen] = useState(false);
  const [batchReport, setBatchReport] = useState<BatchTestReport | null>(null);
  const [autoScenarios, setAutoScenarios] = useState<TestScenario[]>([]);
  const [coverageReport, setCoverageReport] = useState<CoverageReport | null>(null);

  const hasPostureConfig = Boolean(state.activePolicy.posture);
  const engineConnected = isDesktop();

  // Combined scenario list: pre-built + auto-generated (used for results lookup)
  const allScenarios = useMemo(
    () => [...scenarios, ...autoScenarios],
    [scenarios, autoScenarios],
  );

  // Threat level
  const threatLevel = useMemo(
    () => computeThreatLevel(results, allScenarios),
    [results, allScenarios],
  );

  // Determine whether we have a complete batch run (one result per scenario)
  const hasCompleteBatchRun = useMemo(() => {
    if (results.length === 0) return false;
    const resultScenarioIds = new Set(results.map((r) => r.scenarioId));
    return scenarios.every((s) => resultScenarioIds.has(s.id));
  }, [results, scenarios]);

  const resetPosture = useCallback(() => {
    setCumulativePosture(null);
    setPostureStateJson(null);
  }, []);

  const runScenario = useCallback(
    async (scenario: TestScenario): Promise<SimulationResult> => {
      const rustAction = toRustActionType(scenario.actionType);
      if (rustAction) {
        setSimulating(true);
        try {
          const target = extractTarget(scenario.actionType, scenario.payload);
          const content = extractContent(scenario.actionType, scenario.payload);
          const policyYaml = policyToYaml(state.activePolicy);

          if (hasPostureConfig) {
            const resp = await simulateWithPostureNative(
              policyYaml,
              rustAction,
              target,
              content,
              postureStateJson ?? undefined,
            );
            if (resp) {
              const { result, posture, postureStateJson: newStateJson } = fromRustPostureSimulation(scenario.id, resp);
              setResults((prev) => [result, ...prev].slice(0, 20));
              if (newStateJson) {
                setPostureStateJson(newStateJson);
              }
              if (posture) {
                setCumulativePosture((prev) => mergeCumulativePosture(prev, posture));
              }
              toast({
                type: result.overallVerdict === "allow" ? "success" : "error",
                title: `Probe complete — ${result.overallVerdict === "allow" ? "ACCESS GRANTED" : result.overallVerdict === "deny" ? "THREAT BLOCKED" : "ANOMALY DETECTED"}`,
                description: `${result.guardResults.length} guard(s) evaluated (Rust engine)`,
              });
              emitAuditEvent({
                eventType: "simulation.run",
                source: "simulator",
                summary: `Scenario "${scenario.name}" — ${result.overallVerdict} (Rust engine, posture)`,
                details: {
                  scenarioId: scenario.id,
                  scenarioName: scenario.name,
                  actionType: scenario.actionType,
                  verdict: result.overallVerdict,
                  guardsEvaluated: result.guardResults.length,
                  engine: "rust",
                  posture: true,
                },
              });
              return result;
            }
          }

          // Posture-aware path returned null — fall back to non-posture simulation.
          // Posture state (postureStateJson) is maintained via the runScenario closure's
          // captured state and React setState; it is not updated here because the non-posture
          // engine does not produce posture output. The existing posture state remains valid
          // for subsequent posture-aware calls.
          const resp = await simulateActionNative(policyYaml, rustAction, target, content);
          if (resp) {
            const result = fromRustSimulation(scenario.id, resp);
            setResults((prev) => [result, ...prev].slice(0, 20));
            toast({
              type: result.overallVerdict === "allow" ? "success" : "error",
              title: `Probe complete — ${result.overallVerdict === "allow" ? "ACCESS GRANTED" : result.overallVerdict === "deny" ? "THREAT BLOCKED" : "ANOMALY DETECTED"}`,
              description: `${result.guardResults.length} guard(s) evaluated (Rust engine)`,
            });
            emitAuditEvent({
              eventType: "simulation.run",
              source: "simulator",
              summary: `Scenario "${scenario.name}" — ${result.overallVerdict} (Rust engine)`,
              details: {
                scenarioId: scenario.id,
                scenarioName: scenario.name,
                actionType: scenario.actionType,
                verdict: result.overallVerdict,
                guardsEvaluated: result.guardResults.length,
                engine: "rust",
              },
            });
            return result;
          }
        } catch {
          toast({
            type: "warning",
            title: "Rust engine unavailable",
            description: "Falling back to client-side JS simulation",
          });
        } finally {
          setSimulating(false);
        }
      }

      const result = simulatePolicy(state.activePolicy, scenario);
      setResults((prev) => [result, ...prev].slice(0, 20));
      toast({
        type: result.overallVerdict === "allow" ? "success" : "error",
        title: `Probe complete — ${result.overallVerdict === "allow" ? "ACCESS GRANTED" : result.overallVerdict === "deny" ? "THREAT BLOCKED" : "ANOMALY DETECTED"}`,
        description: `${result.guardResults.length} guard(s) evaluated (JS engine)`,
      });
      emitAuditEvent({
        eventType: "simulation.run",
        source: "simulator",
        summary: `Scenario "${scenario.name}" — ${result.overallVerdict} (JS engine)`,
        details: {
          scenarioId: scenario.id,
          scenarioName: scenario.name,
          actionType: scenario.actionType,
          verdict: result.overallVerdict,
          guardsEvaluated: result.guardResults.length,
          engine: "js",
        },
      });
      return result;
    },
    [state.activePolicy, hasPostureConfig, postureStateJson, toast],
  );

  const runAll = useCallback(async () => {
    setSimulating(true);
    let usedFallback = false;
    // Track posture state across the batch so each simulation builds on the last.
    let runningPostureState = postureStateJson;
    try {
      const newResults: SimulationResult[] = [];
      for (const s of scenarios) {
        const rustAction = toRustActionType(s.actionType);
        let result: SimulationResult | null = null;

        if (rustAction) {
          try {
            const target = extractTarget(s.actionType, s.payload);
            const content = extractContent(s.actionType, s.payload);
            const policyYaml = policyToYaml(state.activePolicy);

            if (hasPostureConfig) {
              const resp = await simulateWithPostureNative(
                policyYaml,
                rustAction,
                target,
                content,
                runningPostureState ?? undefined,
              );
              if (resp) {
                const parsed = fromRustPostureSimulation(s.id, resp);
                result = parsed.result;
                if (parsed.postureStateJson) {
                  runningPostureState = parsed.postureStateJson;
                }
                if (parsed.posture) {
                  setCumulativePosture((prev) => mergeCumulativePosture(prev, parsed.posture!));
                }
              }
            }

            if (!result) {
              // Posture state is preserved from the last successful posture-aware evaluation.
              // This scenario's result won't update posture budgets, but subsequent posture-
              // aware evaluations will still have the correct cumulative state.
              const resp = await simulateActionNative(policyYaml, rustAction, target, content);
              if (resp) {
                result = fromRustSimulation(s.id, resp);
              }
            }
          } catch {
            usedFallback = true;
          }
        }

        if (!result) {
          // Posture state is preserved from the last successful posture-aware evaluation.
          // This scenario's result won't update posture budgets, but subsequent posture-
          // aware evaluations will still have the correct cumulative state.
          result = simulatePolicy(state.activePolicy, s);
        }
        newResults.push(result);
      }
      // Persist the final posture state so subsequent runs continue from here.
      setPostureStateJson(runningPostureState);
      setResults((prev) => [...newResults, ...prev].slice(0, 50));
      if (usedFallback) {
        toast({
          type: "warning",
          title: "Rust engine unavailable for some scenarios",
          description: "Fell back to client-side JS simulation",
        });
      }

      const report = generateBatchReport(state.activePolicy, scenarios, newResults);
      setBatchReport(report);
      toast({
        type: "info",
        title: `Batch run complete — ${report.summary.passed}/${report.summary.total} passed`,
        description: "View or download the test report",
      });
      emitAuditEvent({
        eventType: "simulation.batch",
        source: "simulator",
        summary: `Batch run: ${report.summary.passed}/${report.summary.total} passed`,
        details: {
          policyName: state.activePolicy.name,
          total: report.summary.total,
          passed: report.summary.passed,
          failed: report.summary.failed,
          scenarioCount: scenarios.length,
        },
      });
    } finally {
      setSimulating(false);
    }
  }, [scenarios, state.activePolicy, hasPostureConfig, postureStateJson, toast]);

  const handleSelect = useCallback(
    (id: string) => {
      setSelectedId(id);
      setIsCreating(false);
      const s = scenarios.find((sc) => sc.id === id) ?? autoScenarios.find((sc) => sc.id === id);
      if (s) setEditingScenario({ ...s });
    },
    [scenarios, autoScenarios],
  );

  const handleAdd = useCallback(() => {
    setIsCreating(true);
    setSelectedId(null);
    setEditingScenario({
      id: crypto.randomUUID(),
      name: "",
      description: "",
      category: "benign",
      actionType: "file_access",
      payload: {},
    });
  }, []);

  const handleSaveScenario = useCallback(
    (scenario: TestScenario) => {
      if (isCreating) {
        setScenarios((prev) => [...prev, scenario]);
        setIsCreating(false);
      } else {
        setScenarios((prev) => prev.map((s) => (s.id === scenario.id ? scenario : s)));
      }
      setSelectedId(scenario.id);
      setEditingScenario(scenario);
    },
    [isCreating],
  );

  const handleRun = useCallback(
    (scenario: TestScenario) => {
      if (isCreating) {
        handleSaveScenario(scenario);
      }
      void runScenario(scenario);
    },
    [isCreating, handleSaveScenario, runScenario],
  );

  // ---- Smart scenario generation ----

  const handleGenerate = useCallback(() => {
    const result = generateScenariosFromPolicy(state.activePolicy);
    setAutoScenarios(result.scenarios);

    const allScenarios = [...scenarios, ...result.scenarios];
    const coverage = analyzeCoverage(state.activePolicy.guards, allScenarios);
    setCoverageReport(coverage);

    toast({
      type: "success",
      title: `Generated ${result.scenarios.length} smart scenarios`,
      description: `${result.coveredGuards.length} guards covered, ${result.disabledGuards.length} disabled`,
    });
  }, [state.activePolicy, scenarios, toast]);

  const handleRunAutoScenarios = useCallback(async () => {
    if (autoScenarios.length === 0) return;
    setSimulating(true);
    let usedFallback = false;
    let runningPostureState = postureStateJson;
    try {
      const newResults: SimulationResult[] = [];
      for (const s of autoScenarios) {
        const rustAction = toRustActionType(s.actionType);
        let result: SimulationResult | null = null;

        if (rustAction) {
          try {
            const target = extractTarget(s.actionType, s.payload);
            const content = extractContent(s.actionType, s.payload);
            const policyYaml = policyToYaml(state.activePolicy);

            if (hasPostureConfig) {
              const resp = await simulateWithPostureNative(policyYaml, rustAction, target, content, runningPostureState ?? undefined);
              if (resp) {
                const parsed = fromRustPostureSimulation(s.id, resp);
                result = parsed.result;
                if (parsed.postureStateJson) {
                  runningPostureState = parsed.postureStateJson;
                }
                if (parsed.posture) {
                  setCumulativePosture((prev) => mergeCumulativePosture(prev, parsed.posture!));
                }
              }
            }

            if (!result) {
              const resp = await simulateActionNative(policyYaml, rustAction, target, content);
              if (resp) {
                result = fromRustSimulation(s.id, resp);
              }
            }
          } catch {
            usedFallback = true;
          }
        }

        if (!result) {
          result = simulatePolicy(state.activePolicy, s);
        }
        newResults.push(result);
      }
      setPostureStateJson(runningPostureState);
      setResults((prev) => [...newResults, ...prev].slice(0, 50));
      if (usedFallback) {
        toast({
          type: "warning",
          title: "Rust engine unavailable for some smart scenarios",
          description: "Fell back to client-side JS simulation",
        });
      }

      const allScenarios = [...scenarios, ...autoScenarios];
      const allResults = [...newResults, ...results];
      const report = generateBatchReport(state.activePolicy, allScenarios, allResults);
      setBatchReport(report);

      const passed = newResults.filter((r, i) => {
        const sc = autoScenarios[i];
        return sc.expectedVerdict == null || sc.expectedVerdict === r.overallVerdict;
      }).length;

      toast({
        type: "info",
        title: `Smart batch complete -- ${passed}/${newResults.length} passed`,
        description: "Auto-generated scenarios evaluated",
      });
    } finally {
      setSimulating(false);
    }
  }, [autoScenarios, state.activePolicy, hasPostureConfig, postureStateJson, scenarios, results, toast]);

  const handleViewReport = useCallback(() => {
    if (batchReport) {
      setReportDialogOpen(true);
    }
  }, [batchReport]);

  const handleDownloadReport = useCallback(() => {
    if (batchReport) {
      downloadReport(batchReport, state.activePolicy.name);
      toast({
        type: "success",
        title: "Report downloaded",
        description: `${state.activePolicy.name}_test_report.json saved`,
      });
    }
  }, [batchReport, state.activePolicy.name, toast]);

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Header with tabs + status indicators */}
      <SimulatorHeader
        activeTab={activeTab}
        onTabChange={setActiveTab}
        threatLevel={threatLevel}
        engineConnected={engineConnected}
      />

      {/* Tab content */}
      <div className="flex-1 min-h-0">
        {activeTab === "scenarios" && (
          <div className="flex h-full min-h-0 simulator-scan-overlay">
            {/* Left: Scenario list */}
            <div className="w-72 shrink-0 border-r border-[#2d3240] bg-[#0b0d13] flex flex-col max-lg:hidden relative z-[1]">
              <ScenarioList
                scenarios={scenarios}
                autoScenarios={autoScenarios}
                selectedId={selectedId}
                onSelect={handleSelect}
                onAdd={handleAdd}
                onRunAll={runAll}
                onGenerate={handleGenerate}
                onRunAutoScenarios={handleRunAutoScenarios}
                coverageReport={coverageReport}
                policy={state.activePolicy}
                onScenariosGenerated={(generated) => {
                  setAutoScenarios((prev) => [...prev, ...generated]);
                  toast({
                    type: "success",
                    title: `${generated.length} red team scenarios generated`,
                    description: "View them in the Library",
                  });
                }}
              />
            </div>

            {/* Center: Scenario builder */}
            <div className="flex-1 min-w-0 bg-[#05060a] overflow-auto relative z-[1]">
              {/* Mobile scenario list */}
              <div className="lg:hidden border-b border-[#2d3240]">
                <ScenarioList
                  scenarios={scenarios}
                  autoScenarios={autoScenarios}
                  selectedId={selectedId}
                  onSelect={handleSelect}
                  onAdd={handleAdd}
                  onRunAll={runAll}
                  onGenerate={handleGenerate}
                  onRunAutoScenarios={handleRunAutoScenarios}
                  coverageReport={coverageReport}
                  policy={state.activePolicy}
                  onScenariosGenerated={(generated) => {
                    setAutoScenarios((prev) => [...prev, ...generated]);
                    toast({
                      type: "success",
                      title: `${generated.length} red team scenarios generated`,
                      description: "View them in the Library",
                    });
                  }}
                  horizontal
                />
              </div>

              {editingScenario ? (
                <ScenarioBuilder
                  scenario={editingScenario}
                  onChange={setEditingScenario}
                  onRun={handleRun}
                  isCreating={isCreating}
                />
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-[#6f7f9a] px-8">
                  <div className="w-16 h-16 rounded-2xl bg-[#131721] border border-[#2d3240]/60 flex items-center justify-center mb-5">
                    <IconCrosshair size={24} stroke={1.2} className="empty-state-icon text-[#6f7f9a]" />
                  </div>
                  <span className="text-[14px] font-medium text-[#6f7f9a] mb-1.5">No probe selected</span>
                  <span className="text-[12px] text-[#6f7f9a]/60 text-center leading-relaxed max-w-[280px] mb-5">
                    Select a scenario from the threat library or create a custom probe to begin testing
                  </span>
                  <ClaudeCodeHint
                    hintId="simulator.scenarios"
                    className="max-w-md w-full"
                  />
                </div>
              )}
            </div>

            {/* Right: Results + Posture */}
            <div className="w-80 shrink-0 border-l border-[#2d3240] bg-[#0b0d13] flex flex-col max-xl:hidden overflow-auto relative z-[1]">
              <ResultsPanel
                results={results}
                scenarios={allScenarios}
                simulating={simulating}
              />

              {hasCompleteBatchRun && batchReport && (
                <div className="px-4 py-3 border-t border-[#2d3240] shrink-0">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleViewReport}
                      className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-md bg-[#d4a84b]/10 text-[#d4a84b] text-[11px] font-medium hover:bg-[#d4a84b]/20 transition-colors"
                    >
                      <IconFileReport size={13} stroke={1.5} />
                      View Report
                    </button>
                    <button
                      onClick={handleDownloadReport}
                      className="flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded-md bg-[#131721] text-[#6f7f9a] text-[11px] font-medium hover:text-[#ece7dc] hover:bg-[#131721]/80 transition-colors"
                      title="Download report JSON"
                    >
                      <IconDownload size={13} stroke={1.5} />
                    </button>
                  </div>
                </div>
              )}

              <PosturePanel
                postureReport={cumulativePosture}
                hasPostureConfig={hasPostureConfig}
                onReset={resetPosture}
              />
            </div>

            {/* Mobile results */}
            <div className="xl:hidden fixed bottom-0 left-0 right-0 max-h-[40vh] border-t border-[#2d3240] bg-[#0b0d13] overflow-auto z-30 hidden max-xl:block">
              <ResultsPanel
                results={results}
                scenarios={allScenarios}
                simulating={simulating}
                compact
              />

              {hasCompleteBatchRun && batchReport && (
                <div className="px-4 py-3 border-t border-[#2d3240] shrink-0">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleViewReport}
                      className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-md bg-[#d4a84b]/10 text-[#d4a84b] text-[11px] font-medium hover:bg-[#d4a84b]/20 transition-colors"
                    >
                      <IconFileReport size={13} stroke={1.5} />
                      View Report
                    </button>
                    <button
                      onClick={handleDownloadReport}
                      className="flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded-md bg-[#131721] text-[#6f7f9a] text-[11px] font-medium hover:text-[#ece7dc] hover:bg-[#131721]/80 transition-colors"
                      title="Download report JSON"
                    >
                      <IconDownload size={13} stroke={1.5} />
                    </button>
                  </div>
                </div>
              )}

              <PosturePanel
                postureReport={cumulativePosture}
                hasPostureConfig={hasPostureConfig}
                onReset={resetPosture}
              />
            </div>
          </div>
        )}

        {activeTab === "trustprint-lab" && (
          <TrustprintLab />
        )}

        {activeTab === "observe" && (
          <ObservePanel />
        )}

        {activeTab === "coverage" && (
          <ThreatMatrix scenarios={allScenarios} results={results} />
        )}
      </div>

      {/* Report dialog */}
      <ReportDialog
        open={reportDialogOpen}
        onOpenChange={setReportDialogOpen}
        report={batchReport}
        policyName={state.activePolicy.name}
      />
    </div>
  );
}
