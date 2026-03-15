import { useState, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import type { TestScenario, SimulationResult, TestActionType, Verdict, GuardSimResult, EvaluationPathStep, PostureReport, PostureBudget } from "@/lib/workbench/types";
import { useWorkbench, useMultiPolicy } from "@/lib/workbench/multi-policy-store";
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
import { isPolicyFileType, FILE_TYPE_REGISTRY, type FileType } from "@/lib/workbench/file-type-registry";
import { useLabExecution } from "@/lib/workbench/detection-workflow/use-lab-execution";
import { useSwarmLaunch } from "@/lib/workbench/detection-workflow/use-swarm-launch";
import { useEvidencePacks } from "@/lib/workbench/detection-workflow/use-evidence-packs";
import type { EvidencePack, LabRun } from "@/lib/workbench/detection-workflow/shared-types";
import { ScenarioList } from "./scenario-list";
import { ScenarioBuilder } from "./scenario-builder";
import { ResultsPanel } from "./results-panel";
import { PosturePanel } from "./posture-panel";
import { ReportDialog } from "./report-dialog";
import { ObservePanel } from "./observe-panel";
import { ThreatMatrix } from "./threat-matrix";
import { TrustprintLab } from "./trustprint-lab";
import { LabFormatHeader } from "./lab-format-header";
import { LabRunHistoryPanel } from "./lab-run-history-panel";
import { ExplainabilityPanel } from "@/components/workbench/editor/explainability-panel";
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
  IconFlask,
  IconHistory,
  IconTopologyStar3,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { SubTabBar, type SubTab } from "../shared/sub-tab-bar";
import { ClaudeCodeHint } from "@/components/workbench/shared/claude-code-hint";


type SimulatorTab = "scenarios" | "trustprint-lab" | "observe" | "coverage" | "lab" | "history";

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


const SIMULATOR_TABS: SubTab[] = [
  { id: "scenarios", label: "Scenarios", icon: IconTestPipe },
  { id: "trustprint-lab", label: "Trustprint", icon: IconFingerprint, title: "Embedding-based threat screening using vector similarity against known patterns" },
  { id: "observe", label: "Observe", icon: IconEye },
  { id: "coverage", label: "Coverage", icon: IconGrid3x3 },
];

/** Tabs shown for non-policy file types (Sigma, YARA, OCSF). */
const NON_POLICY_TABS: SubTab[] = [
  { id: "lab", label: "Lab", icon: IconFlask },
  { id: "history", label: "History", icon: IconHistory },
];

function SimulatorStatusIndicators({
  threatLevel,
  engineConnected,
}: {
  threatLevel: { color: string; label: string };
  engineConnected: boolean;
}) {
  return (
    <>
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
    </>
  );
}


export function SimulatorLayout() {
  const { state } = useWorkbench();
  const { activeTab: activeTabObj } = useMultiPolicy();
  const { toast } = useToast();
  const navigate = useNavigate();
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

  // ---- Format awareness ----
  const currentFileType = activeTabObj?.fileType;
  const currentDocumentId = activeTabObj?.documentId;
  const currentSource = activeTabObj?.yaml ?? "";
  const isPolicy = currentFileType != null && isPolicyFileType(currentFileType);

  // Lab execution hook — provides adapter-based execution for all formats
  const labExecution = useLabExecution(currentDocumentId, currentFileType);
  const evidencePacks = useEvidencePacks(currentDocumentId, currentFileType);

  // Swarm launch hook — creates detection nodes on the SwarmBoard
  const swarmLaunch = useSwarmLaunch({
    documentId: currentDocumentId,
    fileType: currentFileType,
    tabId: activeTabObj?.id,
    name: activeTabObj?.name,
    filePath: activeTabObj?.filePath,
    onNavigate: (path) => navigate(path),
  });

  // Determine which tabs to show based on file type
  const visibleTabs = useMemo(
    () => (isPolicy ? SIMULATOR_TABS : NON_POLICY_TABS),
    [isPolicy],
  );

  // If the active tab is invalid for the current file type, reset it
  const effectiveTab = useMemo(() => {
    const validIds = visibleTabs.map((t) => t.id);
    if (validIds.includes(activeTab)) return activeTab;
    return validIds[0] as SimulatorTab;
  }, [activeTab, visibleTabs]);

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

  const selectedEvidencePack = useMemo(
    () =>
      evidencePacks.packs.find((pack) => pack.id === evidencePacks.selectedPackId)
      ?? evidencePacks.packs[0]
      ?? null,
    [evidencePacks.packs, evidencePacks.selectedPackId],
  );

  const handleRunDetectionLab = useCallback(async () => {
    if (!selectedEvidencePack || !currentSource) {
      toast({
        type: "warning",
        title: "Lab run unavailable",
        description: !currentSource ? "Open a detection document with source content" : "Select or create an evidence pack",
      });
      return;
    }

    const result = await labExecution.executeRun(selectedEvidencePack, currentSource);
    if (!result) {
      toast({
        type: "error",
        title: "Lab run failed",
        description: "The selected detection could not be executed against the evidence pack.",
      });
      return;
    }

    toast({
      type: result.run.summary.failed === 0 ? "success" : "warning",
      title: result.run.summary.failed === 0 ? "Lab run passed" : "Lab run completed with failures",
      description: `${result.run.summary.passed}/${result.run.summary.totalCases} cases passed`,
    });
  }, [currentSource, labExecution, selectedEvidencePack, toast]);

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
      {/* Format-aware lab header */}
      <LabFormatHeader
        fileType={currentFileType}
        lastRun={labExecution.lastRun}
        isRunning={labExecution.isRunning}
      />

      {/* Sub-tab bar with status indicators */}
      <SubTabBar
        tabs={visibleTabs}
        activeTab={effectiveTab}
        onTabChange={(id) => setActiveTab(id as SimulatorTab)}
      >
        {isPolicy && (
          <SimulatorStatusIndicators
            threatLevel={threatLevel}
            engineConnected={engineConnected}
          />
        )}
      </SubTabBar>

      {/* Tab content */}
      <div className="flex-1 min-h-0">
        {/* ---- Policy-specific tabs (unchanged behavior) ---- */}
        {effectiveTab === "scenarios" && isPolicy && (
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
                    {swarmLaunch.canLaunch && (
                      <button
                        onClick={() => swarmLaunch.openReviewSwarm()}
                        className="flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded-md bg-[#131721] text-[#6f7f9a] text-[11px] font-medium hover:text-[#d4a84b] hover:bg-[#131721]/80 transition-colors"
                        title="Open Review Swarm"
                      >
                        <IconTopologyStar3 size={13} stroke={1.5} />
                      </button>
                    )}
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

        {effectiveTab === "trustprint-lab" && (
          <TrustprintLab />
        )}

        {effectiveTab === "observe" && (
          <ObservePanel />
        )}

        {effectiveTab === "coverage" && (
          <ThreatMatrix scenarios={allScenarios} results={results} />
        )}

        {/* ---- Non-policy Lab tab ---- */}
        {effectiveTab === "lab" && !isPolicy && (
          <div className="flex h-full min-h-0">
            <div className="flex-1 min-w-0">
              <NonPolicyLabContent
                fileType={currentFileType}
                canExecute={labExecution.canExecute}
                isRunning={labExecution.isRunning}
                lastRun={labExecution.lastRun}
                packs={evidencePacks.packs}
                selectedPackId={selectedEvidencePack?.id ?? null}
                onSelectPack={evidencePacks.selectPack}
                onCreatePack={async () => {
                  await evidencePacks.createPack();
                }}
                onRunLab={handleRunDetectionLab}
                swarmLaunch={swarmLaunch}
              />
            </div>
            {labExecution.lastRun &&
              labExecution.lastRun.explainability.length > 0 && (
                <div className="w-[280px] shrink-0 max-xl:hidden">
                  <ExplainabilityPanel
                    documentId={currentDocumentId}
                    lastRun={labExecution.lastRun}
                    baselineRun={
                      labExecution.runHistory.length > 1
                        ? labExecution.runHistory[1]
                        : null
                    }
                  />
                </div>
              )}
          </div>
        )}

        {/* ---- Non-policy History tab ---- */}
        {effectiveTab === "history" && !isPolicy && (
          <LabRunHistoryPanel
            runs={labExecution.runHistory}
            onDeleteRun={labExecution.deleteRun}
          />
        )}
      </div>

      {/* Report dialog (policy only) */}
      {isPolicy && (
        <ReportDialog
          open={reportDialogOpen}
          onOpenChange={setReportDialogOpen}
          report={batchReport}
          policyName={state.activePolicy.name}
        />
      )}
    </div>
  );
}


// ---------------------------------------------------------------------------
// Non-Policy Lab Content
// ---------------------------------------------------------------------------

function NonPolicyLabContent({
  fileType,
  canExecute,
  isRunning,
  lastRun,
  packs,
  selectedPackId,
  onSelectPack,
  onCreatePack,
  onRunLab,
  swarmLaunch,
}: {
  fileType: FileType | undefined;
  canExecute: boolean;
  isRunning: boolean;
  lastRun: LabRun | null;
  packs: EvidencePack[];
  selectedPackId: string | null;
  onSelectPack: (packId: string | null) => void;
  onCreatePack: () => Promise<void>;
  onRunLab: () => Promise<void>;
  swarmLaunch: import("@/lib/workbench/detection-workflow/use-swarm-launch").SwarmLaunchActions;
}) {
  if (!fileType) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-[#6f7f9a] px-8">
        <span className="text-[13px] font-medium">No document selected</span>
      </div>
    );
  }

  const descriptor = FILE_TYPE_REGISTRY[fileType];

  if (!canExecute) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-[#6f7f9a] px-8">
        <div className="w-16 h-16 rounded-2xl bg-[#131721] border border-[#2d3240]/60 flex items-center justify-center mb-5">
          <IconFlask size={24} stroke={1.2} className="empty-state-icon text-[#6f7f9a]" />
        </div>
        <span className="text-[14px] font-medium text-[#6f7f9a] mb-1.5">
          Lab not available
        </span>
        <span className="text-[12px] text-[#6f7f9a]/60 text-center leading-relaxed max-w-[320px] mb-4">
          Lab execution is not yet available for{" "}
          <span style={{ color: descriptor.iconColor }} className="font-semibold">
            {descriptor.label}
          </span>{" "}
          files. A detection workflow adapter must be registered before lab runs
          can be executed for this format.
        </span>
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-[#2d3240] bg-[#131721]">
          <div
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: descriptor.iconColor }}
          />
          <span className="text-[10px] font-mono text-[#6f7f9a]">
            Adapter status: not registered
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center justify-center h-full text-[#6f7f9a] px-8">
      <div className="w-16 h-16 rounded-2xl bg-[#131721] border border-[#2d3240]/60 flex items-center justify-center mb-5">
        <IconFlask
          size={24}
          stroke={1.2}
          style={{ color: descriptor.iconColor }}
          className={isRunning ? "animate-pulse" : ""}
        />
      </div>
      <span className="text-[14px] font-medium text-[#ece7dc] mb-1.5">
        {descriptor.label} Lab
      </span>
      <span className="text-[12px] text-[#6f7f9a]/60 text-center leading-relaxed max-w-[320px] mb-4">
        {isRunning
          ? "Lab run in progress..."
          : lastRun
            ? `Last run: ${lastRun.summary.passed}/${lastRun.summary.totalCases} passed`
            : "Ready to run. Provide an evidence pack and execute a lab run to validate this detection."}
      </span>
      <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-[#2d3240] bg-[#131721]">
        <IconCircle size={6} stroke={0} fill="#3dbf84" className="animate-pulse" />
        <span className="text-[10px] font-mono text-[#3dbf84]/70">
          Adapter registered
        </span>
      </div>
      <div className="mt-4 w-full max-w-[340px] rounded-xl border border-[#2d3240] bg-[#0b0d13] p-4 flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
            Evidence Pack
          </span>
          <button
            type="button"
            onClick={() => {
              void onCreatePack();
            }}
            className="rounded-md border border-[#2d3240] px-2 py-1 text-[10px] font-mono text-[#6f7f9a] hover:text-[#ece7dc] hover:border-[#d4a84b]/30 transition-colors"
          >
            New Pack
          </button>
        </div>
        {packs.length > 0 ? (
          <select
            value={selectedPackId ?? ""}
            onChange={(event) => onSelectPack(event.target.value || null)}
            className="h-8 rounded-md border border-[#2d3240] bg-[#131721] px-2 text-[10px] text-[#ece7dc] focus:outline-none focus:border-[#d4a84b]/40"
          >
            {packs.map((pack) => {
              const caseCount = Object.values(pack.datasets).reduce((sum, items) => sum + items.length, 0);
              return (
                <option key={pack.id} value={pack.id}>
                  {pack.title} ({caseCount} cases)
                </option>
              );
            })}
          </select>
        ) : (
          <div className="rounded-md border border-dashed border-[#2d3240] px-3 py-2 text-[10px] text-[#6f7f9a] text-center">
            No evidence packs yet. Draft from Hunt or create a pack to run this detection.
          </div>
        )}
        <button
          type="button"
          onClick={() => {
            void onRunLab();
          }}
          disabled={isRunning || packs.length === 0 || !selectedPackId}
          className={cn(
            "h-8 rounded-lg text-[11px] font-medium transition-colors",
            isRunning || packs.length === 0 || !selectedPackId
              ? "bg-[#131721] text-[#6f7f9a] border border-[#2d3240] opacity-50 cursor-not-allowed"
              : "bg-[#d4a84b] text-[#05060a] hover:bg-[#e8c36a]",
          )}
        >
          {isRunning ? "Running Lab..." : "Run Detection Lab"}
        </button>
      </div>
      {swarmLaunch.canLaunch && (
        <button
          type="button"
          onClick={() => {
            if (lastRun) {
              swarmLaunch.openReviewSwarmWithRun(lastRun.id);
            } else {
              swarmLaunch.openReviewSwarm();
            }
          }}
          className="mt-4 inline-flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] border border-[#2d3240] hover:border-[#d4a84b]/30 rounded-md transition-colors"
          title="Open Review Swarm"
        >
          <IconTopologyStar3 size={13} stroke={1.5} />
          Open Review Swarm
        </button>
      )}
    </div>
  );
}
