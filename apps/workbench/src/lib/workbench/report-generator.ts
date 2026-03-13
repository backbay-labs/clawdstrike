import type {
  WorkbenchPolicy,
  TestScenario,
  SimulationResult,
  Verdict,
  GuardId,
  ComplianceFramework,
} from "./types";
import {
  scoreFramework,
  COMPLIANCE_FRAMEWORKS,
  type ComplianceRequirementDef,
} from "./compliance-requirements";
import { ALL_GUARD_IDS } from "./guard-registry";

export interface ReportPolicyInfo {
  name: string;
  version: string;
  schema_version: string;
  extends?: string;
}

export interface ReportSummary {
  total: number;
  passed: number;
  failed: number;
  warnings: number;
  pass_rate: number;
}

export interface ReportGuardResult {
  guard_id: string;
  guard_name: string;
  verdict: Verdict;
  message: string;
  engine?: string;
}

export interface ReportScenario {
  scenario_id: string;
  name: string;
  description: string;
  category: string;
  action_type: string;
  target: string;
  expected_verdict: Verdict | null;
  actual_verdict: Verdict;
  passed: boolean;
  guard_results: ReportGuardResult[];
}

export interface ReportComplianceFramework {
  framework: ComplianceFramework;
  framework_name: string;
  score: number;
  total_requirements: number;
  met_count: number;
  gap_count: number;
  met: { id: string; title: string; citation: string }[];
  gaps: { id: string; title: string; citation: string }[];
}

export interface ReportGuardConfig {
  guard_id: GuardId;
  enabled: boolean;
}

export interface ReportPolicyConfig {
  base_ruleset: string | null;
  enabled_guards: ReportGuardConfig[];
}

export interface BatchTestReport {
  report_type: "clawdstrike_policy_test_report";
  version: "1.0";
  generated_at: string;
  policy: ReportPolicyInfo;
  summary: ReportSummary;
  scenarios: ReportScenario[];
  compliance: Record<string, ReportComplianceFramework>;
  policy_config: ReportPolicyConfig;
}

function extractTargetFromPayload(
  actionType: string,
  payload: Record<string, unknown>,
): string {
  switch (actionType) {
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

function buildComplianceSummary(
  policy: WorkbenchPolicy,
): Record<string, ReportComplianceFramework> {
  const result: Record<string, ReportComplianceFramework> = {};

  for (const fw of COMPLIANCE_FRAMEWORKS) {
    const score = scoreFramework(fw.id, policy.guards, policy.settings);
    const mapReq = (r: ComplianceRequirementDef) => ({
      id: r.id,
      title: r.title,
      citation: r.citation,
    });

    result[fw.id === "pci-dss" ? "pci_dss" : fw.id] = {
      framework: fw.id,
      framework_name: fw.name,
      score: score.score,
      total_requirements: fw.requirements.length,
      met_count: score.met.length,
      gap_count: score.gaps.length,
      met: score.met.map(mapReq),
      gaps: score.gaps.map(mapReq),
    };
  }

  return result;
}

function buildPolicyConfig(policy: WorkbenchPolicy): ReportPolicyConfig {
  const enabledGuards: ReportGuardConfig[] = ALL_GUARD_IDS.map((id) => {
    const config = policy.guards[id];
    return {
      guard_id: id,
      enabled: !!(config && (config as { enabled?: boolean }).enabled),
    };
  });

  return {
    base_ruleset: policy.extends ?? null,
    enabled_guards: enabledGuards,
  };
}

function evaluatePass(
  scenario: TestScenario,
  result: SimulationResult,
): boolean {
  if (scenario.expectedVerdict == null) {
    // No expectation set -- treat as pass
    return true;
  }
  return scenario.expectedVerdict === result.overallVerdict;
}

export function generateBatchReport(
  policy: WorkbenchPolicy,
  scenarios: TestScenario[],
  results: SimulationResult[],
): BatchTestReport {
  // Build a lookup map for results by scenario ID
  const resultMap = new Map<string, SimulationResult>();
  for (const r of results) {
    // If there are multiple results for the same scenario, use the most recent
    if (!resultMap.has(r.scenarioId)) {
      resultMap.set(r.scenarioId, r);
    }
  }

  // Build per-scenario details
  const reportScenarios: ReportScenario[] = [];
  let passed = 0;
  let failed = 0;
  let warnings = 0;

  for (const scenario of scenarios) {
    const result = resultMap.get(scenario.id);
    if (!result) continue;

    const isPassed = evaluatePass(scenario, result);
    if (isPassed) {
      passed++;
    } else {
      failed++;
    }

    if (result.overallVerdict === "warn") {
      warnings++;
    }

    reportScenarios.push({
      scenario_id: scenario.id,
      name: scenario.name,
      description: scenario.description,
      category: scenario.category,
      action_type: scenario.actionType,
      target: extractTargetFromPayload(scenario.actionType, scenario.payload),
      expected_verdict: scenario.expectedVerdict ?? null,
      actual_verdict: result.overallVerdict,
      passed: isPassed,
      guard_results: result.guardResults.map((gr) => ({
        guard_id: gr.guardId,
        guard_name: gr.guardName,
        verdict: gr.verdict,
        message: gr.message,
        engine: gr.engine,
      })),
    });
  }

  const total = reportScenarios.length;
  const passRate = total > 0 ? Math.round((passed / total) * 1000) / 1000 : 0;

  return {
    report_type: "clawdstrike_policy_test_report",
    version: "1.0",
    generated_at: new Date().toISOString(),
    policy: {
      name: policy.name,
      version: policy.version,
      schema_version: policy.version,
      extends: policy.extends,
    },
    summary: {
      total,
      passed,
      failed,
      warnings,
      pass_rate: passRate,
    },
    scenarios: reportScenarios,
    compliance: buildComplianceSummary(policy),
    policy_config: buildPolicyConfig(policy),
  };
}

export function reportToJson(report: BatchTestReport): string {
  return JSON.stringify(report, null, 2);
}

export function downloadReport(report: BatchTestReport, policyName: string): void {
  const json = reportToJson(report);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const safeName = policyName.replace(/[^a-zA-Z0-9_-]/g, "_").toLowerCase();
  a.download = `${safeName}_test_report_${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
