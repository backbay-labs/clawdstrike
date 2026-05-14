import {
  generateSwarmId,
  type GuardEvaluationResult,
  type GuardEvaluator,
  type GuardSimResult,
  type GuardedAction,
  type Receipt,
} from "@clawdstrike/swarm-engine";
import { DEFAULT_POLICY } from "@/features/policy/stores/policy-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { simulatePolicy } from "@/lib/workbench/simulation-engine";
import type {
  GuardSimResult as WorkbenchGuardSimResult,
  TestActionType,
  TestScenario,
  Verdict,
  WorkbenchPolicy,
} from "@/lib/workbench/types";

function getActiveWorkbenchPolicy(): WorkbenchPolicy {
  const activeTabId = usePolicyTabsStore.getState().activeTabId;
  if (!activeTabId) {
    return DEFAULT_POLICY;
  }

  return (
    usePolicyEditStore.getState().editStates.get(activeTabId)?.policy ??
    DEFAULT_POLICY
  );
}

function coerceString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function buildScenarioPayload(action: GuardedAction): Record<string, unknown> {
  const content = coerceString(action.context.content);
  const cwd = coerceString(action.context.cwd);
  const command = coerceString(action.context.command);
  const prompt = coerceString(action.context.prompt);
  const toolName = coerceString(action.context.tool);
  const patch = coerceString(action.context.patch);

  switch (action.actionType) {
    case "file_access":
      return { path: action.target };
    case "file_write":
      return {
        path: action.target,
        ...(content ? { content } : {}),
      };
    case "network_egress":
      return { host: action.target };
    case "shell_command":
      return {
        command: command ?? action.target,
        ...(cwd ? { cwd } : {}),
      };
    case "mcp_tool_call":
      return {
        tool: toolName ?? action.target,
      };
    case "patch_apply":
      return {
        path: action.target,
        ...(patch ? { content: patch } : content ? { content } : {}),
      };
    case "user_input":
      return {
        text: prompt ?? command ?? action.target,
      };
    default:
      return {
        actionType: action.actionType,
        target: action.target,
        ...action.context,
      };
  }
}

function buildScenarioCategory(
  action: GuardedAction,
): TestScenario["category"] {
  const operation = coerceString(action.context.operation);
  if (
    operation === "agent_spawn" ||
    operation === "claude_spawn" ||
    operation === "worktree_spawn"
  ) {
    return "benign";
  }

  switch (action.actionType) {
    case "file_access":
      return "benign";
    default:
      return "edge_case";
  }
}

function mapGuardResult(
  guardResult: WorkbenchGuardSimResult,
): GuardSimResult {
  return {
    guardId: guardResult.guardId,
    guard: guardResult.guardName,
    verdict: guardResult.verdict,
    duration_ms: 0,
    details: {
      message: guardResult.message,
      ...(guardResult.evidence ? { evidence: guardResult.evidence } : {}),
      ...(guardResult.engine ? { engine: guardResult.engine } : {}),
    },
  };
}

function pickDecidingGuard(
  guardResults: WorkbenchGuardSimResult[],
): WorkbenchGuardSimResult | null {
  return (
    guardResults.find((result) => result.verdict === "deny") ??
    guardResults.find((result) => result.verdict === "warn") ??
    guardResults[0] ??
    null
  );
}

function stableHex(value: string, length: number): string {
  let output = "";

  for (let salt = 0; output.length < length; salt++) {
    let hash = 0x811c9dc5 ^ salt;
    const salted = `${value}:${salt}`;
    for (let index = 0; index < salted.length; index++) {
      hash ^= salted.charCodeAt(index);
      hash = Math.imul(hash, 0x01000193);
    }
    output += (hash >>> 0).toString(16).padStart(8, "0");
  }

  return output.slice(0, length);
}

function buildReceipt(
  action: GuardedAction,
  policy: WorkbenchPolicy,
  verdict: Verdict,
  guardResults: WorkbenchGuardSimResult[],
  executedAt: number,
): Receipt {
  const decidingGuard = pickDecidingGuard(guardResults);
  const policyName = policy.name || "Workbench Policy";
  const signatureMaterial = JSON.stringify({
    executedAt,
    actionType: action.actionType,
    target: action.target,
    verdict,
    guardResults: guardResults.map((result) => ({
      guardId: result.guardId,
      verdict: result.verdict,
      message: result.message,
    })),
    policyName,
  });

  return {
    id: generateSwarmId("rct"),
    timestamp: new Date(executedAt).toISOString(),
    verdict,
    guard: decidingGuard?.guardName ?? "simulation_engine",
    policyName,
    action: {
      type: action.actionType as TestActionType,
      target: action.target,
    },
    evidence: {
      engine: decidingGuard?.engine ?? "client",
      guard_results: guardResults.map((result) => ({
        guard: result.guardName,
        verdict: result.verdict,
        message: result.message,
      })),
      context: action.context,
    },
    signature: stableHex(signatureMaterial, 128),
    publicKey: stableHex(`workbench:${policyName}`, 64),
    valid: true,
  };
}

export const workbenchGuardEvaluator: GuardEvaluator = {
  async evaluate(action: GuardedAction): Promise<GuardEvaluationResult> {
    const policy = getActiveWorkbenchPolicy();
    const startedAt = Date.now();
    const scenario: TestScenario = {
      id: generateSwarmId("tsk"),
      name: "swarm-session-spawn",
      description: `Guard evaluation for ${action.actionType}`,
      category: buildScenarioCategory(action),
      actionType: action.actionType as TestActionType,
      payload: buildScenarioPayload(action),
    };

    const simulation = simulatePolicy(policy, scenario);
    const evaluatedAt = Date.now();
    const verdict = simulation.overallVerdict;

    return {
      verdict,
      allowed: verdict !== "deny",
      guardResults: simulation.guardResults.map(mapGuardResult),
      receipt: buildReceipt(
        action,
        policy,
        verdict,
        simulation.guardResults,
        evaluatedAt,
      ),
      durationMs: evaluatedAt - startedAt,
      evaluatedAt,
    };
  },
};
