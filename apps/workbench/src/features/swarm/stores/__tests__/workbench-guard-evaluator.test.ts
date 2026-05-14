import { beforeEach, describe, expect, it, vi } from "vitest";
import type { GuardedAction } from "@clawdstrike/swarm-engine";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { simulatePolicy } from "@/lib/workbench/simulation-engine";
import { workbenchGuardEvaluator } from "../workbench-guard-evaluator";

vi.mock("@/lib/workbench/simulation-engine", () => ({
  simulatePolicy: vi.fn(() => ({
    scenarioId: "tsk_test",
    overallVerdict: "allow",
    guardResults: [],
    executedAt: new Date().toISOString(),
  })),
}));

function makeAction(
  overrides?: Partial<GuardedAction>,
): GuardedAction {
  return {
    agentId: "agt_test",
    taskId: null,
    actionType: "shell_command",
    target: "echo hello",
    context: {},
    requestedAt: Date.now(),
    ...overrides,
  };
}

describe("workbenchGuardEvaluator", () => {
  beforeEach(() => {
    usePolicyTabsStore.getState()._reset();
    vi.mocked(simulatePolicy).mockClear();
  });

  it("keeps known spawn operations in the benign category", async () => {
    const result = await workbenchGuardEvaluator.evaluate(
      makeAction({
        context: {
          operation: "agent_spawn",
          command: "zsh",
        },
      }),
    );

    const scenario = vi.mocked(simulatePolicy).mock.calls[0]?.[1];
    expect(scenario?.category).toBe("benign");
    expect(result.receipt.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(result.receipt.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(result.receipt.valid).toBe(true);
  });

  it("treats non-spawn shell commands as edge cases", async () => {
    await workbenchGuardEvaluator.evaluate(
      makeAction({
        target: "curl https://example.com",
      }),
    );

    const scenario = vi.mocked(simulatePolicy).mock.calls[0]?.[1];
    expect(scenario?.category).toBe("edge_case");
  });
});
