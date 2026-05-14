/**
 * Tests for guard pipeline types and events (03-01 Task 1).
 *
 * Coverage: GuardEvaluator interface, AgentPoolConfig, AgentPoolState,
 * DenyNotification, guard pipeline events in SwarmEngineEventMap.
 */

import { describe, it, expect } from "vitest";
import type {
  GuardEvaluator,
  GuardedAction,
  GuardEvaluationResult,
  AgentPoolConfig,
  AgentPoolState,
  DenyNotification,
} from "./types.js";
import type {
  GuardEvaluatedEvent,
  ActionDeniedEvent,
  ActionCompletedEvent,
  SwarmEngineEventMap,
} from "./events.js";
import type { EnvelopeReceipt } from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeGuardedAction(): GuardedAction {
  return {
    agentId: "agt_01HXK8M3N2ABCDEFGHJKMNPQRS",
    taskId: "tsk_01HXK8M3N2ABCDEFGHJKMNPQRS",
    actionType: "file_write",
    target: "/tmp/test.txt",
    context: {},
    requestedAt: Date.now(),
  };
}

function makeReceipt(): EnvelopeReceipt {
  return {
    receiptId: "r_001",
    verdict: "allow",
    decidingGuard: "ForbiddenPathGuard",
    policyHash: "sha256:abc",
    evaluationMs: 3,
    signature: "sig",
    publicKey: "pub",
    evaluatedAt: Date.now(),
  };
}

// ============================================================================
// Tests
// ============================================================================

describe("GuardEvaluator interface", () => {
  it("has evaluate(action: GuardedAction) => Promise<GuardEvaluationResult>", () => {
    // Verify the interface shape by creating a conforming mock
    const evaluator: GuardEvaluator = {
      evaluate: async (action: GuardedAction): Promise<GuardEvaluationResult> => {
        return {
          verdict: "allow",
          allowed: true,
          guardResults: [],
          receipt: {
            id: "r_001",
            timestamp: new Date().toISOString(),
            verdict: "allow",
            guard: "TestGuard",
            policyName: "test",
            action: { type: action.actionType, target: action.target },
            evidence: {},
            signature: "sig",
            publicKey: "pub",
            valid: true,
          },
          durationMs: 5,
          evaluatedAt: Date.now(),
        };
      },
    };

    expect(evaluator.evaluate).toBeDefined();
    expect(typeof evaluator.evaluate).toBe("function");
  });
});

describe("AgentPoolConfig", () => {
  it("has minSize, maxSize, scaleUpThreshold, scaleDownThreshold, cooldownMs, healthCheckIntervalMs", () => {
    const config: AgentPoolConfig = {
      name: "test-pool",
      minSize: 1,
      maxSize: 10,
      scaleUpThreshold: 0.8,
      scaleDownThreshold: 0.2,
      cooldownMs: 30000,
      healthCheckIntervalMs: 10000,
    };

    expect(config.name).toBe("test-pool");
    expect(config.minSize).toBe(1);
    expect(config.maxSize).toBe(10);
    expect(config.scaleUpThreshold).toBe(0.8);
    expect(config.scaleDownThreshold).toBe(0.2);
    expect(config.cooldownMs).toBe(30000);
    expect(config.healthCheckIntervalMs).toBe(10000);
  });
});

describe("DenyNotification", () => {
  it("has action, originalChannel, originalAction, receiptId, verdict, decidingGuard, sender, timestamp", () => {
    const notification: DenyNotification = {
      action: "envelope_denied",
      originalChannel: "agent_lifecycle",
      originalAction: "agent.spawn",
      receiptId: "r_deny_001",
      verdict: "deny",
      decidingGuard: "ShellCommandGuard",
      sender: "agt_01HXK8M3N2ABCDEFGHJKMNPQRS",
      timestamp: Date.now(),
    };

    expect(notification.action).toBe("envelope_denied");
    expect(notification.originalChannel).toBe("agent_lifecycle");
    expect(notification.originalAction).toBe("agent.spawn");
    expect(notification.receiptId).toBe("r_deny_001");
    expect(notification.verdict).toBe("deny");
    expect(notification.decidingGuard).toBe("ShellCommandGuard");
    expect(notification.sender).toContain("agt_");
    expect(typeof notification.timestamp).toBe("number");
  });
});

describe("AgentPoolState", () => {
  it("has config, agents record, availableCount, busyCount, utilization, pendingScale, lastScaleOperation", () => {
    const state: AgentPoolState = {
      config: {
        name: "test-pool",
        minSize: 1,
        maxSize: 10,
        scaleUpThreshold: 0.8,
        scaleDownThreshold: 0.2,
        cooldownMs: 30000,
        healthCheckIntervalMs: 10000,
      },
      agents: {
        agt_001: {
          agentId: "agt_001",
          status: "available",
          lastUsed: Date.now(),
          usageCount: 0,
          health: 1.0,
        },
      },
      availableCount: 1,
      busyCount: 0,
      utilization: 0,
      pendingScale: 0,
      lastScaleOperation: null,
    };

    expect(state.config.name).toBe("test-pool");
    expect(state.agents["agt_001"]!.status).toBe("available");
    expect(state.availableCount).toBe(1);
    expect(state.busyCount).toBe(0);
    expect(state.utilization).toBe(0);
    expect(state.pendingScale).toBe(0);
    expect(state.lastScaleOperation).toBeNull();
  });
});

describe("SwarmEngineEventMap guard events", () => {
  it('includes "guard.evaluated" key', () => {
    // Type-level assertion: this compiles only if guard.evaluated is in the map
    const eventKey: keyof SwarmEngineEventMap = "guard.evaluated";
    expect(eventKey).toBe("guard.evaluated");
  });

  it('includes "action.denied" key', () => {
    const eventKey: keyof SwarmEngineEventMap = "action.denied";
    expect(eventKey).toBe("action.denied");
  });

  it('includes "action.completed" key', () => {
    const eventKey: keyof SwarmEngineEventMap = "action.completed";
    expect(eventKey).toBe("action.completed");
  });
});

describe("GuardEvaluatedEvent", () => {
  it('has kind="guard.evaluated", action, result, durationMs', () => {
    const event: GuardEvaluatedEvent = {
      kind: "guard.evaluated",
      sourceAgentId: "agt_01HXK8M3N2ABCDEFGHJKMNPQRS",
      timestamp: Date.now(),
      action: makeGuardedAction(),
      result: {
        verdict: "allow",
        allowed: true,
        guardResults: [],
        receipt: {
          id: "r_001",
          timestamp: new Date().toISOString(),
          verdict: "allow",
          guard: "TestGuard",
          policyName: "test",
          action: { type: "file_write", target: "/tmp/test.txt" },
          evidence: {},
          signature: "sig",
          publicKey: "pub",
          valid: true,
        },
        durationMs: 5,
        evaluatedAt: Date.now(),
      },
      durationMs: 5,
    };

    expect(event.kind).toBe("guard.evaluated");
    expect(event.action.agentId).toContain("agt_");
    expect(event.result.verdict).toBe("allow");
    expect(typeof event.durationMs).toBe("number");
  });
});

describe("ActionDeniedEvent", () => {
  it('has kind="action.denied", action, receipt, reason', () => {
    const event: ActionDeniedEvent = {
      kind: "action.denied",
      sourceAgentId: "agt_01HXK8M3N2ABCDEFGHJKMNPQRS",
      timestamp: Date.now(),
      action: makeGuardedAction(),
      receipt: makeReceipt(),
      reason: "Forbidden path access",
    };

    expect(event.kind).toBe("action.denied");
    expect(event.action.actionType).toBe("file_write");
    expect(event.receipt.receiptId).toBe("r_001");
    expect(event.reason).toBe("Forbidden path access");
  });
});

describe("ActionCompletedEvent", () => {
  it('has kind="action.completed", action, receipt, durationMs', () => {
    const event: ActionCompletedEvent = {
      kind: "action.completed",
      sourceAgentId: "agt_01HXK8M3N2ABCDEFGHJKMNPQRS",
      timestamp: Date.now(),
      action: makeGuardedAction(),
      receipt: makeReceipt(),
      durationMs: 42,
    };

    expect(event.kind).toBe("action.completed");
    expect(event.action.actionType).toBe("file_write");
    expect(event.receipt.verdict).toBe("allow");
    expect(event.durationMs).toBe(42);
  });
});
