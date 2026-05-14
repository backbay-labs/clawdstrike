/**
 * Type system and ID generation tests.
 *
 * Covers: FOUN-02 (entity types), FOUN-05 (GuardedPayload + EnvelopeReceipt),
 * ULID format, type guards, constants, and serialization constraints.
 */

import { describe, it, expect } from "vitest";
import { generateSwarmId } from "./ids.js";
import type { SwarmEngineIdPrefix } from "./ids.js";
import {
  isAgentSession,
  isTask,
  isSwarmEngineEvent,
  isSwarmEngineEnvelope,
  SWARM_ENGINE_CONSTANTS,
} from "./types.js";
import type {
  AgentSession,
  AgentCapabilities,
  AgentMetrics,
  AgentQualityScores,
  Task,
  GuardedPayload,
  EnvelopeReceipt,
  Verdict,
} from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Crockford Base32 regex (excludes I, L, O, U). */
const CROCKFORD_RE = /^(agt|tsk|swe|top|csn|msg|rct)_[0-9A-HJKMNP-TV-Z]{26}$/;

function makeCapabilities(): AgentCapabilities {
  return {
    codeGeneration: true,
    codeReview: true,
    testing: true,
    documentation: false,
    research: false,
    analysis: true,
    coordination: false,
    securityAnalysis: true,
    languages: ["typescript", "rust"],
    frameworks: ["vitest"],
    domains: ["security"],
    tools: ["tsc"],
    maxConcurrentTasks: 5,
    maxMemoryUsageBytes: 1_000_000_000,
    maxExecutionTimeMs: 600_000,
  };
}

function makeMetrics(): AgentMetrics {
  return {
    tasksCompleted: 10,
    tasksFailed: 1,
    averageExecutionTimeMs: 5_000,
    successRate: 0.91,
    cpuUsage: 0.45,
    memoryUsageBytes: 512_000_000,
    messagesProcessed: 200,
    lastActivityAt: Date.now(),
    responseTimeMs: 120,
    health: 0.95,
  };
}

function makeQuality(): AgentQualityScores {
  return { reliability: 0.95, speed: 0.8, quality: 0.9 };
}

function makeAgentSession(): AgentSession {
  return {
    id: "agt_01HXK8M3N2ABCDEFGHJKMNPQRS",
    name: "Test Agent",
    role: "coder",
    status: "running",
    capabilities: makeCapabilities(),
    metrics: makeMetrics(),
    quality: makeQuality(),
    currentTaskId: null,
    workload: 0.5,
    health: 0.95,
    lastHeartbeatAt: Date.now(),
    topologyRole: null,
    connections: [],
    worktreePath: null,
    branch: null,
    risk: "low",
    policyMode: "strict",
    agentModel: "claude-3.5-sonnet",
    receiptCount: 5,
    blockedActionCount: 0,
    changedFilesCount: 3,
    filesTouched: ["src/main.ts", "src/types.ts", "src/index.ts"],
    toolBoundaryEvents: 12,
    confidence: 85,
    guardResults: [{ guard: "ForbiddenPathGuard", allowed: true, durationMs: 2 }],
    receipt: null,
    sentinelId: null,
    createdAt: Date.now() - 60_000,
    updatedAt: Date.now(),
    exitCode: null,
  };
}

function makeTask(): Task {
  return {
    id: "tsk_01HXK8M3N2ABCDEFGHJKMNPQRS",
    swarmEngineId: "swe_01HXK8M3N2ABCDEFGHJKMNPQRS",
    type: "coding",
    name: "Implement auth module",
    description: "Add JWT authentication",
    priority: "high",
    status: "running",
    sequence: 1,
    assignedTo: "agt_01HXK8M3N2ABCDEFGHJKMNPQRS",
    dependencies: [],
    input: { spec: "auth.md" },
    output: null,
    timeoutMs: 300_000,
    retries: 0,
    maxRetries: 3,
    taskPrompt: "Implement the auth module",
    previewLines: ["const jwt = ..."],
    huntId: null,
    artifactIds: [],
    receipt: null,
    metadata: {},
    createdAt: Date.now() - 30_000,
    startedAt: Date.now() - 10_000,
    completedAt: null,
    updatedAt: Date.now(),
  };
}

// ============================================================================
// Tests
// ============================================================================

describe("generateSwarmId", () => {
  it("produces correctly formatted ULID for agt prefix", () => {
    const id = generateSwarmId("agt");
    expect(id).toMatch(/^agt_[0-9A-HJKMNP-TV-Z]{26}$/);
  });

  it("produces correctly formatted ULID for all 7 prefixes", () => {
    const prefixes: SwarmEngineIdPrefix[] = ["agt", "tsk", "swe", "top", "csn", "msg", "rct"];
    for (const prefix of prefixes) {
      const id = generateSwarmId(prefix);
      expect(id).toMatch(CROCKFORD_RE);
      expect(id.startsWith(`${prefix}_`)).toBe(true);
      expect(id.length).toBe(prefix.length + 1 + 26); // prefix + underscore + 26 ULID chars
    }
  });

  it("generates 100 unique IDs", () => {
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) {
      ids.add(generateSwarmId("agt"));
    }
    expect(ids.size).toBe(100);
  });

  it("generates monotonically non-decreasing timestamp component", () => {
    const ids: string[] = [];
    for (let i = 0; i < 10; i++) {
      ids.push(generateSwarmId("msg"));
    }
    // The timestamp component is the first 10 characters after the prefix+underscore
    for (let i = 1; i < ids.length; i++) {
      const ts1 = ids[i - 1]!.slice(4, 14); // skip "msg_"
      const ts2 = ids[i]!.slice(4, 14);
      expect(ts2 >= ts1).toBe(true);
    }
  });
});

describe("type guards", () => {
  it("isAgentSession returns true for valid AgentSession", () => {
    const session = makeAgentSession();
    expect(isAgentSession(session)).toBe(true);
  });

  it("isAgentSession returns false for plain object", () => {
    expect(isAgentSession({ foo: "bar" })).toBe(false);
  });

  it("isAgentSession returns false for null", () => {
    expect(isAgentSession(null)).toBe(false);
  });

  it("isAgentSession returns false for undefined", () => {
    expect(isAgentSession(undefined)).toBe(false);
  });

  it("isAgentSession returns false for object with tsk_ prefix", () => {
    const task = makeTask();
    expect(isAgentSession(task)).toBe(false);
  });

  it("isTask returns true for valid Task", () => {
    const task = makeTask();
    expect(isTask(task)).toBe(true);
  });

  it("isTask returns false for AgentSession", () => {
    const session = makeAgentSession();
    expect(isTask(session)).toBe(false);
  });

  it("isSwarmEngineEvent returns true for event-shaped object", () => {
    expect(
      isSwarmEngineEvent({
        kind: "agent.spawned",
        timestamp: Date.now(),
        sourceAgentId: null,
      }),
    ).toBe(true);
  });

  it("isSwarmEngineEvent returns false for non-event", () => {
    expect(isSwarmEngineEvent({ action: "spawn" })).toBe(false);
  });

  it("isSwarmEngineEnvelope returns true for envelope-shaped object", () => {
    expect(
      isSwarmEngineEnvelope({
        version: 1,
        type: "agent_lifecycle",
        payload: { kind: "agent.spawned" },
        ttl: 5,
        created: Date.now(),
      }),
    ).toBe(true);
  });

  it("isSwarmEngineEnvelope returns false for wrong version", () => {
    expect(
      isSwarmEngineEnvelope({
        version: 2,
        type: "agent_lifecycle",
        payload: {},
        ttl: 5,
        created: Date.now(),
      }),
    ).toBe(false);
  });
});

describe("GuardedPayload", () => {
  it("accepts valid GuardedPayload shape", () => {
    const payload: GuardedPayload = {
      action: "agent.spawn",
      sender: "agt_01HXK8M3N2ABCDEFGHJKMNPQRS",
    };
    expect(payload.action).toBe("agent.spawn");
    expect(payload.sender).toContain("agt_");
    expect(payload.receipt).toBeUndefined();
  });

  it("accepts GuardedPayload with optional fields", () => {
    const payload: GuardedPayload = {
      action: "task.create",
      sender: "agt_01HXK8M3N2ABCDEFGHJKMNPQRS",
      correlationId: "trace-123",
      receipt: {
        receiptId: "r_001",
        verdict: "allow",
        decidingGuard: "ForbiddenPathGuard",
        policyHash: "abc123",
        evaluationMs: 5,
        signature: "deadbeef",
        publicKey: "cafebabe",
        evaluatedAt: Date.now(),
      },
    };
    expect(payload.receipt).toBeDefined();
    expect(payload.correlationId).toBe("trace-123");
  });
});

describe("EnvelopeReceipt", () => {
  it("accepts valid EnvelopeReceipt shape with all 8 required fields", () => {
    const receipt: EnvelopeReceipt = {
      receiptId: "r_001",
      verdict: "allow",
      decidingGuard: "ForbiddenPathGuard",
      policyHash: "sha256:abc123def456",
      evaluationMs: 3,
      signature: "deadbeef0123456789",
      publicKey: "cafebabe0123456789",
      evaluatedAt: Date.now(),
    };
    expect(receipt.receiptId).toBe("r_001");
    expect(receipt.verdict).toBe("allow");
    expect(receipt.decidingGuard).toBe("ForbiddenPathGuard");
    expect(receipt.policyHash).toContain("sha256:");
    expect(receipt.evaluationMs).toBe(3);
    expect(typeof receipt.signature).toBe("string");
    expect(typeof receipt.publicKey).toBe("string");
    expect(typeof receipt.evaluatedAt).toBe("number");
  });

  it("supports all three Verdict values", () => {
    const verdicts: Verdict[] = ["allow", "deny", "warn"];
    for (const v of verdicts) {
      const receipt: EnvelopeReceipt = {
        receiptId: `r_${v}`,
        verdict: v,
        decidingGuard: "TestGuard",
        policyHash: "hash",
        evaluationMs: 1,
        signature: "sig",
        publicKey: "pub",
        evaluatedAt: Date.now(),
      };
      expect(receipt.verdict).toBe(v);
    }
  });
});

describe("SWARM_ENGINE_CONSTANTS", () => {
  it("has correct DEFAULT_HEARTBEAT_INTERVAL_MS", () => {
    expect(SWARM_ENGINE_CONSTANTS.DEFAULT_HEARTBEAT_INTERVAL_MS).toBe(5_000);
  });

  it("has correct DEFAULT_MAX_AGENTS", () => {
    expect(SWARM_ENGINE_CONSTANTS.DEFAULT_MAX_AGENTS).toBe(100);
  });

  it("has correct HEALTH_FAILOVER_THRESHOLD", () => {
    expect(SWARM_ENGINE_CONSTANTS.HEALTH_FAILOVER_THRESHOLD).toBe(0.3);
  });

  it("has correct DEFAULT_TASK_TIMEOUT_MS", () => {
    expect(SWARM_ENGINE_CONSTANTS.DEFAULT_TASK_TIMEOUT_MS).toBe(300_000);
  });

  it("has correct DEFAULT_CONSENSUS_THRESHOLD", () => {
    expect(SWARM_ENGINE_CONSTANTS.DEFAULT_CONSENSUS_THRESHOLD).toBe(0.66);
  });

  it("is immutable (Object.freeze at runtime)", () => {
    expect(Object.isFrozen(SWARM_ENGINE_CONSTANTS)).toBe(true);
    expect(SWARM_ENGINE_CONSTANTS.MAX_RETRIES).toBe(3);
  });
});

describe("serialization", () => {
  it("AgentSession roundtrips through JSON without data loss", () => {
    const session = makeAgentSession();
    const json = JSON.stringify(session);
    const parsed = JSON.parse(json) as AgentSession;

    expect(parsed.id).toBe(session.id);
    expect(parsed.name).toBe(session.name);
    expect(parsed.role).toBe(session.role);
    expect(parsed.status).toBe(session.status);
    expect(typeof parsed.createdAt).toBe("number");
    expect(typeof parsed.updatedAt).toBe("number");
    expect(typeof parsed.lastHeartbeatAt).toBe("number");
  });

  it("AgentSession has no Map or Date values", () => {
    const session = makeAgentSession();

    // Verify all timestamp fields are numbers
    expect(typeof session.createdAt).toBe("number");
    expect(typeof session.updatedAt).toBe("number");
    expect(typeof session.lastHeartbeatAt).toBe("number");
    expect(typeof session.metrics.lastActivityAt).toBe("number");

    // Verify agents record would be a plain object
    // (AgentSession itself is a single agent; SwarmEngineState.agents is Record<string, AgentSession>)
    const json = JSON.stringify(session);
    expect(json).not.toContain("[object Map]");
    expect(json).not.toContain("[object Date]");
  });

  it("Task roundtrips through JSON without data loss", () => {
    const task = makeTask();
    const json = JSON.stringify(task);
    const parsed = JSON.parse(json) as Task;

    expect(parsed.id).toBe(task.id);
    expect(parsed.type).toBe(task.type);
    expect(parsed.status).toBe(task.status);
    expect(typeof parsed.createdAt).toBe("number");
    expect(typeof parsed.startedAt).toBe("number");
    expect(parsed.completedAt).toBeNull();
  });
});
