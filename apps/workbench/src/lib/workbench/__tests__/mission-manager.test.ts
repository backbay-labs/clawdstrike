import { describe, expect, it } from "vitest";
import { createMission, executeMission } from "../mission-manager";
import type { Sentinel } from "../sentinel-types";

function makeSentinel(driver: Sentinel["runtime"]["driver"]): Sentinel {
  return {
    id: "sen_test",
    name: driver === "claude_code" ? "Scribe" : "Prowl",
    mode: driver === "claude_code" ? "curator" : "hunter",
    owner: "workbench-user",
    identity: {
      publicKey: "a".repeat(64),
      fingerprint: "b".repeat(16),
      sigil: "diamond",
      nickname: "test",
    },
    policy: { ruleset: "default" },
    goals: [],
    memory: {
      knownPatterns: [],
      baselineProfiles: [],
      falsePositiveHashes: [],
      lastUpdated: Date.now(),
    },
    schedule: null,
    status: "paused",
    swarms: [],
    runtime: {
      driver,
      executionMode: driver === "claude_code" ? "assist" : "enforce",
      enforcementTier: driver === "claude_code" ? 1 : 2,
      endpointType: driver === "claude_code" ? "local" : "gateway",
      targetRef: driver === "claude_code" ? "/workspace" : "gateway://node-1",
      runtimeRef: null,
      sessionRef: null,
      health: "planned",
      receiptsEnabled: true,
      emitsSignals: true,
      lastHeartbeatAt: null,
    },
    stats: {
      signalsGenerated: 0,
      findingsCreated: 0,
      intelProduced: 0,
      falsePositivesSuppressed: 0,
      swarmIntelConsumed: 0,
      uptimeMs: 0,
      lastActiveAt: Date.now(),
    },
    fleetAgentId: null,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
}

describe("mission-manager", () => {
  it("does not accept transient target overrides in the compatibility facade", () => {
    const sentinel = makeSentinel("claude_code");

    createMission({
      sentinel,
      templateId: "claude_repo_triage",
      objective: "Inspect the repo for a fix path.",
      priority: "high",
      // @ts-expect-error targetRef is not supported because Mission does not persist execution targets
      targetRef: "/tmp/override",
    });

    expect(sentinel.runtime.targetRef).toBe("/workspace");
  });

  it("forwards launch context when executing Claude missions", () => {
    const sentinel = makeSentinel("claude_code");
    const mission = createMission({
      sentinel,
      templateId: "claude_repo_triage",
      objective: "Inspect the repo for a fix path.",
      priority: "high",
    });

    const result = executeMission(mission, sentinel, {
      claude: {
        mcpStatus: {
          running: true,
          url: "embedded-mcp",
        },
      },
    });

    expect(result.mission.status).toBe("active");
    expect(result.mission.launchState).toBe("ready");
    expect(result.mission.launchSummary).toContain("embedded-mcp");
    expect(result.runtimePatch.runtime?.health).toBe("ready");
    expect(result.signals.length).toBeGreaterThan(0);
  });
});
