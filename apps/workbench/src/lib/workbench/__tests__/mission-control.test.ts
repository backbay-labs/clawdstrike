import { describe, expect, it } from "vitest";
import {
  assessMissionLaunch,
  advanceMission,
  createMission,
  executeMissionDriver,
  startMission,
} from "../mission-control";
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

describe("mission-control", () => {
  it("creates a Claude mission draft with driver-specific stages", () => {
    const sentinel = makeSentinel("claude_code");
    const mission = createMission({
      title: "Repo triage",
      objective: "Inspect the repo for a high-confidence fix path.",
      priority: "high",
      sentinel,
    });

    expect(mission.driver).toBe("claude_code");
    expect(mission.status).toBe("draft");
    expect(mission.launchState).toBeNull();
    expect(mission.stages.map((stage) => stage.label)).toEqual([
      "Intake",
      "Repo Recon",
      "Verification",
      "Finding Promotion",
    ]);
  });

  it("blocks Claude missions when the MCP bridge is offline", () => {
    const sentinel = makeSentinel("claude_code");
    const mission = createMission({
      title: "Repo triage",
      objective: "Inspect the repo for a high-confidence fix path.",
      priority: "high",
      sentinel,
    });

    const launch = assessMissionLaunch(sentinel, {
      claude: { mcpStatus: { running: false, error: "sidecar unavailable" } },
    });
    const execution = executeMissionDriver(mission, sentinel, {
      claude: { mcpStatus: { running: false, error: "sidecar unavailable" } },
    });
    const started = startMission(mission, execution);

    expect(launch.launchState).toBe("blocked");
    expect(execution.signals).toHaveLength(0);
    expect(started.status).toBe("blocked");
    expect(started.stages[0]?.status).toBe("blocked");
  });

  it("executes driver-specific runtime bundles and promotes the first stage to active", () => {
    const sentinel = makeSentinel("openclaw");
    const mission = createMission({
      title: "Phishing triage",
      objective: "Walk the suspicious login flow and capture evidence.",
      priority: "critical",
      sentinel,
    });

    const execution = executeMissionDriver(mission, sentinel, {
      openclaw: {
        connected: true,
        hushdUrl: "https://fleet.example",
        agentCount: 2,
      },
    });
    const started = startMission(mission, execution);
    const advanced = advanceMission(started);

    expect(execution.signals).toHaveLength(3);
    expect(execution.evidence.length).toBeGreaterThanOrEqual(4);
    expect(execution.launchState).toBe("ready");
    expect(started.status).toBe("active");
    expect(started.stages[0]?.status).toBe("completed");
    expect(started.stages[1]?.status).toBe("in_progress");
    expect(advanced.stages[1]?.status).toBe("completed");
    expect(advanced.stages[2]?.status).toBe("in_progress");
  });
});
