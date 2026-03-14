import { describe, expect, it } from "vitest";
import {
  createDefaultRuntimeBinding,
  deriveEnforcementTier,
  getRecommendedDriverForMode,
  getRecommendedGoalTypeForMode,
  updateSentinel,
} from "../sentinel-manager";
import type { Sentinel } from "../sentinel-types";

function makeSentinel(mode: Sentinel["mode"] = "watcher"): Sentinel {
  return {
    id: "sen_test",
    name: "Test Sentinel",
    mode,
    owner: "workbench-user",
    identity: {
      publicKey: "a".repeat(64),
      fingerprint: "b".repeat(16),
      sigil: "diamond",
      nickname: "test-sentinel",
    },
    policy: {
      ruleset: "default",
    },
    goals: [],
    memory: {
      knownPatterns: [],
      baselineProfiles: [],
      falsePositiveHashes: [],
      lastUpdated: 1,
    },
    schedule: null,
    status: "paused",
    swarms: [],
    runtime: createDefaultRuntimeBinding(mode),
    stats: {
      signalsGenerated: 0,
      findingsCreated: 0,
      intelProduced: 0,
      falsePositivesSuppressed: 0,
      swarmIntelConsumed: 0,
      uptimeMs: 0,
      lastActiveAt: 1,
    },
    fleetAgentId: null,
    createdAt: 1,
    updatedAt: 1,
  };
}

describe("getRecommendedDriverForMode", () => {
  it("maps modes to the expected default drivers", () => {
    expect(getRecommendedDriverForMode("watcher")).toBe("hushd_agent");
    expect(getRecommendedDriverForMode("hunter")).toBe("openclaw");
    expect(getRecommendedDriverForMode("curator")).toBe("claude_code");
    expect(getRecommendedDriverForMode("liaison")).toBe("mcp_worker");
  });
});

describe("getRecommendedGoalTypeForMode", () => {
  it("returns mode-compatible default goal types", () => {
    expect(getRecommendedGoalTypeForMode("watcher")).toBe("detect");
    expect(getRecommendedGoalTypeForMode("hunter")).toBe("hunt");
    expect(getRecommendedGoalTypeForMode("curator")).toBe("enrich");
    expect(getRecommendedGoalTypeForMode("liaison")).toBe("enrich");
  });
});

describe("deriveEnforcementTier", () => {
  it("returns tier 0 for observe and tier 1 for assist", () => {
    expect(deriveEnforcementTier("claude_code", "observe")).toBe(0);
    expect(deriveEnforcementTier("openclaw", "assist")).toBe(1);
  });

  it("uses the driver ceiling for enforce mode", () => {
    expect(deriveEnforcementTier("claude_code", "enforce")).toBe(1);
    expect(deriveEnforcementTier("openclaw", "enforce")).toBe(2);
    expect(deriveEnforcementTier("mcp_worker", "enforce")).toBe(2);
  });
});

describe("createDefaultRuntimeBinding", () => {
  it("creates mode-aware defaults and carries fleet targets into the binding", () => {
    const watcherBinding = createDefaultRuntimeBinding("watcher", undefined, "agent-01");
    const hunterBinding = createDefaultRuntimeBinding("hunter");

    expect(watcherBinding).toMatchObject({
      driver: "hushd_agent",
      executionMode: "assist",
      enforcementTier: 1,
      endpointType: "fleet",
      targetRef: "agent-01",
      health: "planned",
      receiptsEnabled: true,
      emitsSignals: true,
    });
    expect(hunterBinding).toMatchObject({
      driver: "openclaw",
      executionMode: "enforce",
      enforcementTier: 2,
      endpointType: "gateway",
    });
  });
});

describe("updateSentinel", () => {
  it("re-normalizes runtime metadata when runtime fields change", () => {
    const sentinel = makeSentinel("hunter");

    const updated = updateSentinel(sentinel, {
      runtime: {
        driver: "claude_code",
        executionMode: "enforce",
      },
    });

    expect(updated.runtime).toMatchObject({
      driver: "claude_code",
      executionMode: "enforce",
      enforcementTier: 1,
      endpointType: "local",
    });
  });

  it("propagates fleet agent changes into runtime targeting", () => {
    const sentinel = makeSentinel("watcher");

    const updated = updateSentinel(sentinel, {
      fleetAgentId: "agent-02",
    });

    expect(updated.fleetAgentId).toBe("agent-02");
    expect(updated.runtime.targetRef).toBe("agent-02");
  });
});
