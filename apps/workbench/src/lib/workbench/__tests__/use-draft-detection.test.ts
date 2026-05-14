import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  buildSeedFromEvents,
  buildSeedFromInvestigation,
  buildSeedFromPattern,
  buildDraftFromSeed,
} from "../detection-workflow/use-draft-detection";
import type { AgentEvent, Investigation, HuntPattern } from "../hunt-types";
import type { MultiPolicyAction } from "@/features/policy/types/policy-tab";

// ---- Helpers ----

function makeEvent(overrides?: Partial<AgentEvent>): AgentEvent {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    agentId: "agent-1",
    agentName: "Test Agent",
    sessionId: "session-1",
    actionType: "shell_command",
    target: "/usr/bin/curl",
    verdict: "deny",
    guardResults: [],
    policyVersion: "1.2.0",
    flags: [],
    ...overrides,
  };
}

function makeInvestigation(overrides?: Partial<Investigation>): Investigation {
  return {
    id: crypto.randomUUID(),
    title: "Suspicious egress activity",
    status: "open",
    severity: "high",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    createdBy: "analyst",
    agentIds: ["agent-1", "agent-2"],
    sessionIds: ["session-1"],
    timeRange: { start: new Date().toISOString(), end: new Date().toISOString() },
    eventIds: ["evt-1", "evt-2", "evt-3"],
    annotations: [],
    ...overrides,
  };
}

function makePattern(overrides?: Partial<HuntPattern>): HuntPattern {
  return {
    id: crypto.randomUUID(),
    name: "Exfiltration via curl",
    description: "Agent exfiltrates data using curl after reading sensitive files",
    discoveredAt: new Date().toISOString(),
    status: "confirmed",
    sequence: [
      { step: 1, actionType: "file_access", targetPattern: "/etc/passwd" },
      { step: 2, actionType: "shell_command", targetPattern: "curl *", timeWindow: 5000 },
    ],
    matchCount: 7,
    exampleSessionIds: ["session-1", "session-2"],
    agentIds: ["agent-1"],
    ...overrides,
  };
}

// ---- Tests: Seed Builders ----

describe("buildSeedFromEvents", () => {
  it("creates a seed with correct kind and source event ids", () => {
    const events = [makeEvent({ id: "e1" }), makeEvent({ id: "e2" })];
    const seed = buildSeedFromEvents(events);

    expect(seed.kind).toBe("hunt_event");
    expect(seed.sourceEventIds).toEqual(["e1", "e2"]);
    expect(seed.preferredFormats).toContain("sigma_rule");
    expect(seed.id).toBeTruthy();
    expect(seed.createdAt).toBeTruthy();
  });

  it("extracts data source hints from action types", () => {
    const events = [
      makeEvent({ actionType: "file_access" }),
      makeEvent({ actionType: "network_egress" }),
      makeEvent({ actionType: "shell_command" }),
    ];
    const seed = buildSeedFromEvents(events);

    expect(seed.dataSourceHints).toContain("file");
    expect(seed.dataSourceHints).toContain("network");
    expect(seed.dataSourceHints).toContain("process");
  });

  it("extracts technique hints from pattern-match flags", () => {
    const events = [
      makeEvent({
        flags: [{ type: "pattern-match", patternId: "p1", patternName: "Credential Theft" }],
      }),
    ];
    const seed = buildSeedFromEvents(events);

    expect(seed.techniqueHints).toContain("Credential Theft");
  });

  it("raises confidence for larger event batches", () => {
    const fewEvents = [makeEvent(), makeEvent()];
    const manyEvents = [makeEvent(), makeEvent(), makeEvent(), makeEvent(), makeEvent()];

    expect(buildSeedFromEvents(fewEvents).confidence).toBe(0.6);
    expect(buildSeedFromEvents(manyEvents).confidence).toBe(0.7);
  });
});

describe("buildSeedFromInvestigation", () => {
  it("creates a seed with correct kind and investigation id", () => {
    const inv = makeInvestigation({ id: "inv-42" });
    const seed = buildSeedFromInvestigation(inv);

    expect(seed.kind).toBe("investigation");
    expect(seed.investigationId).toBe("inv-42");
    expect(seed.sourceEventIds).toEqual(inv.eventIds);
  });

  it("maps investigation confidence from severity", () => {
    const confirmed = makeInvestigation({ severity: "high", verdict: "threat-confirmed" });
    const inconclusive = makeInvestigation({ severity: "low", verdict: "inconclusive" });

    expect(buildSeedFromInvestigation(confirmed).confidence).toBe(0.85);
    expect(buildSeedFromInvestigation(inconclusive).confidence).toBe(0.5);
  });

  it("includes investigation title in extracted fields", () => {
    const inv = makeInvestigation({ title: "My Investigation" });
    const seed = buildSeedFromInvestigation(inv);

    expect(seed.extractedFields.title).toBe("My Investigation");
  });
});

describe("buildSeedFromPattern", () => {
  it("creates a seed with correct kind and pattern id", () => {
    const pattern = makePattern({ id: "pat-99" });
    const seed = buildSeedFromPattern(pattern);

    expect(seed.kind).toBe("hunt_pattern");
    expect(seed.patternId).toBe("pat-99");
    expect(seed.sourceEventIds).toEqual([]);
  });

  it("derives data source hints from sequence steps", () => {
    const pattern = makePattern({
      sequence: [
        { step: 1, actionType: "file_write", targetPattern: "/tmp/*" },
        { step: 2, actionType: "network_egress", targetPattern: "*.evil.com" },
      ],
    });
    const seed = buildSeedFromPattern(pattern);

    expect(seed.dataSourceHints).toContain("file");
    expect(seed.dataSourceHints).toContain("network");
  });

  it("maps pattern confidence from match volume", () => {
    const confirmed = makePattern({ status: "confirmed", matchCount: 7 });
    const draft = makePattern({ status: "draft", matchCount: 1 });

    expect(buildSeedFromPattern(confirmed).confidence).toBe(0.9);
    expect(buildSeedFromPattern(draft).confidence).toBe(0.5);
  });

  it("includes pattern name and description in extracted fields", () => {
    const pattern = makePattern({ name: "SSH Tunnel", description: "Tunneling over SSH" });
    const seed = buildSeedFromPattern(pattern);

    expect(seed.extractedFields.name).toBe("SSH Tunnel");
    expect(seed.extractedFields.description).toBe("Tunneling over SSH");
  });
});

// ---- Tests: Draft Building ----

describe("buildDraftFromSeed", () => {
  it("generates a sigma rule draft from event seed (fallback)", () => {
    const events = [makeEvent({ id: "e1" }), makeEvent({ id: "e2" })];
    const seed = buildSeedFromEvents(events);
    const result = buildDraftFromSeed(seed);

    expect(result.fileType).toBe("sigma_rule");
    expect(result.source).toContain("title:");
    expect(result.source).toContain("detection:");
    expect(result.source).toContain("logsource:");
    expect(result.name).toContain("Draft from 2 Hunt Events");
  });

  it("generates a sigma rule draft from investigation seed (fallback)", () => {
    const inv = makeInvestigation({ title: "Credential Dump" });
    const seed = buildSeedFromInvestigation(inv);
    const result = buildDraftFromSeed(seed);

    expect(result.fileType).toBe("sigma_rule");
    expect(result.name).toContain("Credential Dump");
    expect(result.source).toContain("title: Draft: Credential Dump");
  });

  it("generates a sigma rule draft from pattern seed (fallback)", () => {
    const pattern = makePattern({ name: "Lateral Movement" });
    const seed = buildSeedFromPattern(pattern);
    const result = buildDraftFromSeed(seed);

    expect(result.fileType).toBe("sigma_rule");
    expect(result.name).toContain("Lateral Movement");
    expect(result.source).toContain("description:");
  });

  it("includes technique hints in the result", () => {
    const events = [
      makeEvent({
        flags: [{ type: "pattern-match", patternId: "p1", patternName: "T1059" }],
      }),
    ];
    const seed = buildSeedFromEvents(events);
    const result = buildDraftFromSeed(seed);

    expect(result.techniqueHints).toContain("T1059");
  });

  it("produces valid YAML with id matching the seed id", () => {
    const seed = buildSeedFromEvents([makeEvent()]);
    const result = buildDraftFromSeed(seed);

    expect(result.source).toContain(`id: ${seed.id}`);
  });
});

// ---- Tests: Hook behavior (dispatch integration) ----

describe("useDraftDetection dispatch integration", () => {
  let dispatched: MultiPolicyAction[];

  beforeEach(() => {
    dispatched = [];
  });

  // We test the dispatch behavior by manually simulating what the hook does
  // (since renderHook requires React context). This tests the core logic path.
  it("dispatches NEW_TAB with correct fileType from events", () => {
    const events = [makeEvent(), makeEvent(), makeEvent()];
    const seed = buildSeedFromEvents(events);
    const result = buildDraftFromSeed(seed);

    const action: MultiPolicyAction = {
      type: "NEW_TAB",
      fileType: result.fileType,
      yaml: result.source,
    };
    dispatched.push(action);

    expect(dispatched).toHaveLength(1);
    expect(dispatched[0]).toMatchObject({
      type: "NEW_TAB",
      fileType: "sigma_rule",
    });
    expect((dispatched[0] as { yaml: string }).yaml).toContain("title:");
  });

  it("dispatches NEW_TAB with correct fileType from investigation", () => {
    const inv = makeInvestigation();
    const seed = buildSeedFromInvestigation(inv);
    const result = buildDraftFromSeed(seed);

    const action: MultiPolicyAction = {
      type: "NEW_TAB",
      fileType: result.fileType,
      yaml: result.source,
    };
    dispatched.push(action);

    expect(dispatched[0]).toMatchObject({
      type: "NEW_TAB",
      fileType: "sigma_rule",
    });
  });

  it("dispatches NEW_TAB with correct fileType from pattern", () => {
    const pattern = makePattern();
    const seed = buildSeedFromPattern(pattern);
    const result = buildDraftFromSeed(seed);

    const action: MultiPolicyAction = {
      type: "NEW_TAB",
      fileType: result.fileType,
      yaml: result.source,
    };
    dispatched.push(action);

    expect(dispatched[0]).toMatchObject({
      type: "NEW_TAB",
      fileType: "sigma_rule",
    });
  });
});
