import { describe, it, expect } from "vitest";
import { PRE_BUILT_SCENARIOS } from "../pre-built-scenarios";
import type { TestActionType, Verdict, ThreatSeverity } from "../types";

// ---------------------------------------------------------------------------
// Tests for PRE_BUILT_SCENARIOS — the curated set of probe scenarios
// ---------------------------------------------------------------------------

const VALID_ACTION_TYPES: TestActionType[] = [
  "file_access",
  "file_write",
  "network_egress",
  "shell_command",
  "mcp_tool_call",
  "patch_apply",
  "user_input",
];

const VALID_VERDICTS: Verdict[] = ["allow", "deny", "warn"];
const VALID_SEVERITIES: ThreatSeverity[] = ["critical", "high", "medium", "low"];

describe("PRE_BUILT_SCENARIOS", () => {
  it("has at least 15 scenarios", () => {
    expect(PRE_BUILT_SCENARIOS.length).toBeGreaterThanOrEqual(15);
  });

  it("has no duplicate IDs", () => {
    const ids = PRE_BUILT_SCENARIOS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("all scenarios have required fields", () => {
    for (const s of PRE_BUILT_SCENARIOS) {
      expect(s.id).toBeTruthy();
      expect(s.name).toBeTruthy();
      expect(s.description).toBeTruthy();
      expect(s.category).toBeTruthy();
      expect(s.actionType).toBeTruthy();
      expect(s.payload).toBeDefined();
    }
  });

  it("all scenarios have valid action types", () => {
    for (const s of PRE_BUILT_SCENARIOS) {
      expect(VALID_ACTION_TYPES).toContain(s.actionType);
    }
  });

  it("all scenarios have valid expected verdicts", () => {
    for (const s of PRE_BUILT_SCENARIOS) {
      if (s.expectedVerdict !== undefined) {
        expect(VALID_VERDICTS).toContain(s.expectedVerdict);
      }
    }
  });

  it("all scenarios have valid category", () => {
    for (const s of PRE_BUILT_SCENARIOS) {
      expect(["attack", "benign", "edge_case"]).toContain(s.category);
    }
  });

  it("all scenarios with severity have valid severity", () => {
    for (const s of PRE_BUILT_SCENARIOS) {
      if (s.severity !== undefined) {
        expect(VALID_SEVERITIES).toContain(s.severity);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Category distribution
// ---------------------------------------------------------------------------

describe("scenario category distribution", () => {
  it("has attack scenarios", () => {
    const attacks = PRE_BUILT_SCENARIOS.filter((s) => s.category === "attack");
    expect(attacks.length).toBeGreaterThanOrEqual(5);
  });

  it("has benign scenarios", () => {
    const benign = PRE_BUILT_SCENARIOS.filter((s) => s.category === "benign");
    expect(benign.length).toBeGreaterThanOrEqual(3);
  });

  it("has edge case scenarios", () => {
    const edge = PRE_BUILT_SCENARIOS.filter((s) => s.category === "edge_case");
    expect(edge.length).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// Action type coverage
// ---------------------------------------------------------------------------

describe("action type coverage", () => {
  it("includes file_access scenarios", () => {
    expect(PRE_BUILT_SCENARIOS.some((s) => s.actionType === "file_access")).toBe(true);
  });

  it("includes file_write scenarios", () => {
    expect(PRE_BUILT_SCENARIOS.some((s) => s.actionType === "file_write")).toBe(true);
  });

  it("includes network_egress scenarios", () => {
    expect(PRE_BUILT_SCENARIOS.some((s) => s.actionType === "network_egress")).toBe(true);
  });

  it("includes shell_command scenarios", () => {
    expect(PRE_BUILT_SCENARIOS.some((s) => s.actionType === "shell_command")).toBe(true);
  });

  it("includes mcp_tool_call scenarios", () => {
    expect(PRE_BUILT_SCENARIOS.some((s) => s.actionType === "mcp_tool_call")).toBe(true);
  });

  it("includes user_input scenarios", () => {
    expect(PRE_BUILT_SCENARIOS.some((s) => s.actionType === "user_input")).toBe(true);
  });

  it("includes patch_apply scenarios", () => {
    expect(PRE_BUILT_SCENARIOS.some((s) => s.actionType === "patch_apply")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Payload validation per action type
// ---------------------------------------------------------------------------

describe("payload structure by action type", () => {
  it("file_access scenarios have a path in payload", () => {
    const scenarios = PRE_BUILT_SCENARIOS.filter((s) => s.actionType === "file_access");
    for (const s of scenarios) {
      expect(s.payload).toHaveProperty("path");
      expect(typeof s.payload.path).toBe("string");
    }
  });

  it("file_write scenarios have path and content in payload", () => {
    const scenarios = PRE_BUILT_SCENARIOS.filter((s) => s.actionType === "file_write");
    for (const s of scenarios) {
      expect(s.payload).toHaveProperty("path");
      expect(s.payload).toHaveProperty("content");
    }
  });

  it("network_egress scenarios have host in payload", () => {
    const scenarios = PRE_BUILT_SCENARIOS.filter((s) => s.actionType === "network_egress");
    for (const s of scenarios) {
      expect(s.payload).toHaveProperty("host");
      expect(typeof s.payload.host).toBe("string");
    }
  });

  it("shell_command scenarios have command in payload", () => {
    const scenarios = PRE_BUILT_SCENARIOS.filter((s) => s.actionType === "shell_command");
    for (const s of scenarios) {
      expect(s.payload).toHaveProperty("command");
      expect(typeof s.payload.command).toBe("string");
    }
  });

  it("mcp_tool_call scenarios have tool in payload", () => {
    const scenarios = PRE_BUILT_SCENARIOS.filter((s) => s.actionType === "mcp_tool_call");
    for (const s of scenarios) {
      expect(s.payload).toHaveProperty("tool");
      expect(typeof s.payload.tool).toBe("string");
    }
  });

  it("user_input scenarios have text in payload", () => {
    const scenarios = PRE_BUILT_SCENARIOS.filter((s) => s.actionType === "user_input");
    for (const s of scenarios) {
      expect(s.payload).toHaveProperty("text");
      expect(typeof s.payload.text).toBe("string");
    }
  });

  it("patch_apply scenarios have path and content in payload", () => {
    const scenarios = PRE_BUILT_SCENARIOS.filter((s) => s.actionType === "patch_apply");
    for (const s of scenarios) {
      expect(s.payload).toHaveProperty("path");
      expect(s.payload).toHaveProperty("content");
    }
  });
});

// ---------------------------------------------------------------------------
// Specific scenario smoke checks
// ---------------------------------------------------------------------------

describe("specific scenario integrity", () => {
  it("SSH key exfiltration scenario targets .ssh path", () => {
    const s = PRE_BUILT_SCENARIOS.find((s) => s.id === "attack-ssh-key")!;
    expect(s.actionType).toBe("file_access");
    expect(String(s.payload.path)).toContain(".ssh");
    expect(s.expectedVerdict).toBe("deny");
    expect(s.severity).toBe("critical");
  });

  it("reverse shell scenario uses shell_command", () => {
    const s = PRE_BUILT_SCENARIOS.find((s) => s.id === "attack-reverse-shell")!;
    expect(s.actionType).toBe("shell_command");
    expect(s.expectedVerdict).toBe("deny");
  });

  it("benign source read has allow verdict", () => {
    const s = PRE_BUILT_SCENARIOS.find((s) => s.id === "benign-read-source")!;
    expect(s.expectedVerdict).toBe("allow");
    expect(s.category).toBe("benign");
  });

  it("prompt injection scenario uses user_input", () => {
    const s = PRE_BUILT_SCENARIOS.find((s) => s.id === "attack-prompt-injection")!;
    expect(s.actionType).toBe("user_input");
    expect(s.expectedVerdict).toBe("deny");
  });
});
