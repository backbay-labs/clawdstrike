import { describe, it, expect } from "vitest";
import {
  parseEventLog,
  synthesizePolicy,
  mergeSynthIntoPolicy,
  type ParsedEvent,
  type PolicyEvent,
} from "../observe-synth-engine";
import type { WorkbenchPolicy } from "../types";


function makePolicy(guards: WorkbenchPolicy["guards"]): WorkbenchPolicy {
  return {
    version: "1.2.0",
    name: "test",
    description: "",
    guards,
    settings: {},
  };
}

function jsonl(...events: object[]): string {
  return events.map((e) => JSON.stringify(e)).join("\n");
}

/** Create a minimal valid parsed event for synthesis. */
function makeParsedEvent(overrides: Partial<ParsedEvent> & Pick<PolicyEvent, "action_type" | "target">): ParsedEvent {
  const base: PolicyEvent = {
    action_type: overrides.action_type,
    target: overrides.target,
    content: overrides.content,
    verdict: overrides.verdict,
    guard: overrides.guard,
    timestamp: overrides.timestamp,
    details: overrides.details,
  };
  return {
    ...base,
    parsedTimestamp: new Date(),
    normalizedAction: null, // Will be set by caller or test
    riskLevel: "safe",
    lineIndex: 0,
    ...overrides,
  };
}


describe("parseEventLog with valid events", () => {
  it("parses a single valid JSONL line", () => {
    const input = jsonl({ action_type: "file_access", target: "/etc/passwd" });
    const [events, errors] = parseEventLog(input);
    expect(events).toHaveLength(1);
    expect(errors).toHaveLength(0);
    expect(events[0].action_type).toBe("file_access");
    expect(events[0].target).toBe("/etc/passwd");
  });

  it("parses multiple valid JSONL lines", () => {
    const input = jsonl(
      { action_type: "file_access", target: "/etc/passwd" },
      { action_type: "network_egress", target: "https://api.openai.com/v1/chat" },
      { action_type: "shell_command", target: "ls -la" },
    );
    const [events, errors] = parseEventLog(input);
    expect(events).toHaveLength(3);
    expect(errors).toHaveLength(0);
  });

  it("normalizes action types correctly", () => {
    const input = jsonl(
      { action_type: "file_read", target: "/app/data.json" },
      { action_type: "write_file", target: "/app/output.txt" },
      { action_type: "http", target: "https://example.com" },
      { action_type: "exec", target: "node server.js" },
      { action_type: "tool_call", target: "read_file" },
      { action_type: "patch", target: "/app/main.ts" },
      { action_type: "input", target: "hello" },
    );
    const [events] = parseEventLog(input);
    expect(events[0].normalizedAction).toBe("file_access");
    expect(events[1].normalizedAction).toBe("file_write");
    expect(events[2].normalizedAction).toBe("network_egress");
    expect(events[3].normalizedAction).toBe("shell_command");
    expect(events[4].normalizedAction).toBe("mcp_tool_call");
    expect(events[5].normalizedAction).toBe("patch_apply");
    expect(events[6].normalizedAction).toBe("user_input");
  });

  it("preserves optional fields", () => {
    const input = jsonl({
      action_type: "file_access",
      target: "/app/data.json",
      content: "some content",
      verdict: "allow",
      guard: "forbidden_path",
      timestamp: "2026-03-01T12:00:00Z",
      details: { reason: "test" },
    });
    const [events] = parseEventLog(input);
    expect(events[0].content).toBe("some content");
    expect(events[0].verdict).toBe("allow");
    expect(events[0].guard).toBe("forbidden_path");
    expect(events[0].timestamp).toBe("2026-03-01T12:00:00Z");
    expect(events[0].details).toEqual({ reason: "test" });
  });

  it("assigns parsedTimestamp from timestamp field", () => {
    const input = jsonl({
      action_type: "file_access",
      target: "/app/data.json",
      timestamp: "2026-03-01T12:00:00Z",
    });
    const [events] = parseEventLog(input);
    expect(events[0].parsedTimestamp).toEqual(new Date("2026-03-01T12:00:00Z"));
  });

  it("assigns lineIndex to each event", () => {
    const input = jsonl(
      { action_type: "file_access", target: "/a" },
      { action_type: "file_access", target: "/b" },
      { action_type: "file_access", target: "/c" },
    );
    const [events] = parseEventLog(input);
    expect(events[0].lineIndex).toBe(0);
    expect(events[1].lineIndex).toBe(1);
    expect(events[2].lineIndex).toBe(2);
  });
});


describe("parseEventLog with malformed lines", () => {
  it("skips invalid JSON lines and reports errors", () => {
    const input = [
      JSON.stringify({ action_type: "file_access", target: "/good" }),
      "this is not json",
      JSON.stringify({ action_type: "shell_command", target: "ls" }),
    ].join("\n");
    const [events, errors] = parseEventLog(input);
    expect(events).toHaveLength(2);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("Line 2");
    expect(errors[0]).toContain("invalid JSON");
  });

  it("skips lines missing required fields", () => {
    const input = jsonl(
      { action_type: "file_access" }, // missing target
      { target: "/app/data.json" }, // missing action_type
      { action_type: "file_access", target: "/valid" },
    );
    const [events, errors] = parseEventLog(input);
    expect(events).toHaveLength(1);
    expect(errors).toHaveLength(2);
    expect(errors[0]).toContain("missing required fields");
    expect(errors[1]).toContain("missing required fields");
  });

  it("handles empty input", () => {
    const [events, errors] = parseEventLog("");
    expect(events).toHaveLength(0);
    expect(errors).toHaveLength(0);
  });

  it("skips blank lines without reporting errors", () => {
    const input = `${JSON.stringify({ action_type: "file_access", target: "/a" })}\n\n\n${JSON.stringify({ action_type: "file_access", target: "/b" })}`;
    const [events, errors] = parseEventLog(input);
    expect(events).toHaveLength(2);
    expect(errors).toHaveLength(0);
  });

  it("returns null normalizedAction for unknown action types", () => {
    const input = jsonl({ action_type: "unknown_action", target: "foo" });
    const [events] = parseEventLog(input);
    expect(events[0].normalizedAction).toBeNull();
  });
});


describe("event risk classification", () => {
  it("classifies deny/blocked verdicts as 'blocked'", () => {
    const input = jsonl(
      { action_type: "file_access", target: "/etc/shadow", verdict: "deny" },
      { action_type: "file_access", target: "/etc/shadow", verdict: "blocked" },
      { action_type: "file_access", target: "/etc/shadow", verdict: "denied" },
    );
    const [events] = parseEventLog(input);
    for (const e of events) {
      expect(e.riskLevel).toBe("blocked");
    }
  });

  it("classifies warn/warning/suspicious verdicts as 'suspicious'", () => {
    const input = jsonl(
      { action_type: "file_access", target: "/app/data", verdict: "warn" },
      { action_type: "file_access", target: "/app/data", verdict: "warning" },
      { action_type: "file_access", target: "/app/data", verdict: "suspicious" },
    );
    const [events] = parseEventLog(input);
    for (const e of events) {
      expect(e.riskLevel).toBe("suspicious");
    }
  });

  it("classifies allow/pass verdicts as 'safe'", () => {
    const input = jsonl(
      { action_type: "file_access", target: "/app/data", verdict: "allow" },
      { action_type: "file_access", target: "/app/data", verdict: "allowed" },
      { action_type: "file_access", target: "/app/data", verdict: "pass" },
    );
    const [events] = parseEventLog(input);
    for (const e of events) {
      expect(e.riskLevel).toBe("safe");
    }
  });

  it("uses heuristic for events without a verdict — sensitive paths are suspicious", () => {
    const input = jsonl(
      { action_type: "file_access", target: "/home/user/.ssh/id_rsa" },
      { action_type: "file_access", target: "/home/user/.aws/credentials" },
      { action_type: "file_access", target: "/app/.env" },
      { action_type: "file_access", target: "/etc/passwd" },
    );
    const [events] = parseEventLog(input);
    for (const e of events) {
      expect(e.riskLevel).toBe("suspicious");
    }
  });

  it("uses heuristic for events without a verdict — normal paths are safe", () => {
    const input = jsonl(
      { action_type: "file_access", target: "/app/src/index.ts" },
    );
    const [events] = parseEventLog(input);
    expect(events[0].riskLevel).toBe("safe");
  });
});


describe("synthesizePolicy from file events", () => {
  it("produces forbidden_path config from sensitive file access", () => {
    const [events] = parseEventLog(
      jsonl(
        { action_type: "file_access", target: "/home/user/.ssh/id_rsa" },
        { action_type: "file_access", target: "/home/user/.aws/credentials" },
      ),
    );
    const result = synthesizePolicy(events);
    expect(result.guards.forbidden_path).toBeDefined();
    expect(result.guards.forbidden_path!.enabled).toBe(true);
    expect(result.guards.forbidden_path!.patterns!.length).toBeGreaterThan(0);
    expect(result.guards.forbidden_path!.patterns).toContain("**/.ssh/**");
    expect(result.guards.forbidden_path!.patterns).toContain("**/.aws/**");
  });

  it("produces path_allowlist config from normal file access", () => {
    const [events] = parseEventLog(
      jsonl(
        { action_type: "file_access", target: "/workspace/src/index.ts" },
        { action_type: "file_write", target: "/workspace/src/utils.ts" },
      ),
    );
    const result = synthesizePolicy(events);
    expect(result.guards.path_allowlist).toBeDefined();
    // path_allowlist should start disabled (user must review)
    expect(result.guards.path_allowlist!.enabled).toBe(false);
    expect(result.guards.path_allowlist!.file_access_allow).toBeDefined();
    expect(result.guards.path_allowlist!.file_access_allow!.length).toBeGreaterThan(0);
  });

  it("tracks uniquePaths in stats", () => {
    const [events] = parseEventLog(
      jsonl(
        { action_type: "file_access", target: "/app/a.ts" },
        { action_type: "file_access", target: "/app/b.ts" },
        { action_type: "file_access", target: "/home/.ssh/id_rsa" },
      ),
    );
    const result = synthesizePolicy(events);
    expect(result.stats.uniquePaths).toBe(3);
  });
});


describe("synthesizePolicy from network events", () => {
  it("produces egress_allowlist config from network events", () => {
    const [events] = parseEventLog(
      jsonl(
        { action_type: "network_egress", target: "https://api.openai.com/v1/chat" },
        { action_type: "network_egress", target: "https://api.github.com/repos" },
      ),
    );
    const result = synthesizePolicy(events);
    expect(result.guards.egress_allowlist).toBeDefined();
    expect(result.guards.egress_allowlist!.enabled).toBe(true);
    expect(result.guards.egress_allowlist!.default_action).toBe("block");
    expect(result.guards.egress_allowlist!.allow!.length).toBeGreaterThanOrEqual(2);
  });

  it("creates wildcard patterns for multiple subdomains of the same root", () => {
    const [events] = parseEventLog(
      jsonl(
        { action_type: "network_egress", target: "https://api.openai.com/v1" },
        { action_type: "network_egress", target: "https://chat.openai.com" },
      ),
    );
    const result = synthesizePolicy(events);
    const allowList = result.guards.egress_allowlist!.allow!;
    expect(allowList.some((p) => p.includes("*.openai.com"))).toBe(true);
  });

  it("keeps specific domain when only one subdomain is observed", () => {
    const [events] = parseEventLog(
      jsonl(
        { action_type: "network_egress", target: "https://api.github.com/repos" },
      ),
    );
    const result = synthesizePolicy(events);
    const allowList = result.guards.egress_allowlist!.allow!;
    expect(allowList).toContain("api.github.com");
  });

  it("tracks uniqueDomains in stats", () => {
    const [events] = parseEventLog(
      jsonl(
        { action_type: "network_egress", target: "https://api.openai.com" },
        { action_type: "network_egress", target: "https://api.github.com" },
        { action_type: "network_egress", target: "https://registry.npmjs.org" },
      ),
    );
    const result = synthesizePolicy(events);
    expect(result.stats.uniqueDomains).toBe(3);
  });
});


describe("synthesizePolicy from shell command events", () => {
  it("always produces shell_command guard with dangerous patterns", () => {
    const [events] = parseEventLog(
      jsonl(
        { action_type: "shell_command", target: "ls -la" },
        { action_type: "shell_command", target: "git status" },
      ),
    );
    const result = synthesizePolicy(events);
    expect(result.guards.shell_command).toBeDefined();
    expect(result.guards.shell_command!.enabled).toBe(true);
    expect(result.guards.shell_command!.forbidden_patterns!.length).toBeGreaterThan(0);
    // Should contain standard dangerous patterns
    expect(result.guards.shell_command!.forbidden_patterns!.some(
      (p) => p.includes("rm")
    )).toBe(true);
  });

  it("tracks uniqueCommands in stats", () => {
    const [events] = parseEventLog(
      jsonl(
        { action_type: "shell_command", target: "ls -la" },
        { action_type: "shell_command", target: "git status" },
        { action_type: "shell_command", target: "npm install" },
      ),
    );
    const result = synthesizePolicy(events);
    expect(result.stats.uniqueCommands).toBe(3);
  });
});


describe("synthesizePolicy from MCP tool events", () => {
  it("builds allow and block lists from verdicts", () => {
    const [events] = parseEventLog(
      jsonl(
        { action_type: "mcp_tool_call", target: "read_file", verdict: "allow" },
        { action_type: "mcp_tool_call", target: "dangerous_tool", verdict: "deny" },
      ),
    );
    const result = synthesizePolicy(events);
    expect(result.guards.mcp_tool).toBeDefined();
    expect(result.guards.mcp_tool!.allow).toContain("read_file");
    expect(result.guards.mcp_tool!.block).toContain("dangerous_tool");
  });

  it("sets default_action to block when allowed tools exist", () => {
    const [events] = parseEventLog(
      jsonl(
        { action_type: "mcp_tool_call", target: "read_file", verdict: "allow" },
      ),
    );
    const result = synthesizePolicy(events);
    expect(result.guards.mcp_tool!.default_action).toBe("block");
  });

  it("tracks uniqueTools in stats", () => {
    const [events] = parseEventLog(
      jsonl(
        { action_type: "mcp_tool_call", target: "read_file", verdict: "allow" },
        { action_type: "mcp_tool_call", target: "write_file", verdict: "allow" },
        { action_type: "mcp_tool_call", target: "dangerous_tool", verdict: "deny" },
      ),
    );
    const result = synthesizePolicy(events);
    expect(result.stats.uniqueTools).toBe(3);
  });
});


describe("synthesizePolicy always includes secret_leak", () => {
  it("produces secret_leak config even with only network events", () => {
    const [events] = parseEventLog(
      jsonl({ action_type: "network_egress", target: "https://api.openai.com" }),
    );
    const result = synthesizePolicy(events);
    expect(result.guards.secret_leak).toBeDefined();
    expect(result.guards.secret_leak!.enabled).toBe(true);
    expect(result.guards.secret_leak!.patterns!.length).toBeGreaterThan(0);
  });
});


describe("synthesizePolicy coverage analysis", () => {
  it("returns coverage entries for all events", () => {
    const [events] = parseEventLog(
      jsonl(
        { action_type: "file_access", target: "/etc/passwd" },
        { action_type: "network_egress", target: "https://api.openai.com" },
        { action_type: "shell_command", target: "ls" },
      ),
    );
    const result = synthesizePolicy(events);
    expect(result.coverage).toHaveLength(3);
  });

  it("assigns deny verdict for sensitive file access", () => {
    const [events] = parseEventLog(
      jsonl({ action_type: "file_access", target: "/home/user/.ssh/id_rsa" }),
    );
    const result = synthesizePolicy(events);
    expect(result.coverage[0].synthVerdict).toBe("deny");
    expect(result.coverage[0].guardId).toBe("forbidden_path");
  });

  it("assigns allow verdict for normal file access", () => {
    const [events] = parseEventLog(
      jsonl({ action_type: "file_access", target: "/app/src/index.ts" }),
    );
    const result = synthesizePolicy(events);
    expect(result.coverage[0].synthVerdict).toBe("allow");
    expect(result.coverage[0].guardId).toBe("forbidden_path");
  });

  it("assigns allow verdict for events with unknown action types", () => {
    const [events] = parseEventLog(
      jsonl({ action_type: "custom_thing", target: "whatever" }),
    );
    const result = synthesizePolicy(events);
    expect(result.coverage[0].synthVerdict).toBe("allow");
    expect(result.coverage[0].guardId).toBe("unknown");
  });
});


describe("mergeSynthIntoPolicy", () => {
  it("merges new forbidden_path patterns into existing policy", () => {
    const existingPolicy = makePolicy({
      forbidden_path: {
        enabled: true,
        patterns: ["**/.ssh/**"],
      },
    });
    const synthGuards = {
      forbidden_path: {
        enabled: true,
        patterns: ["**/.ssh/**", "**/.aws/**", "**/.env"],
      },
    };
    const merged = mergeSynthIntoPolicy(existingPolicy, synthGuards);
    const patterns = merged.guards.forbidden_path!.patterns!;
    // Should not duplicate **/.ssh/**
    expect(patterns.filter((p) => p === "**/.ssh/**")).toHaveLength(1);
    // Should add the new patterns
    expect(patterns).toContain("**/.aws/**");
    expect(patterns).toContain("**/.env");
  });

  it("merges new egress domains into existing allow list", () => {
    const existingPolicy = makePolicy({
      egress_allowlist: {
        enabled: true,
        allow: ["api.github.com"],
        default_action: "block",
      },
    });
    const synthGuards = {
      egress_allowlist: {
        enabled: true,
        allow: ["api.github.com", "api.openai.com"],
      },
    };
    const merged = mergeSynthIntoPolicy(existingPolicy, synthGuards);
    const allow = merged.guards.egress_allowlist!.allow!;
    expect(allow.filter((d) => d === "api.github.com")).toHaveLength(1);
    expect(allow).toContain("api.openai.com");
    // Preserves existing default_action
    expect(merged.guards.egress_allowlist!.default_action).toBe("block");
  });

  it("merges new shell forbidden patterns into existing config", () => {
    const existingPolicy = makePolicy({
      shell_command: {
        enabled: true,
        forbidden_patterns: ["rm\\s+-rf\\s+/"],
      },
    });
    const synthGuards = {
      shell_command: {
        enabled: true,
        forbidden_patterns: ["rm\\s+-rf\\s+/", "chmod\\s+777"],
      },
    };
    const merged = mergeSynthIntoPolicy(existingPolicy, synthGuards);
    const patterns = merged.guards.shell_command!.forbidden_patterns!;
    expect(patterns.filter((p) => p === "rm\\s+-rf\\s+/")).toHaveLength(1);
    expect(patterns).toContain("chmod\\s+777");
  });

  it("merges MCP tool allow/block lists", () => {
    const existingPolicy = makePolicy({
      mcp_tool: {
        enabled: true,
        allow: ["read_file"],
        block: ["evil_tool"],
      },
    });
    const synthGuards = {
      mcp_tool: {
        enabled: true,
        allow: ["read_file", "search"],
        block: ["evil_tool", "dangerous_tool"],
      },
    };
    const merged = mergeSynthIntoPolicy(existingPolicy, synthGuards);
    expect(merged.guards.mcp_tool!.allow).toContain("search");
    expect(merged.guards.mcp_tool!.block).toContain("dangerous_tool");
    expect(merged.guards.mcp_tool!.allow!.filter((t) => t === "read_file")).toHaveLength(1);
  });

  it("adds secret_leak if not present in existing policy", () => {
    const existingPolicy = makePolicy({});
    const synthGuards = {
      secret_leak: {
        enabled: true,
        patterns: [{ name: "aws", pattern: "AKIA", severity: "critical" as const }],
      },
    };
    const merged = mergeSynthIntoPolicy(existingPolicy, synthGuards);
    expect(merged.guards.secret_leak).toBeDefined();
    expect(merged.guards.secret_leak!.enabled).toBe(true);
  });

  it("does not overwrite existing secret_leak config", () => {
    const existingPolicy = makePolicy({
      secret_leak: {
        enabled: true,
        patterns: [{ name: "custom", pattern: "custom-pat", severity: "warning" }],
      },
    });
    const synthGuards = {
      secret_leak: {
        enabled: true,
        patterns: [{ name: "aws", pattern: "AKIA", severity: "critical" as const }],
      },
    };
    const merged = mergeSynthIntoPolicy(existingPolicy, synthGuards);
    // Should keep the existing patterns, not overwrite
    expect(merged.guards.secret_leak!.patterns![0].name).toBe("custom");
  });

  it("preserves non-synthesized guards in the existing policy", () => {
    const existingPolicy = makePolicy({
      jailbreak: { enabled: true, detector: { block_threshold: 30 } },
    });
    const synthGuards = {
      shell_command: { enabled: true, forbidden_patterns: ["rm"] },
    };
    const merged = mergeSynthIntoPolicy(existingPolicy, synthGuards);
    expect(merged.guards.jailbreak).toBeDefined();
    expect(merged.guards.jailbreak!.detector!.block_threshold).toBe(30);
  });
});
