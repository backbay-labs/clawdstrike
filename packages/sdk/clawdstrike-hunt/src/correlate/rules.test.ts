import { describe, it, expect } from "vitest";
import { parseRule } from "./rules.js";
import { correlate } from "./engine.js";
import type { TimelineEvent } from "../types.js";

const EXAMPLE_RULE = `
schema: clawdstrike.hunt.correlation.v1
name: "MCP Tool Exfiltration Attempt"
severity: high
description: >
  Detects an MCP tool reading sensitive files followed by
  network egress to an external domain within 30 seconds.
window: 30s
conditions:
  - source: receipt
    action_type: file
    verdict: allow
    target_pattern: "/etc/passwd|/etc/shadow"
    bind: file_access
  - source: [receipt, hubble]
    action_type: egress
    after: file_access
    within: 30s
    bind: egress_event
output:
  title: "Potential data exfiltration via MCP tool"
  evidence:
    - file_access
    - egress_event
`;

describe("parseRule", () => {
  it("parses a valid rule from YAML", () => {
    const rule = parseRule(EXAMPLE_RULE);
    expect(rule.schema).toBe("clawdstrike.hunt.correlation.v1");
    expect(rule.name).toBe("MCP Tool Exfiltration Attempt");
    expect(rule.severity).toBe("high");
    expect(rule.window).toBe(30_000); // 30s in ms
    expect(rule.conditions).toHaveLength(2);

    // First condition — single source string deserialized to array.
    expect(rule.conditions[0].source).toEqual(["receipt"]);
    expect(rule.conditions[0].actionType).toBe("file");
    expect(rule.conditions[0].verdict).toBe("allow");
    expect(rule.conditions[0].targetPattern).toBe("/etc/passwd|/etc/shadow");
    expect(rule.conditions[0].after).toBeUndefined();
    expect(rule.conditions[0].within).toBeUndefined();
    expect(rule.conditions[0].bind).toBe("file_access");

    // Second condition — list source, after + within.
    expect(rule.conditions[1].source).toEqual(["receipt", "hubble"]);
    expect(rule.conditions[1].after).toBe("file_access");
    expect(rule.conditions[1].within).toBe(30_000);
    expect(rule.conditions[1].bind).toBe("egress_event");

    // Output.
    expect(rule.output.title).toBe("Potential data exfiltration via MCP tool");
    expect(rule.output.evidence).toEqual(["file_access", "egress_event"]);
  });

  it("parses single source string", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Single source test"
severity: low
description: "test"
window: 5m
conditions:
  - source: tetragon
    bind: evt
output:
  title: "test"
  evidence:
    - evt
`;
    const rule = parseRule(yaml);
    expect(rule.conditions[0].source).toEqual(["tetragon"]);
    expect(rule.window).toBe(300_000); // 5m
  });

  it("supports various duration formats", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Duration test"
severity: low
description: "test"
window: 2h
conditions:
  - source: receipt
    bind: evt
output:
  title: "test"
  evidence:
    - evt
`;
    const rule = parseRule(yaml);
    expect(rule.window).toBe(7_200_000); // 2h
  });
});

describe("validateRule", () => {
  it("rejects unknown schema", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v99
name: "Bad schema"
severity: low
description: "test"
window: 10s
conditions:
  - source: receipt
    bind: evt
output:
  title: "test"
  evidence:
    - evt
`;
    expect(() => parseRule(yaml)).toThrow("unsupported schema");
  });

  it("rejects empty conditions", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "No conditions"
severity: medium
description: "test"
window: 10s
conditions: []
output:
  title: "test"
  evidence: []
`;
    expect(() => parseRule(yaml)).toThrow("at least one condition");
  });

  it("rejects non-object condition entries", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Bad condition entry"
severity: low
description: "test"
window: 10s
conditions:
  - 123
output:
  title: "test"
  evidence: []
`;
    expect(() => parseRule(yaml)).toThrow("condition 0 must be an object");
  });

  it("rejects condition missing source", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Missing source"
severity: low
description: "test"
window: 10s
conditions:
  - bind: evt
output:
  title: "test"
  evidence:
    - evt
`;
    expect(() => parseRule(yaml)).toThrow("condition 0 has invalid 'source'");
  });

  it("rejects condition source arrays containing non-strings", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Bad source array"
severity: low
description: "test"
window: 10s
conditions:
  - source: [receipt, 123]
    bind: evt
output:
  title: "test"
  evidence:
    - evt
`;
    expect(() => parseRule(yaml)).toThrow("condition 0 has invalid 'source'");
  });

  it("rejects invalid after reference", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Bad after ref"
severity: high
description: "test"
window: 30s
conditions:
  - source: receipt
    after: nonexistent
    bind: evt
output:
  title: "test"
  evidence:
    - evt
`;
    expect(() => parseRule(yaml)).toThrow("unknown bind 'nonexistent'");
  });

  it("rejects invalid evidence reference", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Bad evidence ref"
severity: low
description: "test"
window: 10s
conditions:
  - source: receipt
    bind: evt
output:
  title: "test"
  evidence:
    - missing_bind
`;
    expect(() => parseRule(yaml)).toThrow("unknown bind 'missing_bind'");
  });

  it("rejects missing output title", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Missing title"
severity: low
description: "test"
window: 10s
conditions:
  - source: receipt
    bind: evt
output:
  evidence:
    - evt
`;
    expect(() => parseRule(yaml)).toThrow("output.title must be a string");
  });

  it("rejects within exceeding window", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Within exceeds window"
severity: low
description: "test"
window: 10s
conditions:
  - source: receipt
    bind: first
  - source: hubble
    after: first
    within: 60s
    bind: second
output:
  title: "test"
  evidence:
    - first
    - second
`;
    expect(() => parseRule(yaml)).toThrow("exceeds global window");
  });

  it("rejects within without after", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Within without after"
severity: low
description: "test"
window: 30s
conditions:
  - source: receipt
    within: 10s
    bind: evt
output:
  title: "test"
  evidence:
    - evt
`;
    expect(() => parseRule(yaml)).toThrow("'within' but no 'after'");
  });

  it("rejects duplicate bind names", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Duplicate bind"
severity: high
description: "test"
window: 30s
conditions:
  - source: receipt
    action_type: file
    bind: evt
  - source: hubble
    action_type: egress
    bind: evt
output:
  title: "test"
  evidence:
    - evt
`;
    expect(() => parseRule(yaml)).toThrow("reuses bind name 'evt'");
  });

  it("rejects window <= 0", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Zero window"
severity: low
description: "test"
window: 0s
conditions:
  - source: receipt
    bind: evt
output:
  title: "test"
  evidence:
    - evt
`;
    expect(() => parseRule(yaml)).toThrow("window must be a positive duration");
  });

  it("rejects negative within", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Negative within"
severity: low
description: "test"
window: 30s
conditions:
  - source: receipt
    bind: first
  - source: hubble
    after: first
    within: 0s
    bind: second
output:
  title: "test"
  evidence:
    - first
    - second
`;
    expect(() => parseRule(yaml)).toThrow("'within' must be a positive duration");
  });
});

function makeEvent(
  source: string,
  actionType: string,
  verdict: string,
  summary: string,
  ts: Date,
): TimelineEvent {
  return {
    timestamp: ts,
    source: source as TimelineEvent["source"],
    kind: "guard_decision",
    verdict: verdict as TimelineEvent["verdict"],
    summary,
    actionType,
  };
}

describe("sequence shorthand", () => {
  it("parses a 2-step sequence into conditions", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Two step sequence"
severity: high
description: "test"
window: 30s
sequence:
  - bind: file_access
    source: receipt
    action_type: file
  - bind: egress_event
    source: receipt
    action_type: egress
output:
  title: "test"
  evidence:
    - file_access
    - egress_event
`;
    const rule = parseRule(yaml);
    expect(rule.conditions).toHaveLength(2);
    expect(rule.conditions[0].after).toBeUndefined();
    expect(rule.conditions[0].bind).toBe("file_access");
    expect(rule.conditions[1].after).toBe("file_access");
    expect(rule.conditions[1].bind).toBe("egress_event");
  });

  it("parses a 3-step sequence with auto-wired after", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Three step"
severity: high
description: "test"
window: 60s
sequence:
  - bind: step_a
    source: receipt
    action_type: file
  - bind: step_b
    source: receipt
    action_type: egress
  - bind: step_c
    source: receipt
    action_type: egress
output:
  title: "test"
  evidence:
    - step_a
    - step_b
    - step_c
`;
    const rule = parseRule(yaml);
    expect(rule.conditions).toHaveLength(3);
    expect(rule.conditions[0].after).toBeUndefined();
    expect(rule.conditions[1].after).toBe("step_a");
    expect(rule.conditions[2].after).toBe("step_b");
  });

  it("explicit after override in sequence item", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Override after"
severity: medium
description: "test"
window: 60s
sequence:
  - bind: step_a
    source: receipt
    action_type: file
  - bind: step_b
    source: receipt
    action_type: egress
  - bind: step_c
    source: receipt
    action_type: egress
    after: step_a
output:
  title: "test"
  evidence:
    - step_a
    - step_b
    - step_c
`;
    const rule = parseRule(yaml);
    expect(rule.conditions[2].after).toBe("step_a");
  });

  it("within preserved in sequence items", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Within in sequence"
severity: high
description: "test"
window: 60s
sequence:
  - bind: step_a
    source: receipt
    action_type: file
  - bind: step_b
    source: receipt
    action_type: egress
    within: 10s
output:
  title: "test"
  evidence:
    - step_a
    - step_b
`;
    const rule = parseRule(yaml);
    expect(rule.conditions[1].within).toBe(10_000);
  });

  it("empty sequence throws error", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Empty sequence"
severity: low
description: "test"
window: 10s
sequence: []
output:
  title: "test"
  evidence: []
`;
    expect(() => parseRule(yaml)).toThrow("sequence must have at least one item");
  });

  it("sequence and conditions both present throws error", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Both"
severity: low
description: "test"
window: 10s
sequence:
  - bind: a
    source: receipt
conditions:
  - bind: b
    source: receipt
output:
  title: "test"
  evidence:
    - a
`;
    expect(() => parseRule(yaml)).toThrow("mutually exclusive");
  });

  it("single item sequence has no after", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "Single sequence"
severity: low
description: "test"
window: 30s
sequence:
  - bind: only
    source: receipt
    action_type: file
output:
  title: "test"
  evidence:
    - only
`;
    const rule = parseRule(yaml);
    expect(rule.conditions).toHaveLength(1);
    expect(rule.conditions[0].after).toBeUndefined();
    expect(rule.conditions[0].bind).toBe("only");
  });

  it("end-to-end: sequence rule fires alerts through engine", () => {
    const yaml = `
schema: clawdstrike.hunt.correlation.v1
name: "E2E sequence"
severity: high
description: "test"
window: 30s
sequence:
  - bind: file_read
    source: receipt
    action_type: file
    verdict: allow
  - bind: net_egress
    source: receipt
    action_type: egress
    within: 30s
output:
  title: "Sequence matched"
  evidence:
    - file_read
    - net_egress
`;
    const rule = parseRule(yaml);
    const ts1 = new Date("2025-06-15T12:00:00Z");
    const ts2 = new Date("2025-06-15T12:00:05Z");

    const events: TimelineEvent[] = [
      makeEvent("receipt", "file", "allow", "read /etc/passwd", ts1),
      makeEvent("receipt", "egress", "allow", "evil.com:443", ts2),
    ];

    const alerts = correlate([rule], events);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].title).toBe("Sequence matched");
    expect(alerts[0].evidence).toHaveLength(2);
  });
});
