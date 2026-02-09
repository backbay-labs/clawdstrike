import { describe, expect, it } from "vitest";

import { uuidv7, validateSecurityEvent, type SecurityEvent } from "../src/siem/types";
import { toEcs } from "../src/siem/transforms/ecs";

describe("siem.uuidv7", () => {
  it("generates RFC4122 UUID strings with version 7", () => {
    const id = uuidv7();
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});

describe("siem.SecurityEvent", () => {
  it("validates minimal events", () => {
    const event: SecurityEvent = {
      schema_version: "1.0.0",
      event_id: uuidv7(),
      event_type: "session_start",
      event_category: "session",
      timestamp: new Date().toISOString(),
      agent: { id: "hushd", name: "hushd", version: "0.1.0", type: "clawdstrike" },
      session: { id: "sess-1" },
      outcome: "success",
      action: "session",
      threat: {},
      decision: { allowed: true, guard: "engine", severity: "info", reason: "ok" },
      resource: { type: "configuration", name: "session" },
      metadata: {},
      labels: {},
    };

    expect(() => validateSecurityEvent(event)).not.toThrow();
  });
});

describe("siem.transforms.ecs", () => {
  it("includes @timestamp and event.id", () => {
    const event: SecurityEvent = {
      schema_version: "1.0.0",
      event_id: uuidv7(),
      event_type: "guard_block",
      event_category: "network",
      timestamp: new Date().toISOString(),
      agent: { id: "agent-1", name: "agent-1", version: "0.1.0", type: "clawdstrike" },
      session: { id: "sess-1", environment: "test", tenant_id: "t1" },
      outcome: "failure",
      action: "network_egress",
      threat: { indicator: { type: "domain", value: "evil.com" } },
      decision: { allowed: false, guard: "egress", severity: "high", reason: "blocked" },
      resource: { type: "network", name: "evil.com", host: "evil.com", port: 443 },
      metadata: {},
      labels: { team: "security" },
    };

    const ecs = toEcs(event);
    expect(ecs["@timestamp"]).toBe(event.timestamp);
    expect((ecs.event as any).id).toBe(event.event_id);
  });
});

