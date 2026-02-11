import { describe, expect, it } from "vitest";

import { buildPolicyTestEvent, getPolicyTestTargetPlaceholder } from "./mapping";

describe("buildPolicyTestEvent", () => {
  it("maps file_read requests", () => {
    const event = buildPolicyTestEvent(
      {
        eventType: "file_read",
        target: "/workspace/src/main.ts",
      },
      { eventId: "evt-1", timestamp: "2026-02-11T00:00:00.000Z" }
    );

    expect(event.eventId).toBe("evt-1");
    expect(event.eventType).toBe("file_read");
    expect(event.data).toMatchObject({
      type: "file",
      path: "/workspace/src/main.ts",
      operation: "read",
    });
  });

  it("preserves potentially traversal-like file targets for server-side enforcement", () => {
    const event = buildPolicyTestEvent(
      {
        eventType: "file_read",
        target: "../../etc/passwd",
      },
      { eventId: "evt-2", timestamp: "2026-02-11T00:00:00.000Z" }
    );

    expect(event.data).toMatchObject({
      type: "file",
      path: "../../etc/passwd",
    });
  });

  it("uses actual URL host for userinfo-spoof inputs", () => {
    const event = buildPolicyTestEvent(
      {
        eventType: "network_egress",
        target: "https://api.openai.com:443@evil.example/path",
      },
      { eventId: "evt-3", timestamp: "2026-02-11T00:00:00.000Z" }
    );

    expect(event.data).toMatchObject({
      type: "network",
      host: "evil.example",
      port: 443,
    });
  });

  it("parses private IP network targets without rewriting host", () => {
    const event = buildPolicyTestEvent(
      {
        eventType: "network_egress",
        target: "http://10.0.0.5:8080/metrics",
      },
      { eventId: "evt-4", timestamp: "2026-02-11T00:00:00.000Z" }
    );

    expect(event.data).toMatchObject({
      type: "network",
      host: "10.0.0.5",
      port: 8080,
    });
  });

  it("treats bare IPv6 targets as host-only values", () => {
    const event = buildPolicyTestEvent(
      {
        eventType: "network_egress",
        target: "2001:db8::1",
      },
      { eventId: "evt-5", timestamp: "2026-02-11T00:00:00.000Z" }
    );

    expect(event.data).toMatchObject({
      type: "network",
      host: "2001:db8::1",
      port: 443,
    });
  });

  it("parses bracketed IPv6 host:port targets", () => {
    const event = buildPolicyTestEvent(
      {
        eventType: "network_egress",
        target: "[2001:db8::1]:8443",
      },
      { eventId: "evt-6", timestamp: "2026-02-11T00:00:00.000Z" }
    );

    expect(event.data).toMatchObject({
      type: "network",
      host: "2001:db8::1",
      port: 8443,
    });
  });

  it("rejects invalid tool parameter JSON", () => {
    expect(() =>
      buildPolicyTestEvent({
        eventType: "tool_call",
        target: "mcp__fs__read_file",
        extra: "[1,2,3]",
      })
    ).toThrow("extra must be a JSON object");
  });

  it("provides shared target placeholders across policy test views", () => {
    expect(getPolicyTestTargetPlaceholder("file_read")).toBe("/workspace/file.txt");
    expect(getPolicyTestTargetPlaceholder("network_egress")).toBe(
      "https://api.openai.com/v1/models"
    );
    expect(getPolicyTestTargetPlaceholder("tool_call")).toBe("mcp__fs__read_file");
  });
});
