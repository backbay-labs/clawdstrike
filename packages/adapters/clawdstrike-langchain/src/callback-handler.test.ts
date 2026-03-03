import type { PolicyEngineLike } from "@clawdstrike/adapter-core";
import { describe, expect, it } from "vitest";
import { ClawdstrikeCallbackHandler } from "./callback-handler.js";
import { ClawdstrikeBlockedError } from "@clawdstrike/adapter-core";
import { ClawdstrikeViolationError } from "./errors.js";

describe("ClawdstrikeCallbackHandler", () => {
  it("blocks denied tool runs on handleToolStart", async () => {
    const engine: PolicyEngineLike = {
      evaluate: (event) => ({
        status: event.eventType === "command_exec" ? "deny" : "allow",
        reason: "blocked",
      }),
    };

    const handler = new ClawdstrikeCallbackHandler({ engine, config: { blockOnViolation: true } });

    await expect(
      handler.handleToolStart({ name: "bash" }, JSON.stringify({ cmd: "rm -rf /" }), "run-1"),
    ).rejects.toBeInstanceOf(ClawdstrikeViolationError);
    await expect(
      handler.handleToolStart({ name: "bash" }, JSON.stringify({ cmd: "rm -rf /" }), "run-3"),
    ).rejects.toBeInstanceOf(ClawdstrikeBlockedError);

    const events = handler.getAuditEvents();
    expect(events.some((e) => e.type === "tool_call_blocked")).toBe(true);
  });

  it("records start/end audit events for allowed runs", async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ allowed: true, denied: false, warn: false }),
    };

    const handler = new ClawdstrikeCallbackHandler({ engine });

    await handler.handleToolStart({ name: "calc" }, JSON.stringify({ ok: true }), "run-2");
    await handler.handleToolEnd("ok", "run-2");

    const events = handler.getAuditEvents();
    expect(events.some((e) => e.type === "tool_call_start")).toBe(true);
    expect(events.some((e) => e.type === "tool_call_end")).toBe(true);
  });
});
