import { describe, expect, it } from "vitest";

import { applyGatewayEventFrame, type OpenClawGatewayRuntime } from "./OpenClawContext";

function runtime(overrides?: Partial<OpenClawGatewayRuntime>): OpenClawGatewayRuntime {
  return {
    status: "disconnected",
    lastError: null,
    connectedAtMs: null,
    lastMessageAtMs: null,
    presence: [],
    nodes: [],
    devices: null,
    execApprovalQueue: [],
    ...overrides,
  };
}

describe("OpenClawContext", () => {
  describe("applyGatewayEventFrame", () => {
    it("updates presence from array payloads", () => {
      const next = applyGatewayEventFrame(runtime({ presence: [{ old: true }] }), {
        type: "event",
        event: "presence",
        payload: [{ client: "a" }],
      });
      expect(next.presence).toEqual([{ client: "a" }]);
    });

    it("clears presence on non-array payloads", () => {
      const next = applyGatewayEventFrame(runtime({ presence: [{ old: true }] }), {
        type: "event",
        event: "presence",
        payload: { not: "an array" },
      });
      expect(next.presence).toEqual([]);
    });

    it("dedupes and caps exec approval queue", () => {
      const baseQueue = Array.from({ length: 100 }, (_, i) => ({
        id: `id-${i}`,
        expiresAtMs: Date.now() + 10_000,
        request: { command: `echo ${i}` },
      }));

      const next = applyGatewayEventFrame(runtime({ execApprovalQueue: baseQueue }), {
        type: "event",
        event: "exec.approval.requested",
        payload: {
          id: "id-50",
          expiresAtMs: 123,
          request: { command: "echo updated" },
        },
      });

      expect(next.execApprovalQueue).toHaveLength(100);
      expect(next.execApprovalQueue[0]).toMatchObject({
        id: "id-50",
        request: { command: "echo updated" },
      });
      expect(next.execApprovalQueue.filter((a) => a.id === "id-50")).toHaveLength(1);
    });

    it("ignores malformed exec approval events", () => {
      const current = runtime();
      const next = applyGatewayEventFrame(current, {
        type: "event",
        event: "exec.approval.requested",
        payload: { id: "missing-command" },
      });
      expect(next).toBe(current);
    });
  });
});
