import { describe, expect, it, vi } from "vitest";

import { createRequestId, safeParseGatewayFrame } from "./gatewayProtocol";

describe("gatewayProtocol", () => {
  describe("safeParseGatewayFrame", () => {
    it("returns null for invalid JSON", () => {
      expect(safeParseGatewayFrame("{not-json")).toBeNull();
    });

    it("returns null for non-object frames", () => {
      expect(safeParseGatewayFrame("123")).toBeNull();
      expect(safeParseGatewayFrame('"hello"')).toBeNull();
      expect(safeParseGatewayFrame("null")).toBeNull();
    });

    it("parses request frames", () => {
      expect(
        safeParseGatewayFrame(
          JSON.stringify({ type: "req", id: "1", method: "system-presence", params: { a: 1 } }),
        ),
      ).toEqual({ type: "req", id: "1", method: "system-presence", params: { a: 1 } });
    });

    it("parses response frames", () => {
      expect(
        safeParseGatewayFrame(
          JSON.stringify({ type: "res", id: "1", ok: true, payload: { ok: true } }),
        ),
      ).toEqual({
        type: "res",
        id: "1",
        ok: true,
        payload: { ok: true },
      });
    });

    it("parses event frames", () => {
      expect(
        safeParseGatewayFrame(JSON.stringify({ type: "event", event: "presence", payload: [] })),
      ).toEqual({
        type: "event",
        event: "presence",
        payload: [],
      });
    });

    it("returns null for unknown frame types", () => {
      expect(safeParseGatewayFrame(JSON.stringify({ type: "nope" }))).toBeNull();
    });

    it("returns null for missing required fields", () => {
      expect(safeParseGatewayFrame(JSON.stringify({ type: "req", id: 1, method: "x" }))).toBeNull();
      expect(
        safeParseGatewayFrame(JSON.stringify({ type: "res", id: "1", ok: "true" })),
      ).toBeNull();
      expect(safeParseGatewayFrame(JSON.stringify({ type: "event", event: 123 }))).toBeNull();
    });
  });

  describe("createRequestId", () => {
    it("uses crypto.randomUUID when available", () => {
      const randomUUIDSpy = vi
        .spyOn(globalThis.crypto, "randomUUID")
        .mockReturnValue("00000000-0000-4000-8000-000000000000");

      expect(createRequestId("test")).toBe("test:00000000-0000-4000-8000-000000000000");
      randomUUIDSpy.mockRestore();
    });

    it("falls back to timestamp/random when randomUUID throws", () => {
      const randomUUIDSpy = vi.spyOn(globalThis.crypto, "randomUUID").mockImplementation(() => {
        throw new Error("randomUUID disabled");
      });

      const id = createRequestId("fallback");
      expect(id.startsWith("fallback:")).toBe(true);
      randomUUIDSpy.mockRestore();
    });
  });
});
