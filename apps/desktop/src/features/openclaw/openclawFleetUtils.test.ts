import { describe, expect, it } from "vitest";

import {
  normalizeGatewayUrl,
  originFixHint,
  parseCommand,
  selectSystemRunNodes,
} from "./openclawFleetUtils";

describe("openclawFleetUtils", () => {
  describe("parseCommand", () => {
    it("rejects empty commands", () => {
      expect(parseCommand("   ")).toEqual({
        argv: [],
        rawCommand: null,
        error: "command required",
      });
    });

    it("parses JSON argv arrays", () => {
      expect(parseCommand('["bash","-lc","echo test"]')).toEqual({
        argv: ["bash", "-lc", "echo test"],
        rawCommand: null,
        error: null,
      });
    });

    it("rejects invalid JSON argv", () => {
      const parsed = parseCommand('["unterminated"');
      expect(parsed.error).toBeTruthy();
      expect(parsed.argv).toEqual([]);
    });

    it("rejects empty JSON argv arrays", () => {
      expect(parseCommand("[]")).toEqual({
        argv: [],
        rawCommand: null,
        error: "JSON argv must be a non-empty array",
      });
    });

    it("splits raw commands on whitespace", () => {
      expect(parseCommand("echo   test")).toEqual({
        argv: ["echo", "test"],
        rawCommand: "echo   test",
        error: null,
      });
    });
  });

  describe("normalizeGatewayUrl", () => {
    it("adds ws:// when missing", () => {
      expect(normalizeGatewayUrl("127.0.0.1:18789")).toBe("ws://127.0.0.1:18789");
    });

    it("converts http:// to ws://", () => {
      expect(normalizeGatewayUrl("http://127.0.0.1:18789/")).toBe("ws://127.0.0.1:18789");
    });

    it("converts https:// to wss://", () => {
      expect(normalizeGatewayUrl("https://gw.example.com/")).toBe("wss://gw.example.com");
    });

    it("preserves wss:// scheme", () => {
      expect(normalizeGatewayUrl("wss://gw.example.com/")).toBe("wss://gw.example.com");
    });

    it("returns empty for blank strings", () => {
      expect(normalizeGatewayUrl("   ")).toBe("");
    });
  });

  describe("originFixHint", () => {
    it("returns null when error does not mention origin policy", () => {
      expect(originFixHint("timeout")).toBeNull();
    });

    it("returns a remediation hint for origin not allowed errors", () => {
      const hint = originFixHint("Origin is not allowed") ?? "";
      expect(hint).toContain("OpenClaw rejected this app origin");
      expect(hint).toContain("allowedOrigins");
    });
  });

  describe("selectSystemRunNodes", () => {
    it("filters connected nodes advertising system.run", () => {
      const nodes = [
        { nodeId: "a", connected: true, commands: ["system.run"] },
        { nodeId: "b", connected: true, commands: ["other"] },
        { nodeId: "c", connected: false, commands: ["system.run"] },
        { connected: true, commands: ["system.run"] },
      ];

      expect(selectSystemRunNodes(nodes)).toEqual([
        { nodeId: "a", connected: true, commands: ["system.run"] },
      ]);
    });
  });
});
