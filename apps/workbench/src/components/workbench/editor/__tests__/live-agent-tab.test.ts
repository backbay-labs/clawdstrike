import { describe, expect, it } from "vitest";
import {
  buildHushdAuthHeaders,
  consumeSseMessages,
  describeHushdAuthScopeMismatch,
  endpointsShareAuthScope,
  parseHushdSseEvent,
  resolveProxyBase,
} from "../live-agent-tab";

describe("live-agent hushd monitor helpers", () => {
  it("treats lifecycle events without a decision as INFO instead of DENY", () => {
    const event = parseHushdSseEvent(
      { timestamp: "2026-03-11T12:00:00Z", policy_hash: "abc123" },
      "policy_reload",
    );

    expect(event).not.toBeNull();
    expect(event?.verdict).toBe("INFO");
    expect(event?.guard).toBe("policy_reload");
    expect(event?.target).toBe("abc123");
  });

  it("only attaches hushd auth headers to the configured hushd endpoint", () => {
    expect(
      buildHushdAuthHeaders(
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "secret-token",
      ),
    ).toEqual({});

    expect(
      buildHushdAuthHeaders(
        "http://evil.example:8080",
        "http://localhost:8080",
        "secret-token",
      ),
    ).toEqual({});

    expect(
      buildHushdAuthHeaders(
        "http://localhost:8080",
        "http://localhost:8080",
        "secret-token",
      ),
    ).toEqual({ Authorization: "Bearer secret-token" });
  });

  it("requires exact hushd origin matching for auth scope checks", () => {
    expect(endpointsShareAuthScope("http://127.0.0.1:9000", "http://127.0.0.1:9000")).toBe(true);
    expect(endpointsShareAuthScope("http://127.0.0.1:9000", "http://localhost:9000")).toBe(false);
    expect(endpointsShareAuthScope("http://127.0.0.1:9000", "http://127.0.0.1:9001")).toBe(false);
  });

  it("explains exact-origin auth scope mismatches instead of looking like a bad token", () => {
    expect(
      describeHushdAuthScopeMismatch(
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "secret-token",
      ),
    ).toContain("configured hushd URL (http://localhost:8080)");

    expect(
      describeHushdAuthScopeMismatch(
        "http://localhost:8080",
        "http://localhost:8080",
        "secret-token",
      ),
    ).toBeNull();
    expect(
      describeHushdAuthScopeMismatch(
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "   ",
      ),
    ).toBeNull();
  });

  it("parses named SSE messages and preserves trailing partial data", () => {
    const parsed = consumeSseMessages(
      "event: check\ndata: {\"allowed\":true}\n\n" +
      "event: policy_reload\ndata: {\"policy_hash\":\"abc\"}\n\n" +
      "event: check\ndata: {\"allowed\":false",
    );

    expect(parsed.messages).toEqual([
      { eventType: "check", data: "{\"allowed\":true}" },
      { eventType: "policy_reload", data: "{\"policy_hash\":\"abc\"}" },
    ]);
    expect(parsed.remainder).toBe("event: check\ndata: {\"allowed\":false");
  });

  it("keeps custom localhost ports intact when no dev proxy matches", () => {
    expect(resolveProxyBase("http://127.0.0.1:9000", true)).toBe("http://127.0.0.1:9000");
  });
});
