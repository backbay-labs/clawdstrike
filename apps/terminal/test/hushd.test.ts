/**
 * Hushd Client Tests
 *
 * Tests for the hushd HTTP + SSE client with mocked fetch.
 */

import { describe, test, expect, beforeEach, afterEach, mock } from "bun:test"
import { HushdClient } from "../src/hushd/client"
import { Hushd } from "../src/hushd/index"
import type { CheckRequest, CheckResponse, PolicyResponse, AuditResponse, AuditStats } from "../src/hushd/types"

// =============================================================================
// MOCK HELPERS
// =============================================================================

const originalFetch = globalThis.fetch

function mockFetch(responses: Map<string, { status: number; body: unknown }>) {
  globalThis.fetch = mock(async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url

    for (const [pattern, response] of responses) {
      if (url.includes(pattern)) {
        return new Response(JSON.stringify(response.body), {
          status: response.status,
          headers: { "Content-Type": "application/json" },
        })
      }
    }

    return new Response("Not Found", { status: 404 })
  }) as unknown as typeof fetch
}

function mockFetchError() {
  globalThis.fetch = mock(async () => {
    throw new Error("Connection refused")
  }) as unknown as typeof fetch
}

// =============================================================================
// CLIENT TESTS
// =============================================================================

describe("HushdClient", () => {
  let client: HushdClient

  beforeEach(() => {
    client = new HushdClient("http://127.0.0.1:8080")
  })

  afterEach(() => {
    client.disconnectSSE()
    globalThis.fetch = originalFetch
  })

  describe("probe", () => {
    test("returns true when hushd is reachable", async () => {
      mockFetch(new Map([
        ["/health", { status: 200, body: { status: "ok" } }],
      ]))

      const result = await client.probe()
      expect(result).toBe(true)
    })

    test("returns false when hushd is unreachable", async () => {
      mockFetchError()

      const result = await client.probe()
      expect(result).toBe(false)
    })

    test("returns false on non-200 response", async () => {
      mockFetch(new Map([
        ["/health", { status: 503, body: { status: "unavailable" } }],
      ]))

      const result = await client.probe()
      expect(result).toBe(false)
    })
  })

  describe("check", () => {
    test("submits check request and returns response", async () => {
      const mockResponse: CheckResponse = {
        decision: "allow",
        policy: "default",
        policy_version: "1.2.0",
        guards: [
          {
            guard: "ForbiddenPathGuard",
            decision: "allow",
            severity: "info",
          },
        ],
        receipt_id: "test-receipt",
        timestamp: new Date().toISOString(),
      }

      mockFetch(new Map([
        ["/api/v1/check", { status: 200, body: mockResponse }],
      ]))

      const req: CheckRequest = {
        action_type: "file",
        target: "/tmp/safe-file.txt",
      }

      const result = await client.check(req)
      expect(result).not.toBeNull()
      expect(result!.decision).toBe("allow")
      expect(result!.guards).toHaveLength(1)
    })

    test("returns null on connectivity error", async () => {
      mockFetchError()

      const result = await client.check({
        action_type: "file",
        target: "/etc/passwd",
      })
      expect(result).toBeNull()
    })

    test("returns null on non-200 response", async () => {
      mockFetch(new Map([
        ["/api/v1/check", { status: 500, body: { error: "internal" } }],
      ]))

      const result = await client.check({
        action_type: "file",
        target: "/tmp/test",
      })
      expect(result).toBeNull()
    })
  })

  describe("getPolicy", () => {
    test("fetches active policy", async () => {
      const mockPolicy: PolicyResponse = {
        name: "default",
        version: "1.2.0",
        hash: "abc123",
        schema_version: "1.2.0",
        guards: [
          { id: "ForbiddenPathGuard", enabled: true },
          { id: "SecretLeakGuard", enabled: true },
        ],
        loaded_at: new Date().toISOString(),
      }

      mockFetch(new Map([
        ["/api/v1/policy", { status: 200, body: mockPolicy }],
      ]))

      const result = await client.getPolicy()
      expect(result).not.toBeNull()
      expect(result!.name).toBe("default")
      expect(result!.guards).toHaveLength(2)
    })

    test("returns null on error", async () => {
      mockFetchError()
      const result = await client.getPolicy()
      expect(result).toBeNull()
    })

    test("normalizes the live daemon policy shape", async () => {
      mockFetch(new Map([
        ["/api/v1/policy", {
          status: 200,
          body: {
            name: "Default",
            version: "1.1.0",
            description: "Default security rules",
            policy_hash: "abc123",
            yaml: [
              "version: 1.1.0",
              "name: Default",
              "guards:",
              "  forbidden_path:",
              "    enabled: true",
              "  path_allowlist: null",
              "  secret_leak:",
              "    enabled: false",
            ].join("\n"),
            source: { kind: "ruleset:default" },
            schema: { current: "1.2.0", supported: ["1.1.0", "1.2.0"] },
          },
        }],
      ]))

      const result = await client.getPolicy()
      expect(result).not.toBeNull()
      expect(result!.hash).toBe("abc123")
      expect(result!.schema_version).toBe("1.2.0")
      expect(result!.guards).toEqual([
        { id: "forbidden_path", enabled: true },
        { id: "path_allowlist", enabled: false },
        { id: "secret_leak", enabled: false },
      ])
    })

    test("does not treat guard names containing null as disabled", async () => {
      mockFetch(new Map([
        ["/api/v1/policy", {
          status: 200,
          body: {
            name: "Default",
            version: "1.1.0",
            policy_hash: "abc123",
            yaml: [
              "version: 1.1.0",
              "guards:",
              "  null_check_guard:",
              "    enabled: true",
              "  actually_disabled: null",
            ].join("\n"),
            schema: { current: "1.2.0" },
          },
        }],
      ]))

      const result = await client.getPolicy()
      expect(result).not.toBeNull()
      expect(result!.guards).toEqual([
        { id: "null_check_guard", enabled: true },
        { id: "actually_disabled", enabled: false },
      ])
    })
  })

  describe("getAudit", () => {
    test("queries audit log with parameters", async () => {
      const mockAudit: AuditResponse = {
        events: [
          {
            id: "evt-1",
            timestamp: new Date().toISOString(),
            event_type: "violation",
            action_type: "file",
            target: "/etc/passwd",
            decision: "blocked",
            guard: "ForbiddenPathGuard",
            severity: "critical",
            message: "Path is forbidden",
          },
        ],
        total: 1,
        offset: 0,
        limit: 50,
      }

      mockFetch(new Map([
        ["/api/v1/audit", { status: 200, body: mockAudit }],
      ]))

      const result = await client.getAudit({ limit: 10, decision: "blocked" })
      expect(result).not.toBeNull()
      expect(result!.events).toHaveLength(1)
      expect(result!.events[0].decision).toBe("blocked")
    })

    test("normalizes allow/deny decision filters for the daemon API", async () => {
      const requestedUrls: string[] = []
      globalThis.fetch = mock(async (input: string | URL | Request) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url
        requestedUrls.push(url)
        return new Response(JSON.stringify({ events: [], total: 0, offset: 0, limit: 50 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      }) as unknown as typeof fetch

      await client.getAuditDetailed({ decision: "allow" })
      await client.getAuditDetailed({ decision: "deny" })

      expect(requestedUrls[0]).toContain("decision=allowed")
      expect(requestedUrls[1]).toContain("decision=blocked")
    })

    test("preserves since and until audit filters", async () => {
      const requestedUrls: string[] = []
      globalThis.fetch = mock(async (input: string | URL | Request) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url
        requestedUrls.push(url)
        return new Response(JSON.stringify({ events: [], total: 0, offset: 0, limit: 50 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      }) as unknown as typeof fetch

      await client.getAuditDetailed({
        since: "2026-03-06T00:00:00Z",
        until: "2026-03-06T01:00:00Z",
      })

      expect(requestedUrls[0]).toContain("since=2026-03-06T00%3A00%3A00Z")
      expect(requestedUrls[0]).toContain("until=2026-03-06T01%3A00%3A00Z")
    })

    test("returns null on error", async () => {
      mockFetchError()
      const result = await client.getAudit()
      expect(result).toBeNull()
    })
  })

  describe("getAuditStats", () => {
    test("fetches audit statistics", async () => {
      const mockStats: AuditStats = {
        total_events: 100,
        allowed: 95,
        violations: 5,
        session_id: "sess-1",
        uptime_secs: 42,
      }

      mockFetch(new Map([
        ["/api/v1/audit/stats", { status: 200, body: mockStats }],
      ]))

      const result = await client.getAuditStats()
      expect(result).not.toBeNull()
      expect(result!.total_events).toBe(100)
      expect(result!.violations).toBe(5)
    })

    test("returns null on error", async () => {
      mockFetchError()
      const result = await client.getAuditStats()
      expect(result).toBeNull()
    })
  })

  describe("auth token", () => {
    test("includes Authorization header when token provided", async () => {
      const tokenClient = new HushdClient("http://127.0.0.1:8080", "test-token")

      let capturedHeaders: Record<string, string> = {}
      globalThis.fetch = mock(async (_input: string | URL | Request, init?: RequestInit) => {
        const headers = init?.headers as Record<string, string> | undefined
        if (headers) {
          capturedHeaders = headers
        }
        return new Response(JSON.stringify({ status: "ok" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      }) as unknown as typeof fetch

      await tokenClient.getPolicy()
      expect(capturedHeaders["Authorization"]).toBe("Bearer test-token")

      tokenClient.disconnectSSE()
    })
  })

  describe("ingestAuditBatch", () => {
    test("submits report export audit events", async () => {
      mockFetch(new Map([
        ["/api/v1/audit/batch", { status: 200, body: { accepted: 1, duplicates: 0, rejected: 0 } }],
      ]))

      const result = await client.ingestAuditBatch([
        {
          id: "audit-export-1",
          timestamp: new Date().toISOString(),
          event_type: "report_export",
          action_type: "report_export",
          target: "investigation-1",
          decision: "allowed",
          severity: "info",
          message: "Investigation report exported",
          metadata: { report_id: "investigation-1" },
        },
      ])

      expect(result.ok).toBe(true)
      expect(result.data?.accepted).toBe(1)
    })
  })

  describe("SSE", () => {
    test("isSSEConnected returns false when not connected", () => {
      expect(client.isSSEConnected()).toBe(false)
    })

    test("disconnectSSE is safe to call when not connected", () => {
      // Should not throw
      client.disconnectSSE()
      expect(client.isSSEConnected()).toBe(false)
    })

    test("normalizes hushd SSE event frames using the event field", async () => {
      const encoder = new TextEncoder()
      globalThis.fetch = mock(async () => new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(encoder.encode("event: violation\n"))
          controller.enqueue(encoder.encode("data: {\"timestamp\":\"2026-03-06T06:00:00Z\",\"action_type\":\"shell\",\"target\":\"rm -rf /tmp/demo\",\"allowed\":false,\"guard\":\"policy_guard\",\"severity\":\"critical\",\"message\":\"blocked by policy\"}\n\n"))
          controller.close()
        },
      }), {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      })) as unknown as typeof fetch

      const events: Array<{ type: string; timestamp: string; data: Record<string, unknown> }> = []
      client.connectSSE((event) => {
        events.push(event as { type: string; timestamp: string; data: Record<string, unknown> })
      })

      await Bun.sleep(25)
      client.disconnectSSE()

      expect(events).toHaveLength(1)
      expect(events[0]?.type).toBe("violation")
      expect(events[0]?.timestamp).toBe("2026-03-06T06:00:00Z")
      expect(events[0]?.data.action_type).toBe("shell")
      expect(events[0]?.data.target).toBe("rm -rf /tmp/demo")
      expect(events[0]?.data.decision).toBe("deny")
      expect(events[0]?.data.message).toBe("blocked by policy")
    })

    test("flushes CRLF-delimited SSE frames and normalizes unknown severity to null", async () => {
      const encoder = new TextEncoder()
      globalThis.fetch = mock(async () => new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(encoder.encode("event: check\r\n"))
          controller.enqueue(encoder.encode("data: {\"timestamp\":\"2026-03-06T06:00:01Z\",\"action_type\":\"read\",\"target\":\"/tmp/demo\",\"allowed\":true,\"severity\":\"notice\",\"message\":\"allowed by policy\"}\r\n\r\n"))
          controller.close()
        },
      }), {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      })) as unknown as typeof fetch

      const events: Array<{ type: string; timestamp: string; data: Record<string, unknown> }> = []
      client.connectSSE((event) => {
        events.push(event as { type: string; timestamp: string; data: Record<string, unknown> })
      })

      await Bun.sleep(25)
      client.disconnectSSE()

      expect(events).toHaveLength(1)
      expect(events[0]?.type).toBe("check")
      expect(events[0]?.timestamp).toBe("2026-03-06T06:00:01Z")
      expect(events[0]?.data.decision).toBe("allow")
      expect(events[0]?.data.severity).toBeNull()
    })

    test("strips only the single spec-allowed leading space in SSE event names", async () => {
      const encoder = new TextEncoder()
      globalThis.fetch = mock(async () => new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(encoder.encode("event: violation\n"))
          controller.enqueue(encoder.encode("data: {\"timestamp\":\"2026-03-06T06:00:02Z\",\"action_type\":\"file\",\"target\":\"/tmp/demo\",\"decision\":\"blocked\"}\n\n"))
          controller.close()
        },
      }), {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      })) as unknown as typeof fetch

      const events: Array<{ type: string; timestamp: string; data: Record<string, unknown> }> = []
      client.connectSSE((event) => {
        events.push(event as { type: string; timestamp: string; data: Record<string, unknown> })
      })

      await Bun.sleep(25)
      client.disconnectSSE()

      expect(events).toHaveLength(1)
      expect(events[0]?.type).toBe("violation")
      expect(events[0]?.data.decision).toBe("deny")
    })
  })
})

// =============================================================================
// NAMESPACE TESTS
// =============================================================================

describe("Hushd namespace", () => {
  afterEach(() => {
    Hushd.reset()
    globalThis.fetch = originalFetch
  })

  test("isInitialized returns false before init", () => {
    expect(Hushd.isInitialized()).toBe(false)
  })

  test("init creates client", () => {
    Hushd.init()
    expect(Hushd.isInitialized()).toBe(true)
  })

  test("init with custom URL", () => {
    Hushd.init({ url: "http://custom:9090" })
    expect(Hushd.isInitialized()).toBe(true)
  })

  test("getClient auto-initializes", () => {
    expect(Hushd.isInitialized()).toBe(false)
    const client = Hushd.getClient()
    expect(client).toBeDefined()
    expect(Hushd.isInitialized()).toBe(true)
  })

  test("reset clears client", () => {
    Hushd.init()
    expect(Hushd.isInitialized()).toBe(true)
    Hushd.reset()
    expect(Hushd.isInitialized()).toBe(false)
  })

  test("getClient returns same instance", () => {
    const a = Hushd.getClient()
    const b = Hushd.getClient()
    expect(a).toBe(b)
  })
})
