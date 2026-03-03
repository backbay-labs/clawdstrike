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
  })

  describe("getAudit", () => {
    test("queries audit log with parameters", async () => {
      const mockAudit: AuditResponse = {
        events: [
          {
            id: "evt-1",
            timestamp: new Date().toISOString(),
            action_type: "file",
            target: "/etc/passwd",
            decision: "deny",
            guard: "ForbiddenPathGuard",
            severity: "critical",
            reason: "Path is forbidden",
          },
        ],
        total: 1,
        offset: 0,
        limit: 50,
      }

      mockFetch(new Map([
        ["/api/v1/audit", { status: 200, body: mockAudit }],
      ]))

      const result = await client.getAudit({ limit: 10, decision: "deny" })
      expect(result).not.toBeNull()
      expect(result!.events).toHaveLength(1)
      expect(result!.events[0].decision).toBe("deny")
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
        total_checks: 100,
        allowed: 95,
        denied: 5,
        by_guard: {
          ForbiddenPathGuard: { allowed: 45, denied: 3 },
          SecretLeakGuard: { allowed: 50, denied: 2 },
        },
        by_action_type: {
          file: { allowed: 60, denied: 4 },
          shell: { allowed: 35, denied: 1 },
        },
        since: new Date().toISOString(),
      }

      mockFetch(new Map([
        ["/api/v1/audit/stats", { status: 200, body: mockStats }],
      ]))

      const result = await client.getAuditStats()
      expect(result).not.toBeNull()
      expect(result!.total_checks).toBe(100)
      expect(result!.denied).toBe(5)
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

  describe("SSE", () => {
    test("isSSEConnected returns false when not connected", () => {
      expect(client.isSSEConnected()).toBe(false)
    })

    test("disconnectSSE is safe to call when not connected", () => {
      // Should not throw
      client.disconnectSSE()
      expect(client.isSSEConnected()).toBe(false)
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
