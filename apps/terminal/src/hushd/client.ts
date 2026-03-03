/**
 * Hushd Client - HTTP + SSE client for the hushd daemon
 *
 * Lightweight client using native fetch (no dependencies).
 * All methods return null on connectivity errors (never throw).
 * SSE uses manual fetch with streaming body (Bun lacks native EventSource).
 */

import type {
  CheckRequest,
  CheckResponse,
  PolicyResponse,
  AuditQuery,
  AuditResponse,
  AuditStats,
  DaemonEvent,
} from "./types"

const DEFAULT_TIMEOUT = 5000

export class HushdClient {
  private baseUrl: string
  private token?: string
  private sseController: AbortController | null = null

  constructor(baseUrl: string, token?: string) {
    // Strip trailing slash
    this.baseUrl = baseUrl.replace(/\/$/, "")
    this.token = token
  }

  // ===========================================================================
  // HEADERS
  // ===========================================================================

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      "Content-Type": "application/json",
    }
    if (this.token) {
      h["Authorization"] = `Bearer ${this.token}`
    }
    return h
  }

  // ===========================================================================
  // HEALTH
  // ===========================================================================

  /**
   * Probe hushd health endpoint. Returns true if daemon is reachable.
   */
  async probe(timeoutMs?: number): Promise<boolean> {
    try {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), timeoutMs ?? DEFAULT_TIMEOUT)
      const res = await fetch(`${this.baseUrl}/health`, {
        signal: controller.signal,
      })
      clearTimeout(timeout)
      return res.ok
    } catch {
      return false
    }
  }

  // ===========================================================================
  // CHECK API
  // ===========================================================================

  /**
   * Submit an action for policy check. Returns null on connectivity error.
   */
  async check(req: CheckRequest): Promise<CheckResponse | null> {
    try {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT)
      const res = await fetch(`${this.baseUrl}/api/v1/check`, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify(req),
        signal: controller.signal,
      })
      clearTimeout(timeout)
      if (!res.ok) return null
      return (await res.json()) as CheckResponse
    } catch {
      return null
    }
  }

  // ===========================================================================
  // POLICY API
  // ===========================================================================

  /**
   * Get active policy configuration. Returns null on connectivity error.
   */
  async getPolicy(): Promise<PolicyResponse | null> {
    try {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT)
      const res = await fetch(`${this.baseUrl}/api/v1/policy`, {
        headers: this.headers(),
        signal: controller.signal,
      })
      clearTimeout(timeout)
      if (!res.ok) return null
      return (await res.json()) as PolicyResponse
    } catch {
      return null
    }
  }

  // ===========================================================================
  // AUDIT API
  // ===========================================================================

  /**
   * Query audit log. Returns null on connectivity error.
   */
  async getAudit(query?: AuditQuery): Promise<AuditResponse | null> {
    try {
      const params = new URLSearchParams()
      if (query) {
        if (query.limit !== undefined) params.set("limit", String(query.limit))
        if (query.offset !== undefined) params.set("offset", String(query.offset))
        if (query.action_type) params.set("action_type", query.action_type)
        if (query.decision) params.set("decision", query.decision)
        if (query.guard) params.set("guard", query.guard)
        if (query.since) params.set("since", query.since)
        if (query.until) params.set("until", query.until)
      }

      const qs = params.toString()
      const url = `${this.baseUrl}/api/v1/audit${qs ? `?${qs}` : ""}`

      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT)
      const res = await fetch(url, {
        headers: this.headers(),
        signal: controller.signal,
      })
      clearTimeout(timeout)
      if (!res.ok) return null
      return (await res.json()) as AuditResponse
    } catch {
      return null
    }
  }

  /**
   * Get audit statistics. Returns null on connectivity error.
   */
  async getAuditStats(): Promise<AuditStats | null> {
    try {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT)
      const res = await fetch(`${this.baseUrl}/api/v1/audit/stats`, {
        headers: this.headers(),
        signal: controller.signal,
      })
      clearTimeout(timeout)
      if (!res.ok) return null
      return (await res.json()) as AuditStats
    } catch {
      return null
    }
  }

  // ===========================================================================
  // SSE (Server-Sent Events)
  // ===========================================================================

  /**
   * Connect to hushd SSE event stream.
   * Uses manual fetch with streaming body (Bun lacks native EventSource).
   */
  connectSSE(
    onEvent: (e: DaemonEvent) => void,
    onError?: (err: Error) => void
  ): void {
    // Disconnect existing connection first
    this.disconnectSSE()

    this.sseController = new AbortController()
    const signal = this.sseController.signal

    const connect = async () => {
      try {
        const res = await fetch(`${this.baseUrl}/api/v1/events`, {
          headers: {
            Accept: "text/event-stream",
            ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
          },
          signal,
        })

        if (!res.ok || !res.body) {
          onError?.(new Error(`SSE connection failed: ${res.status}`))
          return
        }

        const reader = res.body.getReader()
        const decoder = new TextDecoder()
        let buffer = ""

        while (true) {
          const { done, value } = await reader.read()
          if (done) break

          buffer += decoder.decode(value, { stream: true })

          // Parse SSE frames
          const lines = buffer.split("\n")
          buffer = lines.pop() ?? ""

          let eventData = ""
          for (const line of lines) {
            if (line.startsWith("data: ")) {
              eventData += line.slice(6)
            } else if (line === "" && eventData) {
              // End of event
              try {
                const event = JSON.parse(eventData) as DaemonEvent
                onEvent(event)
              } catch {
                // Skip malformed events
              }
              eventData = ""
            }
          }
        }
      } catch (err) {
        if (signal.aborted) return // Expected disconnect
        onError?.(err instanceof Error ? err : new Error(String(err)))
      }
    }

    connect()
  }

  /**
   * Disconnect from SSE event stream.
   */
  disconnectSSE(): void {
    if (this.sseController) {
      this.sseController.abort()
      this.sseController = null
    }
  }

  /**
   * Check if SSE is currently connected.
   */
  isSSEConnected(): boolean {
    return this.sseController !== null && !this.sseController.signal.aborted
  }
}
