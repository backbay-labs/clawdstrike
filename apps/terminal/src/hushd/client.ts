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
  AuditEvent,
  AuditBatchResponse,
  AuditStats,
  DaemonEvent,
} from "./types"

const DEFAULT_TIMEOUT = 5000

export interface HushdRequestResult<T> {
  ok: boolean
  status: number | null
  data?: T
  error?: string
}

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

  private async requestJson<T>(
    path: string,
    init: RequestInit = {},
    timeoutMs = DEFAULT_TIMEOUT,
  ): Promise<HushdRequestResult<T>> {
    try {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), timeoutMs)
      const res = await fetch(`${this.baseUrl}${path}`, {
        ...init,
        headers: {
          ...this.headers(),
          ...(init.headers as Record<string, string> | undefined),
        },
        signal: controller.signal,
      })
      clearTimeout(timeout)

      const bodyText = await res.text()
      if (!res.ok) {
        return {
          ok: false,
          status: res.status,
          error: bodyText.trim() || `HTTP ${res.status}`,
        }
      }

      if (!bodyText.trim()) {
        return { ok: true, status: res.status }
      }

      try {
        return {
          ok: true,
          status: res.status,
          data: JSON.parse(bodyText) as T,
        }
      } catch {
        return {
          ok: false,
          status: res.status,
          error: `Failed to parse JSON response: ${bodyText.slice(0, 200)}`,
        }
      }
    } catch (err) {
      return {
        ok: false,
        status: null,
        error: err instanceof Error ? err.message : String(err),
      }
    }
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
    const result = await this.checkDetailed(req)
    return result.data ?? null
  }

  async checkDetailed(req: CheckRequest): Promise<HushdRequestResult<CheckResponse>> {
    return this.requestJson<CheckResponse>("/api/v1/check", {
      method: "POST",
      body: JSON.stringify(req),
    })
  }

  // ===========================================================================
  // POLICY API
  // ===========================================================================

  /**
   * Get active policy configuration. Returns null on connectivity error.
   */
  async getPolicy(): Promise<PolicyResponse | null> {
    const result = await this.getPolicyDetailed()
    return result.data ?? null
  }

  async getPolicyDetailed(): Promise<HushdRequestResult<PolicyResponse>> {
    return this.requestJson<PolicyResponse>("/api/v1/policy", {
      method: "GET",
    })
  }

  // ===========================================================================
  // AUDIT API
  // ===========================================================================

  /**
   * Query audit log. Returns null on connectivity error.
   */
  async getAudit(query?: AuditQuery): Promise<AuditResponse | null> {
    const result = await this.getAuditDetailed(query)
    return result.data ?? null
  }

  async getAuditDetailed(query?: AuditQuery): Promise<HushdRequestResult<AuditResponse>> {
    try {
      const params = new URLSearchParams()
      if (query) {
        if (query.limit !== undefined) params.set("limit", String(query.limit))
        if (query.offset !== undefined) params.set("offset", String(query.offset))
        if (query.cursor) params.set("cursor", query.cursor)
        if (query.event_type) params.set("event_type", query.event_type)
        if (query.action_type) params.set("action_type", query.action_type)
        if (query.decision) params.set("decision", query.decision)
        if (query.guard) params.set("guard", query.guard)
        if (query.session_id) params.set("session_id", query.session_id)
        if (query.agent_id) params.set("agent_id", query.agent_id)
        if (query.runtime_agent_id) params.set("runtime_agent_id", query.runtime_agent_id)
        if (query.runtime_agent_kind) params.set("runtime_agent_kind", query.runtime_agent_kind)
        if (query.format) params.set("format", query.format)
      }

      const qs = params.toString()
      return this.requestJson<AuditResponse>(`/api/v1/audit${qs ? `?${qs}` : ""}`, {
        method: "GET",
      })
    } catch (err) {
      return {
        ok: false,
        status: null,
        error: err instanceof Error ? err.message : String(err),
      }
    }
  }

  /**
   * Get audit statistics. Returns null on connectivity error.
   */
  async getAuditStats(): Promise<AuditStats | null> {
    const result = await this.getAuditStatsDetailed()
    return result.data ?? null
  }

  async getAuditStatsDetailed(): Promise<HushdRequestResult<AuditStats>> {
    return this.requestJson<AuditStats>("/api/v1/audit/stats", {
      method: "GET",
    })
  }

  async ingestAuditBatch(events: AuditEvent[]): Promise<HushdRequestResult<AuditBatchResponse>> {
    return this.requestJson<AuditBatchResponse>("/api/v1/audit/batch", {
      method: "POST",
      body: JSON.stringify({ events }),
    })
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
