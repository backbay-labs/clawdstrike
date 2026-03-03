/**
 * Hushd - Client module for the hushd security daemon
 *
 * Provides init/getClient/reset lifecycle for the hushd HTTP client.
 * Default URL: http://127.0.0.1:8080, override via CLAWDSTRIKE_HUSHD_URL.
 */

import { HushdClient } from "./client"

export type { HushdClient } from "./client"
export type {
  CheckRequest,
  CheckResponse,
  GuardResult,
  PostureInfo,
  AuditQuery,
  AuditEvent,
  AuditResponse,
  AuditStats,
  PolicyResponse,
  PolicyGuardConfig,
  DaemonEvent,
  CheckEventData,
  PolicyReloadData,
  ErrorData,
  HushdConnectionState,
} from "./types"

const DEFAULT_URL = "http://127.0.0.1:8080"

let client: HushdClient | null = null

/**
 * Hushd namespace - Security daemon client lifecycle
 */
export namespace Hushd {
  /**
   * Initialize the hushd client.
   * Uses CLAWDSTRIKE_HUSHD_URL env var or default (http://127.0.0.1:8080).
   */
  export function init(options?: { url?: string; token?: string }): void {
    const url = options?.url ?? process.env.CLAWDSTRIKE_HUSHD_URL ?? DEFAULT_URL
    const token = options?.token ?? process.env.CLAWDSTRIKE_HUSHD_TOKEN
    client = new HushdClient(url, token)
  }

  /**
   * Get the hushd client instance.
   * Initializes with defaults if not already initialized.
   */
  export function getClient(): HushdClient {
    if (!client) {
      init()
    }
    return client!
  }

  /**
   * Reset the hushd client (disconnect SSE, clear instance).
   */
  export function reset(): void {
    if (client) {
      client.disconnectSSE()
      client = null
    }
  }

  /**
   * Check if hushd client is initialized.
   */
  export function isInitialized(): boolean {
    return client !== null
  }
}

export default Hushd
