import type { Decision, PolicyEngineLike, PolicyEvent } from '@clawdstrike/adapter-core';
import { failClosed, parsePolicyEvalResponse } from '@clawdstrike/adapter-core';

export interface StrikeCellOptions {
  baseUrl: string;
  token?: string;
  timeoutMs?: number;
  /** Optional fallback engine to use when hushd is unreachable. */
  fallback?: PolicyEngineLike;
  /**
   * When true (default), connectivity failures trigger the fallback engine
   * instead of an immediate fail-closed deny. Set to false to always fail
   * closed without fallback.
   */
  offlineFallback?: boolean;
}

/**
 * Provenance metadata attached to offline-mode decisions.
 */
const DEGRADED_PROVENANCE = { mode: 'degraded' as const };

export function createStrikeCell(options: StrikeCellOptions): PolicyEngineLike {
  const baseUrl = options.baseUrl.replace(/\/+$/, '');
  const timeoutMs = options.timeoutMs ?? 10_000;
  const token = options.token;
  const fallback = options.fallback;
  const offlineFallback = options.offlineFallback ?? true;

  return {
    async evaluate(event: PolicyEvent): Promise<Decision> {
      try {
        const response = await postJson(
          `${baseUrl}/api/v1/eval`,
          { event },
          token,
          timeoutMs,
        );
        const parsed = parsePolicyEvalResponse(response, 'hushd');
        return parsed.decision;
      } catch (error) {
        // If offline fallback is enabled and we have a fallback engine,
        // delegate to it instead of blanket deny.
        if (offlineFallback && fallback && isConnectivityError(error)) {
          try {
            const decision = await fallback.evaluate(event);
            return {
              ...decision,
              details: {
                ...(typeof decision.details === 'object' && decision.details !== null
                  ? decision.details
                  : {}),
                provenance: DEGRADED_PROVENANCE,
              },
            };
          } catch (fallbackError) {
            return failClosed(fallbackError);
          }
        }

        return failClosed(error);
      }
    },
  };
}

/**
 * Check whether an error represents a connectivity failure (as opposed to
 * a server-side error like 4xx/5xx which should still fail closed).
 */
function isConnectivityError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const msg = error.message.toLowerCase();
  return (
    msg.includes('econnrefused') ||
    msg.includes('econnreset') ||
    msg.includes('enotfound') ||
    msg.includes('fetch failed') ||
    msg.includes('network') ||
    msg.includes('abort') ||
    msg.includes('timeout') ||
    msg.includes('etimedout')
  );
}

async function postJson(
  url: string,
  body: unknown,
  token: string | undefined,
  timeoutMs: number,
): Promise<string> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  timeoutId.unref?.();

  try {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
    };
    if (token) {
      headers.authorization = `Bearer ${token}`;
    }

    const resp = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    const text = await resp.text();
    if (!resp.ok) {
      const truncated = text.length > 2048 ? `${text.slice(0, 2048)}…` : text;
      throw new Error(`hushd returned ${resp.status}: ${truncated}`);
    }
    return text;
  } finally {
    clearTimeout(timeoutId);
  }
}
