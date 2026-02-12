import type { Decision, PolicyEngineLike, PolicyEvent } from '@clawdstrike/adapter-core';
import { failClosed, parsePolicyEvalResponse } from '@clawdstrike/adapter-core';

export interface StrikeCellOptions {
  baseUrl: string;
  token?: string;
  timeoutMs?: number;
}

export function createStrikeCell(options: StrikeCellOptions): PolicyEngineLike {
  const baseUrl = options.baseUrl.replace(/\/+$/, '');
  const timeoutMs = options.timeoutMs ?? 10_000;
  const token = options.token;

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
        return failClosed(error);
      }
    },
  };
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
