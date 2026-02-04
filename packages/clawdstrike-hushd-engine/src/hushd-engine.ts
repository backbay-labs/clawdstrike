import type { Decision, PolicyEngineLike, PolicyEvent } from '@clawdstrike/adapter-core';

export interface HushdEngineOptions {
  baseUrl: string;
  token?: string;
  timeoutMs?: number;
}

type HushPolicyEvalResponseV1 = {
  version: 1;
  command: 'policy_eval';
  decision: Decision;
};

export function createHushdEngine(options: HushdEngineOptions): PolicyEngineLike {
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
        const parsed = parsePolicyEvalResponse(response);
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

function parsePolicyEvalResponse(raw: string): HushPolicyEvalResponseV1 {
  const parsed = JSON.parse(raw) as unknown;
  if (!isRecord(parsed)) {
    throw new Error('Invalid hushd JSON: expected object');
  }

  if (parsed.version !== 1) {
    throw new Error(`Invalid hushd JSON: expected version=1`);
  }

  if (parsed.command !== 'policy_eval') {
    throw new Error(`Invalid hushd JSON: expected command="policy_eval"`);
  }

  const decision = parseDecision(parsed.decision);
  if (!decision) {
    throw new Error(`Invalid hushd JSON: missing/invalid decision`);
  }

  return {
    version: 1,
    command: 'policy_eval',
    decision,
  };
}

function parseDecision(value: unknown): Decision | null {
  if (!isRecord(value)) {
    return null;
  }

  if (
    typeof value.allowed !== 'boolean' ||
    typeof value.denied !== 'boolean' ||
    typeof value.warn !== 'boolean'
  ) {
    return null;
  }

  const decision: Decision = {
    allowed: value.allowed,
    denied: value.denied,
    warn: value.warn,
  };

  if (typeof value.reason === 'string') {
    decision.reason = value.reason;
  }

  if (typeof value.guard === 'string') {
    decision.guard = value.guard;
  }

  if (typeof value.message === 'string') {
    decision.message = value.message;
  }

  if (
    value.severity === 'low' ||
    value.severity === 'medium' ||
    value.severity === 'high' ||
    value.severity === 'critical'
  ) {
    decision.severity = value.severity;
  }

  return decision;
}

function failClosed(error: unknown): Decision {
  const message = error instanceof Error ? error.message : String(error);
  return {
    allowed: false,
    denied: true,
    warn: false,
    reason: 'engine_error',
    message,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

