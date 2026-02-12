import type { Decision } from './types.js';

export type PolicyEvalResponseV1 = {
  version: 1;
  command: 'policy_eval';
  decision: Decision;
};

export function parsePolicyEvalResponse(raw: string, label = 'hush'): PolicyEvalResponseV1 {
  const parsed = JSON.parse(raw) as unknown;
  if (!isRecord(parsed)) {
    throw new Error(`Invalid ${label} JSON: expected object`);
  }

  if (parsed.version !== 1) {
    throw new Error(`Invalid ${label} JSON: expected version=1`);
  }

  if (parsed.command !== 'policy_eval') {
    throw new Error(`Invalid ${label} JSON: expected command="policy_eval"`);
  }

  const decision = parseDecision(parsed.decision);
  if (!decision) {
    throw new Error(`Invalid ${label} JSON: missing/invalid decision`);
  }

  return {
    version: 1,
    command: 'policy_eval',
    decision,
  };
}

export function parseDecision(value: unknown): Decision | null {
  if (!isRecord(value)) {
    return null;
  }

  const status =
    value.status === 'allow' || value.status === 'warn' || value.status === 'deny'
      ? value.status
      : typeof value.allowed === 'boolean' && typeof value.denied === 'boolean' && typeof value.warn === 'boolean'
        ? value.denied
          ? 'deny'
          : value.warn
            ? 'warn'
            : 'allow'
        : null;

  if (!status) {
    return null;
  }

  const decision: Decision = { status };

  if (typeof value.reason === 'string') {
    decision.reason = value.reason;
  }

  if (typeof value.guard === 'string') {
    decision.guard = value.guard;
  }

  if (typeof value.message === 'string') {
    decision.message = value.message;
  }

  if (value.severity === 'low' || value.severity === 'medium' || value.severity === 'high' || value.severity === 'critical') {
    decision.severity = value.severity;
  }

  return decision;
}

export function failClosed(error: unknown): Decision {
  const message = error instanceof Error ? error.message : String(error);
  return {
    status: 'deny',
    reason: 'engine_error',
    message,
  };
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
