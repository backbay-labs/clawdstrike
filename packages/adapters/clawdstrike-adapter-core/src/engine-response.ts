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

  const decision = parseDecision(parsed.decision, parsed.report);
  if (!decision) {
    throw new Error(`Invalid ${label} JSON: missing/invalid decision`);
  }

  return {
    version: 1,
    command: 'policy_eval',
    decision,
  };
}

export function parseDecision(value: unknown, report?: unknown): Decision | null {
  if (!isRecord(value)) {
    return null;
  }

  const legacySanitizePayload = extractLegacySanitizePayload(value, report);
  const legacyStatus = typeof value.allowed === 'boolean'
    && typeof value.denied === 'boolean'
    && typeof value.warn === 'boolean'
    ? value.denied
      ? 'deny'
      : legacySanitizePayload
        ? 'sanitize'
        : value.warn
          ? 'warn'
          : 'allow'
    : null;

  const status =
    value.status === 'allow' || value.status === 'warn' || value.status === 'deny' || value.status === 'sanitize'
      ? value.status
      : legacyStatus;

  if (!status) {
    return null;
  }

  const reasonCode = typeof value.reason_code === 'string'
    ? value.reason_code
    : typeof value.reasonCode === 'string'
      ? value.reasonCode
      : null;
  if (status !== 'allow' && !reasonCode) {
    return null;
  }

  const decision: Decision = status === 'allow'
    ? (reasonCode ? { status, reason_code: reasonCode } : { status })
    : { status, reason_code: reasonCode as string };

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

  if (status === 'sanitize') {
    const d = decision as unknown as Record<string, unknown>;
    const details = value.details !== undefined ? value.details : legacySanitizePayload?.details;
    if (details !== undefined) {
      d.details = details;
    }

    const original = typeof value.original === 'string' ? value.original : legacySanitizePayload?.original;
    const sanitized = typeof value.sanitized === 'string' ? value.sanitized : legacySanitizePayload?.sanitized;
    if (original !== undefined) {
      d.original = original;
    }
    if (sanitized !== undefined) {
      d.sanitized = sanitized;
    }
  }

  return decision;
}

type SanitizePayload = {
  original?: string;
  sanitized?: string;
  details: Record<string, unknown>;
};

function extractLegacySanitizePayload(
  value: Record<string, unknown>,
  report: unknown,
): SanitizePayload | null {
  const fromDecisionDetails = extractSanitizePayload(value.details);
  if (fromDecisionDetails) {
    return fromDecisionDetails;
  }

  if (!isRecord(report)) {
    return null;
  }

  const overall = report.overall;
  if (!isRecord(overall)) {
    return null;
  }

  return extractSanitizePayload(overall.details);
}

function extractSanitizePayload(details: unknown): SanitizePayload | null {
  if (!isRecord(details)) {
    return null;
  }

  if (details.action !== 'sanitized') {
    return null;
  }

  const payload: SanitizePayload = { details };
  if (typeof details.original === 'string') {
    payload.original = details.original;
  }
  if (typeof details.sanitized === 'string') {
    payload.sanitized = details.sanitized;
  }
  return payload;
}

export function failClosed(error: unknown): Decision {
  const message = error instanceof Error ? error.message : String(error);
  return {
    status: 'deny',
    reason_code: 'ADC_GUARD_ERROR',
    reason: 'engine_error',
    message,
  };
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
