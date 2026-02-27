import { describe, expect, it } from 'vitest';

import {
  allowDecision,
  createDecision,
  denyDecision,
  sanitizeDecision,
  warnDecision,
} from './types.js';

describe('decision helpers', () => {
  it('creates sanitize decisions with original/sanitized fields', () => {
    const decision = createDecision('sanitize', {
      reason_code: 'ADC_POLICY_SANITIZE',
      original: 'dangerous text',
      sanitized: 'safe text',
      guard: 'spider_sense',
    });

    expect(decision).toEqual({
      status: 'sanitize',
      reason_code: 'ADC_POLICY_SANITIZE',
      original: 'dangerous text',
      sanitized: 'safe text',
      guard: 'spider_sense',
      severity: undefined,
      message: undefined,
      reason: undefined,
      details: undefined,
    });
  });

  it('enforces reason_code for non-allow statuses', () => {
    expect(() => createDecision('deny', {})).toThrow("reason_code is required for status 'deny'");
    expect(() => createDecision('sanitize', {})).toThrow(
      "reason_code is required for status 'sanitize'",
    );
  });

  it('applies default severities for helper constructors', () => {
    expect(allowDecision()).toMatchObject({ status: 'allow', severity: 'low' });
    expect(
      warnDecision({
        reason_code: 'ADC_POLICY_WARN',
      }),
    ).toMatchObject({ status: 'warn', severity: 'medium' });
    expect(
      denyDecision({
        reason_code: 'ADC_POLICY_DENY',
      }),
    ).toMatchObject({ status: 'deny', severity: 'high' });
    expect(
      sanitizeDecision({
        reason_code: 'ADC_POLICY_SANITIZE',
        sanitized: 'safe',
      }),
    ).toMatchObject({ status: 'sanitize', severity: 'medium', sanitized: 'safe' });
  });
});
