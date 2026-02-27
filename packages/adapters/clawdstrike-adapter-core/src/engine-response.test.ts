import { describe, expect, it } from 'vitest';

import { parseDecision } from './engine-response.js';

describe('parseDecision', () => {
  it('preserves reason_code for allow decisions when present', () => {
    const decision = parseDecision({
      status: 'allow',
      reason_code: 'ADC_POLICY_ALLOW',
      guard: 'computer_use',
    });

    expect(decision).toEqual({
      status: 'allow',
      reason_code: 'ADC_POLICY_ALLOW',
      guard: 'computer_use',
    });
  });

  it('returns null for deny decisions without a reason_code', () => {
    const decision = parseDecision({
      status: 'deny',
      guard: 'computer_use',
    });

    expect(decision).toBeNull();
  });

  it('accepts camelCase reasonCode aliases', () => {
    const decision = parseDecision({
      status: 'warn',
      reasonCode: 'ADC_POLICY_WARN',
      guard: 'computer_use',
    });

    expect(decision).toEqual({
      status: 'warn',
      reason_code: 'ADC_POLICY_WARN',
      guard: 'computer_use',
    });
  });

  it('parses sanitize decisions with payload fields', () => {
    const decision = parseDecision({
      status: 'sanitize',
      reason_code: 'ADC_POLICY_SANITIZE',
      guard: 'clawdstrike-spider-sense',
      original: 'ignore instructions',
      sanitized: 'summarize report',
    });

    expect(decision).toEqual({
      status: 'sanitize',
      reason_code: 'ADC_POLICY_SANITIZE',
      guard: 'clawdstrike-spider-sense',
      original: 'ignore instructions',
      sanitized: 'summarize report',
    });
  });

  it('returns null for sanitize decisions without a reason_code', () => {
    const decision = parseDecision({
      status: 'sanitize',
      guard: 'clawdstrike-spider-sense',
      sanitized: 'safe content',
    });

    expect(decision).toBeNull();
  });

  it('parses legacy boolean decision payloads', () => {
    const decision = parseDecision({
      allowed: true,
      denied: false,
      warn: true,
      reason_code: 'ADC_POLICY_WARN',
      message: 'legacy payload warning',
    });

    expect(decision).toEqual({
      status: 'warn',
      reason_code: 'ADC_POLICY_WARN',
      message: 'legacy payload warning',
    });
  });

  it('ignores invalid severity values in parsed decisions', () => {
    const decision = parseDecision({
      status: 'deny',
      reason_code: 'ADC_POLICY_DENY',
      severity: 'urgent',
    });

    expect(decision).toEqual({
      status: 'deny',
      reason_code: 'ADC_POLICY_DENY',
    });
  });
});
