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
});
