import { describe, it, expect } from 'vitest';
import { validatePolicy } from './validator.js';

describe('validatePolicy', () => {
  it('validates a minimal valid policy', () => {
    const policy = { version: 'hushclaw-v1.0' };
    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('validates a full policy', () => {
    const policy = {
      version: 'hushclaw-v1.0',
      egress: {
        mode: 'allowlist',
        allowed_domains: ['api.github.com'],
      },
      filesystem: {
        forbidden_paths: ['~/.ssh'],
      },
      on_violation: 'cancel',
    };
    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
  });

  it('rejects invalid egress mode', () => {
    const policy = {
      egress: { mode: 'invalid' },
    };
    const result = validatePolicy(policy as any);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('egress.mode');
  });

  it('rejects invalid on_violation', () => {
    const policy = {
      on_violation: 'explode',
    };
    const result = validatePolicy(policy as any);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('on_violation');
  });

  it('warns on empty forbidden_paths', () => {
    const policy = {
      filesystem: { forbidden_paths: [] },
    };
    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.warnings[0]).toContain('empty');
  });
});
