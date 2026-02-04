import { describe, it, expect } from 'vitest';
import { validatePolicy } from './validator.js';

describe('validatePolicy', () => {
  it('validates a minimal valid policy', () => {
    const policy = { version: 'clawdstrike-v1.0' };
    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('validates a full policy', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
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
      version: 'clawdstrike-v1.0',
      egress: { mode: 'invalid' },
    };
    const result = validatePolicy(policy as any);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('egress.mode'))).toBe(true);
  });

  it('rejects invalid on_violation', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      on_violation: 'explode',
    };
    const result = validatePolicy(policy as any);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('on_violation'))).toBe(true);
  });

  it('warns on empty forbidden_paths', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      filesystem: { forbidden_paths: [] },
    };
    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.warnings[0]).toContain('empty');
  });

  it('fails closed when a required env placeholder is missing (custom guards)', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      guards: {
        custom: [
          { package: 'clawdstrike-virustotal', config: { api_key: '${VT_API_KEY}' } },
        ],
      },
    };
    const result = validatePolicy(policy as any);
    expect(result.valid).toBe(false);
    expect(result.errors.join('\n')).toMatch(/missing environment variable/i);
  });
});
