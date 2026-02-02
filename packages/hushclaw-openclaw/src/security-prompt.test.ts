import { describe, it, expect } from 'vitest';
import { generateSecurityPrompt } from './security-prompt.js';
import type { Policy } from './types.js';

describe('generateSecurityPrompt', () => {
  it('generates prompt with allowlist egress info', () => {
    const policy: Policy = {
      egress: {
        mode: 'allowlist',
        allowed_domains: ['api.github.com', 'pypi.org'],
      },
    };
    const prompt = generateSecurityPrompt(policy);
    expect(prompt).toContain('api.github.com');
    expect(prompt).toContain('pypi.org');
    expect(prompt).toContain('allowed');
  });

  it('includes forbidden paths', () => {
    const policy: Policy = {
      filesystem: {
        forbidden_paths: ['~/.ssh', '~/.aws'],
      },
    };
    const prompt = generateSecurityPrompt(policy);
    expect(prompt).toContain('~/.ssh');
    expect(prompt).toContain('~/.aws');
    expect(prompt).toContain('FORBIDDEN');
  });

  it('includes violation handling info', () => {
    const policy: Policy = {
      on_violation: 'cancel',
    };
    const prompt = generateSecurityPrompt(policy);
    expect(prompt).toContain('BLOCKED');
  });

  it('mentions policy_check tool', () => {
    const prompt = generateSecurityPrompt({});
    expect(prompt).toContain('policy_check');
  });

  it('handles empty config gracefully', () => {
    const prompt = generateSecurityPrompt({});
    expect(prompt).toContain('Security Policy');
    expect(typeof prompt).toBe('string');
    expect(prompt.length).toBeGreaterThan(100);
  });
});
