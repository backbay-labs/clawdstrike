import { describe, it, expect } from 'vitest';
import { policyCheckTool } from './policy-check.js';
import { PolicyEngine } from '../policy/engine.js';
import type { PolicyConfig } from '../policy/types.js';

describe('policyCheckTool', () => {
  it('has correct schema', () => {
    const engine = new PolicyEngine({});
    const tool = policyCheckTool(engine);

    expect(tool.name).toBe('policy_check');
    expect(tool.schema.properties.action).toBeDefined();
    expect(tool.schema.properties.resource).toBeDefined();
    expect(tool.schema.required).toContain('action');
    expect(tool.schema.required).toContain('resource');
  });

  it('returns allowed for permitted action', async () => {
    const policy: PolicyConfig = {
      filesystem: {
        forbidden_paths: ['~/.ssh'],
      },
    };
    const engine = new PolicyEngine(policy);
    const tool = policyCheckTool(engine);

    const result = await tool.execute({
      action: 'file_read',
      resource: '/tmp/test.txt',
    });

    expect(result.allowed).toBe(true);
    expect(result.denied).toBe(false);
  });

  it('returns denied for blocked action', async () => {
    const policy: PolicyConfig = {
      filesystem: {
        forbidden_paths: ['~/.ssh'],
      },
    };
    const engine = new PolicyEngine(policy);
    const tool = policyCheckTool(engine);

    const result = await tool.execute({
      action: 'file_read',
      resource: '~/.ssh/id_rsa',
    });

    expect(result.allowed).toBe(false);
    expect(result.denied).toBe(true);
    expect(result.guard).toBe('ForbiddenPathGuard');
  });

  it('provides suggestions for denied actions', async () => {
    const policy: PolicyConfig = {
      filesystem: {
        forbidden_paths: ['~/.ssh'],
      },
    };
    const engine = new PolicyEngine(policy);
    const tool = policyCheckTool(engine);

    const result = await tool.execute({
      action: 'file_write',
      resource: '~/.ssh/authorized_keys',
    });

    expect(result.suggestion).toBeDefined();
    expect(result.suggestion).toContain('SSH');
  });

  it('handles egress checks', async () => {
    const policy: PolicyConfig = {
      egress: {
        mode: 'allowlist',
        allowed_domains: ['api.github.com'],
      },
    };
    const engine = new PolicyEngine(policy);
    const tool = policyCheckTool(engine);

    const result = await tool.execute({
      action: 'network_egress',
      resource: 'https://evil.com',
    });

    expect(result.denied).toBe(true);
    expect(result.suggestion).toContain('allowed domain');
  });
});
