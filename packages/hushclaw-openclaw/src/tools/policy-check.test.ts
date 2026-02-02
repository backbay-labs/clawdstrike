import { describe, it, expect } from 'vitest';
import { policyCheckTool } from './policy-check.js';
import { PolicyEngine } from '../policy/engine.js';
import { homedir } from 'node:os';

describe('policyCheckTool', () => {
  it('has correct schema', () => {
    const engine = new PolicyEngine({ policy: 'hushclaw:ai-agent-minimal', mode: 'deterministic', logLevel: 'error' });
    const tool = policyCheckTool(engine);

    expect(tool.name).toBe('policy_check');
    expect(tool.schema.properties.action).toBeDefined();
    expect(tool.schema.properties.resource).toBeDefined();
    expect(tool.schema.required).toContain('action');
    expect(tool.schema.required).toContain('resource');
  });

  it('returns allowed for permitted action', async () => {
    const engine = new PolicyEngine({ policy: 'hushclaw:ai-agent-minimal', mode: 'deterministic', logLevel: 'error' });
    const tool = policyCheckTool(engine);

    const result = await tool.execute({
      action: 'file_read',
      resource: '/tmp/test.txt',
    } as any);

    expect(result.allowed).toBe(true);
    expect(result.denied).toBe(false);
  });

  it('returns denied for blocked action', async () => {
    const engine = new PolicyEngine({ policy: 'hushclaw:ai-agent-minimal', mode: 'deterministic', logLevel: 'error' });
    const tool = policyCheckTool(engine);

    const result = await tool.execute({
      action: 'file_read',
      resource: `${homedir()}/.ssh/id_rsa`,
    } as any);

    expect(result.allowed).toBe(false);
    expect(result.denied).toBe(true);
    expect(result.guard).toBe('forbidden_path');
  });

  it('provides suggestions for denied actions', async () => {
    const engine = new PolicyEngine({ policy: 'hushclaw:ai-agent-minimal', mode: 'deterministic', logLevel: 'error' });
    const tool = policyCheckTool(engine);

    const result = await tool.execute({
      action: 'file_write',
      resource: `${homedir()}/.ssh/authorized_keys`,
    } as any);

    expect(result.suggestion).toBeDefined();
    expect(result.suggestion).toContain('SSH');
  });

  it('handles egress checks', async () => {
    const engine = new PolicyEngine({ policy: 'hushclaw:ai-agent-minimal', mode: 'deterministic', logLevel: 'error' });
    const tool = policyCheckTool(engine);

    const result = await tool.execute({
      action: 'network',
      resource: 'https://evil.com',
    } as any);

    expect(result.denied).toBe(true);
    expect(result.suggestion).toContain('allowed domain');
  });
});
