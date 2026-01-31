/**
 * @hushclaw/openclaw - Policy Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { homedir } from 'os';
import { PolicyEngine } from '../src/policy/engine.js';
import { loadPolicy, PolicyLoadError } from '../src/policy/loader.js';
import { validatePolicy } from '../src/policy/validator.js';
import type { Policy, PolicyEvent, HushClawConfig } from '../src/types.js';

const HOME = homedir();

describe('PolicyEngine', () => {
  let engine: PolicyEngine;
  const config: HushClawConfig = {
    policy: 'hushclaw:ai-agent-minimal',
    mode: 'deterministic',
    logLevel: 'error',
  };

  beforeEach(() => {
    engine = new PolicyEngine(config);
  });

  it('should initialize with config', () => {
    expect(engine).toBeDefined();
    expect(engine.enabledGuards()).toContain('forbidden_path');
    expect(engine.enabledGuards()).toContain('egress');
  });

  it('should evaluate file read events', async () => {
    const event: PolicyEvent = {
      eventId: 'test-1',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: '/project/src/index.ts',
        operation: 'read',
      },
    };

    const decision = await engine.evaluate(event);
    expect(decision.allowed).toBe(true);
    expect(decision.denied).toBe(false);
  });

  it('should deny access to SSH keys', async () => {
    const event: PolicyEvent = {
      eventId: 'test-2',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: `${HOME}/.ssh/id_rsa`,
        operation: 'read',
      },
    };

    const decision = await engine.evaluate(event);
    expect(decision.denied).toBe(true);
    expect(decision.guard).toBe('forbidden_path');
  });

  it('should respect mode=advisory (warn but allow)', async () => {
    const advisoryEngine = new PolicyEngine({
      ...config,
      mode: 'advisory',
    });

    const event: PolicyEvent = {
      eventId: 'test-3',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: `${HOME}/.ssh/id_rsa`,
        operation: 'read',
      },
    };

    const decision = await advisoryEngine.evaluate(event);
    expect(decision.allowed).toBe(true);
    expect(decision.warn).toBe(true);
    expect(decision.denied).toBe(false);
  });

  it('should respect mode=audit (always allow)', async () => {
    const auditEngine = new PolicyEngine({
      ...config,
      mode: 'audit',
    });

    const event: PolicyEvent = {
      eventId: 'test-4',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: {
        type: 'file',
        path: `${HOME}/.ssh/id_rsa`,
        operation: 'read',
      },
    };

    const decision = await auditEngine.evaluate(event);
    expect(decision.allowed).toBe(true);
    expect(decision.denied).toBe(false);
  });

  it('should redact secrets from content', () => {
    const content = 'API_KEY=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
    const redacted = engine.redactSecrets(content);
    expect(redacted).toContain('[REDACTED]');
  });

  it('should lint valid policy', async () => {
    const result = await engine.lintPolicy('hushclaw:ai-agent-minimal');
    expect(result.valid).toBe(true);
  });

  it('should return current policy', () => {
    const policy = engine.getPolicy();
    expect(policy).toBeDefined();
    expect(policy.version).toBe('hushclaw-v1.0');
  });
});

describe('validatePolicy', () => {
  it('should validate correct policy', () => {
    const policy: Policy = {
      version: 'test-v1',
      egress: {
        mode: 'allowlist',
        allowed_domains: ['example.com'],
      },
      on_violation: 'cancel',
    };

    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('should reject invalid egress mode', () => {
    const policy = {
      egress: {
        mode: 'invalid' as any,
      },
    };

    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('egress.mode'))).toBe(true);
  });

  it('should reject invalid on_violation action', () => {
    const policy: Policy = {
      on_violation: 'invalid' as any,
    };

    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('on_violation'))).toBe(true);
  });

  it('should warn about allowlist mode without domains', () => {
    const policy: Policy = {
      egress: {
        mode: 'allowlist',
        allowed_domains: [],
      },
    };

    const result = validatePolicy(policy);
    expect(result.warnings.some((w) => w.includes('allowlist'))).toBe(true);
  });

  it('should reject paths with null bytes', () => {
    const policy: Policy = {
      filesystem: {
        forbidden_paths: ['/etc/passwd\x00.txt'],
      },
    };

    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('null byte'))).toBe(true);
  });

  it('should reject invalid regex in denied_patterns', () => {
    const policy: Policy = {
      execution: {
        denied_patterns: ['[invalid(regex'],
      },
    };

    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('invalid regex'))).toBe(true);
  });

  it('should validate limits as positive numbers', () => {
    const policy: Policy = {
      limits: {
        max_execution_seconds: -10,
      },
    };

    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('positive number'))).toBe(true);
  });
});

describe('loadPolicy', () => {
  it('should load built-in ai-agent-minimal policy', () => {
    const policy = loadPolicy('hushclaw:ai-agent-minimal');
    expect(policy).toBeDefined();
    expect(policy.version).toBe('hushclaw-v1.0');
    expect(policy.egress?.mode).toBe('allowlist');
  });

  it('should throw for unknown built-in policy', () => {
    expect(() => loadPolicy('hushclaw:nonexistent')).toThrow(PolicyLoadError);
  });

  it('should throw for missing file', () => {
    expect(() => loadPolicy('/nonexistent/policy.yaml')).toThrow(PolicyLoadError);
  });
});
