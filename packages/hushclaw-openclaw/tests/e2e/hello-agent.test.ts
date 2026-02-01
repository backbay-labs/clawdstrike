import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PolicyEngine } from '../../src/policy/engine.js';
import { loadPolicy } from '../../src/policy/loader.js';
import { policyCheckTool } from '../../src/tools/policy-check.js';
import { generateSecurityPrompt } from '../../src/security-prompt.js';
import { mkdirSync, rmSync, existsSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

describe('Hello Secure Agent E2E', () => {
  const exampleDir = join(__dirname, '../../examples/hello-secure-agent');
  let engine: PolicyEngine;
  let tool: ReturnType<typeof policyCheckTool>;

  beforeAll(async () => {
    const policy = await loadPolicy(join(exampleDir, 'policy.yaml'));
    engine = new PolicyEngine(policy);
    tool = policyCheckTool(engine);

    // Create test directory
    if (!existsSync('/tmp/hello-agent')) {
      mkdirSync('/tmp/hello-agent', { recursive: true });
    }
  });

  afterAll(() => {
    rmSync('/tmp/hello-agent', { recursive: true, force: true });
  });

  describe('Filesystem Guards', () => {
    it('blocks forbidden path access (~/.ssh)', async () => {
      const result = await tool.execute({
        action: 'file_read',
        resource: '~/.ssh/id_rsa',
      });
      expect(result.denied).toBe(true);
      expect(result.guard).toBe('ForbiddenPathGuard');
    });

    it('blocks forbidden path access (~/.aws)', async () => {
      const result = await tool.execute({
        action: 'file_read',
        resource: '~/.aws/credentials',
      });
      expect(result.denied).toBe(true);
      expect(result.guard).toBe('ForbiddenPathGuard');
    });

    it('blocks .env file access', async () => {
      const result = await tool.execute({
        action: 'file_read',
        resource: '/workspace/.env',
      });
      expect(result.denied).toBe(true);
    });

    it('allows writes to /tmp/hello-agent', async () => {
      const result = await tool.execute({
        action: 'file_write',
        resource: '/tmp/hello-agent/test.txt',
      });
      expect(result.allowed).toBe(true);
    });

    it('blocks writes outside allowed roots', async () => {
      const result = await tool.execute({
        action: 'file_write',
        resource: '/etc/passwd',
      });
      expect(result.denied).toBe(true);
    });
  });

  describe('Egress Guards', () => {
    it('blocks non-allowlisted domains', async () => {
      const result = await tool.execute({
        action: 'network_egress',
        resource: 'https://evil.com/exfiltrate',
      });
      expect(result.denied).toBe(true);
      expect(result.guard).toBe('EgressAllowlistGuard');
    });

    it('allows api.github.com', async () => {
      const result = await tool.execute({
        action: 'network_egress',
        resource: 'https://api.github.com/user',
      });
      expect(result.allowed).toBe(true);
    });

    it('allows pypi.org', async () => {
      const result = await tool.execute({
        action: 'network_egress',
        resource: 'https://pypi.org/simple/',
      });
      expect(result.allowed).toBe(true);
    });

    it('blocks localhost', async () => {
      const result = await tool.execute({
        action: 'network_egress',
        resource: 'http://localhost:8080',
      });
      expect(result.denied).toBe(true);
    });
  });

  describe('Security Prompt', () => {
    it('generates security context for agent', async () => {
      const policy = await loadPolicy(join(exampleDir, 'policy.yaml'));
      const prompt = generateSecurityPrompt(policy);

      expect(prompt).toContain('api.github.com');
      expect(prompt).toContain('~/.ssh');
      expect(prompt).toContain('policy_check');
      expect(prompt).toContain('BLOCKED');
    });
  });

  describe('Policy Check Tool', () => {
    it('provides helpful suggestions when denied', async () => {
      const result = await tool.execute({
        action: 'file_write',
        resource: '~/.ssh/authorized_keys',
      });
      expect(result.suggestion).toBeDefined();
      expect(result.suggestion).toContain('SSH');
    });

    it('returns reason for denial', async () => {
      const result = await tool.execute({
        action: 'network_egress',
        resource: 'https://malware.com',
      });
      expect(result.reason).toContain('not in egress allowlist');
    });
  });
});
