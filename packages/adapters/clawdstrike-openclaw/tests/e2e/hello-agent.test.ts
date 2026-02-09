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
    engine = new PolicyEngine({
      policy: join(exampleDir, 'policy.yaml'),
      mode: 'deterministic',
      logLevel: 'error',
    });
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
      } as any);
      expect(result.denied).toBe(true);
      expect(result.guard).toBe('forbidden_path');
    });

    it('blocks forbidden path access (~/.aws)', async () => {
      const result = await tool.execute({
        action: 'file_read',
        resource: '~/.aws/credentials',
      } as any);
      expect(result.denied).toBe(true);
      expect(result.guard).toBe('forbidden_path');
    });

    it('blocks .env file access', async () => {
      const result = await tool.execute({
        action: 'file_read',
        resource: '/workspace/.env',
      } as any);
      expect(result.denied).toBe(true);
    });

    it('allows writes to /tmp/hello-agent', async () => {
      const result = await tool.execute({
        action: 'file_write',
        resource: '/tmp/hello-agent/test.txt',
      } as any);
      expect(result.allowed).toBe(true);
    });

    it('blocks writes outside allowed roots', async () => {
      const result = await tool.execute({
        action: 'file_write',
        resource: '/etc/passwd',
      } as any);
      expect(result.denied).toBe(true);
    });
  });

  describe('Egress Guards', () => {
    it('blocks non-allowlisted domains', async () => {
      const result = await tool.execute({
        action: 'network',
        resource: 'https://evil.com/exfiltrate',
      } as any);
      expect(result.denied).toBe(true);
      expect(result.guard).toBe('egress');
    });

    it('allows api.github.com', async () => {
      const result = await tool.execute({
        action: 'network',
        resource: 'https://api.github.com/user',
      } as any);
      expect(result.allowed).toBe(true);
    });

    it('allows pypi.org', async () => {
      const result = await tool.execute({
        action: 'network',
        resource: 'https://pypi.org/simple/',
      } as any);
      expect(result.allowed).toBe(true);
    });

    it('blocks localhost', async () => {
      const result = await tool.execute({
        action: 'network',
        resource: 'http://localhost:8080',
      } as any);
      expect(result.denied).toBe(true);
    });
  });

  describe('Security Prompt', () => {
    it('generates security context for agent', async () => {
      const policy = loadPolicy(join(exampleDir, 'policy.yaml'));
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
      } as any);
      expect(result.suggestion).toBeDefined();
      expect(result.suggestion).toContain('SSH');
    });

    it('returns reason for denial', async () => {
      const result = await tool.execute({
        action: 'network',
        resource: 'https://malware.com',
      } as any);
      expect(result.reason).toContain('non-allowlisted');
    });
  });
});
