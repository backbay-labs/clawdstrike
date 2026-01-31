import { describe, it, expect } from 'vitest';
import { PolicyEngine } from './engine.js';
import type { PolicyConfig } from './types.js';

describe('PolicyEngine', () => {
  describe('file operations', () => {
    it('blocks forbidden paths', async () => {
      const policy: PolicyConfig = {
        filesystem: {
          forbidden_paths: ['~/.ssh', '~/.aws'],
        },
      };
      const engine = new PolicyEngine(policy);
      const decision = await engine.evaluate({
        type: 'file_read',
        resource: '~/.ssh/id_rsa',
      });
      expect(decision.denied).toBe(true);
      expect(decision.guard).toBe('ForbiddenPathGuard');
    });

    it('allows non-forbidden paths', async () => {
      const policy: PolicyConfig = {
        filesystem: {
          forbidden_paths: ['~/.ssh'],
        },
      };
      const engine = new PolicyEngine(policy);
      const decision = await engine.evaluate({
        type: 'file_read',
        resource: '/tmp/test.txt',
      });
      expect(decision.allowed).toBe(true);
    });

    it('blocks writes outside allowed roots', async () => {
      const policy: PolicyConfig = {
        filesystem: {
          allowed_write_roots: ['/tmp', '/workspace'],
        },
      };
      const engine = new PolicyEngine(policy);
      const decision = await engine.evaluate({
        type: 'file_write',
        resource: '/etc/passwd',
      });
      expect(decision.denied).toBe(true);
    });
  });

  describe('egress operations', () => {
    it('blocks non-allowlisted domains in allowlist mode', async () => {
      const policy: PolicyConfig = {
        egress: {
          mode: 'allowlist',
          allowed_domains: ['api.github.com'],
        },
      };
      const engine = new PolicyEngine(policy);
      const decision = await engine.evaluate({
        type: 'network_egress',
        resource: 'https://evil.com/data',
      });
      expect(decision.denied).toBe(true);
      expect(decision.guard).toBe('EgressAllowlistGuard');
    });

    it('allows allowlisted domains', async () => {
      const policy: PolicyConfig = {
        egress: {
          mode: 'allowlist',
          allowed_domains: ['api.github.com'],
        },
      };
      const engine = new PolicyEngine(policy);
      const decision = await engine.evaluate({
        type: 'network_egress',
        resource: 'https://api.github.com/user',
      });
      expect(decision.allowed).toBe(true);
    });

    it('supports wildcard domains', async () => {
      const policy: PolicyConfig = {
        egress: {
          mode: 'allowlist',
          allowed_domains: ['*.github.com'],
        },
      };
      const engine = new PolicyEngine(policy);
      const decision = await engine.evaluate({
        type: 'network_egress',
        resource: 'https://api.github.com/user',
      });
      expect(decision.allowed).toBe(true);
    });
  });

  describe('createEvent helper', () => {
    it('creates file_read event', () => {
      const engine = new PolicyEngine({});
      const event = engine.createEvent('file_read', '/path/to/file');
      expect(event.type).toBe('file_read');
      expect(event.resource).toBe('/path/to/file');
    });
  });
});
