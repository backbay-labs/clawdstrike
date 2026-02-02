import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadPolicy, loadPolicyFromString, PolicyLoadError } from './loader.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('loadPolicyFromString', () => {
  it('parses valid YAML policy', () => {
    const yaml = `
version: hushclaw-v1.0
egress:
  mode: allowlist
  allowed_domains:
    - api.github.com
`;
    const policy = loadPolicyFromString(yaml);
    expect(policy.version).toBe('hushclaw-v1.0');
    expect(policy.egress?.mode).toBe('allowlist');
    expect(policy.egress?.allowed_domains).toContain('api.github.com');
  });

  it('throws on invalid YAML', () => {
    const yaml = `{{{invalid`;
    expect(() => loadPolicyFromString(yaml)).toThrow();
  });
});

describe('loadPolicy', () => {
  const testDir = join(tmpdir(), 'hushclaw-test-' + Date.now());

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it('loads policy from file', () => {
    const policyPath = join(testDir, 'policy.yaml');
    writeFileSync(policyPath, `
version: hushclaw-v1.0
filesystem:
  forbidden_paths:
    - ~/.ssh
`);
    const policy = loadPolicy(policyPath);
    expect(policy.version).toBe('hushclaw-v1.0');
    expect(policy.filesystem?.forbidden_paths).toContain('~/.ssh');
  });

  it('throws on missing file', () => {
    expect(() => loadPolicy('/nonexistent/policy.yaml')).toThrow(PolicyLoadError);
  });
});
