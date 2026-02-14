import { describe, it, expect } from 'vitest';

import { PolicyEngine } from '../src/policy/engine.js';
import { extractPath, normalizeApprovalResource } from '../src/hooks/approval-utils.js';

describe('approval-utils', () => {
  it('extractPath prefers explicit path keys', () => {
    expect(extractPath({ path: '/tmp/a.txt' })).toBe('/tmp/a.txt');
    expect(extractPath({ file_path: '/tmp/b.txt' })).toBe('/tmp/b.txt');
  });

  it('extractPath can pull a path from common read-like commandlines', () => {
    expect(extractPath({ command: 'cat /etc/passwd' })).toBe('/etc/passwd');
  });

  it('normalizeApprovalResource redacts secrets', () => {
    const engine = new PolicyEngine({ policy: 'clawdstrike:ai-agent-minimal', logLevel: 'error' });
    const secret = 'sk-' + 'a'.repeat(48);
    const resource = normalizeApprovalResource(engine, 'bash', { command: `echo ${secret}` });

    expect(resource).toContain('[REDACTED]');
    expect(resource).not.toContain(secret);
  });

  it('normalizeApprovalResource truncates long resources', () => {
    const engine = new PolicyEngine({ policy: 'clawdstrike:ai-agent-minimal', logLevel: 'error' });
    // Avoid matching secret patterns (some rules are intentionally broad).
    const long = 'echo ' + '%'.repeat(2000);
    const resource = normalizeApprovalResource(engine, 'bash', { command: long });

    expect(resource.endsWith('...[truncated]')).toBe(true);
    expect(resource.length).toBe(1024 + '...[truncated]'.length);
  });
});
