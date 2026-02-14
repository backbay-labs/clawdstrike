import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, tmpdir } from 'node:os';

import { PolicyEngine } from './engine.js';
import type { PolicyEvent } from '../types.js';

describe('PolicyEngine', () => {
  const testDir = join(tmpdir(), 'clawdstrike-engine-test-' + Date.now());

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it('denies forbidden file reads (deterministic)', async () => {
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'deterministic',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 't1',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: { type: 'file', path: `${homedir()}/.ssh/id_rsa`, operation: 'read' },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('deny');
    expect(decision.guard).toBe('forbidden_path');
  });

  it('warns but allows in advisory mode', async () => {
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'advisory',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 't2',
      eventType: 'file_read',
      timestamp: new Date().toISOString(),
      data: { type: 'file', path: `${homedir()}/.ssh/id_rsa`, operation: 'read' },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('warn');
  });

  it('blocks secret leaks in tool output', async () => {
    const engine = new PolicyEngine({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'deterministic',
      logLevel: 'error',
    });

    const event: PolicyEvent = {
      eventId: 't3',
      eventType: 'tool_call',
      timestamp: new Date().toISOString(),
      data: { type: 'tool', toolName: 'api_call', parameters: {}, result: 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
    };

    const decision = await engine.evaluate(event);
    expect(decision.status).toBe('deny');
    expect(decision.guard).toBe('secret_leak');
  });

  it('enforces allowed_write_roots for output-style command flags', async () => {
    const policyPath = join(testDir, 'policy.yaml');
    writeFileSync(policyPath, `
extends: clawdstrike:ai-agent-minimal
filesystem:
  allowed_write_roots:
    - /tmp/allowed
`);

    const engine = new PolicyEngine({
      policy: policyPath,
      mode: 'deterministic',
      logLevel: 'error',
      guards: { patch_integrity: false },
    });

    const base: Omit<PolicyEvent, 'eventId' | 'eventType' | 'data'> = {
      timestamp: new Date().toISOString(),
    };

    const denyEq: PolicyEvent = {
      ...base,
      eventId: 't4',
      eventType: 'command_exec',
      data: { type: 'command', command: 'tool', args: ['--output=/tmp/disallowed/out.txt'] },
    };
    const decisionEq = await engine.evaluate(denyEq);
    expect(decisionEq.status).toBe('deny');
    expect(decisionEq.reason).toContain('Write path not in allowed roots');

    const denySpace: PolicyEvent = {
      ...base,
      eventId: 't5',
      eventType: 'command_exec',
      data: { type: 'command', command: 'tool', args: ['--log-file', '/tmp/disallowed/log.txt'] },
    };
    const decisionSpace = await engine.evaluate(denySpace);
    expect(decisionSpace.status).toBe('deny');
    expect(decisionSpace.reason).toContain('Write path not in allowed roots');
  });
});
