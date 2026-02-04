import { describe, it, expect } from 'vitest';
import { homedir } from 'node:os';

import { PolicyEngine } from './engine.js';
import type { PolicyEvent } from '../types.js';

describe('PolicyEngine', () => {
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
});
