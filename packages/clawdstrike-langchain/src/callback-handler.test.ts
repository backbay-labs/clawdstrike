import { describe, it, expect } from 'vitest';

import type { PolicyEngineLike } from '@clawdstrike/adapter-core';

import { ClawdstrikeViolationError } from './errors.js';
import { ClawdstrikeCallbackHandler } from './callback-handler.js';

describe('ClawdstrikeCallbackHandler', () => {
  it('blocks denied tool runs on handleToolStart', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        allowed: event.eventType !== 'command_exec',
        denied: event.eventType === 'command_exec',
        warn: false,
        reason: 'blocked',
      }),
    };

    const handler = new ClawdstrikeCallbackHandler({ engine, config: { blockOnViolation: true } });

    await expect(
      handler.handleToolStart({ name: 'bash' }, JSON.stringify({ cmd: 'rm -rf /' }), 'run-1'),
    ).rejects.toBeInstanceOf(ClawdstrikeViolationError);

    const events = handler.getAuditEvents();
    expect(events.some(e => e.type === 'tool_call_blocked')).toBe(true);
  });

  it('records start/end audit events for allowed runs', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ allowed: true, denied: false, warn: false }),
    };

    const handler = new ClawdstrikeCallbackHandler({ engine });

    await handler.handleToolStart({ name: 'calc' }, JSON.stringify({ ok: true }), 'run-2');
    await handler.handleToolEnd('ok', 'run-2');

    const events = handler.getAuditEvents();
    expect(events.some(e => e.type === 'tool_call_start')).toBe(true);
    expect(events.some(e => e.type === 'tool_call_end')).toBe(true);
  });
});

