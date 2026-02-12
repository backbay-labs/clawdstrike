import { describe, it, expect, vi } from 'vitest';

import type { PolicyEngineLike } from '@clawdstrike/adapter-core';

import { ClawdstrikeBlockedError } from './errors.js';
import { OpenCodeToolBoundary, wrapOpenCodeToolDispatcher } from './tool-boundary.js';

describe('OpenCodeToolBoundary', () => {
  it('blocks denied tool runs', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        status: event.eventType === 'command_exec' ? 'deny' : 'allow',
        reason: 'blocked',
      }),
    };

    const boundary = new OpenCodeToolBoundary({ engine, config: { blockOnViolation: true } });

    await expect(boundary.handleToolStart('bash', { cmd: 'rm -rf /' }, 'run-1')).rejects.toBeInstanceOf(
      ClawdstrikeBlockedError,
    );

    expect(boundary.getAuditEvents().some(e => e.type === 'tool_call_blocked')).toBe(true);
  });

  it('wrapOpenCodeToolDispatcher blocks before dispatch', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        status: event.eventType === 'command_exec' ? 'deny' : 'allow',
        reason: 'blocked',
      }),
    };

    const boundary = new OpenCodeToolBoundary({ engine, config: { blockOnViolation: true } });
    const dispatch = vi.fn(async () => 'ok');
    const wrapped = wrapOpenCodeToolDispatcher(boundary, dispatch);

    await expect(wrapped('bash', { cmd: 'rm -rf /' }, 'run-1')).rejects.toBeInstanceOf(ClawdstrikeBlockedError);
    expect(dispatch).not.toHaveBeenCalled();
  });
});
