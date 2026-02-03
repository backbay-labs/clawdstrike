import { describe, it, expect, vi } from 'vitest';

import type { PolicyEngineLike } from '@clawdstrike/adapter-core';

import { ClawdstrikeBlockedError } from './errors.js';
import { CodexToolBoundary, wrapCodexToolDispatcher } from './tool-boundary.js';

describe('CodexToolBoundary', () => {
  it('blocks denied tool runs', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        allowed: event.eventType !== 'command_exec',
        denied: event.eventType === 'command_exec',
        warn: false,
        reason: 'blocked',
      }),
    };

    const boundary = new CodexToolBoundary({ engine, config: { blockOnViolation: true } });

    await expect(boundary.handleToolStart('bash', { cmd: 'rm -rf /' }, 'run-1')).rejects.toBeInstanceOf(
      ClawdstrikeBlockedError,
    );

    expect(boundary.getAuditEvents().some(e => e.type === 'tool_call_blocked')).toBe(true);
  });

  it('wrapCodexToolDispatcher blocks before dispatch', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        allowed: event.eventType !== 'command_exec',
        denied: event.eventType === 'command_exec',
        warn: false,
        reason: 'blocked',
      }),
    };

    const boundary = new CodexToolBoundary({ engine, config: { blockOnViolation: true } });
    const dispatch = vi.fn(async () => 'ok');
    const wrapped = wrapCodexToolDispatcher(boundary, dispatch);

    await expect(wrapped('bash', { cmd: 'rm -rf /' }, 'run-1')).rejects.toBeInstanceOf(ClawdstrikeBlockedError);
    expect(dispatch).not.toHaveBeenCalled();
  });
});
