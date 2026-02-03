import { describe, it, expect } from 'vitest';

import type { PolicyEngineLike } from '@clawdstrike/adapter-core';

import { ClawdstrikeBlockedError } from './errors.js';
import { OpenCodeToolBoundary } from './tool-boundary.js';

describe('OpenCodeToolBoundary', () => {
  it('blocks denied tool runs', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        allowed: event.eventType !== 'command_exec',
        denied: event.eventType === 'command_exec',
        warn: false,
        reason: 'blocked',
      }),
    };

    const boundary = new OpenCodeToolBoundary({ engine, config: { blockOnViolation: true } });

    await expect(boundary.handleToolStart('bash', { cmd: 'rm -rf /' }, 'run-1')).rejects.toBeInstanceOf(
      ClawdstrikeBlockedError,
    );

    expect(boundary.getAuditEvents().some(e => e.type === 'tool_call_blocked')).toBe(true);
  });
});

