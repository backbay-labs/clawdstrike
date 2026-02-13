import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, expect, vi } from 'vitest';

import type { PolicyEngineLike } from '@clawdstrike/adapter-core';

import { ClawdstrikeBlockedError } from './errors.js';
import { ClaudeToolBoundary, wrapClaudeToolDispatcher } from './tool-boundary.js';

describe('ClaudeToolBoundary', () => {
  it('blocks denied tool runs', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        status: event.eventType === 'command_exec' ? 'deny' : 'allow',
        reason: 'blocked',
      }),
    };

    const boundary = new ClaudeToolBoundary({ engine, config: { blockOnViolation: true } });

    await expect(boundary.handleToolStart('bash', { cmd: 'rm -rf /' }, 'run-1')).rejects.toBeInstanceOf(
      ClawdstrikeBlockedError,
    );

    expect(boundary.getAuditEvents().some(e => e.type === 'tool_call_blocked')).toBe(true);
  });

  it('wrapClaudeToolDispatcher blocks before dispatch', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        status: event.eventType === 'command_exec' ? 'deny' : 'allow',
        reason: 'blocked',
      }),
    };

    const boundary = new ClaudeToolBoundary({ engine, config: { blockOnViolation: true } });
    const dispatch = vi.fn(async () => 'ok');
    const wrapped = wrapClaudeToolDispatcher(boundary, dispatch);

    await expect(wrapped('bash', { cmd: 'rm -rf /' }, 'run-1')).rejects.toBeInstanceOf(ClawdstrikeBlockedError);
    expect(dispatch).not.toHaveBeenCalled();
  });

  it('prevents side effects when a tool call is blocked', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        status: event.eventType === 'command_exec' ? 'deny' : 'allow',
        reason: 'blocked',
      }),
    };

    const boundary = new ClaudeToolBoundary({ engine, config: { blockOnViolation: true } });
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'claude-fail-closed-test-'));
    const sideEffectPath = path.join(tmpDir, 'side-effect.txt');

    const dispatch = vi.fn(async () => {
      fs.writeFileSync(sideEffectPath, 'should-not-exist');
      return 'ok';
    });

    const wrapped = wrapClaudeToolDispatcher(boundary, dispatch);
    await expect(wrapped('bash', { cmd: 'rm -rf /' }, 'run-blocked')).rejects.toBeInstanceOf(
      ClawdstrikeBlockedError,
    );

    expect(dispatch).not.toHaveBeenCalled();
    expect(fs.existsSync(sideEffectPath)).toBe(false);
  });
});
