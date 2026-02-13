import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, expect, vi } from 'vitest';

import type { PolicyEngineLike } from '@clawdstrike/adapter-core';

import { ClawdstrikeBlockedError } from './errors.js';
import { OpenAIToolBoundary, wrapOpenAIToolDispatcher } from './tool-boundary.js';

describe('OpenAIToolBoundary', () => {
  it('blocks denied tool runs', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        status: event.eventType === 'command_exec' ? 'deny' : 'allow',
        reason: 'blocked',
      }),
    };

    const boundary = new OpenAIToolBoundary({ engine, config: { blockOnViolation: true } });

    await expect(boundary.handleToolStart('bash', { cmd: 'rm -rf /' }, 'run-1')).rejects.toBeInstanceOf(
      ClawdstrikeBlockedError,
    );

    expect(boundary.getAuditEvents().some(e => e.type === 'tool_call_blocked')).toBe(true);
  });

  it('wrapOpenAIToolDispatcher blocks before dispatch', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        status: event.eventType === 'command_exec' ? 'deny' : 'allow',
        reason: 'blocked',
      }),
    };

    const boundary = new OpenAIToolBoundary({ engine, config: { blockOnViolation: true } });
    const dispatch = vi.fn(async () => 'ok');
    const wrapped = wrapOpenAIToolDispatcher(boundary, dispatch);

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

    const boundary = new OpenAIToolBoundary({ engine, config: { blockOnViolation: true } });
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'openai-fail-closed-test-'));
    const sideEffectPath = path.join(tmpDir, 'side-effect.txt');

    const dispatch = vi.fn(async () => {
      fs.writeFileSync(sideEffectPath, 'should-not-exist');
      return 'ok';
    });

    const wrapped = wrapOpenAIToolDispatcher(boundary, dispatch);
    await expect(wrapped('bash', { cmd: 'rm -rf /' }, 'run-blocked')).rejects.toBeInstanceOf(
      ClawdstrikeBlockedError,
    );

    expect(dispatch).not.toHaveBeenCalled();
    expect(fs.existsSync(sideEffectPath)).toBe(false);
  });
});
