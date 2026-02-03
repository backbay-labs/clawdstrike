import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { beforeEach, describe, it, expect, vi } from 'vitest';

import type { PolicyEvent } from '@clawdstrike/adapter-core';

type MockChildProcess = EventEmitter & {
  stdin: PassThrough;
  stdout: PassThrough;
  stderr: PassThrough;
  kill: (signal: string) => void;
};

const spawnMock = vi.hoisted(() => vi.fn());

vi.mock('node:child_process', () => ({
  spawn: (...args: unknown[]) => spawnMock(...args),
}));

import { createHushCliEngine } from './hush-cli-engine.js';

function createMockChildProcess(): MockChildProcess {
  const child = new EventEmitter() as MockChildProcess;
  child.stdin = new PassThrough();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = vi.fn();
  return child;
}

const exampleEvent: PolicyEvent = {
  eventId: 'evt-test',
  eventType: 'tool_call',
  timestamp: new Date().toISOString(),
  data: { type: 'tool', toolName: 'demo', parameters: { ok: true } },
};

describe('createHushCliEngine', () => {
  beforeEach(() => {
    spawnMock.mockReset();
  });

  it('spawns hush policy eval with expected args', async () => {
    const child = createMockChildProcess();
    spawnMock.mockReturnValueOnce(child);

    const engine = createHushCliEngine({ policyRef: 'default', resolve: true });
    const pending = engine.evaluate(exampleEvent);

    child.stdout.write(
      JSON.stringify({
        version: 1,
        command: 'policy_eval',
        decision: { allowed: true, denied: false, warn: false },
      }),
    );
    child.emit('close', 0, null);

    await pending;

    expect(spawnMock).toHaveBeenCalledWith(
      'hush',
      ['policy', 'eval', 'default', '-', '--json', '--resolve'],
      { stdio: ['pipe', 'pipe', 'pipe'] },
    );
  });

  it('returns allowed decision on valid response', async () => {
    const child = createMockChildProcess();
    spawnMock.mockReturnValueOnce(child);

    const engine = createHushCliEngine({ policyRef: 'default' });
    const pending = engine.evaluate(exampleEvent);

    child.stdout.write(
      JSON.stringify({
        version: 1,
        command: 'policy_eval',
        decision: { allowed: true, denied: false, warn: false },
      }),
    );
    child.emit('close', 0, null);

    await expect(pending).resolves.toEqual({ allowed: true, denied: false, warn: false });
  });

  it('returns denied decision when policy blocks', async () => {
    const child = createMockChildProcess();
    spawnMock.mockReturnValueOnce(child);

    const engine = createHushCliEngine({ policyRef: 'default' });
    const pending = engine.evaluate(exampleEvent);

    child.stdout.write(
      JSON.stringify({
        version: 1,
        command: 'policy_eval',
        decision: { allowed: false, denied: true, warn: false, reason: 'blocked' },
      }),
    );
    child.emit('close', 0, null);

    await expect(pending).resolves.toMatchObject({ denied: true, reason: 'blocked' });
  });

  it('returns warn decision when policy warns', async () => {
    const child = createMockChildProcess();
    spawnMock.mockReturnValueOnce(child);

    const engine = createHushCliEngine({ policyRef: 'default' });
    const pending = engine.evaluate(exampleEvent);

    child.stdout.write(
      JSON.stringify({
        version: 1,
        command: 'policy_eval',
        decision: { allowed: true, denied: false, warn: true, message: 'heads up' },
      }),
    );
    child.emit('close', 0, null);

    await expect(pending).resolves.toMatchObject({ warn: true, message: 'heads up' });
  });

  it('parses decision even when hush exits with warn (code 1)', async () => {
    const child = createMockChildProcess();
    spawnMock.mockReturnValueOnce(child);

    const engine = createHushCliEngine({ policyRef: 'default' });
    const pending = engine.evaluate(exampleEvent);

    child.stdout.write(
      JSON.stringify({
        version: 1,
        command: 'policy_eval',
        decision: { allowed: true, denied: false, warn: true, reason: 'warned' },
      }),
    );
    child.emit('close', 1, null);

    await expect(pending).resolves.toMatchObject({ warn: true, reason: 'warned' });
  });

  it('parses decision even when hush exits with blocked (code 2)', async () => {
    const child = createMockChildProcess();
    spawnMock.mockReturnValueOnce(child);

    const engine = createHushCliEngine({ policyRef: 'default' });
    const pending = engine.evaluate(exampleEvent);

    child.stdout.write(
      JSON.stringify({
        version: 1,
        command: 'policy_eval',
        decision: { allowed: false, denied: true, warn: false, reason: 'blocked' },
      }),
    );
    child.emit('close', 2, null);

    await expect(pending).resolves.toMatchObject({ denied: true, reason: 'blocked' });
  });

  it('fails closed on malformed JSON', async () => {
    const child = createMockChildProcess();
    spawnMock.mockReturnValueOnce(child);

    const engine = createHushCliEngine({ policyRef: 'default' });
    const pending = engine.evaluate(exampleEvent);

    child.stderr.write('bad json');
    child.stdout.write('{');
    child.emit('close', 0, null);

    await expect(pending).resolves.toMatchObject({
      allowed: false,
      denied: true,
      warn: false,
      reason: 'engine_error',
    });
  });
});
