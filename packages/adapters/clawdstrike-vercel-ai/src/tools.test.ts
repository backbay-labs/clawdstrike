import { describe, it, expect, vi } from 'vitest';

import { BaseToolInterceptor, createSecurityContext } from '@clawdstrike/adapter-core';
import type { PolicyEngineLike, ToolInterceptor } from '@clawdstrike/adapter-core';

import { secureTools } from './tools.js';
import { ClawdstrikeBlockedError } from './errors.js';

describe('secureTools', () => {
  it('allows tool execution when decision allows', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ allowed: true, denied: false, warn: false }),
    };
    const interceptor = new BaseToolInterceptor(engine, {});

    const execute = vi.fn(async (input: { value: number }) => input.value * 2);
    const tools = secureTools({ double: { execute } }, interceptor);

    await expect(tools.double.execute({ value: 21 })).resolves.toBe(42);
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it('does not block execution on warn decisions', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        allowed: true,
        denied: false,
        warn: event.eventType === 'tool_call',
        message: 'warning',
      }),
    };
    const interceptor = new BaseToolInterceptor(engine, {});

    const execute = vi.fn(async () => 'ok');
    const tools = secureTools({ calc: { execute } }, interceptor);

    await expect(tools.calc.execute({})).resolves.toBe('ok');
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it('throws when interceptor blocks', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        status: event.eventType === 'command_exec' ? 'deny' : 'allow',
        message: 'blocked',
      }),
    };
    const interceptor = new BaseToolInterceptor(engine, {});

    const execute = vi.fn(async () => 'should-not-run');
    const tools = secureTools({ bash: { execute } }, interceptor);

    await expect(tools.bash.execute({ cmd: 'rm -rf /' })).rejects.toBeInstanceOf(
      ClawdstrikeBlockedError,
    );
    expect(execute).toHaveBeenCalledTimes(0);
  });

  it('calls onError when tool throws', async () => {
    const onError = vi.fn(async () => undefined);
    const interceptor: ToolInterceptor = {
      beforeExecute: async () => ({
        proceed: true,
        decision: { allowed: true, denied: false, warn: false },
        duration: 0,
      }),
      afterExecute: async (_name, _input, output) => ({ output, modified: false }),
      onError,
    };

    const tools = secureTools(
      {
        boom: {
          async execute() {
            throw new Error('boom');
          },
        },
      },
      interceptor,
    );

    await expect(tools.boom.execute({})).rejects.toThrow('boom');
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it('can create a context per execution', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ allowed: true, denied: false, warn: false }),
    };
    const interceptor = new BaseToolInterceptor(engine, {});

    const sessionIds: string[] = [];
    const tools = secureTools(
      {
        ping: {
          async execute() {
            return 'pong';
          },
        },
      },
      interceptor,
      {
        getContext: () => {
          const created = createSecurityContext({
            sessionId: `sess-${Math.random().toString(36).slice(2, 7)}`,
          });
          sessionIds.push(created.sessionId);
          return created;
        },
      },
    );

    await tools.ping.execute({});
    await tools.ping.execute({});

    expect(sessionIds.length).toBe(2);
    expect(sessionIds[0]).not.toBe(sessionIds[1]);
  });
});
