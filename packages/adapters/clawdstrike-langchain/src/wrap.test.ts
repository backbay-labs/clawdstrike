import { describe, it, expect, vi } from 'vitest';

import { BaseToolInterceptor } from '@clawdstrike/adapter-core';
import type { PolicyEngineLike, ToolInterceptor } from '@clawdstrike/adapter-core';

import { ClawdstrikeViolationError } from './errors.js';
import { wrapTool, wrapToolWithConfig, wrapTools } from './wrap.js';

describe('wrapTool', () => {
  it('wraps invoke() and allows execution when policy allows', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ allowed: true, denied: false, warn: false }),
    };
    const interceptor = new BaseToolInterceptor(engine, {});

    const tool = {
      name: 'calc',
      invoke: vi.fn(async (input: { value: number }) => input.value + 1),
    };

    const secureTool = wrapTool(tool, interceptor);
    await expect(secureTool.invoke({ value: 41 })).resolves.toBe(42);
    expect(tool.invoke).toHaveBeenCalledTimes(1);
  });

  it('wraps _call() and blocks when policy denies', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        status: event.eventType === 'command_exec' ? 'deny' : 'allow',
        message: 'blocked',
      }),
    };
    const interceptor = new BaseToolInterceptor(engine, {});

    const tool = {
      name: 'bash',
      _call: vi.fn(async () => 'ok'),
    };

    const secureTool = wrapTool(tool, interceptor);
    await expect(secureTool._call({ cmd: 'rm -rf /' })).rejects.toBeInstanceOf(
      ClawdstrikeViolationError,
    );
    expect(tool._call).toHaveBeenCalledTimes(0);
  });

  it('calls onError when wrapped method throws', async () => {
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

    const tool = {
      name: 'boom',
      async invoke() {
        throw new Error('boom');
      },
    };

    const secureTool = wrapTool(tool, interceptor);
    await expect(secureTool.invoke({})).rejects.toThrow('boom');
    expect(onError).toHaveBeenCalledTimes(1);
  });
});

describe('wrapTools', () => {
  it('wraps a list of tools with a shared context', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ allowed: true, denied: false, warn: false }),
    };
    const interceptor = new BaseToolInterceptor(engine, {});

    const a = { name: 'a', invoke: vi.fn(async () => 'a') };
    const b = { name: 'b', invoke: vi.fn(async () => 'b') };

    const [wa, wb] = wrapTools([a, b], interceptor);
    await expect(wa.invoke({})).resolves.toBe('a');
    await expect(wb.invoke({})).resolves.toBe('b');
  });
});

describe('wrapToolWithConfig', () => {
  it('supports withConfig override when created from engine+config', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        status: event.eventType === 'command_exec' ? 'deny' : 'allow',
      }),
    };

    const tool = {
      name: 'bash',
      _call: vi.fn(async () => 'ok'),
    };

    const secureTool = wrapToolWithConfig(tool, engine, { blockOnViolation: false });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const secureTool2 = (secureTool as any).withConfig({ blockOnViolation: true });

    await expect(secureTool._call({ cmd: 'rm -rf /' })).resolves.toBe('ok');
    await expect(secureTool2._call({ cmd: 'rm -rf /' })).rejects.toBeInstanceOf(
      ClawdstrikeViolationError,
    );
  });
});
