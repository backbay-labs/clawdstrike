import { describe, expect, it, vi } from 'vitest';

import clawdstrikePlugin from '../src/plugin.js';

const EXPECTED_EVENTS = [
  'before_tool_call',
  'before_tool_call',
  'tool_call',
  'tool_call',
  'tool_result_persist',
  'agent:bootstrap',
] as const;

function makeBaseApi() {
  return {
    logger: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
    registerTool: vi.fn(),
    registerCli: vi.fn(),
  };
}

describe('plugin runtime hook compatibility', () => {
  it('registers named hooks when registerHook accepts options', () => {
    const registerHook = vi.fn();
    const api = {
      ...makeBaseApi(),
      registerHook,
    };

    clawdstrikePlugin(api);

    expect(registerHook).toHaveBeenCalledTimes(EXPECTED_EVENTS.length);
    const calls = registerHook.mock.calls as Array<[string, unknown, { name?: string; entry?: { hook?: { name?: string } } }]>;
    expect(calls.map(([event]) => event)).toEqual(EXPECTED_EVENTS);
    for (const [, , options] of calls) {
      expect(typeof options?.name).toBe('string');
      expect(options?.entry?.hook?.name).toBe(options?.name);
    }
  });

  it('falls back to legacy registerHook(event, handler) when options are rejected', () => {
    const registerHook = vi.fn((_: string, __: unknown, options?: unknown) => {
      if (options !== undefined) {
        throw new Error('legacy-runtime');
      }
    });
    const api = {
      ...makeBaseApi(),
      registerHook,
    };

    clawdstrikePlugin(api);

    const plainCalls = registerHook.mock.calls.filter(([, , options]) => options === undefined);
    expect(plainCalls).toHaveLength(EXPECTED_EVENTS.length);
    expect(plainCalls.map(([event]) => event)).toEqual(EXPECTED_EVENTS);
  });

  it('falls back to api.on when registerHook is unavailable', () => {
    const on = vi.fn();
    const api = {
      ...makeBaseApi(),
      on,
    };

    clawdstrikePlugin(api);

    expect(on).toHaveBeenCalledTimes(EXPECTED_EVENTS.length);
    expect(on.mock.calls.map(([event]) => event)).toEqual(EXPECTED_EVENTS);
  });

  it('forwards hook context through wrapper handlers', async () => {
    const registerHook = vi.fn();
    const api = {
      ...makeBaseApi(),
      registerHook,
    };

    clawdstrikePlugin(api);

    const call = registerHook.mock.calls.find(
      ([event, , options]) =>
        event === 'before_tool_call'
        && options?.name === 'clawdstrike:cua-bridge:before-tool-call',
    );
    expect(call).toBeDefined();

    const wrappedHandler = call?.[1] as
      | ((event: unknown, ctx?: { sessionKey?: string }) => Promise<unknown>)
      | undefined;

    const result = await wrappedHandler?.(
      { toolName: 'cua_notarealaction', params: {} },
      { sessionKey: 'session-from-context' },
    );

    if (result && typeof result === 'object' && 'blockReason' in result) {
      expect(String((result as { blockReason?: string }).blockReason ?? ''))
        .not.toContain('missing session ID');
    }
  });
});
