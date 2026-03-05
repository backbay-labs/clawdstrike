import { beforeEach, describe, expect, it, vi } from 'vitest';

const { interceptInboundMessageMock } = vi.hoisted(() => ({
  interceptInboundMessageMock: vi.fn(),
}));

vi.mock('@clawdstrike/adapter-core', async () => {
  const actual = await vi.importActual<typeof import('@clawdstrike/adapter-core')>(
    '@clawdstrike/adapter-core',
  );

  return {
    ...actual,
    interceptInboundMessage: interceptInboundMessageMock,
  };
});

import clawdstrikePlugin from '../src/plugin.js';

const EXPECTED_EVENTS = [
  'before_tool_call',
  'before_tool_call',
  'tool_call',
  'tool_call',
  'tool_result_persist',
  'inbound_message',
  'user_input',
  'agent:bootstrap',
] as const;

const REQUIRED_CORE_EVENTS = [
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
  beforeEach(() => {
    interceptInboundMessageMock.mockReset();
    interceptInboundMessageMock.mockResolvedValue({
      proceed: true,
      decision: { status: 'allow' },
      duration: 0,
    });
  });

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

  it('skips optional inbound hooks when runtime does not support them', () => {
    const registerHook = vi.fn((event: string, _: unknown, options?: unknown) => {
      if (event === 'inbound_message' || event === 'user_input') {
        throw new Error('unknown hook');
      }
      if (options !== undefined) {
        throw new Error('legacy-runtime');
      }
    });
    const api = {
      ...makeBaseApi(),
      registerHook,
    };

    expect(() => clawdstrikePlugin(api)).not.toThrow();

    const plainCoreCalls = registerHook.mock.calls.filter(
      ([event, , options]) =>
        options === undefined && event !== 'inbound_message' && event !== 'user_input',
    );
    expect(plainCoreCalls.map(([event]) => event)).toEqual(REQUIRED_CORE_EVENTS);
    expect(api.logger.warn).toHaveBeenCalledTimes(2);
  });

  it('refreshes inbound config on every wrapped inbound hook call', async () => {
    const registerHook = vi.fn();
    const pluginConfig: Record<string, unknown> = {
      mode: 'deterministic',
      inbound: { enabled: false },
    };
    const api = {
      ...makeBaseApi(),
      config: {
        plugins: {
          entries: {
            openclaw: { config: pluginConfig },
          },
        },
      },
      registerHook,
    };

    clawdstrikePlugin(api);

    const inboundCall = registerHook.mock.calls.find(
      ([event, , options]) =>
        event === 'inbound_message'
        && options?.name === 'clawdstrike:inbound-message:inbound-message',
    );
    expect(inboundCall).toBeDefined();

    const wrappedInboundHandler = inboundCall?.[1] as
      | ((event: unknown) => Promise<unknown>)
      | undefined;
    const makeLegacyInboundEvent = () => ({
      type: 'inbound_message',
      timestamp: new Date('2026-03-05T15:00:00.000Z').toISOString(),
      context: {
        sessionId: 'session-1',
        message: {
          id: 'message-1',
          text: 'hello',
        },
      },
      messages: [] as string[],
    });

    await wrappedInboundHandler?.(makeLegacyInboundEvent());
    expect(interceptInboundMessageMock).not.toHaveBeenCalled();

    pluginConfig.inbound = { enabled: true };
    await wrappedInboundHandler?.(makeLegacyInboundEvent());
    expect(interceptInboundMessageMock).toHaveBeenCalledTimes(1);
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
