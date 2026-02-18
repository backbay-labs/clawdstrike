import { describe, it, expect } from 'vitest';
import { BaseToolInterceptor } from './base-tool-interceptor.js';
import { createSecurityContext } from './context.js';
import type { PolicyEngineLike } from './engine.js';

describe('BaseToolInterceptor', () => {
  it('blocks denied tools and records audit events', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        status: event.eventType === 'command_exec' ? 'deny' : 'allow',
        message: 'blocked',
      }),
    };

    const interceptor = new BaseToolInterceptor(engine, {
      blockOnViolation: true,
      audit: { logParameters: true },
    });

    const context = createSecurityContext({ contextId: 'ctx-1', sessionId: 'sess-1' });
    const result = await interceptor.beforeExecute('bash', { cmd: 'rm -rf /' }, context);

    expect(result.proceed).toBe(false);
    expect(context.checkCount).toBe(1);
    expect(context.violationCount).toBe(1);
    expect(Array.from(context.blockedTools)).toContain('bash');
    expect(context.auditEvents.some(e => e.type === 'tool_call_blocked')).toBe(true);
  });

  it('propagates security context metadata into policy events for attribution', async () => {
    let seenEvent: unknown = null;
    const engine: PolicyEngineLike = {
      evaluate: (event) => {
        seenEvent = event;
        return { status: 'allow' };
      },
    };

    const interceptor = new BaseToolInterceptor(engine, {});
    const context = createSecurityContext({
      contextId: 'ctx-attr-1',
      sessionId: 'sess-attr-1',
      metadata: { agentId: 'green-runner', swarmRole: 'benign' },
    });

    await interceptor.beforeExecute('bash', { cmd: 'echo hello' }, context);

    expect(seenEvent).not.toBeNull();
    expect(seenEvent).toMatchObject({
      sessionId: 'sess-attr-1',
      metadata: { agentId: 'green-runner', swarmRole: 'benign' },
    });
  });

  it('sanitizes outputs using engine redaction when enabled', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ status: 'allow' }),
      redactSecrets: value => value.replaceAll('SECRET', '[REDACTED]'),
    };

    const interceptor = new BaseToolInterceptor(engine, {
      audit: { logOutputs: true },
    });

    const context = createSecurityContext({ contextId: 'ctx-2', sessionId: 'sess-2' });

    await interceptor.beforeExecute('tool_call', {}, context);
    const processed = await interceptor.afterExecute('tool_call', {}, 'SECRET', context);

    expect(processed.output).toBe('[REDACTED]');
    expect(processed.modified).toBe(true);
    expect(processed.redactions?.[0]?.type).toBe('secret');
    expect(context.auditEvents.some(e => e.type === 'tool_call_end')).toBe(true);
  });

  it('does not mark output as modified when no redactor is available', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ status: 'allow' }),
    };

    const interceptor = new BaseToolInterceptor(engine, {});
    const context = createSecurityContext({ contextId: 'ctx-3', sessionId: 'sess-3' });

    await interceptor.beforeExecute('tool_call', {}, context);
    const output = { ok: true };
    const processed = await interceptor.afterExecute('tool_call', {}, output, context);

    expect(processed.output).toBe(output);
    expect(processed.modified).toBe(false);
    expect(processed.redactions).toEqual([]);
  });

  it('uses provider translator output when configured', async () => {
    let seenEventType: string | null = null;
    let seenCuaAction: string | null = null;
    const engine: PolicyEngineLike = {
      evaluate: event => {
        seenEventType = event.eventType;
        if (event.data.type === 'cua') {
          seenCuaAction = String(event.data.cuaAction);
        }
        return { status: 'allow' };
      },
    };

    const interceptor = new BaseToolInterceptor(engine, {
      translateToolCall: ({ toolName, parameters, sessionId }) => {
        if (toolName !== 'computer_use') return null;
        return {
          eventId: 'evt-provider-1',
          eventType: 'input.inject',
          timestamp: new Date().toISOString(),
          sessionId,
          data: {
            type: 'cua',
            cuaAction: String(parameters.action ?? 'input.inject'),
          },
          metadata: { source: 'provider-translator' },
        };
      },
    });

    const context = createSecurityContext({ contextId: 'ctx-translate-1', sessionId: 'sess-translate-1' });
    const result = await interceptor.beforeExecute('computer_use', { action: 'click' }, context);

    expect(result.proceed).toBe(true);
    expect(seenEventType).toBe('input.inject');
    expect(seenCuaAction).toBe('click');
  });

  it('fails closed when translator throws', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ status: 'allow' }),
    };

    const interceptor = new BaseToolInterceptor(engine, {
      blockOnViolation: true,
      translateToolCall: () => {
        throw new Error('boom');
      },
    });

    const context = createSecurityContext({ contextId: 'ctx-translate-err', sessionId: 'sess-translate-err' });
    const result = await interceptor.beforeExecute('computer_use', { action: 'click' }, context);

    expect(result.proceed).toBe(false);
    expect(result.decision.status).toBe('deny');
    expect(result.decision.guard).toBe('provider_translator');
  });
});
