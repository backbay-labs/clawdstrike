import { describe, it, expect } from 'vitest';
import { BaseToolInterceptor } from './base-tool-interceptor.js';
import { createSecurityContext } from './context.js';
import type { PolicyEngineLike } from './engine.js';

describe('BaseToolInterceptor', () => {
  it('blocks denied tools and records audit events', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        allowed: event.eventType !== 'command_exec',
        denied: event.eventType === 'command_exec',
        warn: false,
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

  it('sanitizes outputs using engine redaction when enabled', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ allowed: true, denied: false, warn: false }),
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
      evaluate: () => ({ allowed: true, denied: false, warn: false }),
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
});
