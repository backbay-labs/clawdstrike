import { describe, it, expect } from 'vitest';

import { createSecurityContext } from './context.js';
import type { PolicyEngineLike } from './engine.js';
import {
  GenericToolBoundary,
  GenericToolCallBlockedError,
  wrapGenericToolDispatcher,
} from './generic-tool-runner.js';

describe('GenericToolBoundary', () => {
  it('blocks denied tool calls before dispatch', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ status: 'deny', message: 'blocked' }),
    };

    const boundary = new GenericToolBoundary({ engine });
    let dispatched = false;

    const wrapped = wrapGenericToolDispatcher(boundary, async () => {
      dispatched = true;
      return 'ok';
    });

    await expect(wrapped('bash', { cmd: 'rm -rf /' }, 'run-1')).rejects.toBeInstanceOf(
      GenericToolCallBlockedError,
    );

    expect(dispatched).toBe(false);
    expect(boundary.getAuditEvents().some(event => event.type === 'tool_call_blocked')).toBe(true);
  });

  it('sanitizes outputs and records end audit events', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ status: 'allow' }),
      redactSecrets: value => value.replaceAll('SECRET', '[REDACTED]'),
    };

    const boundary = new GenericToolBoundary({
      engine,
      config: { sanitizeOutputs: true, audit: { logOutputs: true } },
    });

    const wrapped = wrapGenericToolDispatcher(boundary, async () => 'token=SECRET');
    const output = await wrapped('echo', { value: 1 }, 'run-2');

    expect(output).toBe('token=[REDACTED]');
    expect(boundary.getAuditEvents().some(event => event.type === 'tool_call_end')).toBe(true);
  });

  it('reports tool execution errors through interceptor hooks', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ status: 'allow' }),
    };

    const boundary = new GenericToolBoundary({ engine });
    const wrapped = wrapGenericToolDispatcher(boundary, async () => {
      throw new Error('boom');
    });

    await expect(wrapped('tool', { ok: true }, 'run-3')).rejects.toThrow('boom');
    expect(boundary.getAuditEvents().some(event => event.type === 'tool_call_error')).toBe(true);
  });

  it('supports non-string run IDs with custom key/context mapping', async () => {
    type RunId = { session: string; request: string };
    const runId: RunId = { session: 'sess-42', request: 'req-9' };

    const engine: PolicyEngineLike = {
      evaluate: () => ({ status: 'allow' }),
    };

    const boundary = new GenericToolBoundary<unknown, unknown, RunId>({
      engine,
      keyFromRunId: run => `${run.session}:${run.request}`,
      createContext: run =>
        createSecurityContext({
          sessionId: run.session,
          metadata: { request: run.request },
        }),
    });

    const wrapped = wrapGenericToolDispatcher(boundary, async (_tool, input) => input);
    await wrapped('noop', { ok: true }, runId);

    const context = boundary.getContextIfAny(runId);
    expect(context?.sessionId).toBe('sess-42');
    expect(context?.metadata.request).toBe('req-9');
  });

  it('passes sanitize-modified parameters to the dispatcher', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({
        status: 'sanitize',
        reason_code: 'ADC_POLICY_SANITIZE',
        sanitized: 'safe query',
      }),
    };

    const boundary = new GenericToolBoundary({ engine });
    let dispatchedInput: unknown = null;

    const wrapped = wrapGenericToolDispatcher(boundary, async (_tool, input) => {
      dispatchedInput = input;
      return { ok: true };
    });

    await wrapped('search', { text: 'drop database', keep: 1 }, 'run-4');
    expect(dispatchedInput).toEqual({ text: 'safe query', keep: 1 });
  });

  it('short-circuits dispatcher execution when sanitize provides replacement_result', async () => {
    const replacement = { result: 'policy-safe' };
    const engine: PolicyEngineLike = {
      evaluate: () => ({
        status: 'sanitize',
        reason_code: 'ADC_POLICY_SANITIZE',
        details: { replacement_result: replacement },
      }),
    };

    const boundary = new GenericToolBoundary({ engine });
    let dispatched = false;

    const wrapped = wrapGenericToolDispatcher(boundary, async () => {
      dispatched = true;
      return { result: 'dispatcher-output' };
    });

    const output = await wrapped('tool', { text: 'dangerous' }, 'run-5');
    expect(dispatched).toBe(false);
    expect(output).toEqual(replacement);
  });

  it('preserves string input shape when sanitize rewrites raw string input', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({
        status: 'sanitize',
        reason_code: 'ADC_POLICY_SANITIZE',
        sanitized: 'safe string input',
      }),
    };

    const boundary = new GenericToolBoundary<string>({ engine });
    let dispatchedInput: unknown = null;

    const wrapped = wrapGenericToolDispatcher(boundary, async (_tool, input) => {
      dispatchedInput = input;
      return 'ok';
    });

    await wrapped('string_tool', 'dangerous string input', 'run-6');
    expect(typeof dispatchedInput).toBe('string');
    expect(dispatchedInput).toBe('safe string input');
  });
});
