import { describe, expect, it } from 'vitest';

import type { ToolInterceptor } from './interceptor.js';
import { FrameworkToolBoundary, wrapFrameworkToolDispatcher } from './framework-tool-boundary.js';

function createInterceptor(overrides: Partial<ToolInterceptor> = {}): ToolInterceptor {
  return {
    beforeExecute: async () => ({
      proceed: true,
      duration: 0,
      decision: { status: 'allow' },
    }),
    afterExecute: async (_toolName, _input, output) => ({
      output,
      modified: false,
    }),
    onError: async () => {},
    ...overrides,
  };
}

describe('FrameworkToolBoundary', () => {
  it('forwards sanitize-modified input to framework dispatchers', async () => {
    let dispatchInput: unknown;
    let afterExecuteInput: unknown;
    const interceptor = createInterceptor({
      beforeExecute: async () => ({
        proceed: true,
        duration: 0,
        decision: {
          status: 'sanitize',
          reason_code: 'ADC_POLICY_SANITIZE',
        },
        modifiedInput: 'safe input',
      }),
      afterExecute: async (_toolName, input, output) => {
        afterExecuteInput = input;
        return { output, modified: false };
      },
    });

    const boundary = new FrameworkToolBoundary('openai', { interceptor });
    const wrapped = wrapFrameworkToolDispatcher(boundary, async (_toolName, input) => {
      dispatchInput = input;
      return 'ok';
    });

    const output = await wrapped('summarize', 'unsafe input', 'run-1');

    expect(output).toBe('ok');
    expect(dispatchInput).toBe('safe input');
    expect(afterExecuteInput).toBe('safe input');
  });

  it('forwards sanitize-modified parameters when modifiedInput is absent', async () => {
    let dispatchInput: unknown;
    const interceptor = createInterceptor({
      beforeExecute: async () => ({
        proceed: true,
        duration: 0,
        decision: {
          status: 'sanitize',
          reason_code: 'ADC_POLICY_SANITIZE',
        },
        modifiedParameters: { text: 'safe query' },
      }),
    });

    const boundary = new FrameworkToolBoundary('claude', { interceptor });
    const wrapped = wrapFrameworkToolDispatcher(boundary, async (_toolName, input) => {
      dispatchInput = input;
      return { ok: true };
    });

    await wrapped('search', { text: 'dangerous query' }, 'run-2');
    expect(dispatchInput).toEqual({ text: 'safe query' });
  });

  it('short-circuits dispatch when sanitize provides replacement results', async () => {
    const replacement = { result: 'policy-safe-result' };
    let dispatched = false;
    const interceptor = createInterceptor({
      beforeExecute: async () => ({
        proceed: true,
        duration: 0,
        decision: {
          status: 'sanitize',
          reason_code: 'ADC_POLICY_SANITIZE',
        },
        replacementResult: replacement,
      }),
    });

    const boundary = new FrameworkToolBoundary('opencode', { interceptor });
    const wrapped = wrapFrameworkToolDispatcher(boundary, async () => {
      dispatched = true;
      return { result: 'raw-dispatch-result' };
    });

    const output = await wrapped('tool', { payload: 'unsafe' }, 'run-3');

    expect(dispatched).toBe(false);
    expect(output).toEqual(replacement);
  });
});
