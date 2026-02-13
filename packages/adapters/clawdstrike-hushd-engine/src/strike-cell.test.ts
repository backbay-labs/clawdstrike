import { describe, expect, it, vi } from 'vitest';

import type { PolicyEvent } from '@clawdstrike/adapter-core';

import { createStrikeCell } from './strike-cell.js';

const exampleEvent: PolicyEvent = {
  eventId: 'evt-test',
  eventType: 'tool_call',
  timestamp: new Date().toISOString(),
  data: { type: 'tool', toolName: 'demo', parameters: { ok: true } },
};

describe('createStrikeCell', () => {
  it('POSTs to /api/v1/eval with wrapped event', async () => {
    const fetchMock = vi.fn(async () => {
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            version: 1,
            command: 'policy_eval',
            decision: { allowed: true, denied: false, warn: false },
          }),
      };
    });

    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);

    const engine = createStrikeCell({ baseUrl: 'http://127.0.0.1:9876', timeoutMs: 5000 });
    const decision = await engine.evaluate(exampleEvent);

    expect(decision.status).toBe('allow');

    expect(fetchMock).toHaveBeenCalledWith(
      'http://127.0.0.1:9876/api/v1/eval',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ 'content-type': 'application/json' }),
        body: JSON.stringify({ event: exampleEvent }),
      }),
    );
  });

  it('adds Authorization header when token is provided', async () => {
    const fetchMock = vi.fn(async () => {
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            version: 1,
            command: 'policy_eval',
            decision: { allowed: true, denied: false, warn: false },
          }),
      };
    });

    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);

    const engine = createStrikeCell({
      baseUrl: 'http://127.0.0.1:9876',
      token: 'test-token',
    });
    await engine.evaluate(exampleEvent);

    expect(fetchMock).toHaveBeenCalledWith(
      'http://127.0.0.1:9876/api/v1/eval',
      expect.objectContaining({
        headers: expect.objectContaining({ authorization: 'Bearer test-token' }),
      }),
    );
  });

  it('fails closed on non-2xx response', async () => {
    const fetchMock = vi.fn(async () => {
      return {
        ok: false,
        status: 500,
        text: async () => 'boom',
      };
    });

    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);

    const engine = createStrikeCell({ baseUrl: 'http://127.0.0.1:9876' });
    await expect(engine.evaluate(exampleEvent)).resolves.toMatchObject({
      status: 'deny',
      reason: 'engine_error',
    });
  });

  it('fails closed on network transport failure', async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error('connect ECONNREFUSED');
    });

    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);

    const engine = createStrikeCell({ baseUrl: 'http://127.0.0.1:9876' });
    await expect(engine.evaluate(exampleEvent)).resolves.toMatchObject({
      status: 'deny',
      reason: 'engine_error',
    });
  });

  it('uses fallback engine on connectivity error when offlineFallback is enabled', async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error('connect ECONNREFUSED 127.0.0.1:9876');
    });

    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);

    const fallback = {
      evaluate: vi.fn(async () => ({
        status: 'allow' as const,
        guard: 'cached_policy',
        message: 'Allowed by cached policy',
      })),
    };

    const engine = createStrikeCell({
      baseUrl: 'http://127.0.0.1:9876',
      fallback,
      offlineFallback: true,
    });

    const decision = await engine.evaluate(exampleEvent);
    expect(decision.status).toBe('allow');
    expect(decision.details).toMatchObject({ provenance: { mode: 'degraded' } });
    expect(fallback.evaluate).toHaveBeenCalledWith(exampleEvent);
  });

  it('does not use fallback on server-side errors (non-connectivity)', async () => {
    const fetchMock = vi.fn(async () => {
      return {
        ok: false,
        status: 500,
        text: async () => 'internal error',
      };
    });

    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);

    const fallback = {
      evaluate: vi.fn(async () => ({
        status: 'allow' as const,
      })),
    };

    const engine = createStrikeCell({
      baseUrl: 'http://127.0.0.1:9876',
      fallback,
      offlineFallback: true,
    });

    const decision = await engine.evaluate(exampleEvent);
    expect(decision.status).toBe('deny');
    expect(decision.reason).toBe('engine_error');
    // Fallback should NOT be called for server errors.
    expect(fallback.evaluate).not.toHaveBeenCalled();
  });

  it('falls back to fail-closed when offlineFallback is disabled', async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error('connect ECONNREFUSED');
    });

    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);

    const fallback = {
      evaluate: vi.fn(async () => ({
        status: 'allow' as const,
      })),
    };

    const engine = createStrikeCell({
      baseUrl: 'http://127.0.0.1:9876',
      fallback,
      offlineFallback: false,
    });

    const decision = await engine.evaluate(exampleEvent);
    expect(decision.status).toBe('deny');
    expect(decision.reason).toBe('engine_error');
    expect(fallback.evaluate).not.toHaveBeenCalled();
  });

  it('fails closed when fallback engine itself throws', async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error('connect ECONNREFUSED');
    });

    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);

    const fallback = {
      evaluate: vi.fn(async () => {
        throw new Error('fallback engine broken');
      }),
    };

    const engine = createStrikeCell({
      baseUrl: 'http://127.0.0.1:9876',
      fallback,
      offlineFallback: true,
    });

    const decision = await engine.evaluate(exampleEvent);
    expect(decision.status).toBe('deny');
    expect(decision.reason).toBe('engine_error');
    expect(decision.message).toContain('fallback engine broken');
  });
});
