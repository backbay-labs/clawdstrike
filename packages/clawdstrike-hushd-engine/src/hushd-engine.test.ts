import { describe, expect, it, vi } from 'vitest';

import type { PolicyEvent } from '@clawdstrike/adapter-core';

import { createHushdEngine } from './hushd-engine.js';

const exampleEvent: PolicyEvent = {
  eventId: 'evt-test',
  eventType: 'tool_call',
  timestamp: new Date().toISOString(),
  data: { type: 'tool', toolName: 'demo', parameters: { ok: true } },
};

describe('createHushdEngine', () => {
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

    const engine = createHushdEngine({ baseUrl: 'http://127.0.0.1:9876', timeoutMs: 5000 });
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

    const engine = createHushdEngine({
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

    const engine = createHushdEngine({ baseUrl: 'http://127.0.0.1:9876' });
    await expect(engine.evaluate(exampleEvent)).resolves.toMatchObject({
      status: 'deny',
      reason: 'engine_error',
    });
  });
});
