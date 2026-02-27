import { describe, it, expect, vi, afterEach } from 'vitest';
import { probeRemoteEngine } from './probe.js';

describe('probeRemoteEngine', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('returns true when remote responds with OK status', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });

    const result = await probeRemoteEngine('http://localhost:8080/health', 5000);
    expect(result).toBe(true);
    expect(globalThis.fetch).toHaveBeenCalledWith(
      'http://localhost:8080/health',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('returns false when remote responds with non-OK status', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 503 });

    const result = await probeRemoteEngine('http://localhost:8080/health', 5000);
    expect(result).toBe(false);
  });

  it('returns false on network error', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));

    const result = await probeRemoteEngine('http://localhost:8080/health', 5000);
    expect(result).toBe(false);
  });

  it('returns false on fetch abort (timeout)', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new DOMException('Aborted', 'AbortError'));

    const result = await probeRemoteEngine('http://localhost:8080/health', 1);
    expect(result).toBe(false);
  });

  it('passes signal to fetch for abort support', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });

    await probeRemoteEngine('http://example.com/health', 5000);
    const callArgs = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(callArgs[1]).toHaveProperty('signal');
    expect(callArgs[1].signal).toBeInstanceOf(AbortSignal);
  });
});
