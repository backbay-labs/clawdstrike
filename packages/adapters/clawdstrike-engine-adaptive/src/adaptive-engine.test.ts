import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createAdaptiveEngine } from './adaptive-engine.js';
import type { Decision, PolicyEngineLike, PolicyEvent } from '@clawdstrike/adapter-core';
import type { ModeChangeEvent, EnrichedProvenance } from './types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEvent(id = 'evt-1'): PolicyEvent {
  return {
    eventId: id,
    eventType: 'tool_call',
    timestamp: new Date().toISOString(),
    data: { type: 'tool', toolName: 'test', parameters: {} },
  };
}

function mockEngine(decision: Decision, opts?: { redact?: (v: string) => string }): PolicyEngineLike {
  return {
    evaluate: vi.fn().mockResolvedValue(decision),
    redactSecrets: opts?.redact,
  };
}

function failingEngine(error: Error): PolicyEngineLike {
  return {
    evaluate: vi.fn().mockRejectedValue(error),
  };
}

function connectivityError(): Error {
  return new Error('fetch failed: ECONNREFUSED');
}

function getProvenance(decision: Decision): EnrichedProvenance | undefined {
  const details = decision.details as Record<string, unknown> | undefined;
  return details?.provenance as EnrichedProvenance | undefined;
}

// Disable real timers for probe intervals.
beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
});

afterEach(() => {
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('createAdaptiveEngine', () => {
  describe('standalone mode (no remote)', () => {
    it('evaluates using local engine', async () => {
      const local = mockEngine({ status: 'allow' });
      const engine = createAdaptiveEngine({ local });

      const decision = await engine.evaluate(makeEvent());
      expect(decision.status).toBe('allow');
      expect(local.evaluate).toHaveBeenCalledTimes(1);

      const prov = getProvenance(decision);
      expect(prov).toBeDefined();
      expect(prov!.mode).toBe('standalone');
      expect(prov!.engine).toBe('local');
      engine.dispose();
    });

    it('fails closed on local engine error', async () => {
      const local = failingEngine(new Error('local boom'));
      const engine = createAdaptiveEngine({ local });

      const decision = await engine.evaluate(makeEvent());
      expect(decision.status).toBe('deny');
      expect(decision.reason_code).toBe('ADC_GUARD_ERROR');
      expect(decision.message).toContain('local boom');
      engine.dispose();
    });
  });

  describe('connected mode', () => {
    it('evaluates using remote engine when connected', async () => {
      const local = mockEngine({ status: 'allow' });
      const remote = mockEngine({ status: 'allow' });
      const engine = createAdaptiveEngine({
        local,
        remote,
        initialMode: 'connected',
      });

      const decision = await engine.evaluate(makeEvent());
      expect(decision.status).toBe('allow');
      expect(remote.evaluate).toHaveBeenCalledTimes(1);
      expect(local.evaluate).not.toHaveBeenCalled();

      const prov = getProvenance(decision);
      expect(prov!.mode).toBe('connected');
      expect(prov!.engine).toBe('remote');
      engine.dispose();
    });

    it('fails closed on non-connectivity remote error', async () => {
      const local = mockEngine({ status: 'allow' });
      const remote = failingEngine(new Error('500 internal server error'));
      const engine = createAdaptiveEngine({
        local,
        remote,
        initialMode: 'connected',
      });

      const decision = await engine.evaluate(makeEvent());
      expect(decision.status).toBe('deny');
      expect(decision.reason_code).toBe('ADC_GUARD_ERROR');
      expect(decision.message).toContain('500 internal server error');
      // Should NOT have fallen through to local.
      expect(local.evaluate).not.toHaveBeenCalled();
      engine.dispose();
    });
  });

  describe('mode demotion: connected → degraded', () => {
    it('falls back to local on connectivity error and transitions to degraded', async () => {
      const local = mockEngine({ status: 'allow' });
      const remote = failingEngine(connectivityError());
      const modeChanges: ModeChangeEvent[] = [];
      const engine = createAdaptiveEngine({
        local,
        remote,
        initialMode: 'connected',
        onModeChange: (e) => modeChanges.push(e),
      });

      const decision = await engine.evaluate(makeEvent());
      expect(decision.status).toBe('allow');
      expect(local.evaluate).toHaveBeenCalledTimes(1);

      // Mode should have changed to degraded.
      expect(modeChanges).toHaveLength(1);
      expect(modeChanges[0].from).toBe('connected');
      expect(modeChanges[0].to).toBe('degraded');

      const prov = getProvenance(decision);
      expect(prov!.mode).toBe('degraded');
      expect(prov!.engine).toBe('local');
      engine.dispose();
    });

    it('fails closed when local also fails during fallback', async () => {
      const local = failingEngine(new Error('local also broke'));
      const remote = failingEngine(connectivityError());
      const engine = createAdaptiveEngine({
        local,
        remote,
        initialMode: 'connected',
      });

      const decision = await engine.evaluate(makeEvent());
      expect(decision.status).toBe('deny');
      expect(decision.reason_code).toBe('ADC_GUARD_ERROR');
      expect(decision.message).toContain('local also broke');
      engine.dispose();
    });
  });

  describe('degraded mode', () => {
    it('uses local engine and queues receipts', async () => {
      const local = mockEngine({ status: 'allow' });
      const remote = mockEngine({ status: 'allow' });
      const engine = createAdaptiveEngine({
        local,
        remote,
        initialMode: 'degraded',
      });

      await engine.evaluate(makeEvent('e1'));
      await engine.evaluate(makeEvent('e2'));

      expect(local.evaluate).toHaveBeenCalledTimes(2);
      expect(remote.evaluate).not.toHaveBeenCalled();
      engine.dispose();
    });
  });

  describe('mode promotion: degraded → connected via probe', () => {
    it('promotes to connected and drains queue when probe succeeds', async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });

      const local = mockEngine({ status: 'allow' });
      const remote = mockEngine({ status: 'allow' });
      const modeChanges: ModeChangeEvent[] = [];
      const engine = createAdaptiveEngine({
        local,
        remote,
        initialMode: 'degraded',
        probe: {
          remoteHealthUrl: 'http://localhost:8080/health',
          intervalMs: 1000,
          timeoutMs: 500,
        },
        onModeChange: (e) => modeChanges.push(e),
      });

      // Queue a receipt in degraded mode.
      await engine.evaluate(makeEvent('queued-1'));

      // Allow the initial probe to fire and complete.
      await vi.advanceTimersByTimeAsync(100);

      // The probe should have promoted to connected.
      const promotionEvent = modeChanges.find((e) => e.to === 'connected');
      expect(promotionEvent).toBeDefined();
      expect(modeChanges).toHaveLength(1);
      expect(promotionEvent?.drainedReceipts).toHaveLength(1);
      expect(promotionEvent?.drainedReceipts?.[0]?.event).toMatchObject({ eventId: 'queued-1' });

      // Next evaluation should use remote.
      const decision = await engine.evaluate(makeEvent('after-promotion'));
      expect(remote.evaluate).toHaveBeenCalled();

      const prov = getProvenance(decision);
      expect(prov!.mode).toBe('connected');
      expect(prov!.engine).toBe('remote');

      engine.dispose();
      globalThis.fetch = originalFetch;
    });
  });

  describe('enriched provenance', () => {
    it('preserves existing decision details', async () => {
      const local: PolicyEngineLike = {
        evaluate: vi.fn().mockResolvedValue({
          status: 'allow',
          details: { existing: 'data' },
        }),
      };
      const engine = createAdaptiveEngine({ local });

      const decision = await engine.evaluate(makeEvent());
      const details = decision.details as Record<string, unknown>;
      expect(details.existing).toBe('data');
      expect(details.provenance).toBeDefined();
      engine.dispose();
    });

    it('handles decision with no details', async () => {
      const local = mockEngine({ status: 'allow' });
      const engine = createAdaptiveEngine({ local });

      const decision = await engine.evaluate(makeEvent());
      const details = decision.details as Record<string, unknown>;
      expect(details.provenance).toBeDefined();
      engine.dispose();
    });
  });

  describe('redactSecrets', () => {
    it('delegates to remote engine in connected mode', () => {
      const local = mockEngine({ status: 'allow' }, { redact: (v) => `local:${v}` });
      const remote = mockEngine({ status: 'allow' }, { redact: (v) => `remote:${v}` });
      const engine = createAdaptiveEngine({
        local,
        remote,
        initialMode: 'connected',
      });

      expect(engine.redactSecrets!('secret')).toBe('remote:secret');
      engine.dispose();
    });

    it('delegates to local engine in standalone mode', () => {
      const local = mockEngine({ status: 'allow' }, { redact: (v) => `local:${v}` });
      const engine = createAdaptiveEngine({ local });

      expect(engine.redactSecrets!('secret')).toBe('local:secret');
      engine.dispose();
    });

    it('returns value unchanged when no engine has redactSecrets', () => {
      const local = mockEngine({ status: 'allow' });
      const engine = createAdaptiveEngine({ local });

      expect(engine.redactSecrets!('plaintext')).toBe('plaintext');
      engine.dispose();
    });

    it('falls back to local redactSecrets when connected engine lacks it', () => {
      const local = mockEngine({ status: 'allow' }, { redact: (v) => `local:${v}` });
      const remote = mockEngine({ status: 'allow' }); // no redactSecrets
      const engine = createAdaptiveEngine({
        local,
        remote,
        initialMode: 'connected',
      });

      expect(engine.redactSecrets!('secret')).toBe('local:secret');
      engine.dispose();
    });
  });

  describe('dispose', () => {
    it('stops the probe interval', async () => {
      const originalFetch = globalThis.fetch;
      const fetchMock = vi.fn().mockResolvedValue({ ok: true });
      globalThis.fetch = fetchMock;

      const local = mockEngine({ status: 'allow' });
      const remote = mockEngine({ status: 'allow' });
      const engine = createAdaptiveEngine({
        local,
        remote,
        initialMode: 'standalone',
        probe: {
          remoteHealthUrl: 'http://localhost:8080/health',
          intervalMs: 100,
          timeoutMs: 50,
        },
      });

      // Let initial probe fire.
      await vi.advanceTimersByTimeAsync(50);
      const callsAfterInit = fetchMock.mock.calls.length;

      engine.dispose();

      // Advance time well past multiple probe intervals.
      await vi.advanceTimersByTimeAsync(500);
      expect(fetchMock.mock.calls.length).toBe(callsAfterInit);

      globalThis.fetch = originalFetch;
    });
  });

  describe('fail-closed guarantees', () => {
    it('fails closed when local throws synchronously', async () => {
      const local: PolicyEngineLike = {
        evaluate: vi.fn().mockImplementation(() => {
          throw new Error('sync throw');
        }),
      };
      const engine = createAdaptiveEngine({ local });

      const decision = await engine.evaluate(makeEvent());
      expect(decision.status).toBe('deny');
      expect(decision.reason_code).toBe('ADC_GUARD_ERROR');
      engine.dispose();
    });

    it('fails closed when remote throws synchronously in connected mode', async () => {
      const local = mockEngine({ status: 'allow' });
      const remote: PolicyEngineLike = {
        evaluate: vi.fn().mockImplementation(() => {
          throw new Error('remote sync throw');
        }),
      };
      const engine = createAdaptiveEngine({
        local,
        remote,
        initialMode: 'connected',
      });

      const decision = await engine.evaluate(makeEvent());
      expect(decision.status).toBe('deny');
      expect(decision.reason_code).toBe('ADC_GUARD_ERROR');
      engine.dispose();
    });
  });
});
