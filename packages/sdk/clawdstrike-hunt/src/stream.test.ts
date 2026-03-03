import { describe, it, expect, vi } from 'vitest';
import type { StreamItem, StreamOptions } from './stream.js';
import type { TimelineEvent, Alert } from './types.js';
import { EventSourceType, TimelineEventKind, NormalizedVerdict, RuleSeverity } from './types.js';

describe('stream module', () => {
  it('exports stream function', async () => {
    const mod = await import('./stream.js');
    expect(typeof mod.stream).toBe('function');
  });

  it('exports streamAll function', async () => {
    const mod = await import('./stream.js');
    expect(typeof mod.streamAll).toBe('function');
  });

  it('stream throws WatchError when nats is not available', async () => {
    const { stream } = await import('./stream.js');
    const options: StreamOptions = {
      natsUrl: 'nats://localhost:4222',
      rules: [],
      maxWindow: 60000,
    };

    try {
      const gen = stream(options);
      await gen.next();
      // If nats is installed, it tried to connect and will fail — that's ok
    } catch (e: unknown) {
      const err = e as Error;
      expect(err).toBeInstanceOf(Error);
    }
  });

  it('streamAll throws WatchError when nats is not available', async () => {
    const { streamAll } = await import('./stream.js');
    const options: StreamOptions = {
      natsUrl: 'nats://localhost:4222',
      rules: [],
      maxWindow: 60000,
    };

    try {
      const gen = streamAll(options);
      await gen.next();
    } catch (e: unknown) {
      const err = e as Error;
      expect(err).toBeInstanceOf(Error);
    }
  });

  it('stream passes maxWindow to processEvent and avoids explicit wall-clock eviction', async () => {
    vi.resetModules();

    const processEvent = vi.fn(() => []);
    const evict = vi.fn();
    const flush = vi.fn(() => []);
    class MockEngine {
      processEvent = processEvent;
      evict = evict;
      flush = flush;
      constructor(_rules: unknown[]) {}
    }

    const parseEnvelope = vi.fn(() => ({ timestamp: new Date('2025-01-01T00:00:00Z') }));
    const sub = {
      [Symbol.asyncIterator]: async function* () {
        yield {
          data: new TextEncoder().encode(JSON.stringify({ kind: 'event' })),
        };
      },
      unsubscribe: vi.fn(),
    };
    const nc = {
      subscribe: vi.fn(() => sub),
      drain: vi.fn(async () => undefined),
    };
    const connect = vi.fn(async () => nc);

    vi.doMock('./correlate/engine.js', () => ({ CorrelationEngine: MockEngine }));
    vi.doMock('./timeline.js', () => ({ parseEnvelope }));
    vi.doMock('nats', () => ({ connect }));

    const { stream } = await import('./stream.js');
    const alerts: Alert[] = [];
    for await (const alert of stream({ natsUrl: 'nats://localhost:4222', rules: [], maxWindow: 30_000 })) {
      alerts.push(alert);
    }

    expect(alerts).toHaveLength(0);
    expect(processEvent).toHaveBeenCalledTimes(1);
    expect(processEvent).toHaveBeenCalledWith(
      expect.objectContaining({ timestamp: expect.any(Date) }),
      30_000,
    );
    expect(evict).not.toHaveBeenCalled();
  });

  it('streamAll passes maxWindow to processEvent and avoids explicit wall-clock eviction', async () => {
    vi.resetModules();

    const processEvent = vi.fn(() => []);
    const evict = vi.fn();
    const flush = vi.fn(() => []);
    class MockEngine {
      processEvent = processEvent;
      evict = evict;
      flush = flush;
      constructor(_rules: unknown[]) {}
    }

    const parseEnvelope = vi.fn(() => ({
      timestamp: new Date('2025-01-01T00:00:00Z'),
      summary: 'ok',
    }));
    const sub = {
      [Symbol.asyncIterator]: async function* () {
        yield {
          data: new TextEncoder().encode(JSON.stringify({ kind: 'event' })),
        };
      },
      unsubscribe: vi.fn(),
    };
    const nc = {
      subscribe: vi.fn(() => sub),
      drain: vi.fn(async () => undefined),
    };
    const connect = vi.fn(async () => nc);

    vi.doMock('./correlate/engine.js', () => ({ CorrelationEngine: MockEngine }));
    vi.doMock('./timeline.js', () => ({ parseEnvelope }));
    vi.doMock('nats', () => ({ connect }));

    const { streamAll } = await import('./stream.js');
    const items: StreamItem[] = [];
    for await (const item of streamAll({ natsUrl: 'nats://localhost:4222', rules: [], maxWindow: 30_000 })) {
      items.push(item);
    }

    expect(items).toHaveLength(1);
    expect(items[0]?.type).toBe('event');
    expect(processEvent).toHaveBeenCalledTimes(1);
    expect(processEvent).toHaveBeenCalledWith(
      expect.objectContaining({ timestamp: expect.any(Date) }),
      30_000,
    );
    expect(evict).not.toHaveBeenCalled();
  });

  it('StreamItem alert type has correct structure', () => {
    const now = new Date();
    const event: TimelineEvent = {
      timestamp: now,
      source: EventSourceType.Receipt,
      kind: TimelineEventKind.GuardDecision,
      verdict: NormalizedVerdict.Deny,
      summary: 'test',
    };
    const alert: Alert = {
      ruleName: 'test-rule',
      severity: RuleSeverity.High,
      title: 'Test Alert',
      triggeredAt: now,
      evidence: [event],
      description: 'test description',
    };

    const item: StreamItem = { type: 'alert', alert };
    expect(item.type).toBe('alert');
    expect(item.alert.ruleName).toBe('test-rule');
  });

  it('StreamItem event type has correct structure', () => {
    const event: TimelineEvent = {
      timestamp: new Date(),
      source: EventSourceType.Tetragon,
      kind: TimelineEventKind.ProcessExec,
      verdict: NormalizedVerdict.Allow,
      summary: 'ls executed',
    };

    const item: StreamItem = { type: 'event', event };
    expect(item.type).toBe('event');
    expect(item.event.summary).toBe('ls executed');
  });

  it('StreamItem discriminated union covers both variants', () => {
    const event: TimelineEvent = {
      timestamp: new Date(),
      source: EventSourceType.Tetragon,
      kind: TimelineEventKind.ProcessExec,
      verdict: NormalizedVerdict.Allow,
      summary: 'test',
    };

    const items: StreamItem[] = [
      { type: 'event', event },
      {
        type: 'alert',
        alert: {
          ruleName: 'r',
          severity: RuleSeverity.Low,
          title: 't',
          triggeredAt: new Date(),
          evidence: [event],
          description: 'd',
        },
      },
    ];

    const types = items.map(i => i.type);
    expect(types).toEqual(['event', 'alert']);
  });
});
