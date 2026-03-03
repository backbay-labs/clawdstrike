import { describe, it, expect } from 'vitest';
import type { TimelineEvent, HuntQuery } from './types.js';
import {
  EventSourceType,
  NormalizedVerdict,
  TimelineEventKind,
} from './types.js';
import {
  parseEventSource,
  parseEventSourceList,
  streamName,
  subjectFilter,
  allEventSources,
  parseQueryVerdict,
  createHuntQuery,
  effectiveSources,
  matchesQuery,
} from './query.js';

function makeEvent(overrides?: Partial<TimelineEvent>): TimelineEvent {
  return {
    timestamp: new Date('2025-06-15T12:00:00Z'),
    source: EventSourceType.Tetragon,
    kind: TimelineEventKind.ProcessExec,
    verdict: NormalizedVerdict.Allow,
    summary: 'process_exec /usr/bin/curl',
    process: '/usr/bin/curl',
    namespace: 'default',
    pod: 'agent-pod-abc123',
    actionType: 'process',
    ...overrides,
  };
}

describe('parseEventSource', () => {
  it('parses tetragon', () => {
    expect(parseEventSource('tetragon')).toBe(EventSourceType.Tetragon);
  });

  it('parses case-insensitive', () => {
    expect(parseEventSource('HUBBLE')).toBe(EventSourceType.Hubble);
    expect(parseEventSource('Receipt')).toBe(EventSourceType.Receipt);
  });

  it('accepts receipts alias', () => {
    expect(parseEventSource('receipts')).toBe(EventSourceType.Receipt);
  });

  it('accepts scan and scans', () => {
    expect(parseEventSource('scan')).toBe(EventSourceType.Scan);
    expect(parseEventSource('scans')).toBe(EventSourceType.Scan);
  });

  it('returns undefined for unknown', () => {
    expect(parseEventSource('unknown')).toBeUndefined();
  });
});

describe('parseEventSourceList', () => {
  it('parses comma-separated list', () => {
    expect(parseEventSourceList('tetragon, hubble')).toEqual([
      EventSourceType.Tetragon,
      EventSourceType.Hubble,
    ]);
  });

  it('parses single source', () => {
    expect(parseEventSourceList('SCAN')).toEqual([EventSourceType.Scan]);
  });

  it('returns empty for empty string', () => {
    expect(parseEventSourceList('')).toEqual([]);
  });

  it('skips invalid entries', () => {
    expect(parseEventSourceList('tetragon, invalid, hubble')).toEqual([
      EventSourceType.Tetragon,
      EventSourceType.Hubble,
    ]);
  });
});

describe('streamName', () => {
  it('returns correct stream names', () => {
    expect(streamName(EventSourceType.Tetragon)).toBe(
      'CLAWDSTRIKE_TETRAGON',
    );
    expect(streamName(EventSourceType.Hubble)).toBe('CLAWDSTRIKE_HUBBLE');
    expect(streamName(EventSourceType.Receipt)).toBe(
      'CLAWDSTRIKE_RECEIPTS',
    );
    expect(streamName(EventSourceType.Scan)).toBe('CLAWDSTRIKE_SCANS');
  });
});

describe('subjectFilter', () => {
  it('returns correct subject filters', () => {
    expect(subjectFilter(EventSourceType.Tetragon)).toBe(
      'clawdstrike.sdr.fact.tetragon_event.>',
    );
    expect(subjectFilter(EventSourceType.Hubble)).toBe(
      'clawdstrike.sdr.fact.hubble_flow.>',
    );
    expect(subjectFilter(EventSourceType.Receipt)).toBe(
      'clawdstrike.sdr.fact.receipt.>',
    );
    expect(subjectFilter(EventSourceType.Scan)).toBe(
      'clawdstrike.sdr.fact.scan.>',
    );
  });
});

describe('allEventSources', () => {
  it('returns all 4 sources', () => {
    const all = allEventSources();
    expect(all).toHaveLength(4);
    expect(all).toContain(EventSourceType.Tetragon);
    expect(all).toContain(EventSourceType.Hubble);
    expect(all).toContain(EventSourceType.Receipt);
    expect(all).toContain(EventSourceType.Scan);
  });
});

describe('parseQueryVerdict', () => {
  it('parses allow variants', () => {
    expect(parseQueryVerdict('allow')).toBe(NormalizedVerdict.Allow);
    expect(parseQueryVerdict('ALLOWED')).toBe(NormalizedVerdict.Allow);
    expect(parseQueryVerdict('pass')).toBe(NormalizedVerdict.Allow);
    expect(parseQueryVerdict('passed')).toBe(NormalizedVerdict.Allow);
  });

  it('parses deny variants', () => {
    expect(parseQueryVerdict('deny')).toBe(NormalizedVerdict.Deny);
    expect(parseQueryVerdict('DENIED')).toBe(NormalizedVerdict.Deny);
    expect(parseQueryVerdict('block')).toBe(NormalizedVerdict.Deny);
    expect(parseQueryVerdict('blocked')).toBe(NormalizedVerdict.Deny);
  });

  it('parses warn variants', () => {
    expect(parseQueryVerdict('warn')).toBe(NormalizedVerdict.Warn);
    expect(parseQueryVerdict('warned')).toBe(NormalizedVerdict.Warn);
    expect(parseQueryVerdict('warning')).toBe(NormalizedVerdict.Warn);
  });

  it('parses forwarded variants', () => {
    expect(parseQueryVerdict('forwarded')).toBe(NormalizedVerdict.Forwarded);
    expect(parseQueryVerdict('forward')).toBe(NormalizedVerdict.Forwarded);
  });

  it('parses dropped variants', () => {
    expect(parseQueryVerdict('dropped')).toBe(NormalizedVerdict.Dropped);
    expect(parseQueryVerdict('drop')).toBe(NormalizedVerdict.Dropped);
  });

  it('returns undefined for unknown', () => {
    expect(parseQueryVerdict('unknown')).toBeUndefined();
  });
});

describe('createHuntQuery', () => {
  it('creates query with defaults', () => {
    const q = createHuntQuery();
    expect(q.sources).toEqual([]);
    expect(q.limit).toBe(100);
    expect(q.verdict).toBeUndefined();
    expect(q.start).toBeUndefined();
    expect(q.end).toBeUndefined();
  });

  it('allows overrides', () => {
    const q = createHuntQuery({
      sources: [EventSourceType.Tetragon],
      limit: 50,
    });
    expect(q.sources).toEqual([EventSourceType.Tetragon]);
    expect(q.limit).toBe(50);
  });
});

describe('effectiveSources', () => {
  it('returns all sources when empty', () => {
    const q = createHuntQuery();
    expect(effectiveSources(q)).toEqual(allEventSources());
  });

  it('returns specified sources', () => {
    const q = createHuntQuery({ sources: [EventSourceType.Tetragon] });
    expect(effectiveSources(q)).toEqual([EventSourceType.Tetragon]);
  });

  it('deduplicates preserving order', () => {
    const q = createHuntQuery({
      sources: [
        EventSourceType.Receipt,
        EventSourceType.Receipt,
        EventSourceType.Hubble,
        EventSourceType.Receipt,
        EventSourceType.Hubble,
      ],
    });
    expect(effectiveSources(q)).toEqual([
      EventSourceType.Receipt,
      EventSourceType.Hubble,
    ]);
  });
});

describe('matchesQuery', () => {
  it('matches all with default query', () => {
    const q = createHuntQuery();
    expect(matchesQuery(q, makeEvent())).toBe(true);
  });

  it('filters by source', () => {
    const q = createHuntQuery({ sources: [EventSourceType.Hubble] });
    expect(matchesQuery(q, makeEvent())).toBe(false);

    const q2 = createHuntQuery({ sources: [EventSourceType.Tetragon] });
    expect(matchesQuery(q2, makeEvent())).toBe(true);
  });

  it('filters by verdict', () => {
    const q = createHuntQuery({ verdict: NormalizedVerdict.Deny });
    expect(matchesQuery(q, makeEvent())).toBe(false);

    const q2 = createHuntQuery({ verdict: NormalizedVerdict.Allow });
    expect(matchesQuery(q2, makeEvent())).toBe(true);
  });

  it('filters by forwarded verdict', () => {
    const event = makeEvent({ verdict: NormalizedVerdict.Forwarded });
    const q = createHuntQuery({ verdict: NormalizedVerdict.Forwarded });
    expect(matchesQuery(q, event)).toBe(true);

    const q2 = createHuntQuery({ verdict: NormalizedVerdict.Allow });
    expect(matchesQuery(q2, event)).toBe(false);
  });

  it('filters by dropped verdict', () => {
    const event = makeEvent({ verdict: NormalizedVerdict.Dropped });
    const q = createHuntQuery({ verdict: NormalizedVerdict.Dropped });
    expect(matchesQuery(q, event)).toBe(true);

    const q2 = createHuntQuery({ verdict: NormalizedVerdict.Deny });
    expect(matchesQuery(q2, event)).toBe(false);
  });

  it('filters by time range', () => {
    const event = makeEvent(); // 2025-06-15 12:00:00
    const q = createHuntQuery({
      start: new Date('2025-06-15T13:00:00Z'),
    });
    expect(matchesQuery(q, event)).toBe(false);

    const q2 = createHuntQuery({
      end: new Date('2025-06-15T11:00:00Z'),
    });
    expect(matchesQuery(q2, event)).toBe(false);

    const q3 = createHuntQuery({
      start: new Date('2025-06-15T11:00:00Z'),
      end: new Date('2025-06-15T13:00:00Z'),
    });
    expect(matchesQuery(q3, event)).toBe(true);
  });

  it('filters by action type case-insensitively', () => {
    const q = createHuntQuery({ actionType: 'PROCESS' });
    expect(matchesQuery(q, makeEvent())).toBe(true);
  });

  it('filters by process substring', () => {
    const q = createHuntQuery({ process: 'curl' });
    expect(matchesQuery(q, makeEvent())).toBe(true);

    const q2 = createHuntQuery({ process: 'wget' });
    expect(matchesQuery(q2, makeEvent())).toBe(false);
  });

  it('filters by namespace exact', () => {
    const q = createHuntQuery({ namespace: 'kube-system' });
    expect(matchesQuery(q, makeEvent())).toBe(false);

    const q2 = createHuntQuery({ namespace: 'default' });
    expect(matchesQuery(q2, makeEvent())).toBe(true);
  });

  it('filters by pod substring', () => {
    const q = createHuntQuery({ pod: 'agent-pod' });
    expect(matchesQuery(q, makeEvent())).toBe(true);
  });

  it('handles combined predicates', () => {
    const q = createHuntQuery({
      sources: [EventSourceType.Tetragon],
      verdict: NormalizedVerdict.Allow,
      process: 'curl',
      namespace: 'default',
    });
    expect(matchesQuery(q, makeEvent())).toBe(true);
  });

  it('rejects when optional field is missing', () => {
    const event = makeEvent({ process: undefined });
    const q = createHuntQuery({ process: 'curl' });
    expect(matchesQuery(q, event)).toBe(false);
  });

  it('entity matches pod', () => {
    const q = createHuntQuery({ entity: 'agent-pod' });
    expect(matchesQuery(q, makeEvent())).toBe(true);
  });

  it('entity matches namespace', () => {
    const q = createHuntQuery({ entity: 'default' });
    expect(matchesQuery(q, makeEvent())).toBe(true);
  });

  it('entity no match', () => {
    const q = createHuntQuery({ entity: 'nonexistent' });
    expect(matchesQuery(q, makeEvent())).toBe(false);
  });
});
