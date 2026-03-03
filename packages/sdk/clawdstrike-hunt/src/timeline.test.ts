import { describe, it, expect } from 'vitest';
import {
  EventSourceType,
  NormalizedVerdict,
  TimelineEventKind,
} from './types.js';
import { parseEnvelope, mergeTimeline } from './timeline.js';

describe('parseEnvelope', () => {
  describe('tetragon events', () => {
    it('parses PROCESS_EXEC', () => {
      const envelope = {
        issued_at: '2025-06-15T12:00:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.tetragon_event.v1',
          event_type: 'PROCESS_EXEC',
          process: {
            binary: '/usr/bin/curl',
            pod: {
              namespace: 'default',
              name: 'agent-pod-abc123',
            },
          },
          severity: 'info',
        },
      };

      const event = parseEnvelope(envelope);
      expect(event).toBeDefined();
      expect(event!.source).toBe(EventSourceType.Tetragon);
      expect(event!.kind).toBe(TimelineEventKind.ProcessExec);
      expect(event!.verdict).toBe(NormalizedVerdict.None);
      expect(event!.process).toBe('/usr/bin/curl');
      expect(event!.namespace).toBe('default');
      expect(event!.pod).toBe('agent-pod-abc123');
      expect(event!.severity).toBe('info');
      expect(event!.summary).toBe('process_exec /usr/bin/curl');
      expect(event!.actionType).toBe('process');
    });

    it('parses PROCESS_EXIT', () => {
      const envelope = {
        issued_at: '2025-06-15T12:01:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.tetragon_event.v1',
          event_type: 'PROCESS_EXIT',
          process: { binary: '/usr/bin/ls' },
        },
      };

      const event = parseEnvelope(envelope);
      expect(event).toBeDefined();
      expect(event!.kind).toBe(TimelineEventKind.ProcessExit);
      expect(event!.summary).toBe('process_exit /usr/bin/ls');
    });

    it('parses PROCESS_KPROBE', () => {
      const envelope = {
        issued_at: '2025-06-15T12:02:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.tetragon_event.v1',
          event_type: 'PROCESS_KPROBE',
          process: { binary: '/usr/bin/cat' },
        },
      };

      const event = parseEnvelope(envelope);
      expect(event).toBeDefined();
      expect(event!.kind).toBe(TimelineEventKind.ProcessKprobe);
    });

    it('defaults unknown event type to ProcessExec', () => {
      const envelope = {
        issued_at: '2025-06-15T12:02:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.tetragon_event.v1',
          event_type: 'SOME_FUTURE_TYPE',
          process: { binary: '/bin/sh' },
        },
      };

      const event = parseEnvelope(envelope);
      expect(event).toBeDefined();
      expect(event!.kind).toBe(TimelineEventKind.ProcessExec);
    });

    it('handles missing binary', () => {
      const envelope = {
        issued_at: '2025-06-15T12:00:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.tetragon_event.v1',
          event_type: 'PROCESS_EXEC',
          process: {},
        },
      };

      const event = parseEnvelope(envelope);
      expect(event).toBeDefined();
      expect(event!.summary).toContain('?');
      expect(event!.process).toBeUndefined();
    });
  });

  describe('hubble flow events', () => {
    it('parses FORWARDED verdict', () => {
      const envelope = {
        issued_at: '2025-06-15T12:05:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.hubble_flow.v1',
          verdict: 'FORWARDED',
          traffic_direction: 'EGRESS',
          summary: 'TCP 10.0.0.1:8080 -> 10.0.0.2:443',
          source: {
            namespace: 'production',
            pod_name: 'web-server-xyz',
          },
        },
      };

      const event = parseEnvelope(envelope);
      expect(event).toBeDefined();
      expect(event!.source).toBe(EventSourceType.Hubble);
      expect(event!.kind).toBe(TimelineEventKind.NetworkFlow);
      expect(event!.verdict).toBe(NormalizedVerdict.Forwarded);
      expect(event!.namespace).toBe('production');
      expect(event!.pod).toBe('web-server-xyz');
      expect(event!.summary).toContain('egress');
    });

    it('maps EGRESS to action type egress', () => {
      const envelope = {
        issued_at: '2025-06-15T12:05:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.hubble_flow.v1',
          verdict: 'FORWARDED',
          traffic_direction: 'EGRESS',
          summary: 'flow',
        },
      };
      const event = parseEnvelope(envelope);
      expect(event!.actionType).toBe('egress');
    });

    it('maps INGRESS to action type ingress', () => {
      const envelope = {
        issued_at: '2025-06-15T12:05:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.hubble_flow.v1',
          verdict: 'FORWARDED',
          traffic_direction: 'INGRESS',
          summary: 'flow',
        },
      };
      const event = parseEnvelope(envelope);
      expect(event!.actionType).toBe('ingress');
    });

    it('maps unknown direction to network', () => {
      const envelope = {
        issued_at: '2025-06-15T12:05:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.hubble_flow.v1',
          verdict: 'FORWARDED',
          traffic_direction: 'UNKNOWN',
          summary: 'flow',
        },
      };
      const event = parseEnvelope(envelope);
      expect(event!.actionType).toBe('network');
    });

    it('parses DROPPED verdict', () => {
      const envelope = {
        issued_at: '2025-06-15T12:06:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.hubble_flow.v1',
          verdict: 'DROPPED',
          traffic_direction: 'INGRESS',
          summary: 'blocked connection',
        },
      };
      const event = parseEnvelope(envelope);
      expect(event!.verdict).toBe(NormalizedVerdict.Dropped);
    });
  });

  describe('receipt events', () => {
    it('parses deny receipt', () => {
      const envelope = {
        issued_at: '2025-06-15T12:10:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.receipt.v1',
          decision: 'deny',
          guard: 'ForbiddenPathGuard',
          action_type: 'file',
          severity: 'critical',
        },
      };

      const event = parseEnvelope(envelope);
      expect(event).toBeDefined();
      expect(event!.source).toBe(EventSourceType.Receipt);
      expect(event!.kind).toBe(TimelineEventKind.GuardDecision);
      expect(event!.verdict).toBe(NormalizedVerdict.Deny);
      expect(event!.actionType).toBe('file');
      expect(event!.severity).toBe('critical');
      expect(event!.summary).toContain('ForbiddenPathGuard');
    });

    it('parses source metadata', () => {
      const envelope = {
        issued_at: '2025-06-15T12:10:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.receipt.v1',
          decision: 'deny',
          guard: 'ForbiddenPathGuard',
          action_type: 'file',
          source: {
            namespace: 'prod',
            pod_name: 'agent-worker-1',
          },
        },
      };

      const event = parseEnvelope(envelope);
      expect(event!.namespace).toBe('prod');
      expect(event!.pod).toBe('agent-worker-1');
    });

    it('falls back to pod field when pod_name is missing', () => {
      const envelope = {
        issued_at: '2025-06-15T12:10:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.receipt.v1',
          decision: 'allow',
          guard: 'TestGuard',
          source: {
            namespace: 'prod',
            pod: 'worker-2',
          },
        },
      };

      const event = parseEnvelope(envelope);
      expect(event!.pod).toBe('worker-2');
    });
  });

  describe('scan events', () => {
    it('parses fail scan', () => {
      const envelope = {
        issued_at: '2025-06-15T12:15:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.scan.v1',
          scan_type: 'vulnerability',
          status: 'fail',
          severity: 'high',
        },
      };

      const event = parseEnvelope(envelope);
      expect(event).toBeDefined();
      expect(event!.source).toBe(EventSourceType.Scan);
      expect(event!.kind).toBe(TimelineEventKind.ScanResult);
      expect(event!.verdict).toBe(NormalizedVerdict.Deny);
      expect(event!.severity).toBe('high');
      expect(event!.summary).toContain('vulnerability');
      expect(event!.actionType).toBe('scan');
    });

    it('parses pass scan', () => {
      const envelope = {
        issued_at: '2025-06-15T12:15:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.scan.v1',
          scan_type: 'malware',
          status: 'clean',
        },
      };
      const event = parseEnvelope(envelope);
      expect(event!.verdict).toBe(NormalizedVerdict.Allow);
    });

    it('parses warn scan', () => {
      const envelope = {
        issued_at: '2025-06-15T12:15:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.scan.v1',
          scan_type: 'config',
          status: 'warning',
        },
      };
      const event = parseEnvelope(envelope);
      expect(event!.verdict).toBe(NormalizedVerdict.Warn);
    });
  });

  describe('invalid envelopes', () => {
    it('returns undefined for unknown schema', () => {
      const envelope = {
        issued_at: '2025-06-15T12:00:00Z',
        fact: { schema: 'unknown.schema.v1' },
      };
      expect(parseEnvelope(envelope)).toBeUndefined();
    });

    it('returns undefined for missing fact', () => {
      const envelope = { issued_at: '2025-06-15T12:00:00Z' };
      expect(parseEnvelope(envelope)).toBeUndefined();
    });

    it('returns undefined for missing timestamp', () => {
      const envelope = {
        fact: {
          schema: 'clawdstrike.sdr.fact.tetragon_event.v1',
          event_type: 'PROCESS_EXEC',
          process: { binary: '/bin/sh' },
        },
      };
      expect(parseEnvelope(envelope)).toBeUndefined();
    });

    it('returns undefined for null', () => {
      expect(parseEnvelope(null)).toBeUndefined();
    });

    it('returns undefined for non-object', () => {
      expect(parseEnvelope('string')).toBeUndefined();
      expect(parseEnvelope(42)).toBeUndefined();
    });

    it('returns undefined for invalid timestamp', () => {
      const envelope = {
        issued_at: 'not-a-date',
        fact: {
          schema: 'clawdstrike.sdr.fact.tetragon_event.v1',
          event_type: 'PROCESS_EXEC',
          process: { binary: '/bin/sh' },
        },
      };
      expect(parseEnvelope(envelope)).toBeUndefined();
    });
  });

  describe('raw field', () => {
    it('preserves the original envelope as raw', () => {
      const envelope = {
        issued_at: '2025-06-15T12:00:00Z',
        fact: {
          schema: 'clawdstrike.sdr.fact.tetragon_event.v1',
          event_type: 'PROCESS_EXEC',
          process: { binary: '/usr/bin/curl' },
        },
      };

      const event = parseEnvelope(envelope);
      expect(event!.raw).toBe(envelope);
    });
  });
});

describe('mergeTimeline', () => {
  it('sorts events by timestamp ascending', () => {
    const events = [
      {
        timestamp: new Date('2025-06-15T14:00:00Z'),
        source: EventSourceType.Tetragon as const,
        kind: TimelineEventKind.ProcessExec as const,
        verdict: NormalizedVerdict.None as const,
        summary: 'second',
      },
      {
        timestamp: new Date('2025-06-15T12:00:00Z'),
        source: EventSourceType.Hubble as const,
        kind: TimelineEventKind.NetworkFlow as const,
        verdict: NormalizedVerdict.Forwarded as const,
        summary: 'first',
      },
      {
        timestamp: new Date('2025-06-15T16:00:00Z'),
        source: EventSourceType.Receipt as const,
        kind: TimelineEventKind.GuardDecision as const,
        verdict: NormalizedVerdict.Deny as const,
        summary: 'third',
      },
    ];

    const merged = mergeTimeline(events);
    expect(merged).toHaveLength(3);
    expect(merged[0].summary).toBe('first');
    expect(merged[1].summary).toBe('second');
    expect(merged[2].summary).toBe('third');
  });

  it('returns empty for empty input', () => {
    expect(mergeTimeline([])).toEqual([]);
  });

  it('does not mutate the original array', () => {
    const events = [
      {
        timestamp: new Date('2025-06-15T14:00:00Z'),
        source: EventSourceType.Tetragon as const,
        kind: TimelineEventKind.ProcessExec as const,
        verdict: NormalizedVerdict.None as const,
        summary: 'second',
      },
      {
        timestamp: new Date('2025-06-15T12:00:00Z'),
        source: EventSourceType.Tetragon as const,
        kind: TimelineEventKind.ProcessExec as const,
        verdict: NormalizedVerdict.None as const,
        summary: 'first',
      },
    ];

    mergeTimeline(events);
    expect(events[0].summary).toBe('second');
  });
});
