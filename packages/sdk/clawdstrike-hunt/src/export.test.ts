import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  WebhookAdapter,
  SplunkHECAdapter,
  ElasticAdapter,
  toStix,
  toCSV,
  toJSONL,
} from './export.js';
import { ExportError } from './errors.js';
import type { Alert, TimelineEvent, IocMatch, IocEntry } from './types.js';
import {
  EventSourceType,
  TimelineEventKind,
  NormalizedVerdict,
  RuleSeverity,
  IocType,
} from './types.js';

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function makeEvent(overrides?: Partial<TimelineEvent>): TimelineEvent {
  return {
    timestamp: new Date('2025-01-15T10:00:00Z'),
    source: EventSourceType.Tetragon,
    kind: TimelineEventKind.ProcessExec,
    verdict: NormalizedVerdict.Allow,
    summary: 'ls executed',
    ...overrides,
  };
}

function makeAlert(overrides?: Partial<Alert>): Alert {
  return {
    ruleName: 'test-rule',
    severity: RuleSeverity.High,
    title: 'Test Alert',
    triggeredAt: new Date('2025-01-15T10:00:00Z'),
    evidence: [makeEvent()],
    description: 'test description',
    ...overrides,
  };
}

describe('WebhookAdapter', () => {
  it('constructs with url and optional headers', () => {
    const adapter = new WebhookAdapter('https://example.com/hook', {
      'X-Api-Key': 'secret',
    });
    expect(adapter).toBeDefined();
  });

  it('posts items as JSON to the webhook url', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true });

    const adapter = new WebhookAdapter('https://example.com/hook');
    await adapter.export([makeAlert()]);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe('https://example.com/hook');
    expect(init.method).toBe('POST');
    expect(init.headers['Content-Type']).toBe('application/json');

    const body = JSON.parse(init.body);
    expect(body).toHaveLength(1);
    expect(body[0].type).toBe('alert');
  });

  it('throws ExportError on non-OK response', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
    });

    const adapter = new WebhookAdapter('https://example.com/hook');
    await expect(adapter.export([makeEvent()])).rejects.toThrow(ExportError);
  });
});

describe('SplunkHECAdapter', () => {
  it('sends Splunk auth header', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true });

    const adapter = new SplunkHECAdapter(
      'https://splunk.example.com:8088/services/collector',
      'my-token',
    );
    await adapter.export([makeEvent()]);

    const [, init] = mockFetch.mock.calls[0];
    expect(init.headers['Authorization']).toBe('Splunk my-token');
  });

  it('formats events in HEC format with optional index', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true });

    const adapter = new SplunkHECAdapter(
      'https://splunk.example.com:8088/services/collector',
      'my-token',
      'security',
    );
    await adapter.export([makeEvent()]);

    const [, init] = mockFetch.mock.calls[0];
    const lines = init.body.split('\n');
    const parsed = JSON.parse(lines[0]);
    expect(parsed.event).toBeDefined();
    expect(parsed.index).toBe('security');
  });
});

describe('ElasticAdapter', () => {
  it('sends bulk NDJSON format', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: vi.fn().mockResolvedValue({ errors: false, items: [] }),
    });

    const adapter = new ElasticAdapter(
      'https://elastic.example.com:9200',
      'hunt-events',
    );
    await adapter.export([makeEvent()]);

    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe('https://elastic.example.com:9200/_bulk');
    expect(init.headers['Content-Type']).toBe('application/x-ndjson');

    const lines = init.body.trim().split('\n');
    expect(lines).toHaveLength(2);
    const action = JSON.parse(lines[0]);
    expect(action.index._index).toBe('hunt-events');
  });

  it('sends ApiKey auth header when provided', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: vi.fn().mockResolvedValue({ errors: false, items: [] }),
    });

    const adapter = new ElasticAdapter(
      'https://elastic.example.com:9200',
      'hunt-events',
      'my-api-key',
    );
    await adapter.export([makeEvent()]);

    const [, init] = mockFetch.mock.calls[0];
    expect(init.headers['Authorization']).toBe('ApiKey my-api-key');
  });

  it('throws ExportError on non-OK response', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      statusText: 'Forbidden',
    });

    const adapter = new ElasticAdapter(
      'https://elastic.example.com:9200',
      'hunt-events',
    );
    await expect(adapter.export([makeAlert()])).rejects.toThrow(ExportError);
  });

  it('throws ExportError when bulk response has item errors', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: vi.fn().mockResolvedValue({
        errors: true,
        items: [
          {
            index: {
              status: 400,
              error: { type: 'mapper_parsing_exception', reason: 'failed to parse field' },
            },
          },
        ],
      }),
    });

    const adapter = new ElasticAdapter(
      'https://elastic.example.com:9200',
      'hunt-events',
    );
    await expect(adapter.export([makeAlert()])).rejects.toThrow(ExportError);
  });
});

describe('toStix', () => {
  it('produces valid STIX 2.1 bundle from alerts', () => {
    const bundle = toStix([makeAlert()]);
    expect(bundle.type).toBe('bundle');
    expect(typeof bundle.id).toBe('string');
    expect((bundle.id as string).startsWith('bundle--')).toBe(true);

    const objects = bundle.objects as Record<string, unknown>[];
    expect(objects).toHaveLength(1);
    expect(objects[0].type).toBe('indicator');
    expect(objects[0].spec_version).toBe('2.1');
    expect(objects[0].pattern_type).toBe('clawdstrike');
    expect(objects[0].name).toBe('Test Alert');
  });

  it('includes IOC matches as STIX indicators', () => {
    const iocEntry: IocEntry = {
      indicator: 'evil.example.com',
      iocType: IocType.Domain,
      description: 'Known C2 domain',
    };
    const iocMatch: IocMatch = {
      event: makeEvent(),
      matchedIocs: [iocEntry],
      matchField: 'summary',
    };

    const bundle = toStix([makeAlert()], [iocMatch]);
    const objects = bundle.objects as Record<string, unknown>[];
    expect(objects).toHaveLength(2);
    expect(objects[1].pattern_type).toBe('stix');
    expect(objects[1].pattern).toContain('domain-name:value');
  });

  it('returns empty objects array when no alerts', () => {
    const bundle = toStix([]);
    const objects = bundle.objects as Record<string, unknown>[];
    expect(objects).toHaveLength(0);
  });
});

describe('toCSV', () => {
  it('formats events as CSV', () => {
    const csv = toCSV([makeEvent(), makeEvent({ summary: 'cat /etc/passwd' })]);
    const lines = csv.split('\n');
    expect(lines).toHaveLength(3);
    expect(lines[0]).toBe(
      'timestamp,source,kind,verdict,summary,process,actionType',
    );
    expect(lines[1]).toContain('ls executed');
    expect(lines[2]).toContain('cat /etc/passwd');
  });

  it('formats alerts as CSV', () => {
    const csv = toCSV([makeAlert()]);
    const lines = csv.split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe(
      'ruleName,severity,title,triggeredAt,description,evidenceCount',
    );
    expect(lines[1]).toContain('test-rule');
    expect(lines[1]).toContain('1'); // evidence count
  });

  it('returns empty string for empty input', () => {
    expect(toCSV([])).toBe('');
  });

  it('escapes values containing \\r', () => {
    const csv = toCSV([makeEvent({ summary: 'line1\rline2' })]);
    expect(csv).toContain('"line1\rline2"');
  });
});

describe('toJSONL', () => {
  it('produces one JSON object per line', () => {
    const items = [makeAlert(), makeEvent()];
    const jsonl = toJSONL(items);
    const lines = jsonl.split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).type).toBe('alert');
    expect(JSON.parse(lines[1]).type).toBe('event');
  });

  it('returns empty string for empty input', () => {
    expect(toJSONL([])).toBe('');
  });
});

describe('retry logic', () => {
  it('retries on 500 then succeeds', async () => {
    mockFetch
      .mockResolvedValueOnce({ ok: false, status: 500, statusText: 'Internal Server Error' })
      .mockResolvedValueOnce({ ok: true });

    const adapter = new WebhookAdapter(
      'https://example.com/hook',
      undefined,
      { maxRetries: 2, baseDelayMs: 1 },
    );
    await adapter.export([makeEvent()]);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('does not retry on 4xx', async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 400,
      statusText: 'Bad Request',
    });

    const adapter = new WebhookAdapter(
      'https://example.com/hook',
      undefined,
      { maxRetries: 2, baseDelayMs: 1 },
    );
    await expect(adapter.export([makeEvent()])).rejects.toThrow(ExportError);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('retries on network error', async () => {
    mockFetch
      .mockRejectedValueOnce(new TypeError('fetch failed'))
      .mockResolvedValueOnce({ ok: true });

    const adapter = new SplunkHECAdapter(
      'https://splunk.example.com:8088/services/collector',
      'my-token',
      undefined,
      { maxRetries: 1, baseDelayMs: 1 },
    );
    await adapter.export([makeEvent()]);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('throws after exhausting retries', async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 503,
      statusText: 'Service Unavailable',
    });

    const adapter = new ElasticAdapter(
      'https://elastic.example.com:9200',
      'hunt-events',
      undefined,
      { maxRetries: 2, baseDelayMs: 1 },
    );
    await expect(adapter.export([makeEvent()])).rejects.toThrow(ExportError);
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });
});
