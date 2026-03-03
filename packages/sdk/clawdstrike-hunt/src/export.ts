/**
 * Export adapters — webhook, Splunk HEC, Elasticsearch, STIX 2.1, and CSV.
 */

import { ExportError } from './errors.js';
import type { Alert, TimelineEvent, IocMatch, IocEntry } from './types.js';

export interface RetryConfig {
  maxRetries?: number;
  baseDelayMs?: number;
}

export interface ExportAdapter {
  export(items: (Alert | TimelineEvent)[]): Promise<void>;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null
    ? (value as Record<string, unknown>)
    : undefined;
}

function summarizeElasticBulkFailure(payload: unknown): string | undefined {
  const body = asRecord(payload);
  if (!body || body.errors !== true) {
    return undefined;
  }

  const items = Array.isArray(body.items) ? body.items : [];
  let total = 0;
  let failed = 0;
  let firstFailure: string | undefined;

  for (const item of items) {
    const itemRecord = asRecord(item);
    if (!itemRecord) {
      continue;
    }

    for (const [action, result] of Object.entries(itemRecord)) {
      const actionResult = asRecord(result);
      total += 1;
      if (!actionResult) {
        continue;
      }

      const status = typeof actionResult.status === 'number'
        ? actionResult.status
        : undefined;
      const itemError = actionResult.error;
      const hasError = itemError !== undefined || (status !== undefined && status >= 300);

      if (!hasError) {
        continue;
      }

      failed += 1;
      if (firstFailure === undefined) {
        const errorText = stringifyElasticError(itemError);
        const statusText = status !== undefined ? `status=${status}` : 'status=unknown';
        firstFailure = `${action} ${statusText}${errorText ? `: ${errorText}` : ''}`;
      }
    }
  }

  if (failed > 0) {
    return `${failed}/${total || failed} bulk items failed${firstFailure ? ` (${firstFailure})` : ''}`;
  }

  return 'bulk response reported errors=true';
}

function stringifyElasticError(value: unknown): string | undefined {
  if (typeof value === 'string') {
    return value;
  }

  const obj = asRecord(value);
  if (!obj) {
    return undefined;
  }

  const type = typeof obj.type === 'string' ? obj.type : undefined;
  const reason = typeof obj.reason === 'string' ? obj.reason : undefined;
  if (type && reason) {
    return `${type}: ${reason}`;
  }
  return type ?? reason;
}

async function withRetry(
  fn: () => Promise<Response>,
  config: RetryConfig | undefined,
): Promise<Response> {
  const maxRetries = config?.maxRetries ?? 0;
  const baseDelayMs = config?.baseDelayMs ?? 1000;

  let lastError: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const response = await fn();
      if (response.ok || response.status < 500) {
        return response;
      }
      // 5xx — retryable
      lastError = new ExportError(
        `Server error: ${response.status} ${response.statusText}`,
      );
    } catch (err) {
      // Network error — retryable
      lastError = err;
    }

    if (attempt < maxRetries) {
      await new Promise((resolve) =>
        setTimeout(resolve, baseDelayMs * 2 ** attempt),
      );
    }
  }
  if (lastError instanceof ExportError) throw lastError;
  throw new ExportError(
    `Export failed after ${maxRetries + 1} attempts: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
  );
}

export class WebhookAdapter implements ExportAdapter {
  private url: string;
  private headers: Record<string, string>;
  private retry?: RetryConfig;

  constructor(url: string, headers?: Record<string, string>, retry?: RetryConfig) {
    this.url = url;
    this.headers = headers ?? {};
    this.retry = retry;
  }

  async export(items: (Alert | TimelineEvent)[]): Promise<void> {
    const body = JSON.stringify(items.map(itemToJSON));
    const response = await withRetry(
      () =>
        fetch(this.url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...this.headers },
          body,
        }),
      this.retry,
    );
    if (!response.ok) {
      throw new ExportError(
        `Webhook export failed: ${response.status} ${response.statusText}`,
      );
    }
  }
}

export class SplunkHECAdapter implements ExportAdapter {
  private url: string;
  private token: string;
  private index?: string;
  private retry?: RetryConfig;

  constructor(url: string, token: string, index?: string, retry?: RetryConfig) {
    this.url = url;
    this.token = token;
    this.index = index;
    this.retry = retry;
  }

  async export(items: (Alert | TimelineEvent)[]): Promise<void> {
    const events = items.map((item) => {
      const data = itemToJSON(item);
      const event: Record<string, unknown> = { event: data };
      if (this.index) event.index = this.index;
      return JSON.stringify(event);
    });
    const body = events.join('\n');

    const response = await withRetry(
      () =>
        fetch(this.url, {
          method: 'POST',
          headers: {
            Authorization: `Splunk ${this.token}`,
            'Content-Type': 'application/json',
          },
          body,
        }),
      this.retry,
    );
    if (!response.ok) {
      throw new ExportError(
        `Splunk HEC export failed: ${response.status} ${response.statusText}`,
      );
    }
  }
}

export class ElasticAdapter implements ExportAdapter {
  private url: string;
  private index: string;
  private apiKey?: string;
  private retry?: RetryConfig;

  constructor(url: string, index: string, apiKey?: string, retry?: RetryConfig) {
    this.url = url;
    this.index = index;
    this.apiKey = apiKey;
    this.retry = retry;
  }

  async export(items: (Alert | TimelineEvent)[]): Promise<void> {
    const lines: string[] = [];
    for (const item of items) {
      lines.push(JSON.stringify({ index: { _index: this.index } }));
      lines.push(JSON.stringify(itemToJSON(item)));
    }
    const body = lines.join('\n') + '\n';

    const headers: Record<string, string> = {
      'Content-Type': 'application/x-ndjson',
    };
    if (this.apiKey) {
      headers['Authorization'] = `ApiKey ${this.apiKey}`;
    }

    const response = await withRetry(
      () =>
        fetch(`${this.url}/_bulk`, {
          method: 'POST',
          headers,
          body,
        }),
      this.retry,
    );
    if (!response.ok) {
      throw new ExportError(
        `Elasticsearch export failed: ${response.status} ${response.statusText}`,
      );
    }

    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw new ExportError('Elasticsearch export failed: invalid _bulk JSON response');
    }

    const failureSummary = summarizeElasticBulkFailure(payload);
    if (failureSummary !== undefined) {
      throw new ExportError(`Elasticsearch export failed: ${failureSummary}`);
    }
  }
}

/**
 * Convert alerts and optional IOC matches to a STIX 2.1 bundle.
 */
export function toStix(
  alerts: Alert[],
  iocMatches?: IocMatch[],
): Record<string, unknown> {
  const objects: Record<string, unknown>[] = [];

  for (const alert of alerts) {
    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${generateId()}`,
      created: alert.triggeredAt.toISOString(),
      modified: alert.triggeredAt.toISOString(),
      name: alert.title,
      description: alert.description,
      pattern_type: 'clawdstrike',
      pattern: `[alert:rule_name = '${escapeStixValue(alert.ruleName)}']`,
      valid_from: alert.triggeredAt.toISOString(),
      labels: [alert.severity],
    });
  }

  if (iocMatches) {
    for (const match of iocMatches) {
      for (const ioc of match.matchedIocs) {
        objects.push({
          type: 'indicator',
          spec_version: '2.1',
          id: `indicator--${generateId()}`,
          created: match.event.timestamp.toISOString(),
          modified: match.event.timestamp.toISOString(),
          name: `IOC: ${ioc.indicator}`,
          description: ioc.description ?? `IOC match: ${ioc.indicator}`,
          pattern_type: 'stix',
          pattern: iocToStixPattern(ioc),
          valid_from: match.event.timestamp.toISOString(),
        });
      }
    }
  }

  return {
    type: 'bundle',
    id: `bundle--${generateId()}`,
    objects,
  };
}

/**
 * Convert items to CSV string. Handles alerts, events, and mixed arrays.
 */
export function toCSV(items: (Alert | TimelineEvent)[]): string {
  if (items.length === 0) return '';

  const alerts = items.filter(isAlert);
  const events = items.filter((item): item is TimelineEvent => !isAlert(item));

  const sections: string[] = [];

  if (alerts.length > 0) {
    const headers = [
      'ruleName',
      'severity',
      'title',
      'triggeredAt',
      'description',
      'evidenceCount',
    ];
    const rows = alerts.map((a) =>
      [
        a.ruleName,
        a.severity,
        a.title,
        a.triggeredAt.toISOString(),
        a.description,
        String(a.evidence.length),
      ]
        .map(csvEscape)
        .join(','),
    );
    sections.push([headers.join(','), ...rows].join('\n'));
  }

  if (events.length > 0) {
    const headers = [
      'timestamp',
      'source',
      'kind',
      'verdict',
      'summary',
      'process',
      'actionType',
    ];
    const rows = events.map((e) =>
      [
        e.timestamp.toISOString(),
        e.source,
        e.kind,
        e.verdict,
        e.summary,
        e.process ?? '',
        e.actionType ?? '',
      ]
        .map(csvEscape)
        .join(','),
    );
    sections.push([headers.join(','), ...rows].join('\n'));
  }

  return sections.join('\n');
}

/**
 * Convert items to JSON Lines (JSONL) format — one JSON object per line.
 */
export function toJSONL(items: (Alert | TimelineEvent)[]): string {
  return items.map((item) => JSON.stringify(itemToJSON(item))).join('\n');
}

function isAlert(item: unknown): item is Alert {
  return (
    typeof item === 'object' &&
    item !== null &&
    'ruleName' in item &&
    'triggeredAt' in item
  );
}

function itemToJSON(item: Alert | TimelineEvent): Record<string, unknown> {
  if (isAlert(item)) {
    return {
      type: 'alert',
      ruleName: item.ruleName,
      severity: item.severity,
      title: item.title,
      triggeredAt: item.triggeredAt.toISOString(),
      description: item.description,
      evidenceCount: item.evidence.length,
    };
  }
  return {
    type: 'event',
    timestamp: item.timestamp.toISOString(),
    source: item.source,
    kind: item.kind,
    verdict: item.verdict,
    summary: item.summary,
    process: item.process,
    actionType: item.actionType,
  };
}

function csvEscape(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n') || value.includes('\r')) {
    return '"' + value.replace(/"/g, '""') + '"';
  }
  return value;
}

function escapeStixValue(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/]/g, '\\]');
}

function iocToStixPattern(ioc: IocEntry): string {
  const v = escapeStixValue(ioc.indicator);
  switch (ioc.iocType) {
    case 'sha256':
      return `[file:hashes.'SHA-256' = '${v}']`;
    case 'sha1':
      return `[file:hashes.'SHA-1' = '${v}']`;
    case 'md5':
      return `[file:hashes.MD5 = '${v}']`;
    case 'domain':
      return `[domain-name:value = '${v}']`;
    case 'ipv4':
      return `[ipv4-addr:value = '${v}']`;
    case 'ipv6':
      return `[ipv6-addr:value = '${v}']`;
    case 'url':
      return `[url:value = '${v}']`;
    default:
      return `[x-clawdstrike:value = '${v}']`;
  }
}

function generateId(): string {
  // Use crypto.randomUUID() when available, fall back to random hex.
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
