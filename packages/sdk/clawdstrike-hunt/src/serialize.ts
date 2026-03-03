import type { TimelineEvent, Alert } from './types.js';

export function eventsToJSON(events: TimelineEvent[]): Record<string, unknown>[] {
  return events.map(e => ({
    timestamp: e.timestamp.toISOString(),
    source: e.source,
    kind: e.kind,
    verdict: e.verdict,
    severity: e.severity ?? null,
    summary: e.summary,
    process: e.process ?? null,
    namespace: e.namespace ?? null,
    pod: e.pod ?? null,
    actionType: e.actionType ?? null,
    signatureValid: e.signatureValid ?? null,
  }));
}

export function alertsToJSON(alerts: Alert[]): Record<string, unknown>[] {
  return alerts.map(a => ({
    ruleName: a.ruleName,
    severity: a.severity,
    title: a.title,
    triggeredAt: a.triggeredAt.toISOString(),
    description: a.description,
    evidenceCount: a.evidence.length,
  }));
}

export function eventsToCSV(events: TimelineEvent[]): string {
  const headers = ['timestamp', 'source', 'kind', 'verdict', 'severity', 'summary', 'process', 'namespace', 'pod', 'actionType'];
  const rows = events.map(e => [
    e.timestamp.toISOString(),
    e.source, e.kind, e.verdict,
    e.severity ?? '', e.summary,
    e.process ?? '', e.namespace ?? '',
    e.pod ?? '', e.actionType ?? '',
  ].map(csvEscape).join(','));
  return [headers.join(','), ...rows].join('\n');
}

export function alertsToCSV(alerts: Alert[]): string {
  const headers = ['ruleName', 'severity', 'title', 'triggeredAt', 'description', 'evidenceCount'];
  const rows = alerts.map(a => [
    a.ruleName, a.severity, a.title,
    a.triggeredAt.toISOString(), a.description,
    String(a.evidence.length),
  ].map(csvEscape).join(','));
  return [headers.join(','), ...rows].join('\n');
}

function csvEscape(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return '"' + value.replace(/"/g, '""') + '"';
  }
  return value;
}
