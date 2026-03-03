import type {
  EventSourceType,
  HuntQuery,
  NormalizedVerdict,
  TimelineEvent,
} from './types.js';

import {
  EventSourceType as EST,
  NormalizedVerdict as NV,
} from './types.js';

// ---------------------------------------------------------------------------
// EventSource functions
// ---------------------------------------------------------------------------

/** Parse a source string (case-insensitive). */
export function parseEventSource(s: string): EventSourceType | undefined {
  switch (s.trim().toLowerCase()) {
    case 'tetragon':
      return EST.Tetragon;
    case 'hubble':
      return EST.Hubble;
    case 'receipt':
    case 'receipts':
      return EST.Receipt;
    case 'scan':
    case 'scans':
      return EST.Scan;
    default:
      return undefined;
  }
}

/** Parse a comma-separated list of sources. */
export function parseEventSourceList(s: string): EventSourceType[] {
  return s
    .split(',')
    .map((part) => parseEventSource(part.trim()))
    .filter((v): v is EventSourceType => v !== undefined);
}

/** JetStream stream name for a source. */
export function streamName(source: EventSourceType): string {
  switch (source) {
    case EST.Tetragon:
      return 'CLAWDSTRIKE_TETRAGON';
    case EST.Hubble:
      return 'CLAWDSTRIKE_HUBBLE';
    case EST.Receipt:
      return 'CLAWDSTRIKE_RECEIPTS';
    case EST.Scan:
      return 'CLAWDSTRIKE_SCANS';
  }
}

/** NATS subject filter pattern for a source. */
export function subjectFilter(source: EventSourceType): string {
  switch (source) {
    case EST.Tetragon:
      return 'clawdstrike.sdr.fact.tetragon_event.>';
    case EST.Hubble:
      return 'clawdstrike.sdr.fact.hubble_flow.>';
    case EST.Receipt:
      return 'clawdstrike.sdr.fact.receipt.>';
    case EST.Scan:
      return 'clawdstrike.sdr.fact.scan.>';
  }
}

/** All known event sources. */
export function allEventSources(): EventSourceType[] {
  return [EST.Tetragon, EST.Hubble, EST.Receipt, EST.Scan];
}

// ---------------------------------------------------------------------------
// QueryVerdict parsing
// ---------------------------------------------------------------------------

/** Parse a verdict string (case-insensitive, with aliases). */
export function parseQueryVerdict(s: string): NormalizedVerdict | undefined {
  switch (s.trim().toLowerCase()) {
    case 'allow':
    case 'allowed':
    case 'pass':
    case 'passed':
      return NV.Allow;
    case 'deny':
    case 'denied':
    case 'block':
    case 'blocked':
      return NV.Deny;
    case 'warn':
    case 'warned':
    case 'warning':
      return NV.Warn;
    case 'forwarded':
    case 'forward':
      return NV.Forwarded;
    case 'dropped':
    case 'drop':
      return NV.Dropped;
    default:
      return undefined;
  }
}

// ---------------------------------------------------------------------------
// HuntQuery helpers
// ---------------------------------------------------------------------------

/** Create a HuntQuery with defaults (limit=100, empty sources). */
export function createHuntQuery(overrides?: Partial<HuntQuery>): HuntQuery {
  return {
    sources: [],
    limit: 100,
    ...overrides,
  };
}

/** Returns the effective sources: configured list, or all if empty. Deduplicates. */
export function effectiveSources(query: HuntQuery): EventSourceType[] {
  if (query.sources.length === 0) {
    return allEventSources();
  }
  const deduped: EventSourceType[] = [];
  for (const source of query.sources) {
    if (!deduped.includes(source)) {
      deduped.push(source);
    }
  }
  return deduped;
}

/** Returns true if the event matches ALL active predicates (AND logic). */
export function matchesQuery(
  query: HuntQuery,
  event: TimelineEvent,
): boolean {
  // Source filter
  if (query.sources.length > 0 && !query.sources.includes(event.source)) {
    return false;
  }

  // Verdict filter
  if (query.verdict !== undefined) {
    if (event.verdict !== query.verdict) {
      return false;
    }
  }

  // Time range
  if (query.start !== undefined && event.timestamp < query.start) {
    return false;
  }
  if (query.end !== undefined && event.timestamp > query.end) {
    return false;
  }

  // Action type (case-insensitive exact match)
  if (query.actionType !== undefined) {
    if (
      event.actionType === undefined ||
      event.actionType.toLowerCase() !== query.actionType.toLowerCase()
    ) {
      return false;
    }
  }

  // Process (case-insensitive substring)
  if (query.process !== undefined) {
    if (
      event.process === undefined ||
      !event.process.toLowerCase().includes(query.process.toLowerCase())
    ) {
      return false;
    }
  }

  // Namespace (case-insensitive exact match)
  if (query.namespace !== undefined) {
    if (
      event.namespace === undefined ||
      event.namespace.toLowerCase() !== query.namespace.toLowerCase()
    ) {
      return false;
    }
  }

  // Pod (case-insensitive substring)
  if (query.pod !== undefined) {
    if (
      event.pod === undefined ||
      !event.pod.toLowerCase().includes(query.pod.toLowerCase())
    ) {
      return false;
    }
  }

  // Entity: matches against pod name or namespace (case-insensitive substring)
  if (query.entity !== undefined) {
    const entityLower = query.entity.toLowerCase();
    const podMatch =
      event.pod !== undefined &&
      event.pod.toLowerCase().includes(entityLower);
    const nsMatch =
      event.namespace !== undefined &&
      event.namespace.toLowerCase().includes(entityLower);
    if (!podMatch && !nsMatch) {
      return false;
    }
  }

  return true;
}
