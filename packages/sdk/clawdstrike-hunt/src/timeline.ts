import { createPublicKey, verify } from 'node:crypto';

import { canonicalize, sha256, toHex } from '@clawdstrike/sdk';

import type { TimelineEvent } from './types.js';
import {
  EventSourceType,
  NormalizedVerdict,
  TimelineEventKind,
} from './types.js';

const ED25519_SPKI_DER_PREFIX = Buffer.from(
  '302a300506032b6570032100',
  'hex',
);

/**
 * Parse a spine envelope JSON object into a TimelineEvent.
 * Dispatches on fact.schema to determine the event source.
 * Returns undefined for unrecognized or invalid envelopes.
 */
export function parseEnvelope(
  envelope: unknown,
  verifySignature: boolean = false,
): TimelineEvent | undefined {
  if (typeof envelope !== 'object' || envelope === null) {
    return undefined;
  }
  const env = envelope as Record<string, unknown>;

  const fact = env.fact;
  if (typeof fact !== 'object' || fact === null) {
    return undefined;
  }
  const f = fact as Record<string, unknown>;

  const schema = f.schema;
  if (typeof schema !== 'string') {
    return undefined;
  }

  // Parse timestamp from issued_at
  const issuedAt = env.issued_at;
  if (typeof issuedAt !== 'string') {
    return undefined;
  }
  const timestamp = new Date(issuedAt);
  if (isNaN(timestamp.getTime())) {
    return undefined;
  }

  const signatureValid = verifySignature
    ? verifyEnvelopeSignature(env)
    : undefined;

  if (schema === 'clawdstrike.sdr.fact.tetragon_event.v1') {
    return parseTetragon(f, timestamp, signatureValid, envelope);
  }
  if (schema === 'clawdstrike.sdr.fact.hubble_flow.v1') {
    return parseHubble(f, timestamp, signatureValid, envelope);
  }
  if (schema.startsWith('clawdstrike.sdr.fact.receipt')) {
    return parseReceipt(f, timestamp, signatureValid, envelope);
  }
  if (schema.startsWith('clawdstrike.sdr.fact.scan')) {
    return parseScan(f, timestamp, signatureValid, envelope);
  }

  return undefined;
}

function verifyEnvelopeSignature(envelope: Record<string, unknown>): boolean {
  const issuer = envelope.issuer;
  const signature = envelope.signature;
  const envelopeHash = envelope.envelope_hash;
  if (
    typeof issuer !== 'string' ||
    typeof signature !== 'string' ||
    typeof envelopeHash !== 'string'
  ) {
    return false;
  }

  const publicKeyHex = parseIssuerPublicKeyHex(issuer);
  const signatureHex = normalizeHex(signature, 64);
  if (publicKeyHex === undefined || signatureHex === undefined) {
    return false;
  }

  const unsigned: Record<string, unknown> = { ...envelope };
  delete unsigned.envelope_hash;
  delete unsigned.signature;

  try {
    const canonical = canonicalize(unsigned as Parameters<typeof canonicalize>[0]);
    const message = new TextEncoder().encode(canonical);
    const computedHash = `0x${toHex(sha256(message))}`;
    if (computedHash !== envelopeHash) {
      return false;
    }

    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_DER_PREFIX, Buffer.from(publicKeyHex, 'hex')]),
      format: 'der',
      type: 'spki',
    });

    return verify(
      null,
      Buffer.from(message),
      key,
      Buffer.from(signatureHex, 'hex'),
    );
  } catch {
    return false;
  }
}

function parseIssuerPublicKeyHex(issuer: string): string | undefined {
  const match = /^aegis:ed25519:([0-9a-fA-F]{64})$/.exec(issuer);
  return match ? match[1].toLowerCase() : undefined;
}

function normalizeHex(value: string, expectedBytes: number): string | undefined {
  const hex = value.startsWith('0x') ? value.slice(2) : value;
  if (hex.length !== expectedBytes * 2 || !/^[0-9a-fA-F]+$/.test(hex)) {
    return undefined;
  }
  return hex.toLowerCase();
}

function str(val: unknown): string | undefined {
  return typeof val === 'string' ? val : undefined;
}

function obj(val: unknown): Record<string, unknown> | undefined {
  return typeof val === 'object' && val !== null
    ? (val as Record<string, unknown>)
    : undefined;
}

function parseTetragon(
  fact: Record<string, unknown>,
  timestamp: Date,
  signatureValid: boolean | undefined,
  raw: unknown,
): TimelineEvent {
  const eventType = str(fact.event_type) ?? 'unknown';
  const proc = obj(fact.process);
  const binary = proc ? str(proc.binary) : undefined;
  const severity = str(fact.severity);
  const pod = proc ? obj(proc.pod) : undefined;
  const ns = pod ? str(pod.namespace) : undefined;
  const podName = pod ? str(pod.name) : undefined;

  let kind: TimelineEvent['kind'];
  switch (eventType) {
    case 'PROCESS_EXEC':
      kind = TimelineEventKind.ProcessExec;
      break;
    case 'PROCESS_EXIT':
      kind = TimelineEventKind.ProcessExit;
      break;
    case 'PROCESS_KPROBE':
      kind = TimelineEventKind.ProcessKprobe;
      break;
    default:
      kind = TimelineEventKind.ProcessExec;
      break;
  }

  const summary = `${eventType.toLowerCase()} ${binary ?? '?'}`;

  return {
    timestamp,
    source: EventSourceType.Tetragon,
    kind,
    verdict: NormalizedVerdict.None,
    severity,
    summary,
    process: binary,
    namespace: ns,
    pod: podName,
    actionType: 'process',
    signatureValid,
    raw,
  };
}

function parseHubble(
  fact: Record<string, unknown>,
  timestamp: Date,
  signatureValid: boolean | undefined,
  raw: unknown,
): TimelineEvent {
  const verdictStr = str(fact.verdict) ?? 'UNKNOWN';
  const direction = str(fact.traffic_direction) ?? 'unknown';
  const flowSummary = str(fact.summary) ?? 'network flow';

  let verdict: TimelineEvent['verdict'];
  switch (verdictStr) {
    case 'FORWARDED':
      verdict = NormalizedVerdict.Forwarded;
      break;
    case 'DROPPED':
      verdict = NormalizedVerdict.Dropped;
      break;
    default:
      verdict = NormalizedVerdict.None;
      break;
  }

  const source = obj(fact.source);
  const ns = source ? str(source.namespace) : undefined;
  const podName = source ? str(source.pod_name) : undefined;

  let actionType: string;
  switch (direction) {
    case 'EGRESS':
      actionType = 'egress';
      break;
    case 'INGRESS':
      actionType = 'ingress';
      break;
    default:
      actionType = 'network';
      break;
  }

  const summary = `${direction.toLowerCase()} ${flowSummary}`;

  return {
    timestamp,
    source: EventSourceType.Hubble,
    kind: TimelineEventKind.NetworkFlow,
    verdict,
    summary,
    namespace: ns,
    pod: podName,
    actionType,
    signatureValid,
    raw,
  };
}

function parseReceipt(
  fact: Record<string, unknown>,
  timestamp: Date,
  signatureValid: boolean | undefined,
  raw: unknown,
): TimelineEvent {
  const decision = str(fact.decision) ?? 'unknown';
  const guardName = str(fact.guard) ?? 'unknown';
  const action = str(fact.action_type);
  const severity = str(fact.severity);
  const source = obj(fact.source);
  const ns = source ? str(source.namespace) : undefined;
  const podName = source
    ? str(source.pod_name) ?? str(source.pod)
    : undefined;

  let verdict: TimelineEvent['verdict'];
  switch (decision.toLowerCase()) {
    case 'allow':
    case 'allowed':
    case 'pass':
    case 'passed':
      verdict = NormalizedVerdict.Allow;
      break;
    case 'deny':
    case 'denied':
    case 'block':
    case 'blocked':
      verdict = NormalizedVerdict.Deny;
      break;
    case 'warn':
    case 'warned':
    case 'warning':
      verdict = NormalizedVerdict.Warn;
      break;
    default:
      verdict = NormalizedVerdict.None;
      break;
  }

  const summary = `${guardName} decision=${decision}`;

  return {
    timestamp,
    source: EventSourceType.Receipt,
    kind: TimelineEventKind.GuardDecision,
    verdict,
    severity,
    summary,
    namespace: ns,
    pod: podName,
    actionType: action,
    signatureValid,
    raw,
  };
}

function parseScan(
  fact: Record<string, unknown>,
  timestamp: Date,
  signatureValid: boolean | undefined,
  raw: unknown,
): TimelineEvent {
  const scanType = str(fact.scan_type) ?? 'unknown';
  const status = str(fact.status) ?? 'unknown';
  const severity = str(fact.severity);

  let verdict: TimelineEvent['verdict'];
  switch (status.toLowerCase()) {
    case 'pass':
    case 'passed':
    case 'clean':
      verdict = NormalizedVerdict.Allow;
      break;
    case 'fail':
    case 'failed':
    case 'dirty':
      verdict = NormalizedVerdict.Deny;
      break;
    case 'warn':
    case 'warning':
      verdict = NormalizedVerdict.Warn;
      break;
    default:
      verdict = NormalizedVerdict.None;
      break;
  }

  const summary = `scan ${scanType} status=${status}`;

  return {
    timestamp,
    source: EventSourceType.Scan,
    kind: TimelineEventKind.ScanResult,
    verdict,
    severity,
    summary,
    actionType: 'scan',
    signatureValid,
    raw,
  };
}

/** Sort events by timestamp ascending. */
export function mergeTimeline(events: TimelineEvent[]): TimelineEvent[] {
  return [...events].sort(
    (a, b) => a.timestamp.getTime() - b.timestamp.getTime(),
  );
}
