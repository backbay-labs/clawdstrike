/**
 * @clawdstrike/openclaw - Shared Approval State
 *
 * Tracks user approval decisions from preflight so post-exec can honor them.
 *
 * Notes:
 * - In-memory only (process lifetime). Not persisted to disk.
 * - Keys are hashed to avoid embedding potentially sensitive resource strings.
 * - TTL + LRU eviction prevents unbounded growth.
 */

import { createHash } from 'node:crypto';

export type ApprovalResolutionType = 'allow-once' | 'allow-session' | 'allow-always';

export interface ApprovalRecord {
  resolution: ApprovalResolutionType;
  createdAt: number;
  lastUsedAt: number;
  expiresAt: number;
}

const MAX_SESSION_APPROVALS = 256;
const MAX_ALWAYS_APPROVALS = 256;

const TTL_ALLOW_ONCE_MS = 10 * 60 * 1000; // 10 minutes (covers slow tool runs)
const TTL_ALLOW_SESSION_MS = 6 * 60 * 60 * 1000; // 6 hours
const TTL_ALLOW_ALWAYS_MS = 7 * 24 * 60 * 60 * 1000; // 7 days (still memory-only)

/** Session-scoped approvals: sessionId -> (hashedKey -> record) */
const sessionApprovals = new Map<string, Map<string, ApprovalRecord>>();
/** Global approvals for "allow-always": hashedKey -> record */
const alwaysApprovals = new Map<string, ApprovalRecord>();

function normalizeToolName(toolName: string): string {
  return toolName.trim().toLowerCase();
}

function normalizeResource(resource: string): string {
  return resource.trim();
}

function hashKey(toolName: string, resource: string): string {
  // Avoid embedding raw resource strings in keys (resource may contain secrets).
  // Include a separator that cannot appear in JS strings.
  return createHash('sha256')
    .update(normalizeToolName(toolName))
    .update('\0')
    .update(normalizeResource(resource))
    .digest('hex');
}

function ttlFor(resolution: ApprovalResolutionType): number {
  switch (resolution) {
    case 'allow-once':
      return TTL_ALLOW_ONCE_MS;
    case 'allow-session':
      return TTL_ALLOW_SESSION_MS;
    case 'allow-always':
      return TTL_ALLOW_ALWAYS_MS;
  }
}

export function recordApproval(
  sessionId: string,
  toolName: string,
  resource: string,
  resolution: ApprovalResolutionType,
): void {
  const now = Date.now();
  cleanupExpired(now);

  const key = hashKey(toolName, resource);
  const record: ApprovalRecord = {
    resolution,
    createdAt: now,
    lastUsedAt: now,
    expiresAt: now + ttlFor(resolution),
  };

  if (resolution === 'allow-always') {
    setLru(alwaysApprovals, key, record, MAX_ALWAYS_APPROVALS);
    return;
  }

  let m = sessionApprovals.get(sessionId);
  if (!m) {
    m = new Map<string, ApprovalRecord>();
    sessionApprovals.set(sessionId, m);
  }
  setLru(m, key, record, MAX_SESSION_APPROVALS);
}

function cleanupExpired(now: number): void {
  for (const [key, rec] of alwaysApprovals.entries()) {
    if (now > rec.expiresAt) alwaysApprovals.delete(key);
  }

  for (const [sid, m] of sessionApprovals.entries()) {
    for (const [key, rec] of m.entries()) {
      if (now > rec.expiresAt) m.delete(key);
    }
    if (m.size === 0) sessionApprovals.delete(sid);
  }
}

function touch(m: Map<string, ApprovalRecord>, key: string, rec: ApprovalRecord, now: number): void {
  // LRU: delete+set moves to most-recently-used.
  m.delete(key);
  rec.lastUsedAt = now;

  // Sliding expiration for session/always approvals.
  if (rec.resolution === 'allow-session' || rec.resolution === 'allow-always') {
    rec.expiresAt = now + ttlFor(rec.resolution);
  }
  m.set(key, rec);
}

function setLru(m: Map<string, ApprovalRecord>, key: string, rec: ApprovalRecord, maxSize: number): void {
  if (m.has(key)) m.delete(key);
  m.set(key, rec);
  while (m.size > maxSize) {
    const oldest = m.keys().next().value;
    if (oldest === undefined) break;
    m.delete(oldest);
  }
}

function getRecord(
  sessionId: string,
  toolName: string,
  resource: string,
  now: number,
): { scope: 'session' | 'always'; key: string; record: ApprovalRecord } | null {
  const key = hashKey(toolName, resource);

  const m = sessionApprovals.get(sessionId);
  if (m) {
    const rec = m.get(key);
    if (rec) {
      if (now > rec.expiresAt) {
        m.delete(key);
      } else {
        return { scope: 'session', key, record: rec };
      }
    }
    if (m.size === 0) sessionApprovals.delete(sessionId);
  }

  const rec = alwaysApprovals.get(key);
  if (rec) {
    if (now > rec.expiresAt) {
      alwaysApprovals.delete(key);
    } else {
      return { scope: 'always', key, record: rec };
    }
  }

  return null;
}

/**
 * Check if an approval exists for this (session, tool, resource) without consuming it.
 * Only returns session/always approvals (allow-once is intentionally ignored here).
 */
export function peekApproval(
  sessionId: string,
  toolName: string,
  resource: string,
): ApprovalRecord | null {
  const now = Date.now();
  cleanupExpired(now);

  const found = getRecord(sessionId, toolName, resource, now);
  if (!found) return null;

  const { scope, key, record } = found;
  if (record.resolution === 'allow-once') return null;

  if (scope === 'session') {
    const m = sessionApprovals.get(sessionId);
    if (m) touch(m, key, record, now);
  } else {
    touch(alwaysApprovals, key, record, now);
  }

  return record;
}

/**
 * Check and consume an approval for this (session, tool, resource).
 * Consumes allow-once; keeps allow-session/allow-always.
 */
export function checkAndConsumeApproval(
  sessionId: string,
  toolName: string,
  resource: string,
): ApprovalRecord | null {
  const now = Date.now();
  cleanupExpired(now);

  const found = getRecord(sessionId, toolName, resource, now);
  if (!found) return null;

  const { scope, key, record } = found;
  if (scope === 'session') {
    const m = sessionApprovals.get(sessionId);
    if (m) {
      if (record.resolution === 'allow-once') {
        m.delete(key);
      } else {
        touch(m, key, record, now);
      }
      if (m.size === 0) sessionApprovals.delete(sessionId);
    }
  } else {
    // allow-always only
    touch(alwaysApprovals, key, record, now);
  }

  return record;
}

export function clearSessionApprovals(sessionId: string): void {
  sessionApprovals.delete(sessionId);
}

export function clearAllApprovals(): void {
  sessionApprovals.clear();
  alwaysApprovals.clear();
}
