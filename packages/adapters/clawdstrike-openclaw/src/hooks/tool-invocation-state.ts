/**
 * @clawdstrike/openclaw - Recent tool invocation state
 *
 * Tracks modern runtime tool params long enough for synchronous
 * `tool_result_persist` hooks to recover the original arguments.
 */

interface ToolInvocationRecord {
  id: number;
  sessionId: string;
  toolName: string;
  toolCallId?: string;
  params: Record<string, unknown>;
  expiresAt: number;
}

const MAX_TOOL_CALL_ENTRIES = 512;
const MAX_SESSION_TOOL_KEYS = 256;
const MAX_SESSION_TOOL_ENTRIES = 8;
const TOOL_INVOCATION_TTL_MS = 15 * 60 * 1000;

const invocationsByCallId = new Map<string, ToolInvocationRecord>();
const invocationsBySessionTool = new Map<string, ToolInvocationRecord[]>();

let nextInvocationId = 1;

function normalizeToolName(toolName: string): string {
  return toolName.trim().toLowerCase();
}

function sessionToolKey(sessionId: string, toolName: string): string {
  return `${sessionId}\0${normalizeToolName(toolName)}`;
}

function toolCallKey(sessionId: string, toolCallId: string): string {
  return `${sessionId}\0${toolCallId}`;
}

function cloneParams(params: Record<string, unknown>): Record<string, unknown> {
  return { ...params };
}

function removeFromSessionTool(record: ToolInvocationRecord): void {
  const key = sessionToolKey(record.sessionId, record.toolName);
  const entries = invocationsBySessionTool.get(key);
  if (!entries) {
    return;
  }

  const nextEntries = entries.filter((entry) => entry.id !== record.id);
  if (nextEntries.length === 0) {
    invocationsBySessionTool.delete(key);
    return;
  }

  invocationsBySessionTool.delete(key);
  invocationsBySessionTool.set(key, nextEntries);
}

function cleanupExpired(now: number): void {
  for (const [key, record] of invocationsByCallId.entries()) {
    if (now > record.expiresAt) {
      invocationsByCallId.delete(key);
      removeFromSessionTool(record);
    }
  }

  for (const [key, entries] of invocationsBySessionTool.entries()) {
    const nextEntries = entries.filter((entry) => now <= entry.expiresAt);
    if (nextEntries.length === 0) {
      invocationsBySessionTool.delete(key);
      continue;
    }
    if (nextEntries.length !== entries.length) {
      invocationsBySessionTool.delete(key);
      invocationsBySessionTool.set(key, nextEntries);
    }
  }
}

export function rememberToolInvocation(
  sessionId: string,
  toolName: string,
  params: Record<string, unknown>,
  toolCallId?: string,
): void {
  const now = Date.now();
  cleanupExpired(now);

  const record: ToolInvocationRecord = {
    id: nextInvocationId++,
    sessionId,
    toolName,
    toolCallId,
    params: cloneParams(params),
    expiresAt: now + TOOL_INVOCATION_TTL_MS,
  };

  if (toolCallId) {
    const callIdKey = toolCallKey(sessionId, toolCallId);
    const existing = invocationsByCallId.get(callIdKey);
    if (existing) {
      removeFromSessionTool(existing);
      invocationsByCallId.delete(callIdKey);
    }
    invocationsByCallId.set(callIdKey, record);
    while (invocationsByCallId.size > MAX_TOOL_CALL_ENTRIES) {
      const oldestKey = invocationsByCallId.keys().next().value;
      if (oldestKey === undefined) {
        break;
      }
      const oldest = invocationsByCallId.get(oldestKey);
      invocationsByCallId.delete(oldestKey);
      if (oldest) {
        removeFromSessionTool(oldest);
      }
    }
  }

  const fallbackKey = sessionToolKey(sessionId, toolName);
  const entries = invocationsBySessionTool.get(fallbackKey) ?? [];
  const nextEntries = entries.filter(
    (entry) => !(toolCallId && entry.toolCallId === toolCallId),
  );
  nextEntries.push(record);
  while (nextEntries.length > MAX_SESSION_TOOL_ENTRIES) {
    nextEntries.shift();
  }
  invocationsBySessionTool.delete(fallbackKey);
  invocationsBySessionTool.set(fallbackKey, nextEntries);
  while (invocationsBySessionTool.size > MAX_SESSION_TOOL_KEYS) {
    const oldestKey = invocationsBySessionTool.keys().next().value;
    if (oldestKey === undefined) {
      break;
    }
    const removed = invocationsBySessionTool.get(oldestKey) ?? [];
    invocationsBySessionTool.delete(oldestKey);
    for (const entry of removed) {
      if (entry.toolCallId) {
        invocationsByCallId.delete(toolCallKey(entry.sessionId, entry.toolCallId));
      }
    }
  }
}

export function takeToolInvocationParams(
  sessionId: string,
  toolName: string,
  toolCallId?: string,
): Record<string, unknown> | null {
  const now = Date.now();
  cleanupExpired(now);

  if (toolCallId) {
    const callIdKey = toolCallKey(sessionId, toolCallId);
    const record = invocationsByCallId.get(callIdKey);
    if (record) {
      invocationsByCallId.delete(callIdKey);
      removeFromSessionTool(record);
      return cloneParams(record.params);
    }
  }

  const fallbackKey = sessionToolKey(sessionId, toolName);
  const entries = invocationsBySessionTool.get(fallbackKey);
  if (!entries || entries.length === 0) {
    return null;
  }

  const record = entries.pop();
  if (!record) {
    invocationsBySessionTool.delete(fallbackKey);
    return null;
  }

  if (entries.length === 0) {
    invocationsBySessionTool.delete(fallbackKey);
  } else {
    invocationsBySessionTool.delete(fallbackKey);
    invocationsBySessionTool.set(fallbackKey, entries);
  }

  if (record.toolCallId) {
    invocationsByCallId.delete(toolCallKey(record.sessionId, record.toolCallId));
  }

  return cloneParams(record.params);
}

export function clearAllToolInvocations(): void {
  invocationsByCallId.clear();
  invocationsBySessionTool.clear();
  nextInvocationId = 1;
}
