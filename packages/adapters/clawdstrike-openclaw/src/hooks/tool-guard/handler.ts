/**
 * @clawdstrike/openclaw - Tool Guard Hook Handler
 *
 * Intercepts tool results and enforces security policy.
 */

import { createHash } from 'node:crypto';

import type {
  HookHandler,
  HookEvent,
  ToolResultPersistEvent,
  ClawdstrikeConfig,
  Decision,
  PolicyEvent,
} from '../../types.js';
import { initializeEngine, getSharedEngine } from '../../engine-holder.js';
import type { PolicyEngine } from '../../policy/engine.js';
import { checkAndConsumeApproval } from '../approval-state.js';
import { extractPath, normalizeApprovalResource } from '../approval-utils.js';
import { inferEventTypeFromName } from '../../classification.js';

// ── LRU Decision Cache ──────────────────────────────────────────────

interface CacheEntry {
  decision: Decision;
  expiresAt: number;
}

const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_CACHE_MAX = 256;

function stableStringify(value: unknown, seen = new WeakSet<object>()): string {
  if (value === null) return 'null';

  const t = typeof value;
  if (t === 'string') return JSON.stringify(value);
  if (t === 'number' || t === 'boolean') return String(value);
  if (t === 'bigint') return JSON.stringify(String(value));
  if (t === 'undefined') return '"__undefined__"';
  if (t === 'symbol') return JSON.stringify(String(value));
  if (t === 'function') return '"__function__"';

  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v, seen)).join(',')}]`;
  }

  if (t !== 'object') {
    return JSON.stringify(String(value));
  }

  if (seen.has(value as object)) {
    return '"__cycle__"';
  }
  seen.add(value as object);

  // Only stable-sort plain objects; for other objects (Date, Buffer, etc) defer to
  // JSON.stringify where possible.
  const tag = Object.prototype.toString.call(value);
  if (tag !== '[object Object]') {
    try {
      return JSON.stringify(value);
    } catch {
      return JSON.stringify(String(value));
    }
  }

  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const entries = keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k], seen)}`);
  return `{${entries.join(',')}}`;
}

function shortSha256(value: unknown): string {
  const h = createHash('sha256');
  if (typeof value === 'string') h.update(value);
  else h.update(stableStringify(value));
  return h.digest('hex').slice(0, 16);
}

function policyCacheKey(policy: unknown): string {
  const version =
    policy &&
    typeof policy === 'object' &&
    'version' in policy &&
    typeof (policy as { version?: unknown }).version === 'string'
      ? (policy as { version: string }).version
      : 'unknown';

  return `${version}@${shortSha256(policy)}`;
}

/** Event types that must never be cached (destructive / non-idempotent). */
const UNCACHEABLE_EVENT_TYPES = new Set([
  'command_exec',
  'patch_apply',
  'file_write',
]);

export class DecisionCache {
  private readonly maxSize: number;
  private readonly ttlMs: number;
  private readonly map = new Map<string, CacheEntry>();

  constructor(maxSize = DEFAULT_CACHE_MAX, ttlMs = DEFAULT_CACHE_TTL_MS) {
    this.maxSize = maxSize;
    this.ttlMs = ttlMs;
  }

  /** Build a cache key from event type + resource identifier + policy fingerprint. */
  static key(eventType: string, resource: string, policyKey: string): string {
    return `${eventType}:${resource}:${policyKey}`;
  }

  get(key: string): Decision | undefined {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key);
      return undefined;
    }
    // Move to end (most-recently-used).
    this.map.delete(key);
    this.map.set(key, entry);
    return entry.decision;
  }

  set(key: string, decision: Decision): void {
    // Evict oldest when at capacity.
    if (this.map.size >= this.maxSize) {
      const oldest = this.map.keys().next().value;
      if (oldest !== undefined) this.map.delete(oldest);
    }
    this.map.set(key, { decision, expiresAt: Date.now() + this.ttlMs });
  }

  clear(): void {
    this.map.clear();
  }

  get size(): number {
    return this.map.size;
  }
}

// ── Module State ─────────────────────────────────────────────────────

let currentConfig: ClawdstrikeConfig = {};
let cachedPolicyKey = 'unknown';

/** Shared decision cache (reset on initialize) */
export let decisionCache = new DecisionCache();

/**
 * Initialize the hook with configuration.
 * Delegates to the shared engine holder so all hooks share one PolicyEngine.
 */
export function initialize(config: ClawdstrikeConfig): void {
  const engine = initializeEngine(config);
  currentConfig = config;
  decisionCache = new DecisionCache();
  cachedPolicyKey = policyCacheKey(engine.getPolicy());
}

/**
 * Get or create the policy engine.
 * Delegates to the shared engine holder.
 */
function getEngine(config?: ClawdstrikeConfig): PolicyEngine {
  const engine = getSharedEngine(config);
  const nextPolicyKey = policyCacheKey(engine.getPolicy());
  if (cachedPolicyKey !== nextPolicyKey) {
    // Policy changed (or first access): invalidate cached allow decisions to avoid stale bypasses.
    decisionCache.clear();
    cachedPolicyKey = nextPolicyKey;
  }
  return engine;
}

/**
 * Extract a stable resource identifier from a policy event for cache keying.
 */
function extractResourceKey(event: PolicyEvent): string {
  switch (event.data.type) {
    case 'file':
      return event.data.path;
    case 'network':
      return event.data.host + ':' + event.data.port;
    case 'tool':
      // Tool-call decisions depend on parameters and outputs (e.g., secret leak checks).
      // Include both so cached allows cannot be reused for a different invocation.
      return `${event.data.toolName}:${shortSha256(event.data.parameters)}:${shortSha256(event.data.result ?? '')}`;
    case 'command':
      return event.data.command + ' ' + event.data.args.join(' ');
    case 'patch':
      return event.data.filePath;
    case 'secret':
      return event.data.secretName;
    default:
      return '';
  }
}

/**
 * Hook handler for tool_result_persist events
 */
const handler: HookHandler = async (event: HookEvent): Promise<void> => {
  if (event.type !== 'tool_result_persist') {
    return;
  }

  const toolEvent = event as ToolResultPersistEvent;
  const { toolName, params, result } = toolEvent.context.toolResult;
  const sessionId = toolEvent.context.sessionId;
  const policyEngine = getEngine();

  // Check if preflight already approved this action — skip policy evaluation
  // but still run output sanitization below.
  const resource = normalizeApprovalResource(policyEngine, toolName, params);
  const priorApproval = checkAndConsumeApproval(sessionId, toolName, resource);

  if (!priorApproval) {
    // Create policy event from tool result
    const policyEvent = createPolicyEvent(
      sessionId,
      toolName,
      params,
      result,
    );

    // Check decision cache (skip for destructive ops and advisory/audit modes)
    const mode = currentConfig.mode ?? 'deterministic';
    const useCache = mode === 'deterministic' && !UNCACHEABLE_EVENT_TYPES.has(policyEvent.eventType);
    const cacheKey = useCache
      ? DecisionCache.key(policyEvent.eventType, extractResourceKey(policyEvent), cachedPolicyKey)
      : '';

    let decision = useCache ? decisionCache.get(cacheKey) : undefined;
    if (!decision) {
      decision = await policyEngine.evaluate(policyEvent);
      if (useCache && decision.status === 'allow') {
        decisionCache.set(cacheKey, decision);
      }
    }

    if (decision.status === 'deny') {
      // Block the tool result
      toolEvent.context.toolResult.error = decision.reason ?? 'Policy violation';
      toolEvent.messages.push(
        `[clawdstrike] Blocked by ${decision.guard}: ${decision.reason}`,
      );
      return;
    }

    if (decision.status === 'warn') {
      // Add warning message
      toolEvent.messages.push(
        `[clawdstrike] Warning: ${decision.message ?? decision.reason}`,
      );
    }
  }

  function sanitizeUnknown(
    value: unknown,
    sanitizeString: (s: string) => string,
    seen: WeakSet<object>,
    depth: number,
  ): { value: unknown; changed: boolean } {
    if (typeof value === 'string') {
      const sanitized = sanitizeString(value);
      return { value: sanitized, changed: sanitized !== value };
    }

    if (!value || typeof value !== 'object') {
      return { value, changed: false };
    }

    if (seen.has(value)) {
      return { value, changed: false };
    }

    if (depth > 32) {
      return { value, changed: false };
    }

    // Preserve non-plain objects (Dates, Buffers, class instances, etc).
    const isArray = Array.isArray(value);
    const isPlainObject = Object.prototype.toString.call(value) === '[object Object]';
    if (!isArray && !isPlainObject) {
      return { value, changed: false };
    }

    seen.add(value);

    if (isArray) {
      let changed = false;
      const out = (value as unknown[]).map((item) => {
        const r = sanitizeUnknown(item, sanitizeString, seen, depth + 1);
        changed = changed || r.changed;
        return r.value;
      });
      return { value: changed ? out : value, changed };
    }

    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    let changed = false;
    for (const [k, v] of Object.entries(obj)) {
      const r = sanitizeUnknown(v, sanitizeString, seen, depth + 1);
      out[k] = r.value;
      changed = changed || r.changed;
    }
    return { value: changed ? out : value, changed };
  }

  // Redact secrets from output
  if (result && typeof result === 'string') {
    const sanitized = policyEngine.sanitizeOutput(result);
    if (sanitized !== result) {
      toolEvent.context.toolResult.result = sanitized;
    }
  } else if (result && typeof result === 'object') {
    const { value: sanitized, changed } = sanitizeUnknown(
      result,
      (s) => policyEngine.sanitizeOutput(s),
      new WeakSet<object>(),
      0,
    );
    if (changed) {
      toolEvent.context.toolResult.result = sanitized;
    }
  }
};

/**
 * Create a PolicyEvent from tool execution context
 */
function createPolicyEvent(
  sessionId: string,
  toolName: string,
  params: Record<string, unknown>,
  result: unknown,
): PolicyEvent {
  const eventId = `${sessionId}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const timestamp = new Date().toISOString();

  // Determine event type based on tool name
  const eventType = inferEventType(toolName);

  // Create appropriate event data
  const data = createEventData(toolName, params, result);

  return {
    eventId,
    eventType,
    timestamp,
    sessionId,
    data,
    metadata: {
      toolName,
      originalParams: params,
    },
  };
}

/**
 * Infer event type from tool name using the shared token-based classifier.
 */
function inferEventType(
  toolName: string,
): PolicyEvent['eventType'] {
  return inferEventTypeFromName(toolName) ?? 'tool_call';
}

/**
 * Create event data based on tool name and params
 */
function createEventData(
  toolName: string,
  params: Record<string, unknown>,
  result: unknown,
): PolicyEvent['data'] {
  const eventType = inferEventType(toolName);

  switch (eventType) {
    case 'file_read':
    case 'file_write': {
      const path = extractPath(params);
      const contentHash = typeof params.contentHash === 'string' ? params.contentHash : undefined;
      const { content, contentBase64 } = extractFileContent(params, result, eventType);
      return {
        type: 'file',
        path: path ?? '',
        content,
        contentBase64,
        contentHash,
        operation: eventType === 'file_read' ? 'read' : 'write',
      };
    }

    case 'network_egress': {
      const { host, port, url } = extractNetworkInfo(params);
      return {
        type: 'network',
        host,
        port,
        url,
      };
    }

    case 'command_exec': {
      const { command, args, workingDir } = extractCommandInfo(params);
      return {
        type: 'command',
        command,
        args,
        workingDir,
      };
    }

    case 'patch_apply': {
      const { filePath, patchContent } = extractPatchInfo(params, result);
      return {
        type: 'patch',
        filePath,
        patchContent,
      };
    }

    case 'tool_call':
    default: {
      return {
        type: 'tool',
        toolName,
        parameters: params,
        result: typeof result === 'string' ? result : JSON.stringify(result ?? ''),
      };
    }
  }
}

function extractFileContent(
  params: Record<string, unknown>,
  result: unknown,
  eventType: PolicyEvent['eventType'],
): { content?: string; contentBase64?: string } {
  const maxChars = 2_000_000; // Best-effort cap: avoid huge payloads.

  const contentBase64 =
    typeof params.contentBase64 === 'string'
      ? params.contentBase64
      : typeof params.base64 === 'string'
        ? params.base64
        : undefined;

  if (contentBase64) {
    return { contentBase64: contentBase64.length > maxChars ? contentBase64.slice(0, maxChars) : contentBase64 };
  }

  const content =
    typeof params.content === 'string'
      ? params.content
      : typeof params.text === 'string'
        ? params.text
        : eventType === 'file_read' && typeof result === 'string'
          ? result
          : undefined;

  if (!content) return {};
  return { content: content.length > maxChars ? content.slice(0, maxChars) : content };
}

/**
 * Extract network info from tool params
 */
function extractNetworkInfo(
  params: Record<string, unknown>,
): { host: string; port: number; url?: string } {
  // Try to get URL first
  const url = typeof params.url === 'string' ? params.url
    : typeof params.endpoint === 'string' ? params.endpoint
    : typeof params.href === 'string' ? params.href
    : undefined;

  if (url) {
    try {
      const parsed = new URL(url);
      return {
        host: parsed.hostname,
        port: parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' || parsed.protocol === 'wss:' ? 443 : 80),
        url,
      };
    } catch {
      // Not a valid URL
    }
  }

  // Try to extract from command
  if (typeof params.command === 'string') {
    const urlMatch = params.command.match(/https?:\/\/[^\s'"]+/);
    if (urlMatch) {
      try {
        const parsed = new URL(urlMatch[0]);
        return {
          host: parsed.hostname,
          port: parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' || parsed.protocol === 'wss:' ? 443 : 80),
          url: urlMatch[0],
        };
      } catch {
        // Not a valid URL
      }
    }
  }

  // Fallback
  const host = typeof params.host === 'string' ? params.host
    : typeof params.hostname === 'string' ? params.hostname
    : 'unknown';
  const port = typeof params.port === 'number' ? params.port : 80;
  return { host, port, url };
}

function extractCommandInfo(
  params: Record<string, unknown>,
): { command: string; args: string[]; workingDir?: string } {
  const workingDir =
    typeof params.cwd === 'string'
      ? params.cwd
      : typeof params.workingDir === 'string'
        ? params.workingDir
        : undefined;

  const args =
    Array.isArray(params.args) && params.args.every((a) => typeof a === 'string')
      ? (params.args as string[])
      : Array.isArray(params.argv) && params.argv.every((a) => typeof a === 'string')
        ? (params.argv as string[])
        : undefined;

  const cmdLine =
    typeof params.command === 'string'
      ? params.command
      : typeof params.cmd === 'string'
        ? params.cmd
        : undefined;

  if (cmdLine) {
    const parts = cmdLine.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) {
      return { command: '', args: [], workingDir };
    }
    const [command, ...rest] = parts;
    return { command, args: args ?? rest, workingDir };
  }

  if (typeof params.tool === 'string' && args) {
    return { command: params.tool, args, workingDir };
  }

  return { command: '', args: args ?? [], workingDir };
}

function extractPatchInfo(
  params: Record<string, unknown>,
  result: unknown,
): { filePath: string; patchContent: string } {
  const filePath =
    (typeof params.filePath === 'string' && params.filePath) ||
    (typeof params.path === 'string' && params.path) ||
    (typeof params.file === 'string' && params.file) ||
    '';

  const patchContent =
    (typeof params.patch === 'string' && params.patch) ||
    (typeof params.diff === 'string' && params.diff) ||
    (typeof params.content === 'string' && params.content) ||
    (typeof result === 'string' ? result : JSON.stringify(result ?? ''));

  return { filePath, patchContent };
}

export default handler;
