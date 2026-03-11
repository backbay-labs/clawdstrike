import type {
  ApprovalRequest,
  ApprovalDecision,
  ApprovalScope,
  ApprovalStatus,
  RiskLevel,
  OriginContext,
  OriginProvider,
} from "./approval-types";
import type {
  DelegationGraph,
  DelegationNode,
  DelegationEdge,
  NodeKind,
  TrustLevel,
  EdgeKind,
  Capability,
} from "./delegation-types";
import { yamlToPolicy } from "./yaml-utils";

const DEV = import.meta.env.DEV;

// ---------------------------------------------------------------------------
// URL validation (Finding 3: SSRF prevention)
// ---------------------------------------------------------------------------

function parseIpv4Bytes(hostname: string): number[] | null {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) return null;
  const octets = hostname.split(".").map((part) => Number.parseInt(part, 10));
  if (octets.some((part) => Number.isNaN(part) || part < 0 || part > 255)) return null;
  return octets;
}

function isPrivateOrLoopbackIpv4(octets: number[]): boolean {
  const [a, b, c, d] = octets;
  if ([a, b, c, d].some((part) => part === undefined)) return false;

  return (
    a === 127 ||
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 0 && b === 0 && c === 0 && d === 0)
  );
}

function parseIpv6Bytes(hostname: string): number[] | null {
  let normalized = hostname.toLowerCase();
  if (normalized.startsWith("[") && normalized.endsWith("]")) {
    normalized = normalized.slice(1, -1);
  }

  const zoneIndex = normalized.indexOf("%");
  if (zoneIndex >= 0) {
    normalized = normalized.slice(0, zoneIndex);
  }

  if (!normalized.includes(":")) return null;

  const lastColon = normalized.lastIndexOf(":");
  const maybeIpv4 = lastColon >= 0 ? normalized.slice(lastColon + 1) : "";
  if (maybeIpv4.includes(".")) {
    const ipv4Bytes = parseIpv4Bytes(maybeIpv4);
    if (!ipv4Bytes) return null;
    const high = ((ipv4Bytes[0] << 8) | ipv4Bytes[1]).toString(16);
    const low = ((ipv4Bytes[2] << 8) | ipv4Bytes[3]).toString(16);
    normalized = `${normalized.slice(0, lastColon)}:${high}:${low}`;
  }

  if ((normalized.match(/::/g) || []).length > 1) return null;

  const hasCompression = normalized.includes("::");
  const [leftRaw, rightRaw = ""] = normalized.split("::");
  const leftParts = leftRaw ? leftRaw.split(":").filter(Boolean) : [];
  const rightParts = rightRaw ? rightRaw.split(":").filter(Boolean) : [];
  const parts = [...leftParts, ...rightParts];

  if (parts.some((part) => !/^[0-9a-f]{1,4}$/i.test(part))) {
    return null;
  }

  const missing = 8 - parts.length;
  if ((!hasCompression && parts.length !== 8) || (hasCompression && missing < 0)) {
    return null;
  }

  const hextets = hasCompression
    ? [...leftParts, ...Array.from({ length: missing }, () => "0"), ...rightParts]
    : parts;

  if (hextets.length !== 8) return null;

  return hextets.flatMap((part) => {
    const value = Number.parseInt(part, 16);
    return [(value >> 8) & 0xff, value & 0xff];
  });
}

export function isPrivateOrLoopbackFleetHostname(hostname: string): boolean {
  const ipv4Bytes = parseIpv4Bytes(hostname);
  if (ipv4Bytes) {
    return isPrivateOrLoopbackIpv4(ipv4Bytes);
  }

  const ipv6Bytes = parseIpv6Bytes(hostname);
  if (!ipv6Bytes) return false;

  const isAllZero = ipv6Bytes.every((part) => part === 0);
  if (isAllZero) return true;

  const isLoopback =
    ipv6Bytes.slice(0, 15).every((part) => part === 0) && ipv6Bytes[15] === 1;
  if (isLoopback) return true;

  const isUniqueLocal = (ipv6Bytes[0] & 0xfe) === 0xfc;
  if (isUniqueLocal) return true;

  const isLinkLocal = ipv6Bytes[0] === 0xfe && (ipv6Bytes[1] & 0xc0) === 0x80;
  if (isLinkLocal) return true;

  const isIpv4Mapped =
    ipv6Bytes.slice(0, 10).every((part) => part === 0) &&
    ipv6Bytes[10] === 0xff &&
    ipv6Bytes[11] === 0xff;
  const isIpv4Compatible = ipv6Bytes.slice(0, 12).every((part) => part === 0);
  if (isIpv4Mapped || isIpv4Compatible) {
    return isPrivateOrLoopbackIpv4(ipv6Bytes.slice(12));
  }

  return false;
}

function normalizeFleetUrlInput(url: string): string {
  return url.trim();
}

export function validateFleetUrl(url: string): { valid: true; tlsWarning?: string } | { valid: false; reason: string } {
  const normalizedUrl = normalizeFleetUrlInput(url);
  if (!normalizedUrl) {
    return { valid: false, reason: "URL must not be empty" };
  }

  let parsed: URL;
  try {
    parsed = new URL(normalizedUrl);
  } catch {
    return { valid: false, reason: "Invalid URL format" };
  }

  // Only allow http and https schemes
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { valid: false, reason: `Unsupported URL scheme "${parsed.protocol}" — only http: and https: are allowed` };
  }

  if (parsed.username || parsed.password) {
    return { valid: false, reason: "URLs must not include embedded credentials" };
  }

  const hostname = parsed.hostname.toLowerCase();

  // In production, reject private/loopback addresses (SSRF prevention)
  if (!import.meta.env.DEV) {
    if (hostname === "localhost") {
      return { valid: false, reason: "localhost URLs are not allowed in production" };
    }
    if (isPrivateOrLoopbackFleetHostname(hostname)) {
      return { valid: false, reason: "Private/loopback IP addresses are not allowed in production" };
    }
  }

  // TLS warning (Finding M4): warn about http in non-localhost contexts
  if (parsed.protocol === "http:" && hostname !== "localhost" && hostname !== "127.0.0.1") {
    return { valid: true, tlsWarning: "Connection is using unencrypted HTTP. Use HTTPS in production to protect credentials in transit." };
  }

  return { valid: true };
}

function normalizedValidatedFleetUrl(url: string, fieldName: string): string {
  const normalized = stripTrailingSlash(normalizeFleetUrlInput(url));
  const validation = validateFleetUrl(normalized);
  if (!validation.valid) {
    throw new Error(`Invalid ${fieldName}: ${validation.reason}`);
  }
  return normalized;
}

function sanitizeStoredFleetUrl(url: string | null | undefined, fieldName: string): string {
  if (!url) return "";
  try {
    return normalizedValidatedFleetUrl(url, fieldName);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`[fleet-client] ignoring invalid ${fieldName} from storage: ${message}`);
    return "";
  }
}

/** Rewrite absolute URLs to Vite dev proxy paths; passthrough in production. */
function proxyUrl(absoluteUrl: string, kind: "hushd" | "control"): string {
  const normalizedUrl = normalizeFleetUrlInput(absoluteUrl);
  if (!DEV) return normalizedUrl;

  // Validate URL before proxy rewrite (Finding 3)
  const validation = validateFleetUrl(normalizedUrl);
  if (!validation.valid) {
    throw new Error(`[fleet-client] Invalid fleet URL: ${validation.reason}`);
  }

  try {
    const u = new URL(normalizedUrl);
    return `/_proxy/${kind}${u.pathname}${u.search}`;
  } catch {
    // Don't log the raw URL to avoid credential leakage (Finding M3)
    console.warn("[fleet-client] Invalid URL format for proxy rewrite");
    return normalizedUrl;
  }
}

const isTauri =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window && !DEV;

const tauriFetchPromise: Promise<typeof globalThis.fetch> | null = isTauri
  ? import("@tauri-apps/plugin-http")
      .then((mod) => mod.fetch as typeof globalThis.fetch)
      .catch(() => globalThis.fetch.bind(globalThis))
  : null;

async function httpFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const fn = tauriFetchPromise ? await tauriFetchPromise : globalThis.fetch;
  return fn(input, init);
}

import { secureStore } from "./secure-store";

// Stronghold-backed secure keys used by secureStore (P4-2).
const SS_HUSHD_URL = "hushd_url";
const SS_CONTROL_API_URL = "control_api_url";
const SS_API_KEY = "api_key";
const SS_CONTROL_TOKEN = "control_api_token";

// Legacy localStorage keys kept for synchronous bootstrap reads only.
// New writes go through secureStore; these are cleared after migration.
const LS_HUSHD_URL = "clawdstrike_hushd_url";
const LS_CONTROL_API_URL = "clawdstrike_control_api_url";
const LS_API_KEY = "clawdstrike_api_key";
const LS_CONTROL_TOKEN = "clawdstrike_control_api_token";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuditEvent {
  id: string;
  timestamp: string;
  action_type: string;
  target?: string;
  decision: string;
  guard?: string;
  severity?: string;
  session_id?: string;
  agent_id?: string;
  metadata?: Record<string, unknown>;
}

export interface AuditFilters {
  since?: string;
  until?: string;
  action_type?: string;
  decision?: string;
  agent_id?: string;
  limit?: number;
}

export interface FleetConnection {
  hushdUrl: string;
  controlApiUrl: string;
  apiKey: string;          // hushd Bearer token
  controlApiToken: string; // control-api JWT or API key
  connected: boolean;
  hushdHealth: HealthResponse | null;
  agentCount: number;
}

export interface HealthResponse {
  status: string;
  version?: string;
  uptime_secs?: number;
  policy_hash?: string;
}

export interface PolicyResponse {
  name?: string;
  version?: string;
  description?: string;
  policy_hash?: string;
  yaml?: string;
  source?: { kind: string; path?: string; path_exists?: boolean };
  policy?: unknown;
}

export interface ValidateResponse {
  valid: boolean;
  errors: string[];
  warnings?: string[];
}

export interface DeployResponse {
  success: boolean;
  hash?: string;
  error?: string;
}

export interface AgentDriftFlags {
  policy_drift: boolean;
  daemon_drift: boolean;
  stale: boolean;
}

export interface AgentInfo {
  endpoint_agent_id: string;
  last_heartbeat_at: string;
  last_seen_ip?: string;
  last_session_id?: string;
  posture?: string;
  policy_version?: string;
  daemon_version?: string;
  runtime_count?: number;
  seconds_since_heartbeat?: number;
  online: boolean;
  drift: AgentDriftFlags;
}

export interface AgentStatusResponse {
  generated_at: string;
  stale_after_secs: number;
  endpoints: AgentInfo[];
  runtimes: unknown[];
}

export interface PrincipalInfo {
  id: string;
  name?: string;
  kind?: string;
  role?: string;
  trust_level?: string;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
}

/** Backend delegation graph node shape from GET /api/v1/principals/{id}/delegation-graph */
interface BackendGraphNode {
  id: string;
  kind: string;
  label?: string;
  role?: string;
  trust_level?: string;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
}

/** Backend delegation graph edge shape */
interface BackendGraphEdge {
  id: string;
  from: string;
  to: string;
  kind: string;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
}

/** Backend delegation graph snapshot response */
interface BackendDelegationGraphResponse {
  nodes: BackendGraphNode[];
  edges: BackendGraphEdge[];
  generated_at?: string;
  principal_id?: string;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/**
 * Synchronous bootstrap read from localStorage in the web runtime.
 * Used for initial render before Stronghold is ready.
 * Only reads URL fields from localStorage; secrets are read exclusively
 * from secureStore via loadSavedConnectionAsync(). (Finding 2)
 */
export function loadSavedConnection(): Partial<FleetConnection> {
  try {
    return {
      hushdUrl: sanitizeStoredFleetUrl(localStorage.getItem(LS_HUSHD_URL), "hushd URL"),
      controlApiUrl: sanitizeStoredFleetUrl(
        localStorage.getItem(LS_CONTROL_API_URL),
        "control API URL",
      ),
      apiKey: "",
      controlApiToken: "",
    };
  } catch (e) {
    console.warn("[fleet-client] localStorage read failed:", e);
    return { hushdUrl: "", controlApiUrl: "", apiKey: "", controlApiToken: "" };
  }
}

/**
 * Async credential load from secureStore (Stronghold on desktop).
 * Falls back to localStorage values if Stronghold is unavailable.
 */
export async function loadSavedConnectionAsync(): Promise<Partial<FleetConnection>> {
  const bootstrap = loadSavedConnection();

  try {
    const [hushdUrl, controlApiUrl, apiKey, controlApiToken] = await Promise.all([
      secureStore.get(SS_HUSHD_URL),
      secureStore.get(SS_CONTROL_API_URL),
      secureStore.get(SS_API_KEY),
      secureStore.get(SS_CONTROL_TOKEN),
    ]);

    // If Stronghold had values, use them. Otherwise fall back to localStorage.
    if (hushdUrl || controlApiUrl || apiKey || controlApiToken) {
      return {
        hushdUrl:
          sanitizeStoredFleetUrl(hushdUrl, "hushd URL") || bootstrap.hushdUrl || "",
        controlApiUrl:
          sanitizeStoredFleetUrl(controlApiUrl, "control API URL") ||
          bootstrap.controlApiUrl ||
          "",
        apiKey: apiKey ?? "",
        controlApiToken: controlApiToken ?? "",
      };
    }
  } catch (e) {
    console.warn("[fleet-client] secureStore read failed, using localStorage:", e);
  }

  return bootstrap;
}

/**
 * Save connection config to secureStore (Stronghold on desktop).
 * Only non-secret fields (URLs) are written to localStorage for sync bootstrap.
 * Secret fields (apiKey, controlApiToken) are only written to secureStore.
 * (Finding 2: never write secrets to plaintext localStorage.)
 */
export async function saveConnectionConfig(config: {
  hushdUrl: string;
  controlApiUrl: string;
  apiKey: string;
  controlApiToken: string;
}): Promise<void> {
  const hushdUrl = config.hushdUrl
    ? normalizedValidatedFleetUrl(config.hushdUrl, "hushd URL")
    : "";
  const controlApiUrl = config.controlApiUrl
    ? normalizedValidatedFleetUrl(config.controlApiUrl, "control API URL")
    : "";

  // Write all fields to secureStore (Stronghold on desktop, sessionStorage fallback on web).
  // Finding M6: await the writes instead of fire-and-forget.
  try {
    await Promise.all([
      secureStore.set(SS_HUSHD_URL, hushdUrl),
      secureStore.set(SS_CONTROL_API_URL, controlApiUrl),
      secureStore.set(SS_API_KEY, config.apiKey),
      secureStore.set(SS_CONTROL_TOKEN, config.controlApiToken),
    ]);
  } catch (e) {
    console.warn("[fleet-client] secureStore write failed — credentials may not be persisted securely:", e);
    throw new Error("Failed to persist credentials securely");
  }

  // Only write non-secret URL fields to localStorage for sync-readable bootstrap.
  // Never write apiKey or controlApiToken to localStorage.
  try {
    localStorage.setItem(LS_HUSHD_URL, hushdUrl);
    localStorage.setItem(LS_CONTROL_API_URL, controlApiUrl);
  } catch (e) {
    console.warn("[fleet-client] localStorage write failed:", e);
  }
}

export function clearConnectionConfig() {
  // Clear from secureStore (async, fire-and-forget).
  secureStore.delete(SS_HUSHD_URL).catch(() => {});
  secureStore.delete(SS_CONTROL_API_URL).catch(() => {});
  secureStore.delete(SS_API_KEY).catch(() => {});
  secureStore.delete(SS_CONTROL_TOKEN).catch(() => {});

  // Only URL fields are in localStorage (secrets are never written there).
  try {
    localStorage.removeItem(LS_HUSHD_URL);
    localStorage.removeItem(LS_CONTROL_API_URL);
    // Also clean up any legacy secret keys that may exist from before Finding 2 fix
    localStorage.removeItem(LS_API_KEY);
    localStorage.removeItem(LS_CONTROL_TOKEN);
  } catch (e) {
    console.warn("[fleet-client] localStorage removeItem failed:", e);
  }
}

/** Clear all stored credentials. Call on disconnect / logout. */
export function clearCredentials() {
  secureStore.delete(SS_API_KEY).catch(() => {});
  secureStore.delete(SS_CONTROL_TOKEN).catch(() => {});

  // Clean up any legacy secret keys from localStorage
  try {
    localStorage.removeItem(LS_API_KEY);
    localStorage.removeItem(LS_CONTROL_TOKEN);
  } catch (e) {
    console.warn("[fleet-client] localStorage credential removal failed:", e);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hushdHeaders(apiKey: string): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) h["Authorization"] = `Bearer ${apiKey}`;
  return h;
}

function isJwtLikeToken(token: string): boolean {
  const parts = token.split(".");
  return (
    parts.length === 3 &&
    parts.every((part) => part.length > 0 && /^[A-Za-z0-9_-]+$/.test(part))
  );
}

function controlHeaders(conn: FleetConnection): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  const token = conn.controlApiToken || conn.apiKey;
  if (token) {
    if (isJwtLikeToken(token)) {
      h["Authorization"] = `Bearer ${token}`;
    } else {
      h["x-api-key"] = token;
    }
  }
  return h;
}

/** Max response size accepted by jsonFetch (10 MB). */
const MAX_RESPONSE_BYTES = 10_485_760;
const MAX_ERROR_RESPONSE_BYTES = 2_048;

/** Redact Bearer tokens and API key-like patterns from error messages. (Finding M3) */
function redactSecrets(text: string): string {
  return text
    .replace(/Bearer\s+[^\s]+/gi, "Bearer [REDACTED]")
    .replace(/x-api-key[:\s]+[^\s,;}]+/gi, "x-api-key: [REDACTED]");
}

async function readResponseTextWithLimit(res: Response, maxBytes: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) {
    const body = await res.arrayBuffer();
    if (body.byteLength > maxBytes) {
      throw new Error(`Response too large (${body.byteLength} bytes exceeds ${maxBytes} limit)`);
    }
    return new TextDecoder().decode(body);
  }

  const decoder = new TextDecoder();
  let total = 0;
  let text = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new Error(`Response too large (${total} bytes exceeds ${maxBytes} limit)`);
    }
    text += decoder.decode(value, { stream: true });
  }

  text += decoder.decode();
  return text;
}

async function jsonFetch<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await httpFetch(url, { ...init, signal: init?.signal ?? AbortSignal.timeout(10_000) });
  if (!res.ok) {
    const body = await readResponseTextWithLimit(res, MAX_ERROR_RESPONSE_BYTES).catch(() => "");
    // Finding M3: truncate error body and strip secrets
    const sanitized = redactSecrets(body.slice(0, 200));
    throw new Error(sanitized || `HTTP ${res.status}`);
  }

  // Finding L9: check Content-Length before parsing
  const contentLength = res.headers.get("Content-Length");
  if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_BYTES) {
    throw new Error(`Response too large (${contentLength} bytes exceeds ${MAX_RESPONSE_BYTES} limit)`);
  }
  const bodyText = await readResponseTextWithLimit(res, MAX_RESPONSE_BYTES);
  try {
    return JSON.parse(bodyText) as T;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid JSON";
    throw new Error(`Invalid JSON response: ${message}`);
  }
}

// ---------------------------------------------------------------------------
// API functions
// ---------------------------------------------------------------------------

function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function readStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function readNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function readBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function secondsSince(isoDate?: string | null): number | undefined {
  if (!isoDate) return undefined;
  const ts = new Date(isoDate).getTime();
  if (Number.isNaN(ts)) return undefined;
  return Math.max(0, Math.floor((Date.now() - ts) / 1000));
}

const FALLBACK_STALE_AFTER_SECS = 90;

function toAgentInfo(value: unknown): AgentInfo {
  if (!isRecord(value)) {
    throw new Error("[fleet-client] fetchAgentList: expected each agent row to be an object");
  }

  if (typeof value.endpoint_agent_id === "string" && typeof value.last_heartbeat_at === "string") {
    return {
      endpoint_agent_id: value.endpoint_agent_id,
      last_heartbeat_at: value.last_heartbeat_at,
      last_seen_ip: readString(value.last_seen_ip),
      last_session_id: readString(value.last_session_id),
      posture: readString(value.posture),
      policy_version: readString(value.policy_version),
      daemon_version: readString(value.daemon_version),
      runtime_count: readNumber(value.runtime_count),
      seconds_since_heartbeat: readNumber(value.seconds_since_heartbeat),
      online: value.online === true,
      drift: isRecord(value.drift)
        ? {
            policy_drift: value.drift.policy_drift === true,
            daemon_drift: value.drift.daemon_drift === true,
            stale: value.drift.stale === true,
          }
        : { policy_drift: false, daemon_drift: false, stale: false },
    };
  }

  const agentId = readString(value.agent_id);
  if (!agentId) {
    throw new Error("[fleet-client] fetchAgentList: expected control-api agent rows to include agent_id");
  }

  const metadata = isRecord(value.metadata) ? value.metadata : {};
  const lastHeartbeat =
    readString(value.last_heartbeat_at) ?? readString(value.created_at) ?? new Date(0).toISOString();
  const since = secondsSince(lastHeartbeat);
  const status = (readString(value.status) ?? "").toLowerCase();
  const stale =
    readBoolean(metadata.stale) ??
    (status === "stale" ||
      status === "offline" ||
      status === "inactive" ||
      status === "dead" ||
      (since !== undefined && since > FALLBACK_STALE_AFTER_SECS));
  const online = !["stale", "offline", "inactive", "dead"].includes(status);

  return {
    endpoint_agent_id: agentId,
    last_heartbeat_at: lastHeartbeat,
    last_seen_ip: readString(metadata.last_seen_ip),
    last_session_id: readString(metadata.session_id) ?? readString(metadata.last_session_id),
    posture: readString(metadata.posture),
    policy_version:
      readString(metadata.policy_version) ??
      readString(metadata.active_policy_version) ??
      readString(metadata.policy_hash),
    daemon_version: readString(metadata.daemon_version),
    runtime_count: readNumber(metadata.runtime_count),
    seconds_since_heartbeat: since,
    online,
    drift: {
      policy_drift: readBoolean(metadata.policy_drift) ?? false,
      daemon_drift: readBoolean(metadata.daemon_drift) ?? false,
      stale,
    },
  };
}

function deriveCatalogDifficulty(tags: string[]): string {
  const value = tags.find((tag) => tag.startsWith("difficulty:"))?.slice("difficulty:".length);
  return value === "beginner" || value === "intermediate" || value === "advanced"
    ? value
    : "intermediate";
}

function deriveCatalogCompliance(tags: string[]): string[] {
  const normalized = new Set(tags.map((tag) => tag.toLowerCase()));
  const compliance: string[] = [];
  if (normalized.has("hipaa")) compliance.push("HIPAA");
  if (normalized.has("soc2")) compliance.push("SOC2");
  if (normalized.has("pci-dss") || normalized.has("pci_dss")) compliance.push("PCI-DSS");
  return compliance;
}

function deriveCatalogGuardSummary(policyYaml: string): string[] {
  const [policy] = yamlToPolicy(policyYaml);
  if (!policy) return [];

  return Object.entries(policy.guards)
    .filter(([, config]) => isRecord(config) && config.enabled !== false)
    .map(([guard]) => guard)
    .sort();
}

function normalizeCatalogTags(tags: string[], difficulty?: string): string[] {
  const base = tags.filter((tag) => !tag.startsWith("difficulty:"));
  if (difficulty) base.push(`difficulty:${difficulty}`);
  return Array.from(new Set(base));
}

function toCatalogTemplate(value: unknown): CatalogTemplate {
  if (!isRecord(value) || typeof value.id !== "string" || typeof value.name !== "string") {
    throw new Error("[fleet-client] catalog template response shape is invalid");
  }

  if (typeof value.yaml === "string") {
    const tags = readStringArray(value.tags);
    return {
      id: value.id,
      name: value.name,
      description: readString(value.description) ?? "",
      category: readString(value.category) ?? "general",
      tags,
      author: readString(value.author) ?? "Unknown",
      version: readString(value.version) ?? "1.0.0",
      yaml: value.yaml,
      guard_summary: readStringArray(value.guard_summary),
      use_cases: readStringArray(value.use_cases),
      compliance: readStringArray(value.compliance),
      difficulty: readString(value.difficulty) ?? deriveCatalogDifficulty(tags),
      downloads: readNumber(value.downloads) ?? 0,
      created_at: readString(value.created_at) ?? new Date(0).toISOString(),
      updated_at: readString(value.updated_at) ?? new Date(0).toISOString(),
      metadata: isRecord(value.metadata) ? value.metadata : undefined,
    };
  }

  if (typeof value.policy_yaml !== "string") {
    throw new Error("[fleet-client] catalog template response is missing policy_yaml");
  }

  const tags = readStringArray(value.tags);
  const policyYaml = value.policy_yaml;
  return {
    id: value.id,
    name: value.name,
    description: readString(value.description) ?? "",
    category: readString(value.category) ?? "general",
    tags,
    author: readString(value.author) ?? "Unknown",
    version: readString(value.version) ?? "1.0.0",
    yaml: policyYaml,
    guard_summary: deriveCatalogGuardSummary(policyYaml),
    use_cases: [],
    compliance: deriveCatalogCompliance(tags),
    difficulty: deriveCatalogDifficulty(tags),
    downloads: readNumber(value.downloads) ?? 0,
    created_at: readString(value.created_at) ?? new Date(0).toISOString(),
    updated_at: readString(value.updated_at) ?? new Date(0).toISOString(),
    metadata: isRecord(value.metadata) ? value.metadata : undefined,
  };
}

function toCatalogCategory(value: unknown): CatalogCategoryInfo {
  if (!isRecord(value) || typeof value.id !== "string") {
    throw new Error("[fleet-client] catalog category response shape is invalid");
  }

  const label = readString(value.label) ?? readString(value.name);
  if (!label) {
    throw new Error("[fleet-client] catalog category response is missing label/name");
  }

  return {
    id: value.id,
    label,
    color: readString(value.color) ?? "#6f7f9a",
    count: readNumber(value.count) ?? readNumber(value.template_count) ?? 0,
  };
}

function normalizeCatalogFetchError(error: unknown): Error {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes("HTTP 404")) {
    return new Error("Catalog endpoints are unavailable on the configured control API");
  }
  return error instanceof Error ? error : new Error(message);
}

export async function testConnection(
  hushdUrl: string,
  apiKey: string,
): Promise<HealthResponse & { tlsWarning?: string }> {
  const url = normalizedValidatedFleetUrl(hushdUrl, "fleet URL");
  const validation = validateFleetUrl(url);
  const health = await jsonFetch<HealthResponse>(proxyUrl(`${url}/health`, "hushd"), {
    headers: hushdHeaders(apiKey),
  });

  // Finding M4: surface TLS warning if applicable
  if (validation.valid && validation.tlsWarning) {
    return { ...health, tlsWarning: validation.tlsWarning };
  }

  return health;
}

export async function fetchRemotePolicy(
  conn: FleetConnection,
): Promise<{ yaml: string; name?: string; version?: string; policyHash?: string }> {
  const url = stripTrailingSlash(conn.hushdUrl);
  const res = await jsonFetch<PolicyResponse>(proxyUrl(`${url}/api/v1/policy`, "hushd"), {
    headers: hushdHeaders(conn.apiKey),
  });
  // Runtime validation: ensure yaml field is a string (#18)
  if (res.yaml !== undefined && typeof res.yaml !== "string") {
    throw new Error("[fleet-client] fetchRemotePolicy: expected res.yaml to be a string");
  }
  return {
    yaml: res.yaml ?? "",
    name: res.name,
    version: res.version,
    policyHash: res.policy_hash,
  };
}

export async function deployPolicy(
  conn: FleetConnection,
  yaml: string,
): Promise<DeployResponse> {
  const url = stripTrailingSlash(conn.hushdUrl);
  try {
    const res = await jsonFetch<{ policy_hash?: string }>(proxyUrl(`${url}/api/v2/policy`, "hushd"), {
      method: "POST",
      headers: hushdHeaders(conn.apiKey),
      body: JSON.stringify({ yaml }),
    });
    return { success: true, hash: res.policy_hash };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function validateRemotely(
  conn: FleetConnection,
  yaml: string,
): Promise<ValidateResponse> {
  const url = stripTrailingSlash(conn.hushdUrl);
  return jsonFetch<ValidateResponse>(proxyUrl(`${url}/api/v2/policy/validate`, "hushd"), {
    method: "POST",
    headers: hushdHeaders(conn.apiKey),
    body: JSON.stringify({ yaml }),
  });
}

export async function fetchAgentCount(conn: FleetConnection): Promise<number> {
  try {
    return (await fetchAgentList(conn)).length;
  } catch (e) {
    console.warn("[fleet-client] fetchAgentCount failed:", e);
    return 0;
  }
}

/** Falls back to control-api /api/v1/agents if hushd endpoint is unavailable. */
export async function fetchAgentList(conn: FleetConnection): Promise<AgentInfo[]> {
  const url = stripTrailingSlash(conn.hushdUrl);
  try {
    const res = await jsonFetch<AgentStatusResponse>(
      proxyUrl(`${url}/api/v1/agents/status?include_stale=true`, "hushd"),
      { headers: hushdHeaders(conn.apiKey) },
    );
    return res.endpoints ?? [];
  } catch (e) {
    console.warn("[fleet-client] hushd agent list failed, trying control-api:", e);
    if (!conn.controlApiUrl) return [];
    const ctrlUrl = normalizedValidatedFleetUrl(conn.controlApiUrl, "control API URL");
    const res = await jsonFetch<unknown>(proxyUrl(`${ctrlUrl}/api/v1/agents`, "control"), {
      headers: controlHeaders(conn),
    });
    // Runtime validation: ensure response is an array (#18)
    if (!Array.isArray(res)) {
      throw new Error("[fleet-client] fetchAgentList: expected response to be an array");
    }
    return res.map(toAgentInfo);
  }
}

export async function fetchAuditEvents(
  conn: FleetConnection,
  filters?: AuditFilters,
): Promise<AuditEvent[]> {
  const url = stripTrailingSlash(conn.hushdUrl);
  const params = new URLSearchParams();
  if (filters?.since) params.set("since", filters.since);
  if (filters?.until) params.set("until", filters.until);
  if (filters?.action_type) params.set("action_type", filters.action_type);
  if (filters?.decision) params.set("decision", filters.decision);
  if (filters?.agent_id) params.set("agent_id", filters.agent_id);
  if (filters?.limit) params.set("limit", String(filters.limit));
  const qs = params.toString();
  const endpoint = `${url}/api/v1/audit${qs ? `?${qs}` : ""}`;
  const res = await jsonFetch<{ events?: AuditEvent[] } | AuditEvent[]>(proxyUrl(endpoint, "hushd"), {
    headers: hushdHeaders(conn.apiKey),
  });
  // Runtime validation: ensure response has .events array or is itself an array (#18)
  if (Array.isArray(res)) return res;
  if (res && typeof res === "object" && "events" in res) {
    if (!Array.isArray(res.events)) {
      throw new Error("[fleet-client] fetchAuditEvents: expected res.events to be an array");
    }
    return res.events;
  }
  throw new Error("[fleet-client] fetchAuditEvents: unexpected response shape");
}

export async function distributePolicy(
  conn: FleetConnection,
  yaml: string,
): Promise<DeployResponse> {
  if (!conn.controlApiUrl) {
    return { success: false, error: "Control API URL not configured" };
  }
  try {
    const ctrlUrl = normalizedValidatedFleetUrl(conn.controlApiUrl, "control API URL");
    const res = await jsonFetch<{ success?: boolean; hash?: string }>(
      proxyUrl(`${ctrlUrl}/api/v1/policies/deploy`, "control"),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify({ policy_yaml: yaml }),
      },
    );
    return { success: res.success !== false, hash: res.hash };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function preferredUrl(conn: FleetConnection): { url: string; kind: "control" | "hushd" } {
  if (conn.controlApiUrl) {
    return {
      url: normalizedValidatedFleetUrl(conn.controlApiUrl, "control API URL"),
      kind: "control",
    };
  }
  return { url: normalizedValidatedFleetUrl(conn.hushdUrl, "hushd URL"), kind: "hushd" };
}

// ---------------------------------------------------------------------------
// Backend approval shape adapter (P2-1)
// ---------------------------------------------------------------------------

/**
 * Raw approval row returned by the control-api backend.
 *
 * The backend stores a flat DB row with an opaque `event_data` JSONB blob.
 * The frontend expects a richer `ApprovalRequest` + `ApprovalDecision` pair.
 * This type captures the wire format so we can adapt it cleanly.
 */
interface BackendApproval {
  id: string;
  tenant_id: string;
  principal_id?: string | null;
  agent_id: string;
  request_id: string;
  event_type: string;
  event_data: Record<string, unknown>;
  status: string;
  resolved_by?: string | null;
  resolved_at?: string | null;
  created_at: string;
}

/** Known backend status values that map directly to frontend status. */
const BACKEND_KNOWN_STATUSES = new Set<string>(["pending", "approved", "denied"]);

/** Known provider identifiers accepted by the frontend OriginProvider type. */
const BACKEND_KNOWN_PROVIDERS = new Set<string>(["slack", "teams", "github", "jira", "cli", "api"]);

/** Known risk levels accepted by the frontend RiskLevel type. */
const BACKEND_KNOWN_RISK_LEVELS = new Set<string>(["low", "medium", "high", "critical"]);

/**
 * Derive the frontend `ApprovalStatus` from the backend row.
 *
 * The backend DB only stores "pending", "approved", or "denied".
 * The frontend also has "expired", which we derive by checking whether
 * a still-pending request has passed its `expires_at` timestamp.
 */
function deriveApprovalStatus(
  backendStatus: string,
  expiresAt: string | undefined,
): ApprovalStatus {
  const normalized = backendStatus.toLowerCase();
  if (normalized === "pending" && expiresAt) {
    const expiresMs = new Date(expiresAt).getTime();
    if (!Number.isNaN(expiresMs) && expiresMs < Date.now()) {
      return "expired";
    }
  }
  if (BACKEND_KNOWN_STATUSES.has(normalized)) {
    return normalized as ApprovalStatus;
  }
  // Fail-closed: unknown statuses treated as denied in the UI.
  return "denied";
}

/**
 * Safely extract an OriginContext from the backend event_data blob.
 * Supports both snake_case (`origin_context`) and camelCase (`originContext`) keys.
 */
function extractOriginContext(eventData: Record<string, unknown>): OriginContext {
  const raw =
    (eventData.origin_context as Record<string, unknown> | undefined) ??
    (eventData.originContext as Record<string, unknown> | undefined);

  if (!raw || typeof raw !== "object") {
    return { provider: "api" };
  }

  const providerRaw = String(raw.provider ?? "api").toLowerCase();
  const provider: OriginProvider = BACKEND_KNOWN_PROVIDERS.has(providerRaw)
    ? (providerRaw as OriginProvider)
    : "api";

  return {
    provider,
    tenant_id: optionalString(raw.tenant_id),
    space_id: optionalString(raw.space_id),
    space_type: optionalString(raw.space_type),
    actor_id: optionalString(raw.actor_id),
    actor_name: optionalString(raw.actor_name),
    visibility: optionalString(raw.visibility),
  };
}

/** Safely extract a RiskLevel from the event_data blob. */
function extractRiskLevel(eventData: Record<string, unknown>): RiskLevel {
  const raw = optionalString(eventData.risk_level ?? eventData.riskLevel ?? eventData.severity);
  if (raw && BACKEND_KNOWN_RISK_LEVELS.has(raw.toLowerCase())) {
    return raw.toLowerCase() as RiskLevel;
  }
  return "medium";
}

/** Convert a value to a trimmed string if truthy, otherwise undefined. */
function optionalString(value: unknown): string | undefined {
  if (value == null) return undefined;
  const s = String(value).trim();
  return s.length > 0 ? s : undefined;
}

/**
 * Default expiry: 30 minutes from the request's created_at timestamp.
 * Used when the backend event_data does not include an `expires_at` field.
 */
function defaultExpiresAt(createdAt: string): string {
  const ts = new Date(createdAt).getTime();
  if (Number.isNaN(ts)) return new Date(Date.now() + 30 * 60_000).toISOString();
  return new Date(ts + 30 * 60_000).toISOString();
}

/**
 * Adapt a single backend approval row into the frontend `ApprovalRequest` shape.
 *
 * Fields are extracted from the opaque `event_data` JSON blob with sensible
 * defaults for any missing values.
 */
function adaptBackendApproval(raw: BackendApproval): ApprovalRequest {
  const ed = raw.event_data ?? {};

  const toolName =
    optionalString(ed.tool) ??
    optionalString(ed.tool_name) ??
    optionalString(ed.toolName) ??
    optionalString(ed.resource) ??
    "unknown";

  const expiresAtRaw =
    optionalString(ed.expires_at) ?? optionalString(ed.expiresAt);
  const expiresAt = expiresAtRaw ?? defaultExpiresAt(raw.created_at);

  const status = deriveApprovalStatus(raw.status, expiresAt);

  return {
    id: raw.request_id || raw.id,
    originContext: extractOriginContext(ed),
    enclaveId: optionalString(ed.enclave_id ?? ed.enclaveId),
    toolName,
    reason:
      optionalString(ed.reason) ??
      optionalString(ed.guard) ??
      `Approval required for ${toolName}`,
    requestedBy:
      optionalString(ed.requested_by) ??
      optionalString(ed.requestedBy) ??
      optionalString(ed.actor_name) ??
      raw.agent_id,
    requestedAt: raw.created_at,
    expiresAt,
    status,
    agentId: raw.agent_id,
    agentName: optionalString(ed.agent_name) ?? optionalString(ed.agentName),
    capability: optionalString(ed.capability),
    riskLevel: extractRiskLevel(ed),
  };
}

/**
 * If the backend approval is resolved, produce a corresponding
 * `ApprovalDecision` for the frontend decision map.
 */
function adaptBackendDecision(raw: BackendApproval): ApprovalDecision | null {
  const normalizedStatus = raw.status.toLowerCase();
  if (normalizedStatus !== "approved" && normalizedStatus !== "denied") {
    return null;
  }
  return {
    requestId: raw.request_id || raw.id,
    decision: normalizedStatus as "approved" | "denied",
    reason: optionalString(raw.event_data?.resolution_reason as unknown),
    decidedBy: raw.resolved_by ?? "control-api",
    decidedAt: raw.resolved_at ?? raw.created_at,
  };
}

/**
 * Adapt the backend response (a flat array of approval rows or a wrapped
 * `{ requests, decisions }` object) into the frontend-expected shape.
 *
 * Handles three response shapes:
 * 1. `BackendApproval[]` -- control-api returns a flat array
 * 2. `{ requests, decisions }` -- already in frontend shape (passthrough)
 * 3. `{ approvals: BackendApproval[] }` -- alternate wrapper
 */
function adaptApprovalsResponse(
  res: unknown,
): { requests: ApprovalRequest[]; decisions: ApprovalDecision[] } {
  // Shape 1: flat array of backend approval rows
  if (Array.isArray(res)) {
    const requests: ApprovalRequest[] = [];
    const decisions: ApprovalDecision[] = [];
    for (const item of res) {
      if (!item || typeof item !== "object") continue;
      const row = item as Record<string, unknown>;

      // Heuristic: if the item has `event_data` it is a backend row.
      // If it has `toolName` or `originContext` it is already a frontend shape.
      if ("event_data" in row) {
        requests.push(adaptBackendApproval(row as unknown as BackendApproval));
        const decision = adaptBackendDecision(row as unknown as BackendApproval);
        if (decision) decisions.push(decision);
      } else if ("toolName" in row || "originContext" in row) {
        // Already in frontend shape -- passthrough
        requests.push(row as unknown as ApprovalRequest);
      }
    }
    return { requests, decisions };
  }

  // Shape 2 or 3: wrapped object
  if (res && typeof res === "object") {
    const obj = res as Record<string, unknown>;

    // If it already has `requests` key, check if items need adaptation
    if ("requests" in obj && Array.isArray(obj.requests)) {
      const rawRequests = obj.requests as Record<string, unknown>[];
      const needsAdaptation =
        rawRequests.length > 0 && "event_data" in rawRequests[0];
      if (needsAdaptation) {
        return adaptApprovalsResponse(rawRequests);
      }
      return {
        requests: rawRequests as unknown as ApprovalRequest[],
        decisions: (Array.isArray(obj.decisions)
          ? obj.decisions
          : []) as ApprovalDecision[],
      };
    }

    // Alternate wrapper: `{ approvals: [...] }`
    if ("approvals" in obj && Array.isArray(obj.approvals)) {
      return adaptApprovalsResponse(obj.approvals);
    }
  }

  // Unknown shape -- return empty (fail-closed)
  console.warn(
    "[fleet-client] fetchApprovals: unexpected response shape, returning empty",
  );
  return { requests: [], decisions: [] };
}

export async function fetchApprovals(
  conn: FleetConnection,
): Promise<{ requests: ApprovalRequest[]; decisions: ApprovalDecision[] }> {
  const { url, kind } = preferredUrl(conn);
  const res = await jsonFetch<unknown>(
    proxyUrl(`${url}/api/v1/approvals`, kind),
    { headers: controlHeaders(conn) },
  );
  return adaptApprovalsResponse(res);
}

export async function resolveApproval(
  conn: FleetConnection,
  requestId: string,
  decision: "approved" | "denied",
  opts?: { scope?: ApprovalScope; reason?: string },
): Promise<{ success: boolean; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  try {
    await jsonFetch<{ ok: boolean }>(
      proxyUrl(`${url}/api/v1/approvals/${encodeURIComponent(requestId)}/resolve`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify({
          decision,
          scope: opts?.scope,
          reason: opts?.reason,
          decided_by: "workbench-user",
        }),
      },
    );
    return { success: true };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function fetchDelegationGraphFromApi(
  conn: FleetConnection,
): Promise<DelegationGraph | null> {
  if (!conn.controlApiUrl) return null;
  try {
    const url = normalizedValidatedFleetUrl(conn.controlApiUrl, "control API URL");
    const grants = await jsonFetch<unknown[]>(proxyUrl(`${url}/api/v1/grants`, "control"), {
      headers: controlHeaders(conn),
    });
    // Validate grant shape before processing
    const validGrants = (grants as unknown[]).filter((g): g is Record<string, unknown> => {
      if (!g || typeof g !== "object") return false;
      const obj = g as Record<string, unknown>;
      return typeof obj.id === "string"
        && typeof obj.issuer_principal_id === "string"
        && typeof obj.subject_principal_id === "string";
    });
    return validGrants.length > 0 ? grantsToGraph(validGrants) : null;
  } catch (e) {
    console.warn("[fleet-client] Failed to fetch delegation graph:", e);
    return null;
  }
}

/** Known NodeKind values the frontend recognizes. */
const KNOWN_NODE_KINDS = new Set<string>([
  "Principal", "Session", "Grant", "Approval", "Event", "ResponseAction",
]);

/** Known TrustLevel values the frontend recognizes. */
const KNOWN_TRUST_LEVELS = new Set<string>([
  "Untrusted", "Low", "Medium", "High", "System",
]);

/** Known EdgeKind values the frontend recognizes. */
const KNOWN_EDGE_KINDS = new Set<string>([
  "IssuedGrant", "ReceivedGrant", "DerivedFromGrant", "SpawnedPrincipal",
  "ApprovedBy", "RevokedBy", "ExercisedInSession", "ExercisedInEvent",
  "TriggeredResponseAction",
]);

/** Known Capability values the frontend recognizes. */
const KNOWN_CAPABILITIES = new Set<string>([
  "FileRead", "FileWrite", "NetworkEgress", "CommandExec", "SecretAccess",
  "McpTool", "DeployApproval", "AgentAdmin", "Custom",
]);

function mapNodeKind(kind: string): NodeKind {
  return KNOWN_NODE_KINDS.has(kind) ? (kind as NodeKind) : "Principal";
}

function mapTrustLevel(level: string | undefined): TrustLevel | undefined {
  if (!level) return undefined;
  return KNOWN_TRUST_LEVELS.has(level) ? (level as TrustLevel) : undefined;
}

function mapEdgeKind(kind: string): EdgeKind {
  return KNOWN_EDGE_KINDS.has(kind) ? (kind as EdgeKind) : "IssuedGrant";
}

function mapCapabilities(caps: string[] | undefined): Capability[] | undefined {
  if (!caps || caps.length === 0) return undefined;
  return caps
    .filter((c) => KNOWN_CAPABILITIES.has(c))
    .map((c) => c as Capability);
}

/**
 * Map a backend delegation graph response to frontend DelegationGraph types.
 * Gracefully coerces unknown `kind` / `trust_level` values to safe defaults.
 */
function mapBackendGraphToFrontend(backend: BackendDelegationGraphResponse): DelegationGraph {
  const nodes: DelegationNode[] = backend.nodes.map((n) => ({
    id: n.id,
    kind: mapNodeKind(n.kind),
    label: n.label ?? n.id,
    role: n.role as DelegationNode["role"],
    trustLevel: mapTrustLevel(n.trust_level),
    capabilities: mapCapabilities(n.capabilities),
    metadata: n.metadata ?? {},
  }));

  const edges: DelegationEdge[] = backend.edges.map((e) => ({
    id: e.id,
    from: e.from,
    to: e.to,
    kind: mapEdgeKind(e.kind),
    capabilities: mapCapabilities(e.capabilities),
    metadata: e.metadata,
  }));

  return { nodes, edges };
}

/**
 * Fetch a full delegation graph snapshot for a given principal from the backend.
 * Calls GET /api/v1/principals/{id}/delegation-graph on the control API.
 * Falls back to the grants-based graph if the direct delegation-graph route
 * is not exposed by the current deployment.
 */
export async function fetchDelegationGraphSnapshot(
  conn: FleetConnection,
  principalId: string,
): Promise<DelegationGraph | null> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return null;

  try {
    const res = await jsonFetch<BackendDelegationGraphResponse>(
      proxyUrl(`${url}/api/v1/principals/${encodeURIComponent(principalId)}/delegation-graph`, kind),
      { headers: controlHeaders(conn) },
    );
    // Runtime validation
    if (!res || !Array.isArray(res.nodes) || !Array.isArray(res.edges)) {
      throw new Error("[fleet-client] fetchDelegationGraphSnapshot: unexpected response shape");
    }
    const graph = mapBackendGraphToFrontend(res);
    return graph.nodes.length > 0 ? graph : null;
  } catch (e) {
    console.warn("[fleet-client] delegation-graph endpoint unavailable, falling back to grants:", e);
    // Fallback to the alternate grants-based graph path.
    return fetchDelegationGraphFromApi(conn);
  }
}

/**
 * List available principals from the control API.
 * Prefers the console principals endpoint and falls back to GET
 * /api/v1/principals when that route is the one exposed by the deployment.
 */
export async function fetchPrincipals(
  conn: FleetConnection,
): Promise<PrincipalInfo[]> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return [];

  const principalPaths = [
    `${url}/api/v1/console/principals`,
    `${url}/api/v1/principals`,
  ];

  for (const path of principalPaths) {
    try {
      const res = await jsonFetch<unknown>(proxyUrl(path, kind), {
        headers: controlHeaders(conn),
      });
      const list = extractPrincipalList(res);
      if (list.length > 0) {
        return list;
      }
    } catch (e) {
      console.warn(`[fleet-client] fetchPrincipals failed for ${path}:`, e);
    }
  }

  return [];
}

function mapPrincipalInfo(value: unknown): PrincipalInfo | null {
  if (!isRecord(value)) return null;

  const directId = readString(value.id);
  if (directId) {
    return {
      id: directId,
      name: readString(value.name),
      kind: readString(value.kind),
      role: readString(value.role),
      trust_level: readString(value.trust_level),
      capabilities: readStringArray(value.capabilities),
      metadata: isRecord(value.metadata) ? value.metadata : undefined,
      created_at: readString(value.created_at),
      updated_at: readString(value.updated_at),
    };
  }

  const consoleId = readString(value.principalId);
  if (!consoleId) return null;

  const principalType = readString(value.principalType);
  return {
    id: consoleId,
    name: readString(value.displayName) ?? readString(value.stableRef) ?? consoleId,
    kind: principalType,
    role: principalType,
    trust_level: readString(value.trustLevel),
    capabilities: readStringArray(value.capabilityGroupNames),
    metadata: {
      lifecycle_state: readString(value.lifecycleState),
      liveness_state: readString(value.livenessState),
      endpoint_posture: readString(value.endpointPosture),
      stable_ref: readString(value.stableRef),
    },
    updated_at: readString(value.lastHeartbeatAt),
  };
}

function extractPrincipalList(res: unknown): PrincipalInfo[] {
  let list: unknown[];
  if (Array.isArray(res)) {
    list = res;
  } else if (isRecord(res) && "principals" in res && Array.isArray(res.principals)) {
    list = res.principals;
  } else {
    throw new Error("[fleet-client] fetchPrincipals: unexpected response shape");
  }

  return list
    .map(mapPrincipalInfo)
    .filter((principal): principal is PrincipalInfo => principal !== null);
}

// ---------------------------------------------------------------------------
// Scoped Policies & Policy Assignments (P2-3: Hierarchy sync)
// ---------------------------------------------------------------------------

/**
 * A scoped policy as stored in the backend.
 * Represents a policy bound to a scope within the org hierarchy.
 */
export interface ScopedPolicy {
  id: string;
  scope_type: "org" | "team" | "agent";
  scope_id: string;
  scope_name: string;
  policy_yaml: string;
  policy_name?: string;
  parent_scope_id?: string | null;
  metadata?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
}

/**
 * Input shape for creating a new scoped policy.
 */
export interface ScopedPolicyInput {
  scope_type: "org" | "team" | "agent";
  scope_id: string;
  scope_name: string;
  policy_yaml: string;
  policy_name?: string;
  parent_scope_id?: string | null;
  metadata?: Record<string, unknown>;
}

/**
 * A policy assignment linking a scope node to a specific policy.
 */
export interface PolicyAssignment {
  id: string;
  scope_id: string;
  scope_name: string;
  scope_type: "org" | "team" | "agent";
  policy_id?: string;
  policy_name?: string;
  parent_scope_id?: string | null;
  children?: string[];
  created_at?: string;
}

/**
 * Input shape for creating a policy assignment.
 */
export interface PolicyAssignmentInput {
  scope_id: string;
  scope_name: string;
  scope_type: "org" | "team" | "agent";
  policy_id?: string;
  policy_name?: string;
  parent_scope_id?: string | null;
  children?: string[];
}

/**
 * Fetch all scoped policies from the backend.
 * Calls GET /api/v1/scoped-policies on the preferred (control-api or hushd) endpoint.
 */
export async function fetchScopedPolicies(
  conn: FleetConnection,
): Promise<ScopedPolicy[]> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return [];

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/scoped-policies`, kind),
      { headers: controlHeaders(conn) },
    );

    // Handle wrapped or bare array responses
    let list: unknown[];
    if (Array.isArray(res)) {
      list = res;
    } else if (res && typeof res === "object" && "scoped_policies" in res) {
      const wrapped = res as { scoped_policies: unknown };
      if (!Array.isArray(wrapped.scoped_policies)) {
        throw new Error("[fleet-client] fetchScopedPolicies: expected scoped_policies to be an array");
      }
      list = wrapped.scoped_policies;
    } else if (res && typeof res === "object" && "policies" in res) {
      const wrapped = res as { policies: unknown };
      if (!Array.isArray(wrapped.policies)) {
        throw new Error("[fleet-client] fetchScopedPolicies: expected policies to be an array");
      }
      list = wrapped.policies;
    } else {
      throw new Error("[fleet-client] fetchScopedPolicies: unexpected response shape");
    }

    return list.filter((p): p is ScopedPolicy => {
      if (!p || typeof p !== "object") return false;
      const obj = p as Record<string, unknown>;
      return typeof obj.id === "string" && typeof obj.scope_id === "string";
    });
  } catch (e) {
    console.warn("[fleet-client] fetchScopedPolicies failed:", e);
    return [];
  }
}

/**
 * Create a new scoped policy on the backend.
 * Calls POST /api/v1/scoped-policies.
 */
export async function createScopedPolicy(
  conn: FleetConnection,
  policy: ScopedPolicyInput,
): Promise<{ success: boolean; id?: string; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    const res = await jsonFetch<{ id?: string; success?: boolean }>(
      proxyUrl(`${url}/api/v1/scoped-policies`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify(policy),
      },
    );
    return { success: true, id: res.id };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Fetch all policy assignments from the backend.
 * Calls GET /api/v1/policy-assignments on the preferred endpoint.
 */
export async function fetchPolicyAssignments(
  conn: FleetConnection,
): Promise<PolicyAssignment[]> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return [];

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/policy-assignments`, kind),
      { headers: controlHeaders(conn) },
    );

    let list: unknown[];
    if (Array.isArray(res)) {
      list = res;
    } else if (res && typeof res === "object" && "assignments" in res) {
      const wrapped = res as { assignments: unknown };
      if (!Array.isArray(wrapped.assignments)) {
        throw new Error("[fleet-client] fetchPolicyAssignments: expected assignments to be an array");
      }
      list = wrapped.assignments;
    } else {
      throw new Error("[fleet-client] fetchPolicyAssignments: unexpected response shape");
    }

    return list.filter((a): a is PolicyAssignment => {
      if (!a || typeof a !== "object") return false;
      const obj = a as Record<string, unknown>;
      return typeof obj.id === "string" && typeof obj.scope_id === "string";
    });
  } catch (e) {
    console.warn("[fleet-client] fetchPolicyAssignments failed:", e);
    return [];
  }
}

/**
 * Create a policy assignment on the backend.
 * Calls POST /api/v1/policy-assignments.
 */
export async function assignPolicyToScope(
  conn: FleetConnection,
  assignment: PolicyAssignmentInput,
): Promise<{ success: boolean; id?: string; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    const res = await jsonFetch<{ id?: string; success?: boolean }>(
      proxyUrl(`${url}/api/v1/policy-assignments`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify(assignment),
      },
    );
    return { success: true, id: res.id };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

// ---------------------------------------------------------------------------
// Grants → DelegationGraph conversion
// ---------------------------------------------------------------------------

function grantsToGraph(grants: Record<string, unknown>[]): DelegationGraph {
  const nodesMap = new Map<string, DelegationNode>();
  const edges: DelegationEdge[] = [];

  for (const g of grants) {
    for (const pid of [g.issuer_principal_id as string, g.subject_principal_id as string]) {
      if (!nodesMap.has(pid)) {
        nodesMap.set(pid, { id: pid, kind: "Principal", label: pid, metadata: {} });
      }
    }

    const grantId = `grant-${g.id as string}`;
    nodesMap.set(grantId, {
      id: grantId,
      kind: "Grant",
      label: (g.grant_type as string) || "delegation",
      metadata: {
        depth: g.delegation_depth,
        status: g.status,
        purpose: g.purpose,
        capabilities: g.capabilities,
      },
    });
    edges.push({
      id: `edge-issued-${g.id as string}`,
      from: g.issuer_principal_id as string,
      to: grantId,
      kind: "IssuedGrant",
    });
    edges.push({
      id: `edge-received-${g.id as string}`,
      from: grantId,
      to: g.subject_principal_id as string,
      kind: "ReceivedGrant",
    });
  }

  return {
    nodes: Array.from(nodesMap.values()),
    edges,
  };
}

// ---------------------------------------------------------------------------
// Receipt Store (P3-4: Fleet Receipt Store)
// ---------------------------------------------------------------------------

/**
 * Backend receipt shape as stored by the control-api receipt endpoints.
 * The wire format uses snake_case; the frontend Receipt type uses camelCase.
 */
export interface FleetReceipt {
  id: string;
  timestamp: string;
  verdict: string;
  guard: string;
  policy_name: string;
  evidence?: Record<string, unknown>;
  signature: string;
  public_key: string;
  chain_hash?: string;
  metadata?: Record<string, unknown>;
  signed_receipt?: Record<string, unknown>;
  action_type?: string;
  action_target?: string;
  valid?: boolean;
}

export interface FleetReceiptListResponse {
  receipts: FleetReceipt[];
  total: number;
  offset: number;
  limit: number;
}

export interface FleetReceiptVerifyResponse {
  receipt_id: string;
  valid: boolean;
  signer_valid?: boolean;
  errors?: string[];
  reason?: string;
  verified_at: string;
}

interface StoreReceiptPayload {
  timestamp: string;
  verdict: string;
  guard: string;
  policy_name: string;
  signature: string;
  public_key: string;
  chain_hash?: string;
  evidence?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  signed_receipt?: Record<string, unknown>;
}

/**
 * Fetch paginated receipts from the backend receipt store.
 * Calls GET /api/v1/receipts on the control-api.
 */
export async function fetchReceipts(
  conn: FleetConnection,
  opts?: { offset?: number; limit?: number },
): Promise<FleetReceiptListResponse> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { receipts: [], total: 0, offset: 0, limit: 50 };

  const params = new URLSearchParams();
  if (opts?.offset != null) params.set("offset", String(opts.offset));
  if (opts?.limit != null) params.set("limit", String(opts.limit));
  const qs = params.toString();
  const endpoint = `${url}/api/v1/receipts${qs ? `?${qs}` : ""}`;

  const res = await jsonFetch<unknown>(
    proxyUrl(endpoint, kind),
    { headers: controlHeaders(conn) },
  );

  // Handle response shapes: { items, total, offset, limit }, { receipts, ... }, or bare array.
  if (Array.isArray(res)) {
    const receipts = res.filter(isFleetReceipt);
    return { receipts, total: receipts.length, offset: opts?.offset ?? 0, limit: opts?.limit ?? 50 };
  }
  if (res && typeof res === "object") {
    const obj = res as Record<string, unknown>;
    const items =
      "items" in obj && Array.isArray(obj.items)
        ? obj.items
        : "receipts" in obj && Array.isArray(obj.receipts)
          ? obj.receipts
          : null;
    if (items) {
      return {
        receipts: items.filter(isFleetReceipt),
        total: typeof obj.total === "number" ? obj.total : items.length,
        offset: typeof obj.offset === "number" ? obj.offset : (opts?.offset ?? 0),
        limit: typeof obj.limit === "number" ? obj.limit : (opts?.limit ?? 50),
      };
    }
  }

  throw new Error("[fleet-client] fetchReceipts: unexpected response shape");
}

/**
 * Store a single receipt on the fleet backend.
 * Calls POST /api/v1/receipts on the control-api.
 */
export async function storeReceipt(
  conn: FleetConnection,
  receipt: FleetReceipt,
): Promise<{ success: boolean; id?: string; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/receipts`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify(toStoreReceiptPayload(receipt)),
      },
    );
    const storedId =
      res && typeof res === "object" && typeof (res as Record<string, unknown>).id === "string"
        ? ((res as Record<string, unknown>).id as string)
        : receipt.id;
    return { success: true, id: storedId };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Batch-store receipts on the fleet backend.
 * Calls POST /api/v1/receipts/batch on the control-api.
 */
export async function storeReceiptsBatch(
  conn: FleetConnection,
  receipts: FleetReceipt[],
): Promise<{ success: boolean; stored: number; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, stored: 0, error: "No API URL configured" };

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/receipts/batch`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify({ receipts: receipts.map(toStoreReceiptPayload) }),
      },
    );
    const response = res as Record<string, unknown>;
    const storedCount =
      typeof response?.count === "number"
        ? response.count
        : Array.isArray(response?.stored)
          ? response.stored.length
          : receipts.length;
    return { success: true, stored: storedCount };
  } catch (err) {
    return {
      success: false,
      stored: 0,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Fetch the receipt chain for a given policy name.
 * Calls GET /api/v1/receipts/chain/{policy_name} on the control-api.
 */
export async function fetchReceiptChain(
  conn: FleetConnection,
  policyName: string,
): Promise<FleetReceipt[]> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return [];

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/receipts/chain/${encodeURIComponent(policyName)}`, kind),
      { headers: controlHeaders(conn) },
    );

    // Handle array, PaginatedResponse { items }, or wrapped { receipts } response
    if (Array.isArray(res)) {
      return res.filter(isFleetReceipt);
    }
    if (res && typeof res === "object") {
      const obj = res as Record<string, unknown>;
      const items =
        "items" in obj && Array.isArray(obj.items)
          ? obj.items
          : "receipts" in obj && Array.isArray(obj.receipts)
            ? obj.receipts
            : null;
      if (items) {
        return (items as unknown[]).filter(isFleetReceipt);
      }
    }
    throw new Error("[fleet-client] fetchReceiptChain: unexpected response shape");
  } catch (e) {
    console.warn("[fleet-client] fetchReceiptChain failed:", e);
    return [];
  }
}

/**
 * Verify a receipt server-side.
 * Calls POST /api/v1/receipts/{id}/verify on the control-api.
 */
export async function verifyReceiptRemote(
  conn: FleetConnection,
  receiptId: string,
): Promise<FleetReceiptVerifyResponse> {
  const { url, kind } = preferredUrl(conn);
  if (!url) throw new Error("No API URL configured");

  const res = await jsonFetch<unknown>(
    proxyUrl(`${url}/api/v1/receipts/${encodeURIComponent(receiptId)}/verify`, kind),
    {
      method: "POST",
      headers: controlHeaders(conn),
      body: JSON.stringify({}),
    },
  );

  if (!res || typeof res !== "object") {
    throw new Error("[fleet-client] verifyReceiptRemote: unexpected response shape");
  }

  const obj = res as Record<string, unknown>;
  const errors = Array.isArray(obj.errors)
    ? obj.errors.filter((value): value is string => typeof value === "string")
    : [];
  const valid = typeof obj.valid === "boolean" ? obj.valid : false;
  const signerValid = typeof obj.signer_valid === "boolean" ? obj.signer_valid : valid;

  return {
    receipt_id: typeof obj.receipt_id === "string" ? obj.receipt_id : receiptId,
    valid,
    signer_valid: signerValid,
    errors,
    reason: errors.length > 0 ? errors.join("; ") : undefined,
    verified_at: new Date().toISOString(),
  };
}

/** Type guard for FleetReceipt shape. */
function isFleetReceipt(value: unknown): value is FleetReceipt {
  if (!value || typeof value !== "object") return false;
  const obj = value as Record<string, unknown>;
  return (
    typeof obj.id === "string" &&
    typeof obj.timestamp === "string" &&
    typeof obj.verdict === "string" &&
    typeof obj.guard === "string" &&
    typeof obj.policy_name === "string" &&
    typeof obj.signature === "string" &&
    typeof obj.public_key === "string"
  );
}

function toStoreReceiptPayload(receipt: FleetReceipt): StoreReceiptPayload {
  const metadata: Record<string, unknown> = { ...(receipt.metadata ?? {}) };
  const signedReceipt =
    receipt.signed_receipt ??
    (receipt.evidence?.signed_receipt &&
    typeof receipt.evidence.signed_receipt === "object" &&
    !Array.isArray(receipt.evidence.signed_receipt)
      ? (receipt.evidence.signed_receipt as Record<string, unknown>)
      : undefined);

  metadata.client_receipt_id = receipt.id;
  if (receipt.action_type) metadata.action_type = receipt.action_type;
  if (receipt.action_target) metadata.action_target = receipt.action_target;
  if (typeof receipt.valid === "boolean") metadata.valid = receipt.valid;

  const payload: StoreReceiptPayload = {
    timestamp: receipt.timestamp,
    verdict: receipt.verdict,
    guard: receipt.guard,
    policy_name: receipt.policy_name,
    signature: receipt.signature,
    public_key: receipt.public_key,
  };

  if (receipt.chain_hash) payload.chain_hash = receipt.chain_hash;
  if (receipt.evidence) payload.evidence = receipt.evidence;
  if (Object.keys(metadata).length > 0) payload.metadata = metadata;
  if (signedReceipt) payload.signed_receipt = signedReceipt;

  return payload;
}

// ---------------------------------------------------------------------------
// Catalog Registry (P3-6: Live Catalog)
// ---------------------------------------------------------------------------

/**
 * A catalog template as returned by the control-api catalog endpoints.
 * Wire format uses snake_case.
 */
export interface CatalogTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  tags: string[];
  author: string;
  version: string;
  yaml: string;
  guard_summary: string[];
  use_cases: string[];
  compliance: string[];
  difficulty: string;
  downloads: number;
  created_at: string;
  updated_at: string;
  metadata?: Record<string, unknown>;
}

/**
 * A catalog category as returned by GET /api/v1/catalog/categories.
 */
export interface CatalogCategoryInfo {
  id: string;
  label: string;
  color: string;
  count: number;
}

/**
 * Fetch catalog templates from the backend, optionally filtered by category or tag.
 * Calls GET /api/v1/catalog/templates on the control-api.
 */
export async function fetchCatalogTemplates(
  conn: FleetConnection,
  opts?: { category?: string; tag?: string },
): Promise<CatalogTemplate[]> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return [];

  const params = new URLSearchParams();
  if (opts?.category) params.set("category", opts.category);
  if (opts?.tag) params.set("tag", opts.tag);
  const qs = params.toString();
  const endpoint = `${url}/api/v1/catalog/templates${qs ? `?${qs}` : ""}`;

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(endpoint, kind),
      { headers: controlHeaders(conn) },
    );

    // Handle wrapped or bare array responses
    let list: unknown[];
    if (Array.isArray(res)) {
      list = res;
    } else if (res && typeof res === "object" && "templates" in res) {
      const wrapped = res as { templates: unknown };
      if (!Array.isArray(wrapped.templates)) {
        throw new Error("[fleet-client] fetchCatalogTemplates: expected templates to be an array");
      }
      list = wrapped.templates;
    } else {
      throw new Error("[fleet-client] fetchCatalogTemplates: unexpected response shape");
    }

    return list.map(toCatalogTemplate);
  } catch (e) {
    throw normalizeCatalogFetchError(e);
  }
}

/**
 * Fetch a single catalog template by ID.
 * Calls GET /api/v1/catalog/templates/{id} on the control-api.
 */
export async function fetchCatalogTemplate(
  conn: FleetConnection,
  id: string,
): Promise<CatalogTemplate | null> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return null;

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/catalog/templates/${encodeURIComponent(id)}`, kind),
      { headers: controlHeaders(conn) },
    );

    if (isRecord(res) && "template" in res) {
      return toCatalogTemplate(res.template);
    }
    return toCatalogTemplate(res);
  } catch (e) {
    console.warn("[fleet-client] fetchCatalogTemplate failed:", e);
    return null;
  }
}

/**
 * Publish a new template to the catalog.
 * Calls POST /api/v1/catalog/templates on the control-api.
 */
export async function publishCatalogTemplate(
  conn: FleetConnection,
  template: {
    name: string;
    description: string;
    category: string;
    tags: string[];
    yaml: string;
    difficulty?: string;
  },
): Promise<{ success: boolean; id?: string; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    const [policy] = yamlToPolicy(template.yaml);
    const res = await jsonFetch<{ id?: string; success?: boolean }>(
      proxyUrl(`${url}/api/v1/catalog/templates`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify({
          name: template.name,
          description: template.description,
          category: template.category,
          tags: normalizeCatalogTags(template.tags, template.difficulty),
          policy_yaml: template.yaml,
          version: policy?.version,
        }),
      },
    );
    return { success: true, id: res.id };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Fork a catalog template to create a personal copy.
 * Calls POST /api/v1/catalog/templates/{id}/fork on the control-api.
 */
export async function forkCatalogTemplate(
  conn: FleetConnection,
  id: string,
): Promise<{ success: boolean; template?: CatalogTemplate; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/catalog/templates/${encodeURIComponent(id)}/fork`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
      },
    );

    if (isRecord(res) && "template" in res) {
      return { success: true, template: toCatalogTemplate(res.template) };
    }
    return { success: true, template: toCatalogTemplate(res) };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Fetch available catalog categories.
 * Calls GET /api/v1/catalog/categories on the control-api.
 */
export async function fetchCatalogCategories(
  conn: FleetConnection,
): Promise<CatalogCategoryInfo[]> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return [];

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/catalog/categories`, kind),
      { headers: controlHeaders(conn) },
    );

    let list: unknown[];
    if (Array.isArray(res)) {
      list = res;
    } else if (res && typeof res === "object" && "categories" in res) {
      const wrapped = res as { categories: unknown };
      if (!Array.isArray(wrapped.categories)) {
        throw new Error("[fleet-client] fetchCatalogCategories: expected categories to be an array");
      }
      list = wrapped.categories;
    } else {
      throw new Error("[fleet-client] fetchCatalogCategories: unexpected response shape");
    }

    return list.map(toCatalogCategory);
  } catch (e) {
    throw normalizeCatalogFetchError(e);
  }
}

// ---------------------------------------------------------------------------
// Hierarchy CRUD API (P3-2: Fleet Hierarchy Sync)
// ---------------------------------------------------------------------------

/**
 * Backend hierarchy node as returned by the control-api hierarchy endpoints.
 * Uses snake_case wire format. Depending on the endpoint, `children` may be
 * nested nodes or a list of child ids.
 */
export type HierarchyNodeChild = HierarchyNode | string;

export interface HierarchyNode {
  id: string;
  name: string;
  node_type: string; // "org" | "team" | "project" | "agent"
  parent_id?: string | null;
  policy_id?: string | null;
  policy_name?: string | null;
  children?: HierarchyNodeChild[];
  metadata?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
}

/**
 * Input shape for creating a new hierarchy node via POST /api/v1/hierarchy/nodes.
 */
export interface HierarchyNodeInput {
  name: string;
  node_type: string;
  parent_id?: string | null;
  policy_id?: string | null;
  policy_name?: string | null;
  metadata?: Record<string, unknown>;
}

/**
 * Input shape for updating an existing hierarchy node via PUT /api/v1/hierarchy/nodes/{id}.
 */
export interface HierarchyNodeUpdate {
  name?: string;
  node_type?: string;
  parent_id?: string | null;
  policy_id?: string | null;
  policy_name?: string | null;
  metadata?: Record<string, unknown>;
}

/**
 * Full hierarchy tree response from GET /api/v1/hierarchy/tree.
 */
export interface HierarchyTreeResponse {
  root_id: string | null;
  nodes: HierarchyNode[];
}

/**
 * Fetch all hierarchy nodes from the backend (flat list).
 * Calls GET /api/v1/hierarchy/nodes on the control-api.
 */
export async function fetchHierarchyNodes(
  conn: FleetConnection,
): Promise<HierarchyNode[]> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return [];

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/hierarchy/nodes`, kind),
      { headers: controlHeaders(conn) },
    );

    // Handle wrapped or bare array responses
    let list: unknown[];
    if (Array.isArray(res)) {
      list = res;
    } else if (res && typeof res === "object" && "nodes" in res) {
      const wrapped = res as { nodes: unknown };
      if (!Array.isArray(wrapped.nodes)) {
        throw new Error("[fleet-client] fetchHierarchyNodes: expected nodes to be an array");
      }
      list = wrapped.nodes;
    } else {
      throw new Error("[fleet-client] fetchHierarchyNodes: unexpected response shape");
    }

    return list.filter(isHierarchyNode);
  } catch (e) {
    console.warn("[fleet-client] fetchHierarchyNodes failed:", e);
    return [];
  }
}

/**
 * Fetch the full hierarchy tree from the backend.
 * Calls GET /api/v1/hierarchy/tree on the control-api.
 */
export async function fetchHierarchyTree(
  conn: FleetConnection,
): Promise<HierarchyTreeResponse | null> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return null;

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/hierarchy/tree`, kind),
      { headers: controlHeaders(conn) },
    );

    if (!res || typeof res !== "object") {
      throw new Error("[fleet-client] fetchHierarchyTree: unexpected response shape");
    }

    const obj = res as Record<string, unknown>;
    const rootId = obj.root_id;
    if (
      (typeof rootId !== "string" && rootId !== null) ||
      !Array.isArray(obj.nodes)
    ) {
      throw new Error("[fleet-client] fetchHierarchyTree: expected { root_id, nodes }");
    }

    return {
      root_id: rootId,
      nodes: (obj.nodes as unknown[]).filter(isHierarchyNode),
    };
  } catch (e) {
    console.warn("[fleet-client] fetchHierarchyTree failed:", e);
    return null;
  }
}

/**
 * Create a new hierarchy node on the backend.
 * Calls POST /api/v1/hierarchy/nodes on the control-api.
 */
export async function createHierarchyNode(
  conn: FleetConnection,
  node: HierarchyNodeInput,
): Promise<{ success: boolean; id?: string; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    const res = await jsonFetch<{ id?: string; success?: boolean }>(
      proxyUrl(`${url}/api/v1/hierarchy/nodes`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify(node),
      },
    );
    return { success: true, id: res.id };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Update an existing hierarchy node on the backend.
 * Calls PUT /api/v1/hierarchy/nodes/{id} on the control-api.
 */
export async function updateHierarchyNode(
  conn: FleetConnection,
  id: string,
  updates: HierarchyNodeUpdate,
): Promise<{ success: boolean; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    await jsonFetch<{ success?: boolean }>(
      proxyUrl(`${url}/api/v1/hierarchy/nodes/${encodeURIComponent(id)}`, kind),
      {
        method: "PUT",
        headers: controlHeaders(conn),
        body: JSON.stringify(updates),
      },
    );
    return { success: true };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Delete a hierarchy node from the backend.
 * Calls DELETE /api/v1/hierarchy/nodes/{id}?reparent=true|false on the control-api.
 * When reparent=true, children are moved to the deleted node's parent.
 * When reparent=false, all descendants are also deleted.
 */
export async function deleteHierarchyNode(
  conn: FleetConnection,
  id: string,
  reparent: boolean = false,
): Promise<{ success: boolean; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    const endpoint = `${url}/api/v1/hierarchy/nodes/${encodeURIComponent(id)}?reparent=${reparent}`;
    await jsonFetch<{ success?: boolean }>(
      proxyUrl(endpoint, kind),
      {
        method: "DELETE",
        headers: controlHeaders(conn),
      },
    );
    return { success: true };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/** Type guard for HierarchyNode shape. */
function isHierarchyNode(value: unknown): value is HierarchyNode {
  if (!value || typeof value !== "object") return false;
  const obj = value as Record<string, unknown>;
  return typeof obj.id === "string" && typeof obj.name === "string" && typeof obj.node_type === "string";
}

// ---------------------------------------------------------------------------
// Convenience client (reads saved credentials from secureStore + localStorage)
// ---------------------------------------------------------------------------

async function savedConnectionAsync(): Promise<FleetConnection> {
  const saved = await loadSavedConnectionAsync();
  return {
    hushdUrl: saved.hushdUrl ?? "",
    controlApiUrl: saved.controlApiUrl ?? "",
    apiKey: saved.apiKey ?? "",
    controlApiToken: saved.controlApiToken ?? "",
    connected: false,
    hushdHealth: null,
    agentCount: 0,
  };
}

export const fleetClient = {
  async healthCheck(): Promise<boolean> {
    const conn = await savedConnectionAsync();
    if (!conn.hushdUrl) return false;
    try {
      await testConnection(conn.hushdUrl, conn.apiKey);
      return true;
    } catch (e) {
      console.warn("[fleet-client] healthCheck failed:", e);
      return false;
    }
  },

  async fetchDelegationGraph(): Promise<DelegationGraph | null> {
    const conn = await savedConnectionAsync();
    return conn.controlApiUrl ? fetchDelegationGraphFromApi(conn) : null;
  },

  async fetchDelegationGraphSnapshot(principalId: string): Promise<DelegationGraph | null> {
    const conn = await savedConnectionAsync();
    return fetchDelegationGraphSnapshot(conn, principalId);
  },

  async fetchPrincipals(): Promise<PrincipalInfo[]> {
    const conn = await savedConnectionAsync();
    return fetchPrincipals(conn);
  },

  async fetchApprovals(): Promise<{ requests: ApprovalRequest[]; decisions: ApprovalDecision[] } | null> {
    const conn = await savedConnectionAsync();
    if (!conn.controlApiUrl && !conn.hushdUrl) return null;
    try {
      return await fetchApprovals(conn);
    } catch (e) {
      console.warn("[fleet-client] fetchApprovals failed:", e);
      return null;
    }
  },

  async resolveApproval(
    requestId: string,
    decision: "approved" | "denied",
    opts?: { scope?: ApprovalScope; reason?: string },
  ): Promise<{ success: boolean; error?: string }> {
    const conn = await savedConnectionAsync();
    return resolveApproval(conn, requestId, decision, opts);
  },
};
