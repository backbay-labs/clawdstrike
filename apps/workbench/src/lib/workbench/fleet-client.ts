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

const DEV = import.meta.env.DEV;

/** Rewrite absolute URLs to Vite dev proxy paths; passthrough in production. */
function proxyUrl(absoluteUrl: string, kind: "hushd" | "control"): string {
  if (!DEV) return absoluteUrl;
  try {
    const u = new URL(absoluteUrl);
    return `/_proxy/${kind}${u.pathname}${u.search}`;
  } catch (e) {
    console.warn("[fleet-client] URL parse failed for proxy rewrite:", e);
    return absoluteUrl;
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
 * Synchronous bootstrap read from localStorage (legacy).
 * Used for initial render before Stronghold is ready.
 */
export function loadSavedConnection(): Partial<FleetConnection> {
  try {
    return {
      hushdUrl: localStorage.getItem(LS_HUSHD_URL) ?? "",
      controlApiUrl: localStorage.getItem(LS_CONTROL_API_URL) ?? "",
      apiKey: localStorage.getItem(LS_API_KEY) ?? "",
      controlApiToken: localStorage.getItem(LS_CONTROL_TOKEN) ?? "",
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
  try {
    const [hushdUrl, controlApiUrl, apiKey, controlApiToken] = await Promise.all([
      secureStore.get(SS_HUSHD_URL),
      secureStore.get(SS_CONTROL_API_URL),
      secureStore.get(SS_API_KEY),
      secureStore.get(SS_CONTROL_TOKEN),
    ]);

    // If Stronghold had values, use them. Otherwise fall back to localStorage.
    if (hushdUrl || apiKey) {
      return {
        hushdUrl: hushdUrl ?? "",
        controlApiUrl: controlApiUrl ?? "",
        apiKey: apiKey ?? "",
        controlApiToken: controlApiToken ?? "",
      };
    }
  } catch (e) {
    console.warn("[fleet-client] secureStore read failed, using localStorage:", e);
  }

  return loadSavedConnection();
}

/**
 * Save connection config to secureStore (Stronghold on desktop).
 * Also writes to localStorage as a sync-readable cache for initial render.
 */
export function saveConnectionConfig(config: {
  hushdUrl: string;
  controlApiUrl: string;
  apiKey: string;
  controlApiToken: string;
}) {
  // Write to secureStore (async, fire-and-forget).
  secureStore.set(SS_HUSHD_URL, config.hushdUrl).catch(() => {});
  secureStore.set(SS_CONTROL_API_URL, config.controlApiUrl).catch(() => {});
  secureStore.set(SS_API_KEY, config.apiKey).catch(() => {});
  secureStore.set(SS_CONTROL_TOKEN, config.controlApiToken).catch(() => {});

  // Also keep localStorage as sync-readable fallback for initial render.
  try {
    localStorage.setItem(LS_HUSHD_URL, config.hushdUrl);
    localStorage.setItem(LS_CONTROL_API_URL, config.controlApiUrl);
    localStorage.setItem(LS_API_KEY, config.apiKey);
    localStorage.setItem(LS_CONTROL_TOKEN, config.controlApiToken);
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

  try {
    localStorage.removeItem(LS_HUSHD_URL);
    localStorage.removeItem(LS_CONTROL_API_URL);
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

function controlHeaders(conn: FleetConnection): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  const token = conn.controlApiToken || conn.apiKey;
  if (token) h["Authorization"] = `Bearer ${token}`;
  return h;
}

async function jsonFetch<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await httpFetch(url, { ...init, signal: init?.signal ?? AbortSignal.timeout(10_000) });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(body || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// API functions
// ---------------------------------------------------------------------------

function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

export async function testConnection(
  hushdUrl: string,
  apiKey: string,
): Promise<HealthResponse> {
  const url = stripTrailingSlash(hushdUrl);
  return jsonFetch<HealthResponse>(proxyUrl(`${url}/health`, "hushd"), {
    headers: hushdHeaders(apiKey),
  });
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
    const ctrlUrl = stripTrailingSlash(conn.controlApiUrl);
    const res = await jsonFetch<unknown>(proxyUrl(`${ctrlUrl}/api/v1/agents`, "control"), {
      headers: controlHeaders(conn),
    });
    // Runtime validation: ensure response is an array (#18)
    if (!Array.isArray(res)) {
      throw new Error("[fleet-client] fetchAgentList: expected response to be an array");
    }
    return res as AgentInfo[];
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
  const ctrlUrl = stripTrailingSlash(conn.controlApiUrl);
  try {
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
    return { url: stripTrailingSlash(conn.controlApiUrl), kind: "control" };
  }
  return { url: stripTrailingSlash(conn.hushdUrl), kind: "hushd" };
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
  const url = stripTrailingSlash(conn.controlApiUrl);
  try {
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
 * Falls back to the grants-based graph if the endpoint is unavailable.
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
    // Fallback to the older grants-based approach
    return fetchDelegationGraphFromApi(conn);
  }
}

/**
 * List available principals from the control API.
 * Calls GET /api/v1/principals on the control API.
 */
export async function fetchPrincipals(
  conn: FleetConnection,
): Promise<PrincipalInfo[]> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return [];

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/principals`, kind),
      { headers: controlHeaders(conn) },
    );
    // The response may be { principals: [...] } or a bare array
    let list: unknown[];
    if (Array.isArray(res)) {
      list = res;
    } else if (res && typeof res === "object" && "principals" in res) {
      const wrapped = res as { principals: unknown };
      if (!Array.isArray(wrapped.principals)) {
        throw new Error("[fleet-client] fetchPrincipals: expected principals to be an array");
      }
      list = wrapped.principals;
    } else {
      throw new Error("[fleet-client] fetchPrincipals: unexpected response shape");
    }

    // Validate and coerce each entry
    return list.filter((p): p is PrincipalInfo => {
      if (!p || typeof p !== "object") return false;
      return typeof (p as Record<string, unknown>).id === "string";
    });
  } catch (e) {
    console.warn("[fleet-client] fetchPrincipals failed:", e);
    return [];
  }
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
  action_type: string;
  action_target: string;
  evidence?: Record<string, unknown>;
  signature: string;
  public_key: string;
  valid: boolean;
  metadata?: Record<string, unknown>;
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
  reason?: string;
  verified_at: string;
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

  // Handle response shapes: { receipts, total, offset, limit } or bare array
  if (Array.isArray(res)) {
    const receipts = res.filter(isFleetReceipt);
    return { receipts, total: receipts.length, offset: opts?.offset ?? 0, limit: opts?.limit ?? 50 };
  }
  if (res && typeof res === "object") {
    const obj = res as Record<string, unknown>;
    if ("receipts" in obj && Array.isArray(obj.receipts)) {
      return {
        receipts: (obj.receipts as unknown[]).filter(isFleetReceipt),
        total: typeof obj.total === "number" ? obj.total : (obj.receipts as unknown[]).length,
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
    const res = await jsonFetch<{ id?: string; success?: boolean }>(
      proxyUrl(`${url}/api/v1/receipts`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify(receipt),
      },
    );
    return { success: true, id: res.id ?? receipt.id };
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
    const res = await jsonFetch<{ stored?: number; success?: boolean }>(
      proxyUrl(`${url}/api/v1/receipts/batch`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify({ receipts }),
      },
    );
    return { success: true, stored: res.stored ?? receipts.length };
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

    // Handle array or wrapped response
    if (Array.isArray(res)) {
      return res.filter(isFleetReceipt);
    }
    if (res && typeof res === "object" && "receipts" in res) {
      const wrapped = res as { receipts: unknown };
      if (Array.isArray(wrapped.receipts)) {
        return (wrapped.receipts as unknown[]).filter(isFleetReceipt);
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

  return jsonFetch<FleetReceiptVerifyResponse>(
    proxyUrl(`${url}/api/v1/receipts/${encodeURIComponent(receiptId)}/verify`, kind),
    {
      method: "POST",
      headers: controlHeaders(conn),
    },
  );
}

/** Type guard for FleetReceipt shape. */
function isFleetReceipt(value: unknown): value is FleetReceipt {
  if (!value || typeof value !== "object") return false;
  const obj = value as Record<string, unknown>;
  return typeof obj.id === "string" && typeof obj.verdict === "string";
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

    return list.filter(isCatalogTemplate);
  } catch (e) {
    console.warn("[fleet-client] fetchCatalogTemplates failed:", e);
    return [];
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

    if (res && typeof res === "object" && isCatalogTemplate(res)) {
      return res;
    }
    throw new Error("[fleet-client] fetchCatalogTemplate: unexpected response shape");
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
    const res = await jsonFetch<{ id?: string; success?: boolean }>(
      proxyUrl(`${url}/api/v1/catalog/templates`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify(template),
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

    if (res && typeof res === "object" && isCatalogTemplate(res)) {
      return { success: true, template: res };
    }
    // Some backends return { template: {...} } wrapper
    const obj = res as Record<string, unknown>;
    if ("template" in obj && isCatalogTemplate(obj.template)) {
      return { success: true, template: obj.template as CatalogTemplate };
    }
    return { success: true };
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

    return list.filter((c): c is CatalogCategoryInfo => {
      if (!c || typeof c !== "object") return false;
      const obj = c as Record<string, unknown>;
      return typeof obj.id === "string" && typeof obj.label === "string";
    });
  } catch (e) {
    console.warn("[fleet-client] fetchCatalogCategories failed:", e);
    return [];
  }
}

/** Type guard for CatalogTemplate shape. */
function isCatalogTemplate(value: unknown): value is CatalogTemplate {
  if (!value || typeof value !== "object") return false;
  const obj = value as Record<string, unknown>;
  return typeof obj.id === "string" && typeof obj.name === "string" && typeof obj.yaml === "string";
}

// ---------------------------------------------------------------------------
// Hierarchy CRUD API (P3-2: Fleet Hierarchy Sync)
// ---------------------------------------------------------------------------

/**
 * Backend hierarchy node as returned by the control-api hierarchy endpoints.
 * Uses snake_case wire format.
 */
export interface HierarchyNode {
  id: string;
  name: string;
  node_type: string; // "org" | "team" | "project" | "agent"
  parent_id?: string | null;
  policy_id?: string | null;
  policy_name?: string | null;
  children?: HierarchyNode[];
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
  root_id: string;
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
 * Fetch the full hierarchy tree (with nested children) from the backend.
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
    if (typeof obj.root_id !== "string" || !Array.isArray(obj.nodes)) {
      throw new Error("[fleet-client] fetchHierarchyTree: expected { root_id, nodes }");
    }

    return {
      root_id: obj.root_id,
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
// Convenience client (reads saved credentials from localStorage)
// ---------------------------------------------------------------------------

function savedConnection(): FleetConnection {
  const saved = loadSavedConnection();
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
    const conn = savedConnection();
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
    const conn = savedConnection();
    return conn.controlApiUrl ? fetchDelegationGraphFromApi(conn) : null;
  },

  async fetchDelegationGraphSnapshot(principalId: string): Promise<DelegationGraph | null> {
    const conn = savedConnection();
    return fetchDelegationGraphSnapshot(conn, principalId);
  },

  async fetchPrincipals(): Promise<PrincipalInfo[]> {
    const conn = savedConnection();
    return fetchPrincipals(conn);
  },

  async fetchApprovals(): Promise<{ requests: ApprovalRequest[]; decisions: ApprovalDecision[] } | null> {
    const conn = savedConnection();
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
    return resolveApproval(savedConnection(), requestId, decision, opts);
  },
};
