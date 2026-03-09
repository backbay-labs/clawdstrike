import type { ApprovalRequest, ApprovalDecision, ApprovalScope } from "./approval-types";
import type { DelegationGraph, DelegationNode, DelegationEdge } from "./delegation-types";

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

// SECURITY: Credentials stored in plaintext localStorage as a temporary measure.
// TODO: Migrate to tauri-plugin-stronghold or OS keychain for production.
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

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

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

export function saveConnectionConfig(config: {
  hushdUrl: string;
  controlApiUrl: string;
  apiKey: string;
  controlApiToken: string;
}) {
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
      proxyUrl(`${ctrlUrl}/api/v1/policy/distribute`, "control"),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify({ yaml }),
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

export async function fetchApprovals(
  conn: FleetConnection,
): Promise<{ requests: ApprovalRequest[]; decisions: ApprovalDecision[] }> {
  const { url, kind } = preferredUrl(conn);
  const res = await jsonFetch<{
    requests?: ApprovalRequest[];
    decisions?: ApprovalDecision[];
  }>(proxyUrl(`${url}/api/v1/approvals`, kind), {
    headers: controlHeaders(conn),
  });
  return {
    requests: res.requests ?? [],
    decisions: res.decisions ?? [],
  };
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
