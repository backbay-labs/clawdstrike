import type {
  ApprovalRequest,
  ApprovalDecision,
  ApprovalScope,
  ApprovalStatus,
  RiskLevel,
  OriginContext,
  OriginProvider,
} from "@/lib/workbench/approval-types";
import type {
  DelegationGraph,
  DelegationNode,
  DelegationEdge,
  NodeKind,
  TrustLevel,
  EdgeKind,
  Capability,
} from "@/lib/workbench/delegation-types";
import {
  isHeadAnnouncement,
  isHubConfig,
  type FindingEnvelope,
  type HeadAnnouncement,
  type HubConfig,
} from "@/features/swarm/swarm-protocol";

import { secureStore } from "@/features/settings/secure-store";
import { validateFleetUrl } from "@/features/fleet/fleet-url-policy";

import {
  controlHeaders,
  hushdHeaders,
  isRecord,
  jsonFetch,
  normalizedValidatedFleetUrl,
  preferredControlUrl,
  proxyUrl,
  readBoolean,
  readNumber,
  readString,
  readStringArray,
  sanitizeStoredFleetUrl,
  stripTrailingSlash,
} from "./fleet-client/internal";
import type {
  AgentInfo,
  AgentStatusResponse,
  AuditEvent,
  AuditFilters,
  DeployResponse,
  FleetConnection,
  FleetConnectionInfo,
  HealthResponse,
  PolicyResponse,
  PrincipalInfo,
  SwarmFindingPublishResponse,
  ValidateResponse,
} from "./fleet-client/types";

// Public re-exports from sub-modules — keep consumers importing from
// "@/features/fleet/fleet-client" while the implementation lives by domain.
export {
  isPrivateOrLoopbackFleetHostname,
  validateFleetUrl,
} from "@/features/fleet/fleet-url-policy";
export * from "./fleet-client/types";
export * from "./fleet-client/receipts";
export * from "./fleet-client/catalog";
export * from "./fleet-client/hierarchy";
export * from "./fleet-client/scoped-policies";

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

/** Strip credentials from a FleetConnection for safe context exposure. */
export function redactFleetConnection(conn: FleetConnection): FleetConnectionInfo {
  const { apiKey: _apiKey, controlApiToken: _controlApiToken, ...info } = conn;
  return info;
}

interface BackendGraphNode {
  id: string;
  kind: string;
  label?: string;
  role?: string;
  trust_level?: string;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
}

interface BackendGraphEdge {
  id: string;
  from: string;
  to: string;
  kind: string;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
}

interface BackendDelegationGraphResponse {
  nodes: BackendGraphNode[];
  edges: BackendGraphEdge[];
  generated_at?: string;
  principal_id?: string;
}

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

function isSwarmFindingPublishResponse(value: unknown): value is SwarmFindingPublishResponse {
  if (!isRecord(value)) {
    return false;
  }
  const feedSeq = readNumber(value.feedSeq);
  return (
    readBoolean(value.accepted) !== undefined &&
    readBoolean(value.idempotent) !== undefined &&
    typeof value.feedId === "string" &&
    typeof value.issuerId === "string" &&
    typeof value.findingId === "string" &&
    feedSeq !== undefined &&
    Number.isSafeInteger(feedSeq) &&
    feedSeq >= 0 &&
    isHeadAnnouncement(value.headAnnouncement)
  );
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

export async function fetchSwarmHubConfig(conn: FleetConnection): Promise<HubConfig> {
  // Finding M1: re-validate URL at call site for defense-in-depth
  normalizedValidatedFleetUrl(conn.hushdUrl, "hushd URL");
  const url = stripTrailingSlash(conn.hushdUrl);
  const res = await jsonFetch<unknown>(proxyUrl(`${url}/api/v1/swarm/hub/config`, "hushd"), {
    headers: hushdHeaders(conn.apiKey),
  });
  if (!isHubConfig(res)) {
    throw new Error("[fleet-client] fetchSwarmHubConfig: unexpected response shape");
  }
  return res;
}

export async function publishSwarmFinding(
  conn: FleetConnection,
  envelope: FindingEnvelope,
): Promise<SwarmFindingPublishResponse> {
  // Finding M1: re-validate URL at call site for defense-in-depth
  normalizedValidatedFleetUrl(conn.hushdUrl, "hushd URL");
  const url = stripTrailingSlash(conn.hushdUrl);
  const res = await jsonFetch<unknown>(
    proxyUrl(`${url}/api/v1/swarm/feeds/${encodeURIComponent(envelope.feedId)}/findings`, "hushd"),
    {
      method: "POST",
      headers: hushdHeaders(conn.apiKey),
      body: JSON.stringify(envelope),
    },
  );
  if (!isSwarmFindingPublishResponse(res)) {
    throw new Error("[fleet-client] publishSwarmFinding: unexpected response shape");
  }
  if (
    res.feedId !== envelope.feedId ||
    res.issuerId !== envelope.issuerId ||
    res.feedSeq !== envelope.feedSeq ||
    res.findingId !== envelope.findingId
  ) {
    throw new Error("[fleet-client] publishSwarmFinding: response mismatch");
  }
  if (!res.accepted) {
    throw new Error("[fleet-client] publishSwarmFinding: publish rejected");
  }
  if (
    res.headAnnouncement.feedId !== envelope.feedId ||
    res.headAnnouncement.issuerId !== envelope.issuerId ||
    res.headAnnouncement.headSeq !== envelope.feedSeq
  ) {
    throw new Error("[fleet-client] publishSwarmFinding: head mismatch");
  }
  return res;
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

export async function fetchAgentList(
  conn: FleetConnection,
  opts?: { expectedPolicyVersion?: string },
): Promise<AgentInfo[]> {
  const url = stripTrailingSlash(conn.hushdUrl);
  try {
    let qs = "include_stale=true";
    if (opts?.expectedPolicyVersion) {
      qs += `&expected_policy_version=${encodeURIComponent(opts.expectedPolicyVersion)}`;
    }
    const res = await jsonFetch<AgentStatusResponse>(
      proxyUrl(`${url}/api/v1/agents/status?${qs}`, "hushd"),
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

function validateAuditEvent(event: unknown): event is AuditEvent {
  if (!event || typeof event !== "object") return false;
  const e = event as Record<string, unknown>;
  if (typeof e.id !== "string" || !e.id) return false;
  if (typeof e.timestamp !== "string" || !e.timestamp) return false;
  if (typeof e.action_type !== "string" || !e.action_type) return false;
  if (typeof e.decision !== "string" || !e.decision) return false;
  return true;
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
  let raw: unknown[];
  if (Array.isArray(res)) {
    raw = res;
  } else if (res && typeof res === "object" && "events" in res) {
    if (!Array.isArray(res.events)) {
      throw new Error("[fleet-client] fetchAuditEvents: expected res.events to be an array");
    }
    raw = res.events;
  } else {
    throw new Error("[fleet-client] fetchAuditEvents: unexpected response shape");
  }
  // Validate individual events and filter out malformed entries
  const valid: AuditEvent[] = [];
  for (const item of raw) {
    if (validateAuditEvent(item)) {
      valid.push(item);
    } else {
      console.warn("[fleet-client] fetchAuditEvents: dropping invalid audit event", item);
    }
  }
  return valid;
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

const BACKEND_KNOWN_STATUSES = new Set<string>(["pending", "approved", "denied"]);

const BACKEND_KNOWN_PROVIDERS = new Set<string>(["slack", "teams", "github", "jira", "email", "discord", "webhook", "cli", "api"]);

const BACKEND_KNOWN_RISK_LEVELS = new Set<string>(["low", "medium", "high", "critical"]);

/**
 * Derive the frontend `ApprovalStatus` from the backend row.
 *
 * The backend DB only stores "pending", "approved", or "denied".
 * The frontend also has "expired", which we derive by checking whether
 * a still-pending request has passed its `expires_at` timestamp.
 *
 * **Limitation:** This derivation runs once at fetch time. If the fetched
 * data sits in memory without being re-fetched, a "pending" approval that
 * passes its `expires_at` will still show as "pending" until the next
 * fetch cycle. Consumers that display approvals should either re-fetch on
 * a reasonable interval (the approval queue polls every 30s) or re-derive
 * the status client-side based on the current time (the approval-queue
 * component does this via its per-second `tick` effect).
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
    thread_id: optionalString(raw.thread_id),
    actor_id: optionalString(raw.actor_id),
    actor_type: optionalString(raw.actor_type) as OriginContext["actor_type"],
    actor_role: optionalString(raw.actor_role),
    actor_name: optionalString(raw.actor_name),
    visibility: optionalString(raw.visibility) as OriginContext["visibility"],
    external_participants:
      typeof raw.external_participants === "boolean"
        ? raw.external_participants
        : undefined,
    tags: Array.isArray(raw.tags)
      ? (raw.tags as unknown[]).map(String)
      : undefined,
    sensitivity: optionalString(raw.sensitivity),
    provenance_confidence: optionalString(raw.provenance_confidence) as OriginContext["provenance_confidence"],
    metadata:
      raw.metadata != null && typeof raw.metadata === "object" && !Array.isArray(raw.metadata)
        ? (raw.metadata as Record<string, unknown>)
        : undefined,
  };
}

function extractRiskLevel(eventData: Record<string, unknown>): RiskLevel {
  const raw = optionalString(eventData.risk_level ?? eventData.riskLevel ?? eventData.severity);
  if (raw && BACKEND_KNOWN_RISK_LEVELS.has(raw.toLowerCase())) {
    return raw.toLowerCase() as RiskLevel;
  }
  return "medium";
}

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
  const url = preferredControlUrl(conn);
  if (!url) {
    return { requests: [], decisions: [] };
  }
  const res = await jsonFetch<unknown>(
    proxyUrl(`${url}/api/v1/approvals`, "control"),
    { headers: controlHeaders(conn) },
  );
  return adaptApprovalsResponse(res);
}

export async function resolveApproval(
  conn: FleetConnection,
  requestId: string,
  decision: "approved" | "denied",
  opts?: { scope?: ApprovalScope; reason?: string; decidedBy?: string },
): Promise<{ success: boolean; error?: string }> {
  const url = preferredControlUrl(conn);
  if (!url) {
    return {
      success: false,
      error: "Control API URL is not configured",
    };
  }
  try {
    await jsonFetch<{ ok: boolean }>(
      proxyUrl(`${url}/api/v1/approvals/${encodeURIComponent(requestId)}/resolve`, "control"),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify({
          decision,
          scope: opts?.scope,
          reason: opts?.reason,
          decided_by: opts?.decidedBy ?? "workbench-user",
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

const KNOWN_NODE_KINDS = new Set<string>([
  "Principal", "Session", "Grant", "Approval", "Event", "ResponseAction",
]);

const KNOWN_TRUST_LEVELS = new Set<string>([
  "Untrusted", "Low", "Medium", "High", "System",
]);

const KNOWN_EDGE_KINDS = new Set<string>([
  "IssuedGrant", "ReceivedGrant", "DerivedFromGrant", "SpawnedPrincipal",
  "ApprovedBy", "RevokedBy", "ExercisedInSession", "ExercisedInEvent",
  "TriggeredResponseAction",
]);

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

/** Falls back to grants-based graph if the delegation-graph route is unavailable. */
export async function fetchDelegationGraphSnapshot(
  conn: FleetConnection,
  principalId: string,
): Promise<DelegationGraph | null> {
  const url = preferredControlUrl(conn);
  if (!url) return null;

  try {
    const res = await jsonFetch<BackendDelegationGraphResponse>(
      proxyUrl(`${url}/api/v1/principals/${encodeURIComponent(principalId)}/delegation-graph`, "control"),
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

export async function fetchPrincipals(
  conn: FleetConnection,
): Promise<PrincipalInfo[]> {
  const url = preferredControlUrl(conn);
  if (!url) return [];

  const principalPaths = [
    `${url}/api/v1/console/principals`,
    `${url}/api/v1/principals`,
  ];

  for (const path of principalPaths) {
    try {
      const res = await jsonFetch<unknown>(proxyUrl(path, "control"), {
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
    if (!conn.controlApiUrl.trim()) return null;
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
    opts?: { scope?: ApprovalScope; reason?: string; decidedBy?: string },
  ): Promise<{ success: boolean; error?: string }> {
    const conn = await savedConnectionAsync();
    return resolveApproval(conn, requestId, decision, opts);
  },
};
