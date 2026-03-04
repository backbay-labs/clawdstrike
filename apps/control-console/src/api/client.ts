function getApiBase(): string {
  return localStorage.getItem("hushd_url") || "";
}

function getHeaders(): Record<string, string> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const apiBase = getApiBase();
  const apiKey = localStorage.getItem("hushd_api_key");
  // In same-origin mode (empty apiBase), agent auth is bootstrapped by cookie.
  if (apiBase && apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }
  return headers;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  action_type: string;
  target?: string;
  decision: string;
  guard?: string;
  severity?: string;
  message?: string;
  session_id?: string;
  agent_id?: string;
  metadata?: Record<string, unknown>;
}

export interface AuditResponse {
  events: AuditEvent[];
  total: number;
  limit?: number;
  offset?: number;
  next_cursor?: string;
  has_more?: boolean;
}

export interface AuditStats {
  total_events: number;
  violations: number;
  allowed: number;
  session_id?: string;
  uptime_secs: number;
}

export interface HealthResponse {
  status: string;
  version?: string;
  uptime_secs?: number;
  policy_hash?: string;
}

export interface PolicySource {
  kind: string;
  path?: string;
  path_exists?: boolean;
}

export interface PolicyResponse {
  name?: string;
  version?: string;
  description?: string;
  policy_hash?: string;
  yaml?: string;
  source?: PolicySource;
  policy?: unknown;
}

export interface AuditFilters {
  decision?: string;
  action_type?: string;
  session_id?: string;
  agent_id?: string;
  runtime_agent_id?: string;
  runtime_agent_kind?: string;
  limit?: number;
  offset?: number;
  cursor?: string;
}

export interface AgentDriftFlags {
  policy_drift: boolean;
  daemon_drift: boolean;
  stale: boolean;
}

export interface EndpointStatus {
  endpoint_agent_id: string;
  last_heartbeat_at: string;
  last_seen_ip?: string;
  last_session_id?: string;
  posture?: string;
  policy_version?: string;
  daemon_version?: string;
  runtime_count: number;
  seconds_since_heartbeat: number;
  online: boolean;
  drift: AgentDriftFlags;
}

export interface RuntimeStatus {
  runtime_agent_id: string;
  endpoint_agent_id: string;
  runtime_agent_kind: string;
  last_heartbeat_at: string;
  last_session_id?: string;
  posture?: string;
  policy_version?: string;
  daemon_version?: string;
  seconds_since_heartbeat: number;
  online: boolean;
  drift: AgentDriftFlags;
}

export interface AgentStatusResponse {
  generated_at: string;
  stale_after_secs: number;
  endpoints: EndpointStatus[];
  runtimes: RuntimeStatus[];
}

export interface IntegrationSiemSettings {
  provider: string;
  endpoint: string;
  api_key: string;
  enabled: boolean;
}

export interface IntegrationWebhookSettings {
  url: string;
  secret: string;
  enabled: boolean;
}

export interface IntegrationSettings {
  siem: IntegrationSiemSettings;
  webhooks: IntegrationWebhookSettings;
}

export interface IntegrationSettingsUpdate {
  siem?: Partial<IntegrationSiemSettings>;
  webhooks?: Partial<IntegrationWebhookSettings>;
  apply?: boolean;
}

export interface IntegrationApplyResponse {
  integrations: IntegrationSettings;
  restarted: boolean;
  daemon?: {
    state?: string;
  };
  exporter_status?: {
    enabled?: boolean;
    exporters?: Array<{
      name?: string;
      health?: {
        running?: boolean;
        exported_total?: number;
        failed_total?: number;
      };
    }>;
  };
  warning?: string;
}

export type IntegrationTestTarget = "siem" | "webhook";

export interface IntegrationTestResult {
  target: IntegrationTestTarget;
  endpoint: string;
  delivered: boolean;
  status_code?: number;
  attempts: number;
  retry_count: number;
  latency_ms: number;
  last_error?: string;
  tested_at: string;
}

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${getApiBase()}/health`, { headers: getHeaders() });
  if (!res.ok) throw new Error(`Health check failed: ${res.status}`);
  return res.json();
}

export async function fetchAuditEvents(filters?: AuditFilters): Promise<AuditResponse> {
  const params = new URLSearchParams();
  if (filters?.decision) params.set("decision", filters.decision);
  if (filters?.action_type) params.set("action_type", filters.action_type);
  if (filters?.session_id) params.set("session_id", filters.session_id);
  if (filters?.agent_id) params.set("agent_id", filters.agent_id);
  if (filters?.runtime_agent_id) params.set("runtime_agent_id", filters.runtime_agent_id);
  if (filters?.runtime_agent_kind) params.set("runtime_agent_kind", filters.runtime_agent_kind);
  if (filters?.limit != null) params.set("limit", String(filters.limit));
  if (filters?.offset != null) params.set("offset", String(filters.offset));
  if (filters?.cursor) params.set("cursor", filters.cursor);

  const qs = params.toString();
  const url = `${getApiBase()}/api/v1/audit${qs ? `?${qs}` : ""}`;
  const res = await fetch(url, { headers: getHeaders() });
  if (!res.ok) throw new Error(`Audit query failed: ${res.status}`);
  return res.json();
}

export async function fetchAuditStats(): Promise<AuditStats> {
  const res = await fetch(`${getApiBase()}/api/v1/audit/stats`, { headers: getHeaders() });
  if (!res.ok) throw new Error(`Audit stats failed: ${res.status}`);
  return res.json();
}

export async function fetchAgentStatus(params?: {
  endpoint_agent_id?: string;
  runtime_agent_id?: string;
  runtime_agent_kind?: string;
  include_stale?: boolean;
  stale_after_secs?: number;
  limit?: number;
}): Promise<AgentStatusResponse> {
  const query = new URLSearchParams();
  if (params?.endpoint_agent_id) query.set("endpoint_agent_id", params.endpoint_agent_id);
  if (params?.runtime_agent_id) query.set("runtime_agent_id", params.runtime_agent_id);
  if (params?.runtime_agent_kind) query.set("runtime_agent_kind", params.runtime_agent_kind);
  if (params?.include_stale != null) query.set("include_stale", String(params.include_stale));
  if (params?.stale_after_secs != null) query.set("stale_after_secs", String(params.stale_after_secs));
  if (params?.limit != null) query.set("limit", String(params.limit));

  const qs = query.toString();
  const res = await fetch(`${getApiBase()}/api/v1/agents/status${qs ? `?${qs}` : ""}`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error(`Agent status query failed: ${res.status}`);
  return res.json();
}

export async function fetchPolicy(): Promise<PolicyResponse> {
  const res = await fetch(`${getApiBase()}/api/v1/policy`, { headers: getHeaders() });
  if (!res.ok) throw new Error(`Policy fetch failed: ${res.status}`);
  return res.json();
}

export async function fetchIntegrationSettings(): Promise<IntegrationSettings> {
  const res = await fetch("/api/v1/agent/integrations", { headers: getHeaders() });
  if (!res.ok) throw new Error(`Integration settings fetch failed: ${res.status}`);
  return res.json();
}

export async function saveIntegrationSettings(
  input: IntegrationSettingsUpdate,
): Promise<IntegrationApplyResponse> {
  const res = await fetch("/api/v1/agent/integrations", {
    method: "PUT",
    headers: getHeaders(),
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Integration settings update failed: ${res.status}`);
  }
  return res.json();
}

export async function testIntegrationDelivery(
  target: IntegrationTestTarget,
  maxRetries = 2,
): Promise<IntegrationTestResult> {
  const res = await fetch("/api/v1/agent/integrations/test", {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({
      target,
      max_retries: maxRetries,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Integration test failed: ${res.status}`);
  }
  return res.json();
}
