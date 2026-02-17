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
}

export interface AuditResponse {
  events: AuditEvent[];
  total: number;
  limit?: number;
  offset?: number;
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
  limit?: number;
  offset?: number;
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
  if (filters?.limit != null) params.set("limit", String(filters.limit));
  if (filters?.offset != null) params.set("offset", String(filters.offset));

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
