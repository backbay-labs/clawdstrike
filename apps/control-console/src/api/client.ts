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

export type BrokerProvider = "openai" | "github" | "slack" | "generic_https";
export type BrokerCapabilityState = "active" | "revoked" | "frozen" | "expired";
export type BrokerExecutionOutcome = "success" | "upstream_error" | "incomplete";
export type BrokerExecutionPhase = "started" | "completed";
export type BrokerIntentRiskLevel = "low" | "medium" | "high";
export type BrokerApprovalState = "not_required" | "pending" | "approved" | "rejected";
export type BrokerMintedIdentityKind =
  | "static"
  | "github_app_installation"
  | "slack_app_session"
  | "aws_sts_session";

export interface BrokerMintedIdentity {
  kind: BrokerMintedIdentityKind;
  subject: string;
  issued_at: string;
  expires_at: string;
  metadata?: Record<string, string>;
}

export interface BrokerIntentResource {
  kind: string;
  value: string;
}

export interface BrokerIntentPreview {
  preview_id: string;
  provider: BrokerProvider;
  operation: string;
  summary: string;
  created_at: string;
  risk_level: BrokerIntentRiskLevel;
  data_classes?: string[];
  resources?: BrokerIntentResource[];
  egress_host: string;
  estimated_cost_usd_micros?: number;
  approval_required: boolean;
  approval_state: BrokerApprovalState;
  approved_at?: string;
  approver?: string;
}

export interface BrokerDelegationLineage {
  token_jti: string;
  parent_token_jti?: string;
  chain?: string[];
  depth: number;
  issuer: string;
  subject: string;
  purpose?: string;
}

export interface BrokerCapabilityStatus {
  capability_id: string;
  provider: BrokerProvider;
  state: BrokerCapabilityState;
  issued_at: string;
  expires_at: string;
  policy_hash: string;
  session_id?: string;
  endpoint_agent_id?: string;
  runtime_agent_id?: string;
  runtime_agent_kind?: string;
  origin_fingerprint?: string;
  secret_ref_id: string;
  url: string;
  method: string;
  state_reason?: string;
  revoked_at?: string;
  execution_count: number;
  last_executed_at?: string;
  last_status_code?: number;
  last_outcome?: BrokerExecutionOutcome;
  intent_preview?: BrokerIntentPreview;
  minted_identity?: BrokerMintedIdentity;
  lineage?: BrokerDelegationLineage;
  suspicion_reason?: string;
}

export interface BrokerCapabilitiesResponse {
  capabilities: BrokerCapabilityStatus[];
}

export interface BrokerExecutionEvidence {
  execution_id: string;
  capability_id: string;
  provider: BrokerProvider;
  phase: BrokerExecutionPhase;
  executed_at: string;
  secret_ref_id: string;
  url: string;
  method: string;
  request_body_sha256?: string;
  response_body_sha256?: string;
  status_code?: number;
  bytes_sent: number;
  bytes_received: number;
  stream_chunk_count?: number;
  provider_metadata?: Record<string, string>;
  outcome?: BrokerExecutionOutcome;
  minted_identity?: BrokerMintedIdentity;
  preview_id?: string;
  lineage?: BrokerDelegationLineage;
  suspicion_reason?: string;
}

export interface BrokerCapabilityDetailResponse {
  capability: BrokerCapabilityStatus;
  executions: BrokerExecutionEvidence[];
}

export interface BrokerFrozenProviderStatus {
  provider: BrokerProvider;
  frozen_at: string;
  reason: string;
}

export interface BrokerFrozenProvidersResponse {
  frozen_providers: BrokerFrozenProviderStatus[];
}

export interface BrokerPreviewResponse {
  preview: BrokerIntentPreview;
}

export interface BrokerPreviewListResponse {
  previews: BrokerIntentPreview[];
}

export interface BrokerReplayDiff {
  field: string;
  previous: string;
  current: string;
}

export interface BrokerReplayResponse {
  capability_id: string;
  current_policy_hash: string;
  current_state: BrokerCapabilityState;
  provider_frozen: boolean;
  egress_allowed: boolean;
  provider_allowed: boolean;
  policy_changed: boolean;
  approval_required: boolean;
  preview_still_approved?: boolean;
  delegated_subject?: string;
  minted_identity_kind?: BrokerMintedIdentityKind;
  would_allow: boolean;
  reason: string;
  diffs?: BrokerReplayDiff[];
  notes?: string[];
}

export interface BrokerRevokeAllResponse {
  revoked_count: number;
}

export interface BrokerCompletionBundle {
  generated_at: string;
  capability: BrokerCapabilityStatus;
  executions: BrokerExecutionEvidence[];
}

export interface BrokerCompletionBundleResponse {
  envelope: string;
  bundle: BrokerCompletionBundle;
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

export async function fetchBrokerCapabilities(filters?: {
  state?: BrokerCapabilityState;
  provider?: BrokerProvider;
  limit?: number;
}): Promise<BrokerCapabilitiesResponse> {
  const params = new URLSearchParams();
  if (filters?.state) params.set("state", filters.state);
  if (filters?.provider) params.set("provider", filters.provider);
  if (filters?.limit != null) params.set("limit", String(filters.limit));

  const qs = params.toString();
  const res = await fetch(`${getApiBase()}/api/v1/broker/capabilities${qs ? `?${qs}` : ""}`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error(`Broker capability query failed: ${res.status}`);
  return res.json();
}

export async function fetchBrokerCapability(
  capabilityId: string,
): Promise<BrokerCapabilityDetailResponse> {
  const res = await fetch(`${getApiBase()}/api/v1/broker/capabilities/${capabilityId}`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error(`Broker capability fetch failed: ${res.status}`);
  return res.json();
}

export async function fetchBrokerPreviews(filters?: {
  provider?: BrokerProvider;
  limit?: number;
}): Promise<BrokerPreviewListResponse> {
  const params = new URLSearchParams();
  if (filters?.provider) params.set("provider", filters.provider);
  if (filters?.limit != null) params.set("limit", String(filters.limit));

  const qs = params.toString();
  const res = await fetch(`${getApiBase()}/api/v1/broker/previews${qs ? `?${qs}` : ""}`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error(`Broker preview query failed: ${res.status}`);
  return res.json();
}

export async function fetchBrokerPreview(previewId: string): Promise<BrokerPreviewResponse> {
  const res = await fetch(`${getApiBase()}/api/v1/broker/previews/${previewId}`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error(`Broker preview fetch failed: ${res.status}`);
  return res.json();
}

export async function approveBrokerPreview(
  previewId: string,
  approver?: string,
): Promise<BrokerIntentPreview> {
  const res = await fetch(`${getApiBase()}/api/v1/broker/previews/${previewId}/approve`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ approver }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Broker preview approval failed: ${res.status}`);
  }
  const payload = (await res.json()) as BrokerPreviewResponse;
  return payload.preview;
}

export async function revokeBrokerCapability(
  capabilityId: string,
  reason?: string,
): Promise<BrokerCapabilityStatus> {
  const res = await fetch(`${getApiBase()}/api/v1/broker/capabilities/${capabilityId}/revoke`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ reason }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Broker capability revoke failed: ${res.status}`);
  }
  const payload = (await res.json()) as { capability: BrokerCapabilityStatus };
  return payload.capability;
}

export async function fetchFrozenBrokerProviders(): Promise<BrokerFrozenProvidersResponse> {
  const res = await fetch(`${getApiBase()}/api/v1/broker/providers/freeze`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error(`Broker provider freeze query failed: ${res.status}`);
  return res.json();
}

export async function freezeBrokerProvider(
  provider: BrokerProvider,
  reason: string,
): Promise<BrokerFrozenProvidersResponse> {
  const res = await fetch(`${getApiBase()}/api/v1/broker/providers/${provider}/freeze`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ reason }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Broker provider freeze failed: ${res.status}`);
  }
  return res.json();
}

export async function unfreezeBrokerProvider(
  provider: BrokerProvider,
): Promise<BrokerFrozenProvidersResponse> {
  const res = await fetch(`${getApiBase()}/api/v1/broker/providers/${provider}/freeze`, {
    method: "DELETE",
    headers: getHeaders(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Broker provider unfreeze failed: ${res.status}`);
  }
  return res.json();
}

export async function replayBrokerCapability(
  capabilityId: string,
): Promise<BrokerReplayResponse> {
  const res = await fetch(`${getApiBase()}/api/v1/broker/capabilities/${capabilityId}/replay`, {
    method: "POST",
    headers: getHeaders(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Broker capability replay failed: ${res.status}`);
  }
  return res.json();
}

export async function exportBrokerCompletionBundle(
  capabilityId: string,
): Promise<BrokerCompletionBundleResponse> {
  const res = await fetch(`${getApiBase()}/api/v1/broker/capabilities/${capabilityId}/bundle`, {
    headers: getHeaders(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Broker completion bundle export failed: ${res.status}`);
  }
  return res.json();
}

export async function revokeAllBrokerCapabilities(
  reason?: string,
): Promise<BrokerRevokeAllResponse> {
  const res = await fetch(`${getApiBase()}/api/v1/broker/capabilities/revoke-all`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ reason }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Broker revoke-all failed: ${res.status}`);
  }
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
