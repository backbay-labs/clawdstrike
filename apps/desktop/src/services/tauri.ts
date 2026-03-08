/**
 * Tauri IPC Wrappers - Commands for Rust backend
 */

// Check if running in Tauri environment
export function isTauri(): boolean {
  if (typeof window === "undefined") return false;
  const win = window as unknown as Record<string, unknown>;
  return Boolean(
    "__TAURI__" in win || "__TAURI_INTERNALS__" in win || typeof win.__TAURI_IPC__ === "function",
  );
}

// Lazy import Tauri API to avoid errors in browser
async function getTauriInvoke() {
  if (!isTauri()) {
    throw new Error("Not running in Tauri environment");
  }
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke;
}

// === Connection Commands ===

export interface DaemonStatusResult {
  connected: boolean;
  version?: string;
  policy_hash?: string;
  uptime_secs?: number;
}

export async function testDaemonConnection(url: string): Promise<DaemonStatusResult> {
  if (!isTauri()) {
    // Fallback to fetch in browser
    const response = await fetch(`${url}/health`);
    if (!response.ok) throw new Error("Connection failed");
    const data = await response.json();
    return { connected: true, ...data };
  }

  const invoke = await getTauriInvoke();
  return invoke("test_connection", { url });
}

export async function getDaemonStatus(): Promise<DaemonStatusResult> {
  if (!isTauri()) {
    throw new Error("getDaemonStatus requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("get_daemon_status");
}

// === Policy Commands ===

export interface PolicyCheckRequest {
  policy_ref: string;
  action_type: string;
  target: string;
  content?: string;
}

export interface PolicyCheckResult {
  allowed: boolean;
  guard?: string;
  severity?: string;
  message?: string;
  suggestion?: string;
}

export interface TauriPolicySourceInfo {
  kind: string;
  path?: string;
  path_exists?: boolean;
}

export interface TauriPolicySchemaInfo {
  current: string;
  supported: string[];
}

export interface PolicyLoadResult {
  name: string;
  version: string;
  description: string;
  policy_hash: string;
  yaml: string;
  source?: TauriPolicySourceInfo;
  schema?: TauriPolicySchemaInfo;
}

export interface PolicyValidationIssue {
  path: string;
  code: string;
  message: string;
}

export interface PolicyValidationResult {
  valid: boolean;
  errors: PolicyValidationIssue[];
  warnings: PolicyValidationIssue[];
  normalized_version?: string;
}

export interface PolicySaveResult {
  success: boolean;
  message: string;
  policy_hash?: string;
}

export async function policyCheck(request: PolicyCheckRequest): Promise<PolicyCheckResult> {
  if (!isTauri()) {
    throw new Error("policyCheck requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("policy_check", request as unknown as Record<string, unknown>);
}

export async function policyLoad(): Promise<PolicyLoadResult> {
  if (!isTauri()) {
    throw new Error("policyLoad requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("policy_load");
}

export async function policyValidate(yaml: string): Promise<PolicyValidationResult> {
  if (!isTauri()) {
    throw new Error("policyValidate requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("policy_validate", { yaml });
}

export async function policyEvalEvent(
  event: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (!isTauri()) {
    throw new Error("policyEvalEvent requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("policy_eval_event", { event });
}

export async function policySave(yaml: string): Promise<PolicySaveResult> {
  if (!isTauri()) {
    throw new Error("policySave requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("policy_save", { yaml });
}

// === Workflow Commands ===

export interface Workflow {
  id: string;
  name: string;
  enabled: boolean;
  trigger: WorkflowTrigger;
  actions: WorkflowAction[];
  last_run?: string;
  run_count: number;
  created_at: string;
}

export type WorkflowTrigger =
  | { type: "event_match"; conditions: TriggerCondition[] }
  | { type: "schedule"; cron: string }
  | { type: "aggregation"; conditions: TriggerCondition[]; threshold: number; window: string };

export interface TriggerCondition {
  field: "verdict" | "guard" | "agent" | "severity" | "action_type";
  operator: "equals" | "not_equals" | "contains" | "greater_than";
  value: string | number;
}

export type WorkflowAction =
  | { type: "slack_webhook"; url: string; channel: string; template: string }
  | { type: "pagerduty"; routing_key: string; severity: string }
  | { type: "email"; to: string[]; subject: string; template: string }
  | { type: "webhook"; url: string; method: string; headers: Record<string, string>; body: string }
  | { type: "log"; path: string; format: string };

export async function listWorkflows(): Promise<Workflow[]> {
  if (!isTauri()) {
    // Return mock data for browser testing
    return [];
  }

  const invoke = await getTauriInvoke();
  return invoke("list_workflows");
}

export async function saveWorkflow(workflow: Workflow): Promise<void> {
  if (!isTauri()) {
    throw new Error("saveWorkflow requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("save_workflow", { workflow });
}

export async function deleteWorkflow(workflowId: string): Promise<void> {
  if (!isTauri()) {
    throw new Error("deleteWorkflow requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("delete_workflow", { workflowId });
}

export async function testWorkflow(
  workflowId: string,
): Promise<{ success: boolean; message?: string }> {
  if (!isTauri()) {
    throw new Error("testWorkflow requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("test_workflow", { workflowId });
}

// === Receipt Commands ===

export interface ReceiptVerificationResult {
  valid: boolean;
  signature_valid: boolean;
  merkle_valid?: boolean;
  timestamp_valid: boolean;
  errors: string[];
  warnings?: string[];
}

export async function verifyReceipt(receipt: unknown): Promise<ReceiptVerificationResult> {
  if (!isTauri()) {
    // Mock verification for browser
    return {
      valid: true,
      signature_valid: true,
      timestamp_valid: true,
      errors: [],
    };
  }

  const invoke = await getTauriInvoke();
  return invoke("verify_receipt", { receipt });
}

// === Marketplace Commands ===

export interface MarketplacePolicyDto {
  entry_id: string;
  bundle_uri: string;
  title: string;
  description: string;
  category?: string | null;
  tags: string[];
  author?: string | null;
  author_url?: string | null;
  icon?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  attestation_uid?: string | null;
  notary_url?: string | null;
  spine_envelope_hash?: string | null;
  bundle_public_key?: string | null;
  curator_name?: string | null;
  curator_trust_level?: string | null;
  install_allowed: boolean;
  signed_bundle: SignedPolicyBundle;
}

export interface SignedPolicyBundle {
  bundle: PolicyBundle;
  signature: string;
  public_key?: string;
  [k: string]: unknown;
}

export interface PolicyBundle {
  version: string;
  bundle_id: string;
  compiled_at: string;
  policy: PolicySummary;
  policy_hash: string;
  sources?: string[];
  metadata?: unknown;
  [k: string]: unknown;
}

export interface PolicySummary {
  version: string;
  name: string;
  description: string;
  [k: string]: unknown;
}

export interface MarketplaceListResponse {
  feed_id: string;
  published_at: string;
  seq: number;
  signer_public_key: string;
  policies: MarketplacePolicyDto[];
  warnings?: string[];
}

export async function listMarketplacePolicies(
  sources?: string[],
): Promise<MarketplaceListResponse> {
  if (!isTauri()) {
    throw new Error("Marketplace requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("marketplace_list_policies", { sources });
}

export async function installMarketplacePolicy(
  daemonUrl: string,
  feedId: string,
  entryId: string,
  policyHash: string,
  bundleSignature: string,
): Promise<void> {
  if (!isTauri()) {
    throw new Error("Marketplace requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("marketplace_install_policy", {
    daemon_url: daemonUrl,
    feed_id: feedId,
    entry_id: entryId,
    policy_hash: policyHash,
    bundle_signature: bundleSignature,
  });
}

export interface MarketplaceProvenanceSettingsPayload {
  notaryUrl: string | null;
  proofsApiUrl: string | null;
  trustedAttesters: string[];
  requireVerified: boolean;
  preferSpine: boolean;
  trustedWitnessKeys: string[];
}

export async function saveMarketplaceProvenanceConfig(
  settings: MarketplaceProvenanceSettingsPayload,
): Promise<void> {
  if (!isTauri()) {
    throw new Error("Marketplace requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("marketplace_save_provenance_settings", { settings });
}

export interface NotaryVerifyResult {
  valid: boolean;
  attester?: string | null;
  attested_at?: string | null;
  error?: string | null;
}

export async function verifyMarketplaceAttestation(
  uid: string,
): Promise<NotaryVerifyResult> {
  if (!isTauri()) {
    throw new Error("Marketplace requires Tauri");
  }
  const invoke = await getTauriInvoke();
  return invoke("marketplace_verify_attestation", { uid });
}

// === Marketplace Discovery Commands ===

export interface MarketplaceDiscoveryConfig {
  listen_port?: number | null;
  bootstrap?: string[];
  topic?: string | null;
}

export interface MarketplaceDiscoveryAnnouncement {
  v?: number;
  feed_uri: string;
  feed_id?: string | null;
  seq?: number | null;
  signer_public_key?: string | null;
}

export interface MarketplaceDiscoveryEvent {
  received_at: string;
  from_peer_id: string;
  announcement: MarketplaceDiscoveryAnnouncement;
}

export interface MarketplaceDiscoveryStatus {
  running: boolean;
  peer_id?: string | null;
  listen_addrs?: string[];
  topic: string;
  connected_peers: number;
  last_error?: string | null;
}

export async function startMarketplaceDiscovery(
  config?: MarketplaceDiscoveryConfig,
): Promise<MarketplaceDiscoveryStatus> {
  if (!isTauri()) {
    throw new Error("Marketplace discovery requires Tauri");
  }
  const invoke = await getTauriInvoke();
  return invoke("marketplace_discovery_start", { config });
}

export async function stopMarketplaceDiscovery(): Promise<void> {
  if (!isTauri()) {
    throw new Error("Marketplace discovery requires Tauri");
  }
  const invoke = await getTauriInvoke();
  return invoke("marketplace_discovery_stop");
}

export async function getMarketplaceDiscoveryStatus(): Promise<MarketplaceDiscoveryStatus> {
  if (!isTauri()) {
    throw new Error("Marketplace discovery requires Tauri");
  }
  const invoke = await getTauriInvoke();
  return invoke("marketplace_discovery_status");
}

export async function announceMarketplaceDiscovery(
  announcement: MarketplaceDiscoveryAnnouncement,
): Promise<void> {
  if (!isTauri()) {
    throw new Error("Marketplace discovery requires Tauri");
  }
  const invoke = await getTauriInvoke();
  return invoke("marketplace_discovery_announce", { announcement });
}

// === OpenClaw Commands ===

export type OpenClawGatewayDiscoverResult = {
  timeoutMs?: number;
  domains?: string[];
  count?: number;
  beacons?: Array<{
    instanceName?: string;
    displayName?: string;
    host?: string;
    port?: number;
    domain?: string;
    wsUrl?: string;
  }>;
};

export async function openclawAgentRequest<TPayload = unknown>(
  method: "GET" | "POST" | "PATCH" | "PUT" | "DELETE",
  path: string,
  body?: unknown,
): Promise<TPayload> {
  if (!isTauri()) {
    throw new Error("OpenClaw agent request requires Tauri");
  }
  const invoke = await getTauriInvoke();
  return invoke("openclaw_agent_request", {
    method,
    path,
    body: body ?? null,
  });
}

export async function openclawGatewayDiscover(
  timeoutMs?: number,
): Promise<OpenClawGatewayDiscoverResult> {
  if (!isTauri()) {
    throw new Error("OpenClaw discovery requires Tauri");
  }
  const invoke = await getTauriInvoke();
  return invoke(
    "openclaw_gateway_discover",
    typeof timeoutMs === "number" ? { timeout_ms: timeoutMs } : {},
  );
}

export type OpenClawGatewayProbeResult = {
  ok?: boolean;
  network?: {
    localLoopbackUrl?: string;
    localTailnetUrl?: string;
    tailnetIPv4?: string;
  };
  discovery?: {
    count?: number;
    beacons?: Array<{ wsUrl?: string; displayName?: string; host?: string; domain?: string }>;
  };
};

export async function openclawGatewayProbe(
  timeoutMs?: number,
): Promise<OpenClawGatewayProbeResult> {
  if (!isTauri()) {
    throw new Error("OpenClaw probe requires Tauri");
  }
  const invoke = await getTauriInvoke();
  return invoke(
    "openclaw_gateway_probe",
    typeof timeoutMs === "number" ? { timeout_ms: timeoutMs } : {},
  );
}
