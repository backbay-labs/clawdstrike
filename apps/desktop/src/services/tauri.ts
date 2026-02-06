/**
 * Tauri IPC Wrappers - Commands for Rust backend
 */

// Check if running in Tauri environment
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI__" in window;
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

export async function policyCheck(request: PolicyCheckRequest): Promise<PolicyCheckResult> {
  if (!isTauri()) {
    throw new Error("policyCheck requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("policy_check", request as unknown as Record<string, unknown>);
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

export async function testWorkflow(workflowId: string): Promise<{ success: boolean; message?: string }> {
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
  bundle_public_key?: string | null;
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

export async function listMarketplacePolicies(sources?: string[]): Promise<MarketplaceListResponse> {
  if (!isTauri()) {
    throw new Error("Marketplace requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("marketplace_list_policies", { sources });
}

export async function installMarketplacePolicy(daemonUrl: string, signedBundle: SignedPolicyBundle): Promise<void> {
  if (!isTauri()) {
    throw new Error("Marketplace requires Tauri");
  }

  const invoke = await getTauriInvoke();
  return invoke("marketplace_install_policy", { daemon_url: daemonUrl, signed_bundle: signedBundle });
}

export interface NotaryVerifyResult {
  valid: boolean;
  attester?: string | null;
  attested_at?: string | null;
  error?: string | null;
}

export async function verifyMarketplaceAttestation(notaryUrl: string, uid: string): Promise<NotaryVerifyResult> {
  if (!isTauri()) {
    throw new Error("Marketplace requires Tauri");
  }
  const invoke = await getTauriInvoke();
  return invoke("marketplace_verify_attestation", { notary_url: notaryUrl, uid });
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

export async function startMarketplaceDiscovery(config?: MarketplaceDiscoveryConfig): Promise<MarketplaceDiscoveryStatus> {
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

export async function announceMarketplaceDiscovery(announcement: MarketplaceDiscoveryAnnouncement): Promise<void> {
  if (!isTauri()) {
    throw new Error("Marketplace discovery requires Tauri");
  }
  const invoke = await getTauriInvoke();
  return invoke("marketplace_discovery_announce", { announcement });
}
