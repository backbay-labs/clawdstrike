// ---- Policy Schema Types (mirroring Rust/TS canonical schema) ----

export type PolicySchemaVersion = "1.1.0" | "1.2.0" | "1.3.0" | "1.4.0";

export type Verdict = "allow" | "deny" | "warn";

export type GuardId =
  | "forbidden_path"
  | "path_allowlist"
  | "egress_allowlist"
  | "secret_leak"
  | "patch_integrity"
  | "shell_command"
  | "mcp_tool"
  | "prompt_injection"
  | "jailbreak"
  | "computer_use"
  | "remote_desktop_side_channel"
  | "input_injection_capability"
  | "spider_sense";

// ---- Per-guard config interfaces ----

export interface ForbiddenPathConfig {
  enabled?: boolean;
  patterns?: string[];
  exceptions?: string[];
}

export interface PathAllowlistConfig {
  enabled?: boolean;
  file_access_allow?: string[];
  file_write_allow?: string[];
  patch_allow?: string[];
}

export interface EgressAllowlistConfig {
  enabled?: boolean;
  allow?: string[];
  block?: string[];
  default_action?: "allow" | "block";
}

export interface SecretPattern {
  name: string;
  pattern: string;
  severity: "info" | "warning" | "error" | "critical";
}

export interface SecretLeakConfig {
  enabled?: boolean;
  patterns?: SecretPattern[];
  skip_paths?: string[];
}

export interface PatchIntegrityConfig {
  enabled?: boolean;
  max_additions?: number;
  max_deletions?: number;
  require_balance?: boolean;
  max_imbalance_ratio?: number;
  forbidden_patterns?: string[];
}

export interface ShellCommandConfig {
  enabled?: boolean;
  forbidden_patterns?: string[];
  enforce_forbidden_paths?: boolean;
}

export interface McpToolConfig {
  enabled?: boolean;
  allow?: string[];
  block?: string[];
  require_confirmation?: string[];
  default_action?: "allow" | "block";
  max_args_size?: number;
}

export interface PromptInjectionConfig {
  enabled?: boolean;
  warn_at_or_above?: "safe" | "suspicious" | "high" | "critical";
  block_at_or_above?: "safe" | "suspicious" | "high" | "critical";
  max_scan_bytes?: number;
}

export interface JailbreakConfig {
  enabled?: boolean;
  detector?: {
    block_threshold?: number;
    warn_threshold?: number;
    max_input_bytes?: number;
    session_aggregation?: boolean;
  };
}

export interface ComputerUseConfig {
  enabled?: boolean;
  mode?: "observe" | "guardrail" | "fail_closed";
  allowed_actions?: string[];
}

export interface RemoteDesktopSideChannelConfig {
  enabled?: boolean;
  clipboard_enabled?: boolean;
  file_transfer_enabled?: boolean;
  audio_enabled?: boolean;
  drive_mapping_enabled?: boolean;
  printing_enabled?: boolean;
  session_share_enabled?: boolean;
  max_transfer_size_bytes?: number;
}

export interface InputInjectionCapabilityConfig {
  enabled?: boolean;
  allowed_input_types?: string[];
  require_postcondition_probe?: boolean;
}

export interface SpiderSenseConfig {
  enabled?: boolean;
  embedding_api_url?: string;
  /**
   * API key for embedding service.
   * WARNING: This value is included in YAML exports and localStorage persistence.
   * Do not use production API keys in the workbench.
   */
  embedding_api_key?: string;
  embedding_model?: string;
  similarity_threshold?: number;
  ambiguity_band?: number;
  top_k?: number;
  pattern_db_path?: string;
}

export interface GuardConfigMap {
  forbidden_path?: ForbiddenPathConfig;
  path_allowlist?: PathAllowlistConfig;
  egress_allowlist?: EgressAllowlistConfig;
  secret_leak?: SecretLeakConfig;
  patch_integrity?: PatchIntegrityConfig;
  shell_command?: ShellCommandConfig;
  mcp_tool?: McpToolConfig;
  prompt_injection?: PromptInjectionConfig;
  jailbreak?: JailbreakConfig;
  computer_use?: ComputerUseConfig;
  remote_desktop_side_channel?: RemoteDesktopSideChannelConfig;
  input_injection_capability?: InputInjectionCapabilityConfig;
  spider_sense?: SpiderSenseConfig;
}

export interface PolicySettings {
  fail_fast?: boolean;
  verbose_logging?: boolean;
  session_timeout_secs?: number;
}

export interface PostureState {
  description?: string;
  capabilities?: string[];
  budgets?: Record<string, number>;
}

export interface PostureTransition {
  from: string;
  to: string;
  on: string;
  after?: string;
}

export interface PostureConfig {
  initial: string;
  states: Record<string, PostureState>;
  transitions?: PostureTransition[];
}

// ---- Origin / Enclave types (v1.4.0) ----

export type OriginProvider =
  | "slack"
  | "teams"
  | "github"
  | "jira"
  | "email"
  | "discord"
  | "webhook";

export type SpaceType =
  | "channel"
  | "group"
  | "dm"
  | "thread"
  | "issue"
  | "ticket"
  | "pull_request"
  | "email_thread";

export type Visibility =
  | "private"
  | "internal"
  | "public"
  | "external_shared"
  | "unknown";

export type ProvenanceConfidence = "strong" | "medium" | "weak" | "unknown";

export type ActorType = "human" | "bot" | "service" | "unknown";

export type OriginDefaultBehavior = "deny" | "minimal_profile";

export interface OriginMatch {
  provider?: OriginProvider | string;
  tenant_id?: string;
  space_id?: string;
  space_type?: SpaceType | string;
  thread_id?: string;
  visibility?: Visibility;
  external_participants?: boolean;
  tags?: string[];
  sensitivity?: string;
  actor_role?: string;
  provenance_confidence?: ProvenanceConfidence;
}

export interface OriginDataPolicy {
  allow_external_sharing?: boolean;
  redact_before_send?: boolean;
  block_sensitive_outputs?: boolean;
}

export interface OriginBudgets {
  mcp_tool_calls?: number;
  egress_calls?: number;
  shell_commands?: number;
}

export interface BridgeTarget {
  provider?: OriginProvider | string;
  space_type?: SpaceType | string;
  tags?: string[];
  visibility?: Visibility;
}

export interface BridgePolicy {
  allow_cross_origin?: boolean;
  allowed_targets?: BridgeTarget[];
  require_approval?: boolean;
}

export interface OriginProfile {
  id: string;
  match_rules: OriginMatch;
  posture?: string;
  mcp?: McpToolConfig;
  egress?: EgressAllowlistConfig;
  data?: OriginDataPolicy;
  budgets?: OriginBudgets;
  bridge_policy?: BridgePolicy;
  explanation?: string;
}

export interface OriginsConfig {
  default_behavior?: OriginDefaultBehavior;
  profiles: OriginProfile[];
}

/**
 * Origin context for simulation scenarios (mirrors Rust OriginContext).
 * Passed to the simulation engine to test origin-aware enforcement.
 */
export interface OriginContext {
  provider: OriginProvider | string;
  tenant_id?: string;
  space_id?: string;
  space_type?: SpaceType | string;
  thread_id?: string;
  actor_id?: string;
  actor_type?: ActorType;
  actor_role?: string;
  visibility?: Visibility;
  external_participants?: boolean;
  tags?: string[];
  sensitivity?: string;
  provenance_confidence?: ProvenanceConfidence;
}

// ---- Top-level policy ----

export interface WorkbenchPolicy {
  version: PolicySchemaVersion;
  name: string;
  description: string;
  extends?: string;
  guards: GuardConfigMap;
  settings: PolicySettings;
  posture?: PostureConfig;
  origins?: OriginsConfig;
}

// ---- Workbench persistence ----

export interface SavedPolicy {
  id: string;
  policy: WorkbenchPolicy;
  yaml: string;
  createdAt: string;
  updatedAt: string;
}

// ---- Validation ----

export interface ValidationIssue {
  path: string;
  message: string;
  severity: "error" | "warning";
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationIssue[];
  warnings: ValidationIssue[];
}

// ---- Simulator ----

export type TestActionType =
  | "file_access"
  | "file_write"
  | "network_egress"
  | "shell_command"
  | "mcp_tool_call"
  | "patch_apply"
  | "user_input";

export type ThreatSeverity = "critical" | "high" | "medium" | "low" | "informational";

/** Common agent runtime types for the agent profile selector. */
export type AgentRuntime = "claude" | "gpt-4" | "gemini" | "llama" | "mistral" | "custom";

/**
 * Agent profile attached to a test scenario.
 * When fleet is connected, `agentId` references a real fleet agent.
 * When disconnected, the user can provide free-text values.
 */
export interface AgentProfile {
  /** Fleet agent ID (optional -- only set when selected from fleet). */
  agentId?: string;
  /** Display name for the agent. */
  agentName: string;
  /** Agent runtime type (e.g. "claude", "gpt-4", "custom"). */
  agentType: AgentRuntime;
  /** Optional list of permissions/capabilities the agent holds. */
  permissions?: string[];
}

export interface TestScenario {
  id: string;
  name: string;
  description: string;
  category: "attack" | "benign" | "edge_case";
  actionType: TestActionType;
  payload: Record<string, unknown>;
  expectedVerdict?: Verdict;
  /** Threat severity classification for UI display. */
  severity?: ThreatSeverity;
  /** MITRE ATT&CK or similar threat reference. */
  threatRef?: string;
  /** Optional origin context for v1.4.0 origin-aware simulation. */
  originContext?: OriginContext;
  /** Optional agent profile describing the agent executing this scenario. */
  agentProfile?: AgentProfile;
  /** Optional promptfoo red-team plugin identifier. */
  redteamPluginId?: string;
  /** Optional promptfoo red-team strategy identifier. */
  redteamStrategyId?: string;
}

export type SimulationEngine = "native" | "client" | "stubbed";

export interface GuardSimResult {
  guardId: GuardId;
  guardName: string;
  verdict: Verdict;
  message: string;
  evidence?: Record<string, unknown>;
  engine?: SimulationEngine;
}

export interface EvaluationPathStep {
  guard: string;
  stage: string;
  stage_duration_ms: number;
  result: string;
}

export interface SimulationResult {
  scenarioId: string;
  overallVerdict: Verdict;
  guardResults: GuardSimResult[];
  executedAt: string;
  /** Ordered evaluation path from the native engine. Empty for client-side simulations. */
  evaluationPath?: EvaluationPathStep[];
  /** Optional red-team grading result from promptfoo evaluation. */
  redteamGrade?: { pass: boolean; score: number; reason: string };
  /** Optional aggregate risk score from red-team evaluation. */
  riskScore?: { score: number; level: string };
}

// ---- Posture / Budget ----

export interface PostureBudget {
  name: string;
  limit: number;
  consumed: number;
  remaining: number;
}

export interface PostureReport {
  budgets: PostureBudget[];
  violations: string[];
  state: string;
  stateBefore: string;
  transitioned: boolean;
}

// ---- Compliance ----

export type ComplianceFramework = "hipaa" | "soc2" | "pci-dss";

export interface ComplianceRequirement {
  id: string;
  framework: ComplianceFramework;
  title: string;
  description: string;
  satisfiedBy: GuardId[];
  configCheck?: (guards: GuardConfigMap) => boolean;
}

export interface ComplianceScore {
  framework: ComplianceFramework;
  score: number;
  met: ComplianceRequirement[];
  gaps: ComplianceRequirement[];
}

// ---- Receipt ----

export interface Receipt {
  id: string;
  timestamp: string;
  verdict: Verdict;
  guard: string;
  policyName: string;
  action: { type: TestActionType; target: string };
  evidence: Record<string, unknown>;
  signature: string;
  publicKey: string;
  valid: boolean;
  /** "persistent" (Stronghold-stored key) or "ephemeral" (generated per-sign). */
  keyType?: "persistent" | "ephemeral";
  /** Imported receipts stay local and are never eligible for fleet sync. */
  imported?: boolean;
}

// ---- Guard metadata (for UI rendering) ----

export type GuardCategory =
  | "filesystem"
  | "network"
  | "content"
  | "tools"
  | "detection"
  | "cua";

export type ConfigFieldType =
  | "toggle"
  | "string_list"
  | "pattern_list"
  | "number_slider"
  | "number_input"
  | "select"
  | "secret_pattern_list";

export interface ConfigFieldDef {
  key: string;
  label: string;
  type: ConfigFieldType;
  description?: string;
  defaultValue?: unknown;
  options?: { value: string; label: string }[];
  min?: number;
  max?: number;
  step?: number;
}

export interface GuardMeta {
  id: GuardId;
  name: string;
  technicalName: string;
  description: string;
  category: GuardCategory;
  defaultVerdict: Verdict;
  icon: string;
  configFields: ConfigFieldDef[];
}
