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
  body_sha256?: string;
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
  max_executions?: number;
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

export interface ResponseExecutionActor {
  userId?: string;
  sessionId?: string;
  agentId?: string;
  workloadId?: string;
  approvalId?: string;
  endpointId?: string;
  [key: string]: unknown;
}

export interface ResponseExecutionEvidenceBundle {
  bundleId?: string;
  graphSliceId?: string;
  contentHash?: string;
  nodeCount?: number;
  edgeCount?: number;
  [key: string]: unknown;
}

export interface ResponseExecutionEffect {
  effectId?: string;
  effectType?: string;
  target?: string;
  artifact?: string | null;
  contentHash?: string | null;
  byteCount?: number | null;
  [key: string]: unknown;
}

export interface ResponseExecutionReport {
  executionId: string;
  actionId?: string;
  action?: string;
  status?: string;
  rootNodeId?: string;
  completedAt?: string;
  ttlSeconds?: number;
  rollbackRef?: string;
  reason?: string;
  actor?: ResponseExecutionActor;
  evidenceBundle?: ResponseExecutionEvidenceBundle;
  effects?: ResponseExecutionEffect[];
  [key: string]: unknown;
}

export interface ResponseExecutionRecord {
  execution: ResponseExecutionReport;
  expiresAt?: string;
  expired?: boolean;
  rollbackRef?: string;
  affectedIdentityCount?: number;
  affectedToolCount?: number;
  affectedIdentities?: CausalSliceAffectedIdentities;
  affectedTools?: CausalSliceAffectedTool[];
}

export interface ResponseExecutionsResponse {
  path?: string;
  execution_count: number;
  executions: ResponseExecutionRecord[];
}

export interface ResponseActionPlan {
  actionId: string;
  action: EndpointDecisionAction;
  dryRun: boolean;
  rootNodeId: string;
  graphSliceId: string;
  ttlSeconds: number;
  rollbackRef: string;
  reason: string;
  createdAt: string;
  expiresAt: string;
  nodeCount: number;
  edgeCount: number;
}

export interface ResponseActionInput {
  action: EndpointDecisionAction;
  rootNodeId?: string;
  process?: EndpointProcessInput;
  actor?: ResponseExecutionActor;
  ttlSeconds?: number;
  reason?: string;
  dryRun?: boolean;
}

export interface EvidenceBundleArtifactJson {
  bundleId: string;
  path?: string | null;
  byteCount: number;
  contentHash: string;
}

export interface ResponseActionResponse {
  plan: ResponseActionPlan;
  graph: CausalGraphJson;
  affectedIdentityCount?: number;
  affectedToolCount?: number;
  affectedIdentities?: CausalSliceAffectedIdentities;
  affectedTools?: CausalSliceAffectedTool[];
  receipt: SignedReceiptJson;
  execution?: ResponseExecutionReport | null;
  evidenceBundleArtifact?: EvidenceBundleArtifactJson | null;
  executionReceipt?: SignedReceiptJson | null;
  evidenceBundleReceipt?: SignedReceiptJson | null;
}

export interface ResponseRollbackReport {
  rollbackId: string;
  executionId: string;
  action: EndpointDecisionAction | string;
  status: string;
  rootNodeId?: string;
  graphSliceId?: string;
  ttlSeconds: number;
  rollbackRef: string;
  reason: string;
  completedAt?: string;
  effects: ResponseExecutionEffect[];
  summary?: string;
  [key: string]: unknown;
}

export interface ResponseExecutionRollbackResponse {
  path?: string | null;
  execution: ResponseExecutionRecord;
  rollback: ResponseRollbackReport;
  receipt: SignedReceiptJson;
}

export interface ResponseExecutionRollbackInput {
  reason?: string;
}

export interface AgentSecretTouchesInput {
  sessionId?: string;
  credentialKind?: string;
  requireAgentContext?: boolean;
  upstreamDepth?: number;
  downstreamDepth?: number;
  limit?: number;
}

export interface AgentSecretTouch {
  credentialNodeId: string;
  credentialLabel: string;
  credentialKind?: string | null;
  path?: string | null;
  name?: string | null;
  agentNodeIds: string[];
  agentLabels: string[];
  processNodeIds: string[];
  graph: CausalGraphJson;
  receipt: SignedReceiptJson;
}

export interface AgentSecretTouchesResponse {
  touchCount: number;
  touches: AgentSecretTouch[];
}

export interface AgentSecretTouchesPublishedEvent {
  eventId: string;
  rawRef: string;
  credentialNodeId: string;
}

export interface AgentSecretTouchesFleetPublishResponse {
  touchCount: number;
  publishedCount: number;
  events: AgentSecretTouchesPublishedEvent[];
}

export interface EndpointGraphReference {
  graphSliceId?: string;
  rootNodeId?: string;
  processNodeId?: string;
  contentHash?: string;
  nodeCount?: number;
  edgeCount?: number;
  [key: string]: unknown;
}

export interface EndpointProviderState {
  providerId?: string;
  providerKind?: string;
  installed?: boolean;
  active?: boolean;
  healthy?: boolean;
  degraded?: boolean;
  degradationReasons?: string[];
  droppedEventCount?: number;
  deadlineMissCount?: number;
  fullDiskAccess?: boolean | null;
  lastSeen?: string | null;
  stale?: boolean;
  [key: string]: unknown;
}

export interface EndpointSensorState {
  providers: EndpointProviderState[];
  [key: string]: unknown;
}

export type SignedReceiptJson = Record<string, unknown>;

export type EndpointTelemetryPrivacyMode =
  | "local_only"
  | "hashes_features"
  | "summary_with_receipts"
  | "raw_artifact_permitted";

export type EndpointEvidenceRedactionClass =
  | "hash_only"
  | "metadata_only"
  | "redacted"
  | "local_only"
  | "raw_artifact_permitted";

export interface EndpointTelemetryFieldProjection {
  fieldPath: string;
  redactionClass: EndpointEvidenceRedactionClass;
  valueHash?: string | null;
  featureValue?: string | null;
  rawValue?: string | null;
  reason: string;
}

export interface EndpointTelemetryObservationProjection {
  observationId: string;
  eventKind: string;
  fieldCount: number;
  rawSuppressedCount: number;
  localOnlyCount: number;
  projections: EndpointTelemetryFieldProjection[];
}

export interface EndpointTelemetryPrivacyReport {
  reportId: string;
  privacyMode: EndpointTelemetryPrivacyMode;
  rawArtifactUploadPermitted: boolean;
  rawArtifactApprovalId?: string | null;
  rawArtifactApprovalReasonHash?: string | null;
  observationCount: number;
  fieldCount: number;
  hashOnlyCount: number;
  metadataOnlyCount: number;
  redactedCount: number;
  rawSuppressedCount: number;
  localOnlyCount: number;
  observations: EndpointTelemetryObservationProjection[];
}

export interface EndpointTelemetryPrivacyPolicyDecision {
  requestedPrivacyMode: EndpointTelemetryPrivacyMode;
  effectivePrivacyMode: EndpointTelemetryPrivacyMode;
  rawArtifactUploadRequested: boolean;
  rawArtifactUploadAllowed: boolean;
  rawArtifactApprovalRequired: boolean;
  rawArtifactApprovalProvided: boolean;
  rawArtifactApprovalId?: string | null;
  rawArtifactApprovalReasonHash?: string | null;
  policySource: string;
  deniedReason?: string | null;
}

export interface CreatePrivacyReportInput {
  observations: Record<string, unknown>[];
  privacyMode?: EndpointTelemetryPrivacyMode;
  rawArtifactApprovalId?: string;
  rawArtifactApprovalReason?: string;
}

export interface CreatePrivacyReportResponse {
  report: EndpointTelemetryPrivacyReport;
  privacy_policy: EndpointTelemetryPrivacyPolicyDecision;
  receipt: SignedReceiptJson;
}

export interface CausalGraphNode {
  node_id?: string;
  nodeId?: string;
  kind?: string;
  label?: string;
  attributes?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface CausalGraphEdge {
  from?: string;
  to?: string;
  kind?: string;
  [key: string]: unknown;
}

export interface CausalGraphJson {
  nodes?: Record<string, CausalGraphNode>;
  edges?: CausalGraphEdge[];
  [key: string]: unknown;
}

export interface DetectionFindingJson {
  findingId?: string;
  ruleId?: string;
  title?: string;
  severity?: string;
  [key: string]: unknown;
}

export interface FindingGroupAffectedIdentity {
  nodeId: string;
  label: string;
  id: string;
}

export interface FindingGroupAffectedIdentities {
  hosts: FindingGroupAffectedIdentity[];
  users: FindingGroupAffectedIdentity[];
  sessions: FindingGroupAffectedIdentity[];
  agents: FindingGroupAffectedIdentity[];
  workloads: FindingGroupAffectedIdentity[];
  approvals: FindingGroupAffectedIdentity[];
}

export interface FindingGroupAffectedTool {
  nodeId: string;
  label: string;
  toolName: string;
}

export type CausalSliceAffectedIdentity = FindingGroupAffectedIdentity;
export type CausalSliceAffectedIdentities = FindingGroupAffectedIdentities;
export type CausalSliceAffectedTool = FindingGroupAffectedTool;

export interface FindingGroup {
  groupId: string;
  rootNodeId: string;
  rootLabel: string;
  findingCount: number;
  nodeCount: number;
  edgeCount: number;
  ruleIds: string[];
  findingIds: string[];
  findings: DetectionFindingJson[];
  affectedIdentityCount?: number;
  affectedToolCount?: number;
  affectedIdentities?: FindingGroupAffectedIdentities;
  affectedTools?: FindingGroupAffectedTool[];
  graph: CausalGraphJson;
  receipt: SignedReceiptJson;
}

export interface FindingGroupsResponse {
  groupCount: number;
  findingCount: number;
  groups: FindingGroup[];
}

export interface FindingGroupsQuery {
  limit?: number;
  maxDepth?: number;
}

export interface EndpointProcessInput {
  processGuid?: string;
  process_guid?: string;
  pid?: number;
  image?: string;
  commandLine?: string;
  command_line?: string;
  [key: string]: unknown;
}

export interface CausalSubgraphInput {
  rootNodeId?: string;
  process?: EndpointProcessInput;
  maxDepth?: number;
}

export interface CausalSubgraphResponse {
  root_node_id: string;
  max_depth: number;
  node_count: number;
  edge_count: number;
  affected_identity_count?: number;
  affected_tool_count?: number;
  affected_identities?: CausalSliceAffectedIdentities;
  affected_tools?: CausalSliceAffectedTool[];
  graph: CausalGraphJson;
  receipt: SignedReceiptJson;
}

export interface CausalContextInput {
  rootNodeId?: string;
  process?: EndpointProcessInput;
  upstreamDepth?: number;
  downstreamDepth?: number;
}

export interface CausalContextResponse {
  root_node_id: string;
  upstream_depth: number;
  downstream_depth: number;
  node_count: number;
  edge_count: number;
  affected_identity_count?: number;
  affected_tool_count?: number;
  affected_identities?: CausalSliceAffectedIdentities;
  affected_tools?: CausalSliceAffectedTool[];
  graph: CausalGraphJson;
  receipt: SignedReceiptJson;
}

export type GraphSliceKind = "causal_subgraph" | "causal_context";
export type EndpointDecisionAction =
  | "allow"
  | "observe"
  | "warn"
  | "alert"
  | "block"
  | "restrict_egress"
  | "suspend_process_tree"
  | "terminate_process_tree"
  | "quarantine_file"
  | "revoke_grant"
  | "disable_persistence"
  | "collect_evidence";
export type EndpointSimulationImpactLevel = "none" | "low" | "medium" | "high" | "critical";

export interface GraphSliceExportInput {
  rootNodeId?: string;
  process?: EndpointProcessInput;
  sliceKind?: GraphSliceKind;
  maxDepth?: number;
  upstreamDepth?: number;
  downstreamDepth?: number;
  reason?: string;
}

export interface EndpointEvidenceBundleReferenceJson {
  bundleId: string;
  graphSliceId: string;
  contentHash: string;
  nodeCount: number;
  edgeCount: number;
  createdAt?: string;
}

export interface GraphSliceExportResponse {
  rootNodeId: string;
  sliceKind: GraphSliceKind;
  nodeCount: number;
  edgeCount: number;
  affectedIdentityCount?: number;
  affectedToolCount?: number;
  affectedIdentities?: CausalSliceAffectedIdentities;
  affectedTools?: CausalSliceAffectedTool[];
  graph: CausalGraphJson;
  bundle: EndpointEvidenceBundleReferenceJson;
  artifact: EvidenceBundleArtifactJson;
  receipt: SignedReceiptJson;
}

export interface EndpointPolicySnapshotJson {
  policyVersion: string;
  policyHash: string;
  policyEpoch: number;
}

export interface PolicySimulationAffectedNode {
  nodeId: string;
  kind: string;
  label: string;
  breakageScore: number;
  reason: string;
}

export interface PolicySimulationIdentityContext {
  identityKind: string;
  value: string;
  sourceNodeId: string;
  sourceNodeKind: string;
}

export interface PolicySimulationToolContext {
  toolName: string;
  toolCallId?: string;
  sourceNodeId: string;
}

export interface PolicySimulationReport {
  simulationId: string;
  ruleId: string;
  action: EndpointDecisionAction;
  rootNodeId: string;
  graphSliceId: string;
  wouldBlock: boolean;
  createdAt: string;
  affectedNodeCount: number;
  affectedEdgeCount: number;
  affectedProcessCount: number;
  affectedFileCount: number;
  affectedNetworkCount: number;
  affectedCredentialCount: number;
  affectedToolCount: number;
  developerBreakageScore: number;
  impactLevel: EndpointSimulationImpactLevel;
  summary: string;
  affectedNodes: PolicySimulationAffectedNode[];
  affectedIdentities?: PolicySimulationIdentityContext[];
  affectedTools?: PolicySimulationToolContext[];
}

export interface PolicyReplayReport {
  replayId: string;
  replayedAt: string;
  mode: string;
  policy: EndpointPolicySnapshotJson;
  rootNodeId: string;
  rootLabel: string;
  rootKind: string;
  action: EndpointDecisionAction;
  graphSliceId: string;
  observationCount: number;
  nodeCount: number;
  edgeCount: number;
  flightRecorderObservationCount: number;
  wouldEnforce: boolean;
  developerBreakageScore: number;
  impactLevel: EndpointSimulationImpactLevel;
  summary: string;
}

export interface PolicyReplayInput {
  rootNodeId?: string;
  process?: EndpointProcessInput;
  action?: EndpointDecisionAction;
  ruleId?: string;
  description?: string;
  maxDepth?: number;
}

export interface PolicyReplayResponse {
  replay: PolicyReplayReport;
  simulation: PolicySimulationReport;
  graph: CausalGraphJson;
  receipt: SignedReceiptJson;
}

export interface DetectionCandidate {
  ruleId: string;
  action: EndpointDecisionAction;
  description: string;
  rootNodeId: string;
  rootLabel: string;
  rootKind: string;
  graphSliceId: string;
}

export interface DetectionCandidateStage {
  stage: string;
  action: EndpointDecisionAction;
  promotionGate: string;
  recommended: boolean;
}

export interface DetectionCandidateInput {
  rootNodeId?: string;
  process?: EndpointProcessInput;
  action?: EndpointDecisionAction;
  description?: string;
  maxDepth?: number;
}

export interface DetectionCandidateResponse {
  candidate: DetectionCandidate;
  recommendedStage: string;
  stagePlan: DetectionCandidateStage[];
  simulation: PolicySimulationReport;
  graph: CausalGraphJson;
  receipt: SignedReceiptJson;
}

export interface StageDetectionInput extends DetectionCandidateInput {
  selectedStage?: string;
  stagedBy?: string;
  note?: string;
  crossWindowImpactHash?: string;
  crossWindowRecommendationHash?: string;
}

export interface StagedDetectionRecord {
  stagedDetectionId: string;
  stagedAt: string;
  stagedBy: string;
  stage: string;
  note?: string | null;
  policy: EndpointPolicySnapshotJson;
  candidate: DetectionCandidate;
  recommendedStage: string;
  stagePlan: DetectionCandidateStage[];
  simulation: PolicySimulationReport;
  simulationReceipt: SignedReceiptJson;
  crossWindowImpactHash?: string | null;
  crossWindowRecommendationHash?: string | null;
}

export interface StageDetectionResponse {
  path?: string | null;
  record: StagedDetectionRecord;
  graph: CausalGraphJson;
}

export interface PolicyDeltaInput {
  stagedDetectionId?: string;
  ruleId?: string;
  stage?: string;
  generatedBy?: string;
  note?: string;
}

export interface PolicyDeltaTargetPolicy {
  basePolicyVersion?: string;
  basePolicyHash: string;
  basePolicyEpoch?: number;
  targetPolicyEpoch: number;
}

export interface PolicyDeltaRollout {
  stage: string;
  action: EndpointDecisionAction;
  recommendedStage?: string;
  promotionGate?: string;
  developerBreakageScore?: number;
  impactLevel?: EndpointSimulationImpactLevel | string;
  wouldBlock?: boolean;
  crossWindowImpactHash?: string | null;
  crossWindowRecommendationHash?: string | null;
}

export interface PolicyDeltaArtifact {
  schemaVersion?: string;
  policyDeltaId?: string;
  generatedAt?: string;
  generatedBy?: string;
  note?: string | null;
  stagedDetectionId?: string;
  sourceSimulationId?: string;
  sourceSimulationReceiptId?: string | null;
  sourceAffectedIdentities?: PolicySimulationIdentityContext[];
  sourceAffectedTools?: PolicySimulationToolContext[];
  candidate?: Partial<DetectionCandidate>;
  targetPolicy: PolicyDeltaTargetPolicy;
  rollout: PolicyDeltaRollout;
  policyPatch?: Record<string, unknown>;
}

export interface PolicyDeltaRecord {
  policyDeltaId: string;
  generatedAt?: string;
  generatedBy?: string;
  ruleId: string;
  stage: string;
  action: EndpointDecisionAction;
  artifactHash: string;
  artifactPath?: string | null;
  artifact: PolicyDeltaArtifact;
  receipt: SignedReceiptJson;
}

export interface PolicyDeltaResponse {
  path?: string | null;
  record: PolicyDeltaRecord;
}

export interface PolicyDeltaApplyInput {
  dryRun?: boolean;
  allowBasePolicyDrift?: boolean;
  reloadDaemonPolicy?: boolean;
  restartDaemon?: boolean;
  verifyProtectionState?: boolean;
  providerAckTimeoutMs?: number;
  appliedBy?: string;
  actor?: ResponseExecutionActor;
  note?: string;
}

export interface PolicyDeltaApplyRecord {
  policyDeltaId: string;
  appliedAt: string;
  appliedBy: string;
  note?: string | null;
  dryRun: boolean;
  applied: boolean;
  allowBasePolicyDrift: boolean;
  crossWindowImpactHash?: string | null;
  crossWindowRecommendationHash?: string | null;
  policyPath: string;
  backupPath?: string | null;
  expectedBasePolicyHash: string;
  previousPolicyHash: string;
  newPolicyHash: string;
  previousPolicyEpoch: number;
  newPolicyEpoch: number;
}

export interface PolicyDeltaProviderAcknowledgementPoll {
  requested?: boolean;
  timeoutMs?: number;
  elapsedMs?: number;
  attempts?: number;
  satisfied?: boolean;
}

export interface PolicyDeltaProviderAcknowledgement {
  providerId?: string;
  providerKind?: string;
  active?: boolean;
  observedPolicyEpoch?: number | null;
  expectedPolicyEpoch?: number;
  policyEpochMatches?: boolean | null;
  policySynced?: boolean | null;
  enforcementReady?: boolean | null;
  acknowledged?: boolean;
  reasons?: string[];
}

export interface PolicyDeltaApplyEnforcementProof {
  policySyncedToDisk?: boolean;
  crossWindowImpactHash?: string | null;
  crossWindowRecommendationHash?: string | null;
  localPolicy?: EndpointPolicySnapshotJson;
  daemonPolicyReload?: Record<string, unknown>;
  providerStatusRefresh?: Record<string, unknown>;
  providerAcknowledgementPoll?: PolicyDeltaProviderAcknowledgementPoll;
  providerPolicyAcknowledgements?: PolicyDeltaProviderAcknowledgement[];
  daemonRestartRequested?: boolean;
  daemonRestarted?: boolean;
  daemonRestartError?: string | null;
  daemon?: Record<string, unknown>;
  daemonPolicyVersion?: string | null;
  sensorState?: Record<string, unknown>;
  receipt?: SignedReceiptJson;
  degradedProviderReceipts?: SignedReceiptJson[];
}

export interface PolicyDeltaApplyResponse {
  record: PolicyDeltaApplyRecord;
  policyDelta: PolicyDeltaRecord;
  receipt: SignedReceiptJson | null;
  postApplyEnforcement?: PolicyDeltaApplyEnforcementProof | null;
}

export interface ResponseExecutionProofResponse {
  executionPath?: string;
  receiptPath?: string;
  execution: ResponseExecutionRecord;
  graph: EndpointGraphReference;
  affectedIdentityCount?: number;
  affectedToolCount?: number;
  affectedIdentities?: CausalSliceAffectedIdentities;
  affectedTools?: CausalSliceAffectedTool[];
  providerState: EndpointSensorState;
  evidenceBundleArtifact?: EvidenceBundleArtifactJson;
  requestReceipt: SignedReceiptJson;
  executionReceipt: SignedReceiptJson;
  evidenceBundleReceipt: SignedReceiptJson;
  transitionReceipts?: SignedReceiptJson[];
  rollbackReceipts?: SignedReceiptJson[];
  acknowledgementReceipts?: SignedReceiptJson[];
}

export interface NetworkExtensionEgressPolicyProofInput {
  refreshProviders?: boolean;
  providerRefreshTimeoutMs?: number;
  executionId?: string;
}

export interface NetworkExtensionReloadDeliveryProof {
  executionId: string;
  observed: boolean;
  matched: boolean;
  requestIdMatches: boolean;
  generationMatches: boolean;
  policySnapshotPathMatches: boolean;
  providerReloaded?: boolean | null;
}

export interface NetworkExtensionEgressPolicyProofResponse {
  providerPolicyPath: string;
  snapshotPresent: boolean;
  snapshotDecodable: boolean;
  snapshotHash?: string | null;
  generatedAt?: string | null;
  restrictionCount: number;
  activeRestrictionCount: number;
  expiredRestrictionCount: number;
  enforcementReady: boolean;
  flowCounterObserved?: boolean;
  observedFlowCount?: number;
  blockedFlowCount?: number;
  remediationRequestCount?: number;
  droppedVerdictCount?: number;
  providerReloadObserved?: boolean;
  providerReloadRequestId?: string | null;
  providerReloadGeneration?: number | null;
  providerReloadPolicySnapshotPath?: string | null;
  providerReloadAccepted?: boolean | null;
  providerReloadReloaded?: boolean | null;
  providerReloadError?: string | null;
  providerReloadDelivery?: NetworkExtensionReloadDeliveryProof | null;
  readError?: string | null;
  providerStatusRefresh?: Record<string, unknown>;
  networkExtensionProvider?: Record<string, unknown>;
  sensorState?: EndpointSensorState;
  receipt: SignedReceiptJson;
  degradedProviderReceipts?: SignedReceiptJson[];
}

export interface EndpointEvidenceArchiveRecord {
  tenantId?: string;
  archiveId: string;
  rawRef: string;
  archiveHash: string;
  bundleId: string;
  endpointAgentId?: string | null;
  eventId?: string | null;
  contentHash?: string | null;
  graphSliceId?: string | null;
  rawArtifactApprovalId?: string | null;
  rawArtifactApprovalReasonHash?: string | null;
  uploadedAt: string;
  expiresAt: string;
  retentionDays: number;
  sizeBytes: number;
  verification: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface EndpointEvidenceArchiveDownload {
  record: EndpointEvidenceArchiveRecord;
  archive: {
    bundle?: {
      bundleId?: string;
      graphSliceId?: string;
      contentHash?: string;
      nodeCount?: number;
      edgeCount?: number;
      createdAt?: string;
    };
    artifact?: Record<string, unknown>;
    graph?: Record<string, unknown>;
    receipts?: unknown[];
    [key: string]: unknown;
  };
}

export interface EndpointEvidenceArchiveControlUploadReport {
  controlApiUrl?: string | null;
  attempted: boolean;
  accepted: boolean;
  rawArtifactUploadAllowed: boolean;
  rawArtifactApprovalRequired: boolean;
  rawArtifactApprovalProvided: boolean;
  rawArtifactApprovalId?: string | null;
  rawArtifactApprovalReasonHash?: string | null;
  policySource: string;
  skippedReason?: string | null;
  httpStatus?: number | null;
  responseHash?: string | null;
  errorHash?: string | null;
  error?: string | null;
  retryQueued: boolean;
  retryId?: string | null;
  nextRetryAt?: string | null;
}

export interface EndpointEvidenceBundleFleetPublishResponse {
  bundleId: string;
  archiveId: string;
  archiveHash: string;
  published: boolean;
  queued: boolean;
  controlUpload?: EndpointEvidenceArchiveControlUploadReport | null;
  outboxId?: string | null;
  nextRetryAt?: string | null;
  eventId: string;
  rawRef: string;
}

export interface EndpointEvidenceArchiveBackfillInput {
  bundleId?: string;
  limit?: number;
  rawArtifactApprovalId?: string;
  rawArtifactApprovalReason?: string;
}

export interface EndpointEvidenceArchiveBackfillRecord {
  bundleId: string;
  archiveId: string;
  archiveHash: string;
  rawRef: string;
  controlUpload?: EndpointEvidenceArchiveControlUploadReport | null;
}

export interface EndpointEvidenceArchiveBackfillResponse {
  attempted: number;
  delivered: number;
  failed: number;
  skipped: number;
  records: EndpointEvidenceArchiveBackfillRecord[];
}

export interface CaseArtifactRef {
  id: string;
  caseId: string;
  artifactKind: string;
  artifactId: string;
  summary?: string;
  metadata: Record<string, unknown>;
  addedBy: string;
  addedAt: string;
}

export type FleetCaseSeverity = "low" | "medium" | "high" | "critical";
export type FleetCaseStatus = "open" | "in_progress" | "contained" | "closed";

export interface FleetCase {
  id: string;
  tenantId: string;
  title: string;
  summary?: string;
  severity: FleetCaseSeverity;
  status: FleetCaseStatus;
  createdBy: string;
  principalIds: string[];
  detectionIds: string[];
  responseActionIds: string[];
  grantIds: string[];
  tags: string[];
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface FleetEvidenceBundle {
  exportId: string;
  tenantId: string;
  caseId?: string | null;
  status: string;
  requestedBy: string;
  requestedAt: string;
  completedAt?: string | null;
  filePath?: string | null;
  sha256?: string | null;
  sizeBytes?: number | null;
  manifestRef?: string | null;
  expiresAt?: string | null;
  retentionDays: number;
  filters: Record<string, unknown>;
  artifactCounts: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface FleetCaseDetail {
  case: FleetCase;
  artifacts: CaseArtifactRef[];
  evidenceBundles: FleetEvidenceBundle[];
}

export interface CaseTimelineEvent {
  id: string;
  caseId: string;
  eventKind: string;
  actorId: string;
  payload: Record<string, unknown>;
  createdAt: string;
}

export interface CreateFleetCaseInput {
  title: string;
  summary?: string;
  severity: FleetCaseSeverity;
  status?: FleetCaseStatus;
  principalIds?: string[];
  detectionIds?: string[];
  responseActionIds?: string[];
  grantIds?: string[];
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface FleetCaseFilters {
  query?: string;
  status?: FleetCaseStatus;
  severity?: FleetCaseSeverity;
}

export interface UpdateFleetCaseInput {
  title?: string;
  summary?: string;
  severity?: FleetCaseSeverity;
  status?: FleetCaseStatus;
  principalIds?: string[];
  detectionIds?: string[];
  responseActionIds?: string[];
  grantIds?: string[];
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface ExportFleetCaseEvidenceBundleInput {
  start?: string;
  end?: string;
  principalIds?: string[];
  detectionIds?: string[];
  responseActionIds?: string[];
  sourceFamilies?: string[];
  includeRawEnvelopes?: boolean;
  includeOcsf?: boolean;
  retentionDays?: number;
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

async function brokerGet<T>(path: string, label: string, params?: URLSearchParams): Promise<T> {
  const qs = params?.toString();
  const url = `${getApiBase()}${path}${qs ? `?${qs}` : ""}`;
  const res = await fetch(url, { headers: getHeaders() });
  if (!res.ok) throw new Error(`${label} failed: ${res.status}`);
  return res.json();
}

async function brokerMutate<T>(
  path: string,
  label: string,
  method: "POST" | "DELETE",
  body?: unknown,
): Promise<T> {
  const res = await fetch(`${getApiBase()}${path}`, {
    method,
    headers: getHeaders(),
    ...(body !== undefined && { body: JSON.stringify(body) }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `${label} failed: ${res.status}`);
  }
  return res.json();
}

async function agentPost<T>(path: string, label: string, body: unknown): Promise<T> {
  const res = await fetch(`${getApiBase()}${path}`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `${label} failed: ${res.status}`);
  }
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
  return brokerGet("/api/v1/broker/capabilities", "Broker capability query", params);
}

export async function fetchBrokerCapability(
  capabilityId: string,
): Promise<BrokerCapabilityDetailResponse> {
  return brokerGet(`/api/v1/broker/capabilities/${capabilityId}`, "Broker capability fetch");
}

export async function fetchBrokerPreviews(filters?: {
  provider?: BrokerProvider;
  limit?: number;
}): Promise<BrokerPreviewListResponse> {
  const params = new URLSearchParams();
  if (filters?.provider) params.set("provider", filters.provider);
  if (filters?.limit != null) params.set("limit", String(filters.limit));
  return brokerGet("/api/v1/broker/previews", "Broker preview query", params);
}

export async function fetchBrokerPreview(previewId: string): Promise<BrokerPreviewResponse> {
  return brokerGet(`/api/v1/broker/previews/${previewId}`, "Broker preview fetch");
}

export async function approveBrokerPreview(
  previewId: string,
  approver?: string,
): Promise<BrokerIntentPreview> {
  const payload = await brokerMutate<BrokerPreviewResponse>(
    `/api/v1/broker/previews/${previewId}/approve`,
    "Broker preview approval",
    "POST",
    { approver },
  );
  return payload.preview;
}

export async function revokeBrokerCapability(
  capabilityId: string,
  reason?: string,
): Promise<BrokerCapabilityStatus> {
  const payload = await brokerMutate<{ capability: BrokerCapabilityStatus }>(
    `/api/v1/broker/capabilities/${capabilityId}/revoke`,
    "Broker capability revoke",
    "POST",
    { reason },
  );
  return payload.capability;
}

export async function fetchFrozenBrokerProviders(): Promise<BrokerFrozenProvidersResponse> {
  return brokerGet("/api/v1/broker/providers/freeze", "Broker provider freeze query");
}

export async function freezeBrokerProvider(
  provider: BrokerProvider,
  reason: string,
): Promise<BrokerFrozenProvidersResponse> {
  return brokerMutate(
    `/api/v1/broker/providers/${provider}/freeze`,
    "Broker provider freeze",
    "POST",
    { reason },
  );
}

export async function unfreezeBrokerProvider(
  provider: BrokerProvider,
): Promise<BrokerFrozenProvidersResponse> {
  return brokerMutate(
    `/api/v1/broker/providers/${provider}/freeze`,
    "Broker provider unfreeze",
    "DELETE",
  );
}

export async function replayBrokerCapability(capabilityId: string): Promise<BrokerReplayResponse> {
  return brokerMutate(
    `/api/v1/broker/capabilities/${capabilityId}/replay`,
    "Broker capability replay",
    "POST",
  );
}

export async function exportBrokerCompletionBundle(
  capabilityId: string,
): Promise<BrokerCompletionBundleResponse> {
  return brokerGet(
    `/api/v1/broker/capabilities/${capabilityId}/bundle`,
    "Broker completion bundle export",
  );
}

export async function revokeAllBrokerCapabilities(
  reason?: string,
): Promise<BrokerRevokeAllResponse> {
  return brokerMutate("/api/v1/broker/capabilities/revoke-all", "Broker revoke-all", "POST", {
    reason,
  });
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
  if (params?.stale_after_secs != null)
    query.set("stale_after_secs", String(params.stale_after_secs));
  if (params?.limit != null) query.set("limit", String(params.limit));

  const qs = query.toString();
  const res = await fetch(`${getApiBase()}/api/v1/agents/status${qs ? `?${qs}` : ""}`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error(`Agent status query failed: ${res.status}`);
  return res.json();
}

export async function fetchResponseExecutions(params?: {
  limit?: number;
}): Promise<ResponseExecutionsResponse> {
  const query = new URLSearchParams();
  if (params?.limit != null) query.set("limit", String(params.limit));

  const qs = query.toString();
  const res = await fetch(
    `${getApiBase()}/api/v1/agent/edr/response-executions${qs ? `?${qs}` : ""}`,
    { headers: getHeaders() },
  );
  if (!res.ok) throw new Error(`Response execution query failed: ${res.status}`);
  return res.json();
}

export async function createResponseAction(
  input: ResponseActionInput,
): Promise<ResponseActionResponse> {
  return agentPost("/api/v1/agent/edr/response-action", "Response action", input);
}

export async function rollbackResponseExecution(
  executionId: string,
  input?: ResponseExecutionRollbackInput,
): Promise<ResponseExecutionRollbackResponse> {
  const trimmed = executionId.trim();
  if (!trimmed) throw new Error("Response execution id is required");
  return agentPost(
    `/api/v1/agent/edr/response-executions/${encodeURIComponent(trimmed)}/rollback`,
    "Response execution rollback",
    input ?? {},
  );
}

export async function fetchAgentSecretTouches(
  input: AgentSecretTouchesInput,
): Promise<AgentSecretTouchesResponse> {
  return agentPost("/api/v1/agent/edr/agent-secret-touches", "Agent secret touches", input);
}

export async function publishAgentSecretTouchesToFleet(
  input: AgentSecretTouchesInput,
): Promise<AgentSecretTouchesFleetPublishResponse> {
  return agentPost(
    "/api/v1/agent/edr/agent-secret-touches/fleet-publish",
    "Agent secret touches fleet publish",
    input,
  );
}

export async function fetchResponseExecutionProof(
  executionId: string,
): Promise<ResponseExecutionProofResponse> {
  const trimmed = executionId.trim();
  if (!trimmed) throw new Error("Response execution id is required");

  const res = await fetch(
    `${getApiBase()}/api/v1/agent/edr/response-executions/${encodeURIComponent(trimmed)}/proof`,
    { headers: getHeaders() },
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Response execution proof fetch failed: ${res.status}`);
  }
  return res.json();
}

export async function fetchNetworkExtensionEgressPolicyProof(
  input: NetworkExtensionEgressPolicyProofInput = {},
): Promise<NetworkExtensionEgressPolicyProofResponse> {
  return agentPost(
    "/api/v1/agent/edr/network-extension/egress-policy/proof",
    "NetworkExtension egress policy proof",
    input,
  );
}

export async function fetchEndpointEvidenceArchive(
  archiveId: string,
): Promise<EndpointEvidenceArchiveRecord> {
  const trimmed = archiveId.trim();
  if (!trimmed) throw new Error("Endpoint evidence archive id is required");

  const res = await fetch(
    `${getApiBase()}/api/v1/hunt/evidence-bundle-archives/${encodeURIComponent(trimmed)}`,
    { headers: getHeaders() },
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Endpoint evidence archive fetch failed: ${res.status}`);
  }
  return res.json();
}

export async function publishEndpointEvidenceBundleToFleet(
  bundleId: string,
  input: { rawArtifactApprovalId?: string; rawArtifactApprovalReason?: string } = {},
): Promise<EndpointEvidenceBundleFleetPublishResponse> {
  const trimmed = bundleId.trim();
  if (!trimmed) throw new Error("Endpoint evidence bundle id is required");
  const params = new URLSearchParams();
  if (input.rawArtifactApprovalId?.trim()) {
    params.set("rawArtifactApprovalId", input.rawArtifactApprovalId.trim());
  }
  if (input.rawArtifactApprovalReason?.trim()) {
    params.set("rawArtifactApprovalReason", input.rawArtifactApprovalReason.trim());
  }
  const query = params.toString();
  const res = await fetch(
    `${getApiBase()}/api/v1/agent/edr/evidence-bundles/${encodeURIComponent(trimmed)}/fleet-publish${
      query ? `?${query}` : ""
    }`,
    { method: "POST", headers: getHeaders() },
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Endpoint evidence bundle fleet publish failed: ${res.status}`);
  }
  return res.json();
}

export async function backfillEndpointEvidenceArchivesToControl(
  input: EndpointEvidenceArchiveBackfillInput = {},
): Promise<EndpointEvidenceArchiveBackfillResponse> {
  return agentPost(
    "/api/v1/agent/edr/control-archive-uploads/backfill",
    "Endpoint evidence archive Control API backfill",
    {
      ...(input.bundleId?.trim() && { bundleId: input.bundleId.trim() }),
      ...(input.limit != null && { limit: input.limit }),
      ...(input.rawArtifactApprovalId?.trim() && {
        rawArtifactApprovalId: input.rawArtifactApprovalId.trim(),
      }),
      ...(input.rawArtifactApprovalReason?.trim() && {
        rawArtifactApprovalReason: input.rawArtifactApprovalReason.trim(),
      }),
    },
  );
}

export async function downloadEndpointEvidenceArchive(
  archiveId: string,
): Promise<EndpointEvidenceArchiveDownload> {
  const trimmed = archiveId.trim();
  if (!trimmed) throw new Error("Endpoint evidence archive id is required");

  const res = await fetch(
    `${getApiBase()}/api/v1/hunt/evidence-bundle-archives/${encodeURIComponent(trimmed)}/download`,
    { headers: getHeaders() },
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Endpoint evidence archive download failed: ${res.status}`);
  }
  return res.json();
}

export async function attachEndpointEvidenceArchiveToCase(
  caseId: string,
  archiveId: string,
): Promise<CaseArtifactRef> {
  const trimmedCaseId = caseId.trim();
  const trimmedArchiveId = archiveId.trim();
  if (!trimmedCaseId) throw new Error("Case id is required");
  if (!trimmedArchiveId) throw new Error("Endpoint evidence archive id is required");

  const res = await fetch(
    `${getApiBase()}/api/v1/cases/${encodeURIComponent(trimmedCaseId)}/artifacts`,
    {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({
        artifactKind: "endpoint_evidence_archive",
        artifactId: trimmedArchiveId,
      }),
    },
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Endpoint evidence archive case attach failed: ${res.status}`);
  }
  return res.json();
}

export async function fetchFleetCases(filters?: FleetCaseFilters): Promise<FleetCase[]> {
  const params = new URLSearchParams();
  if (filters?.query?.trim()) params.set("q", filters.query.trim());
  if (filters?.status) params.set("status", filters.status);
  if (filters?.severity) params.set("severity", filters.severity);

  const qs = params.toString();
  const res = await fetch(`${getApiBase()}/api/v1/cases${qs ? `?${qs}` : ""}`, {
    headers: getHeaders(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Fleet case query failed: ${res.status}`);
  }
  return res.json();
}

export async function createFleetCase(input: CreateFleetCaseInput): Promise<FleetCase> {
  const title = input.title.trim();
  if (!title) throw new Error("Case title is required");

  const body = {
    title,
    ...(input.summary !== undefined && { summary: input.summary }),
    severity: input.severity,
    ...(input.status !== undefined && { status: input.status }),
    ...(input.principalIds !== undefined && { principalIds: input.principalIds }),
    ...(input.detectionIds !== undefined && { detectionIds: input.detectionIds }),
    ...(input.responseActionIds !== undefined && { responseActionIds: input.responseActionIds }),
    ...(input.grantIds !== undefined && { grantIds: input.grantIds }),
    ...(input.tags !== undefined && { tags: input.tags }),
    ...(input.metadata !== undefined && { metadata: input.metadata }),
  };

  const res = await fetch(`${getApiBase()}/api/v1/cases`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Fleet case creation failed: ${res.status}`);
  }
  return res.json();
}

export async function fetchFleetCase(caseId: string): Promise<FleetCaseDetail> {
  const trimmed = caseId.trim();
  if (!trimmed) throw new Error("Case id is required");

  const res = await fetch(`${getApiBase()}/api/v1/cases/${encodeURIComponent(trimmed)}`, {
    headers: getHeaders(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Fleet case detail query failed: ${res.status}`);
  }
  return res.json();
}

export async function updateFleetCase(
  caseId: string,
  input: UpdateFleetCaseInput,
): Promise<FleetCase> {
  const trimmed = caseId.trim();
  if (!trimmed) throw new Error("Case id is required");

  const body = {
    ...(input.title !== undefined && { title: input.title.trim() }),
    ...(input.summary !== undefined && { summary: input.summary }),
    ...(input.severity !== undefined && { severity: input.severity }),
    ...(input.status !== undefined && { status: input.status }),
    ...(input.principalIds !== undefined && { principalIds: input.principalIds }),
    ...(input.detectionIds !== undefined && { detectionIds: input.detectionIds }),
    ...(input.responseActionIds !== undefined && { responseActionIds: input.responseActionIds }),
    ...(input.grantIds !== undefined && { grantIds: input.grantIds }),
    ...(input.tags !== undefined && { tags: input.tags }),
    ...(input.metadata !== undefined && { metadata: input.metadata }),
  };

  const res = await fetch(`${getApiBase()}/api/v1/cases/${encodeURIComponent(trimmed)}`, {
    method: "PATCH",
    headers: getHeaders(),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Fleet case update failed: ${res.status}`);
  }
  return res.json();
}

export async function bulkUpdateFleetCaseStatus(
  caseIds: string[],
  status: FleetCaseStatus,
): Promise<FleetCase[]> {
  const normalizedCaseIds = Array.from(
    new Set(caseIds.map((caseId) => caseId.trim()).filter(Boolean)),
  );
  if (normalizedCaseIds.length === 0) throw new Error("At least one case id is required");

  const res = await fetch(`${getApiBase()}/api/v1/cases/bulk`, {
    method: "PATCH",
    headers: getHeaders(),
    body: JSON.stringify({
      caseIds: normalizedCaseIds,
      status,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Fleet case bulk update failed: ${res.status}`);
  }
  return res.json();
}

export async function fetchFleetCaseTimeline(caseId: string): Promise<CaseTimelineEvent[]> {
  const trimmed = caseId.trim();
  if (!trimmed) throw new Error("Case id is required");

  const res = await fetch(`${getApiBase()}/api/v1/cases/${encodeURIComponent(trimmed)}/timeline`, {
    headers: getHeaders(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Fleet case timeline query failed: ${res.status}`);
  }
  return res.json();
}

export async function exportFleetCaseEvidenceBundle(
  caseId: string,
  input: ExportFleetCaseEvidenceBundleInput = {},
): Promise<FleetEvidenceBundle> {
  const trimmed = caseId.trim();
  if (!trimmed) throw new Error("Case id is required");

  const res = await fetch(
    `${getApiBase()}/api/v1/cases/${encodeURIComponent(trimmed)}/evidence/export`,
    {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify(input),
    },
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Fleet case evidence export failed: ${res.status}`);
  }
  return res.json();
}

export async function downloadFleetEvidenceBundle(exportId: string): Promise<Blob> {
  const trimmed = exportId.trim();
  if (!trimmed) throw new Error("Evidence bundle export id is required");

  const res = await fetch(
    `${getApiBase()}/api/v1/evidence-bundles/${encodeURIComponent(trimmed)}/download`,
    { headers: getHeaders() },
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Evidence bundle download failed: ${res.status}`);
  }
  return res.blob();
}

export async function createPrivacyReport(
  input: CreatePrivacyReportInput,
): Promise<CreatePrivacyReportResponse> {
  const res = await fetch(`${getApiBase()}/api/v1/agent/edr/privacy-report`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({
      ...(input.privacyMode && { privacyMode: input.privacyMode }),
      ...(input.rawArtifactApprovalId && { rawArtifactApprovalId: input.rawArtifactApprovalId }),
      ...(input.rawArtifactApprovalReason && {
        rawArtifactApprovalReason: input.rawArtifactApprovalReason,
      }),
      observations: input.observations,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Privacy report generation failed: ${res.status}`);
  }
  return res.json();
}

export async function fetchFindingGroups(
  params?: FindingGroupsQuery,
): Promise<FindingGroupsResponse> {
  const query = new URLSearchParams();
  if (params?.limit != null) query.set("limit", String(params.limit));
  if (params?.maxDepth != null) query.set("maxDepth", String(params.maxDepth));

  const qs = query.toString();
  const res = await fetch(`${getApiBase()}/api/v1/agent/edr/finding-groups${qs ? `?${qs}` : ""}`, {
    headers: getHeaders(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Finding group query failed: ${res.status}`);
  }
  return res.json();
}

export async function createCausalSubgraph(
  input: CausalSubgraphInput,
): Promise<CausalSubgraphResponse> {
  return agentPost("/api/v1/agent/edr/causal-subgraph", "Causal subgraph query", input);
}

export async function createCausalContext(
  input: CausalContextInput,
): Promise<CausalContextResponse> {
  return agentPost("/api/v1/agent/edr/causal-context", "Causal context query", input);
}

export async function exportGraphSlice(
  input: GraphSliceExportInput,
): Promise<GraphSliceExportResponse> {
  return agentPost("/api/v1/agent/edr/graph-slices/export", "Graph slice export", input);
}

export async function createPolicyReplay(input: PolicyReplayInput): Promise<PolicyReplayResponse> {
  return agentPost("/api/v1/agent/edr/policy-replay", "Policy replay", input);
}

export async function createDetectionCandidate(
  input: DetectionCandidateInput,
): Promise<DetectionCandidateResponse> {
  return agentPost("/api/v1/agent/edr/detection-candidate", "Detection candidate", input);
}

export async function createStagedDetection(
  input: StageDetectionInput,
): Promise<StageDetectionResponse> {
  return agentPost("/api/v1/agent/edr/staged-detections", "Stage detection", input);
}

export async function createPolicyDelta(input: PolicyDeltaInput): Promise<PolicyDeltaResponse> {
  return agentPost("/api/v1/agent/edr/policy-deltas", "Policy delta", input);
}

export async function applyPolicyDelta(
  policyDeltaId: string,
  input: PolicyDeltaApplyInput,
): Promise<PolicyDeltaApplyResponse> {
  const trimmed = policyDeltaId.trim();
  if (!trimmed) throw new Error("Policy delta id is required");
  return agentPost(
    `/api/v1/agent/edr/policy-deltas/${encodeURIComponent(trimmed)}/apply`,
    "Policy delta apply",
    input,
  );
}

export async function dryRunPolicyDeltaApply(
  policyDeltaId: string,
  input?: Omit<PolicyDeltaApplyInput, "dryRun">,
): Promise<PolicyDeltaApplyResponse> {
  return applyPolicyDelta(policyDeltaId, { dryRun: true, ...input });
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
