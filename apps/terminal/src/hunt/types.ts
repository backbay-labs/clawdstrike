// hunt/types.ts - TypeScript types mirroring Rust hunt CLI JSON output

// --- Event Sources ---

export type EventSource = "tetragon" | "hubble" | "receipt" | "spine"

// --- Timeline ---

export type TimelineEventKind =
  | "process_exec"
  | "process_exit"
  | "file_open"
  | "file_write"
  | "file_delete"
  | "network_connect"
  | "network_accept"
  | "network_dns"
  | "policy_check"
  | "policy_violation"
  | "checkpoint"
  | "attestation"
  | "unknown"

export type NormalizedVerdict = "allow" | "deny" | "audit" | "unknown"

export interface TimelineEvent {
  timestamp: string
  source: EventSource
  kind: TimelineEventKind
  verdict: NormalizedVerdict
  summary: string
  details: Record<string, unknown>
  raw?: unknown
}

// --- Correlation Rules & Alerts ---

export type RuleSeverity = "low" | "medium" | "high" | "critical"

export interface RuleCondition {
  source?: EventSource
  kind?: TimelineEventKind
  verdict?: NormalizedVerdict
  pattern?: string
  field?: string
  value?: string
}

export interface RuleOutput {
  title: string
  severity: RuleSeverity
  description?: string
  mitre_attack?: string[]
  evidence_fields?: string[]
}

export interface CorrelationRule {
  name: string
  description?: string
  severity: RuleSeverity
  window_seconds: number
  conditions: RuleCondition[]
  min_count?: number
  output: RuleOutput
}

export interface Alert {
  rule: string
  severity: RuleSeverity
  timestamp: string
  title: string
  description?: string
  matched_events: TimelineEvent[]
  evidence: Record<string, unknown>
  mitre_attack?: string[]
}

// --- MCP Scan ---

export interface Tool {
  name: string
  description?: string
  input_schema?: Record<string, unknown>
}

export interface ServerSignature {
  name: string
  version?: string
  tools: Tool[]
  prompts: string[]
  resources: string[]
}

export type IssueSeverity = "info" | "warning" | "error" | "critical"

export interface Issue {
  severity: IssueSeverity
  code: string
  message: string
  detail?: string
}

export interface PolicyViolation {
  guard: string
  action_type: string
  target: string
  decision: "deny"
  reason?: string
}

export interface ScanError {
  path: string
  error: string
}

export interface ServerScanResult {
  name: string
  command: string
  args?: string[]
  env?: Record<string, string>
  signature?: ServerSignature
  issues: Issue[]
  violations: PolicyViolation[]
  error?: string
}

export interface ScanPathResult {
  path: string
  client: string
  servers: ServerScanResult[]
  errors: ScanError[]
}

// --- Scan Diff ---

export type ChangeKind = "added" | "removed" | "modified"

export interface ServerChange {
  server_name: string
  kind: ChangeKind
  old?: ServerScanResult
  new?: ServerScanResult
  tool_changes?: { added: string[]; removed: string[] }
}

export interface ScanDiff {
  timestamp: string
  previous_timestamp?: string
  changes: ServerChange[]
  summary: { added: number; removed: number; modified: number }
}

// --- IOC (Indicators of Compromise) ---

export type IocType =
  | "ip"
  | "domain"
  | "hash"
  | "url"
  | "email"
  | "file_path"
  | "command"

export interface IocEntry {
  type: IocType
  value: string
  source?: string
  severity?: RuleSeverity
  tags?: string[]
}

export interface IocMatch {
  ioc: IocEntry
  event: TimelineEvent
  context?: string
}

// --- Evidence & Reports ---

export interface EvidenceItem {
  index: number
  event: TimelineEvent
  relevance: string
  merkle_proof?: string[]
}

export interface HuntReport {
  id: string
  title: string
  severity: RuleSeverity
  created_at: string
  alert: Alert
  evidence: EvidenceItem[]
  merkle_root?: string
  summary: string
  recommendations?: string[]
}

// --- Watch Mode ---

export interface WatchStats {
  events_processed: number
  alerts_fired: number
  uptime_seconds: number
  active_rules: number
}

export type WatchJsonLine =
  | { type: "event"; data: TimelineEvent }
  | { type: "alert"; data: Alert }
  | { type: "stats"; data: WatchStats }

// --- MITRE ATT&CK ---

export interface MitreTechnique {
  id: string
  name: string
  tactic: string
  description?: string
}

// --- Playbook ---

export type PlaybookStepStatus =
  | "pending"
  | "running"
  | "passed"
  | "failed"
  | "skipped"

export interface PlaybookStep {
  name: string
  description: string
  command: string
  args: string[]
  status: PlaybookStepStatus
  output?: unknown
  error?: string
  duration_ms?: number
}

export interface PlaybookResult {
  name: string
  steps: PlaybookStep[]
  started_at: string
  completed_at?: string
  success: boolean
  report?: HuntReport
}
