// --- Enum-like const objects ---

export const EventSourceType = {
  Tetragon: 'tetragon',
  Hubble: 'hubble',
  Receipt: 'receipt',
  Scan: 'scan',
} as const;
export type EventSourceType = (typeof EventSourceType)[keyof typeof EventSourceType];

export const TimelineEventKind = {
  ProcessExec: 'process_exec',
  ProcessExit: 'process_exit',
  ProcessKprobe: 'process_kprobe',
  NetworkFlow: 'network_flow',
  GuardDecision: 'guard_decision',
  ScanResult: 'scan_result',
} as const;
export type TimelineEventKind = (typeof TimelineEventKind)[keyof typeof TimelineEventKind];

export const NormalizedVerdict = {
  Allow: 'allow',
  Deny: 'deny',
  Warn: 'warn',
  None: 'none',
  Forwarded: 'forwarded',
  Dropped: 'dropped',
} as const;
export type NormalizedVerdict = (typeof NormalizedVerdict)[keyof typeof NormalizedVerdict];

/** @deprecated Use {@link NormalizedVerdict} instead. Will be removed in a future release. */
export const QueryVerdict = {
  Allow: 'allow',
  Deny: 'deny',
  Warn: 'warn',
  Forwarded: 'forwarded',
  Dropped: 'dropped',
} as const;
/** @deprecated Use {@link NormalizedVerdict} instead. */
export type QueryVerdict = (typeof QueryVerdict)[keyof typeof QueryVerdict];

export const RuleSeverity = {
  Low: 'low',
  Medium: 'medium',
  High: 'high',
  Critical: 'critical',
} as const;
export type RuleSeverity = (typeof RuleSeverity)[keyof typeof RuleSeverity];

export const IocType = {
  Sha256: 'sha256',
  Sha1: 'sha1',
  Md5: 'md5',
  Domain: 'domain',
  IPv4: 'ipv4',
  IPv6: 'ipv6',
  Url: 'url',
} as const;
export type IocType = (typeof IocType)[keyof typeof IocType];

// --- Interfaces ---

export interface TimelineEvent {
  timestamp: Date;
  source: EventSourceType;
  kind: TimelineEventKind;
  verdict: NormalizedVerdict;
  severity?: string;
  summary: string;
  process?: string;
  namespace?: string;
  pod?: string;
  actionType?: string;
  signatureValid?: boolean;
  raw?: unknown;
}

export interface HuntQuery {
  sources: EventSourceType[];
  verdict?: NormalizedVerdict;
  start?: Date;
  end?: Date;
  actionType?: string;
  process?: string;
  namespace?: string;
  pod?: string;
  limit: number;
  entity?: string;
}

export interface RuleCondition {
  source: string[];
  actionType?: string;
  verdict?: string;
  targetPattern?: string;
  notTargetPattern?: string;
  after?: string;
  within?: number;
  bind: string;
}

export interface RuleOutput {
  title: string;
  evidence: string[];
}

export interface CorrelationRule {
  schema: string;
  name: string;
  severity: RuleSeverity;
  description: string;
  window: number;
  conditions: RuleCondition[];
  output: RuleOutput;
}

export interface Alert {
  ruleName: string;
  severity: RuleSeverity;
  title: string;
  triggeredAt: Date;
  evidence: TimelineEvent[];
  description: string;
}

export interface IocEntry {
  indicator: string;
  iocType: IocType;
  description?: string;
  source?: string;
}

export interface IocMatch {
  event: TimelineEvent;
  matchedIocs: IocEntry[];
  matchField: string;
}

export interface EvidenceItem {
  index: number;
  sourceType: string;
  timestamp: Date;
  summary: string;
  data: Record<string, unknown>;
}

export interface HuntReport {
  title: string;
  generatedAt: Date;
  evidence: EvidenceItem[];
  merkleRoot: string;
  merkleProofs: string[];
  signature?: string;
  signer?: string;
}

export interface WatchConfig {
  natsUrl: string;
  natsCreds?: string;
  rules: CorrelationRule[];
  maxWindow: number;
}

export interface WatchStats {
  eventsProcessed: number;
  alertsTriggered: number;
  startTime: Date;
}
