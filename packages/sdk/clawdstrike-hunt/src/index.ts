export {
  HuntError,
  QueryError,
  ParseError,
  IoError,
  CorrelationError,
  IocError,
  WatchError,
  ReportError,
  HuntAlertError,
  PlaybookError,
} from './errors.js';

export {
  EventSourceType,
  TimelineEventKind,
  NormalizedVerdict,
  QueryVerdict,
  RuleSeverity,
  IocType,
} from './types.js';

export type {
  TimelineEvent,
  HuntQuery,
  RuleCondition,
  RuleOutput,
  CorrelationRule,
  Alert,
  IocEntry,
  IocMatch,
  EvidenceItem,
  HuntReport,
  WatchConfig,
  WatchStats,
} from './types.js';

export {
  matchesQuery,
  parseQueryVerdict,
} from './query.js';

export { parseEnvelope, mergeTimeline } from './timeline.js';

export { defaultLocalDirs, queryLocalFiles, hunt } from './local.js';
export type { HuntOptions } from './local.js';

// Correlate
export {
  CorrelationEngine,
  correlate,
  detectIocType,
  IocDatabase,
  loadRulesFromFiles,
  parseRule,
  validateRule,
} from './correlate/index.js';

// Report
export {
  buildReport,
  evidenceFromAlert,
  evidenceFromEvents,
  evidenceFromIocMatches,
  collectEvidence,
  signReport,
  verifyReport,
} from './report.js';

// Watch
export { runWatch } from './watch.js';

// Decorators
export { guarded } from './decorator.js';
export type { GuardedOptions } from './decorator.js';

// Serialize
export { eventsToJSON, alertsToJSON, eventsToCSV, alertsToCSV } from './serialize.js';

// Playbook
export { Playbook } from './playbook.js';
export type { PlaybookResult } from './playbook.js';

// Testing
export { testRule, event } from './testing.js';
export type { TestResult, TestRuleOptions } from './testing.js';

// Replay
export { replay } from './replay.js';
export type { ReplayResult, ReplayOptions } from './replay.js';

// MITRE
export { mapEventToMitre, mapAlertToMitre, coverageMatrix } from './mitre.js';
export type { MitreTechnique } from './mitre.js';

// Anomaly
export { Baseline, scoreAnomalies } from './anomaly.js';
export type { ScoredEvent, BaselineData } from './anomaly.js';

// Streaming
export { stream, streamAll } from './stream.js';
export type { StreamOptions, StreamItem } from './stream.js';

// Export
export {
  WebhookAdapter,
  SplunkHECAdapter,
  ElasticAdapter,
  toStix,
  toCSV,
  toJSONL,
} from './export.js';
export type { ExportAdapter, RetryConfig } from './export.js';
export { ExportError } from './errors.js';
