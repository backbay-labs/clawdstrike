import type { TestActionType, Verdict, GuardSimResult } from "./types";


/** A single agent action observed in production via fleet */
export interface AgentEvent {
  id: string;
  timestamp: string;
  agentId: string;
  agentName: string;
  teamId?: string;
  sessionId: string;
  actionType: TestActionType;
  target: string;
  content?: string;
  verdict: Verdict;
  guardResults: GuardSimResult[];
  receiptId?: string;
  policyVersion: string;

  // Hunt enrichments (computed client-side)
  anomalyScore?: number;       // 0–1, deviation from baseline
  trustprintScore?: number;    // Spider Sense similarity
  flags: EventFlag[];
}

export type EventFlag =
  | { type: "anomaly"; reason: string; score: number }
  | { type: "escalated"; by: string; at: string; note?: string }
  | { type: "tag"; label: string; color?: string }
  | { type: "pattern-match"; patternId: string; patternName: string };


export interface StreamFilters {
  agentId?: string;
  teamId?: string;
  actionType?: TestActionType;
  verdict?: Verdict;
  minAnomalyScore?: number;
  timeRange: "1h" | "6h" | "24h" | "7d";
  search?: string;
}

export interface StreamStats {
  total: number;
  allowed: number;
  denied: number;
  warned: number;
  anomalies: number;
  byActionType: Record<string, number>;
}


export interface AgentBaseline {
  agentId: string;
  agentName: string;
  teamId?: string;
  period: { start: string; end: string };

  // Statistical profiles
  actionDistribution: Record<string, number>;
  hourlyActivity: number[];    // 24 buckets
  dailyActivity: number[];     // 7 buckets (Mon–Sun)
  topTargets: { target: string; count: number; actionType: string }[];
  avgSessionLength: number;
  avgDailyEvents: number;

  // Thresholds
  anomalyThreshold: number;
  driftSensitivity: "low" | "medium" | "high";

  // Drift tracking
  driftMetrics: DriftMetric[];
}

export interface DriftMetric {
  metric: string;
  baseline: number;
  current: number;
  percentChange: number;
  significance: "normal" | "notable" | "alert";
}


export type InvestigationStatus = "open" | "in-progress" | "resolved" | "false-positive";
export type InvestigationVerdict = "threat-confirmed" | "false-positive" | "policy-gap" | "inconclusive";
export type InvestigationAction = "policy-updated" | "pattern-added" | "agent-revoked" | "escalated";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Investigation {
  id: string;
  title: string;
  status: InvestigationStatus;
  severity: Severity;
  createdAt: string;
  updatedAt: string;
  createdBy: string;

  // Scope
  agentIds: string[];
  sessionIds: string[];
  timeRange: { start: string; end: string };
  eventIds: string[];

  // Findings
  annotations: Annotation[];

  // Outcome
  verdict?: InvestigationVerdict;
  actions?: InvestigationAction[];
}

export interface Annotation {
  id: string;
  eventId?: string;
  text: string;
  createdAt: string;
  createdBy: string;
}


export type PatternStatus = "draft" | "confirmed" | "promoted" | "dismissed";

export interface HuntPattern {
  id: string;
  name: string;
  description: string;
  discoveredAt: string;
  status: PatternStatus;

  // Pattern definition
  sequence: PatternStep[];

  // Evidence
  matchCount: number;
  exampleSessionIds: string[];
  agentIds: string[];

  // Promotion
  promotedToTrustprint?: string;
  promotedToScenario?: string;
}

export interface PatternStep {
  step: number;
  actionType: TestActionType;
  targetPattern: string;
  timeWindow?: number;  // max ms to next step
}


export interface AnomalyResult {
  score: number;           // 0–1
  factors: AnomalyFactor[];
}

export interface AnomalyFactor {
  name: string;
  weight: number;
  zScore: number;
  description: string;
}
