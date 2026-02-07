/**
 * Spine Event Types - Normalized data model for Tetragon/Hubble/hushd events
 *
 * All runtime security events are normalized to SDREvent before being consumed
 * by views. This allows the views to work identically whether events come from
 * a live NATS/spine connection or the built-in demo simulator.
 */

// ---------------------------------------------------------------------------
// Core SDREvent
// ---------------------------------------------------------------------------

export type SDREventSource = "tetragon" | "hubble" | "hushd";

export type SDREventCategory =
  | "process_exec"
  | "process_exit"
  | "file_access"
  | "file_write"
  | "network_connect"
  | "network_flow"
  | "dns_query"
  | "policy_violation"
  | "secret_leak"
  | "privilege_escalation";

export type SDRSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface SDREvent {
  /** Unique event id */
  id: string;
  /** ISO-8601 timestamp */
  timestamp: string;
  /** Originating telemetry source */
  source: SDREventSource;
  /** Normalized event category */
  category: SDREventCategory;
  /** Severity score 0-1 */
  severity: number;
  /** Severity label */
  severityLabel: SDRSeverity;
  /** Human-readable summary */
  summary: string;
  /** Process or pod that generated the event */
  origin?: SDREventOrigin;
  /** Network-specific fields (for Hubble flows) */
  network?: SDRNetworkInfo;
  /** MITRE ATT&CK mapping (if applicable) */
  mitre?: SDRMitreMapping;
  /** Raw payload from the source system */
  raw?: Record<string, unknown>;
}

export interface SDREventOrigin {
  /** Process exec_id (Tetragon lineage tracking) */
  execId?: string;
  /** Parent exec_id for process tree reconstruction */
  parentExecId?: string;
  /** Binary path */
  binary?: string;
  /** Command-line arguments */
  args?: string[];
  /** Kubernetes pod name */
  pod?: string;
  /** Kubernetes namespace */
  namespace?: string;
  /** Node hostname */
  node?: string;
  /** Container ID */
  containerId?: string;
  /** UID of the process */
  uid?: number;
}

export interface SDRNetworkInfo {
  /** Source IP */
  srcIp?: string;
  /** Destination IP */
  dstIp?: string;
  /** Source port */
  srcPort?: number;
  /** Destination port */
  dstPort?: number;
  /** Protocol (tcp, udp, icmp) */
  protocol?: string;
  /** DNS name if resolved */
  dnsName?: string;
  /** Bytes transferred */
  bytes?: number;
  /** Flow direction: ingress or egress */
  direction?: "ingress" | "egress";
  /** Hubble verdict */
  verdict?: "forwarded" | "dropped" | "error" | "audit";
}

export interface SDRMitreMapping {
  /** MITRE ATT&CK technique ID (e.g. T1059.001) */
  techniqueId: string;
  /** Technique name */
  techniqueName: string;
  /** Tactic (e.g. execution, persistence) */
  tactic: string;
}

// ---------------------------------------------------------------------------
// Spine connection state
// ---------------------------------------------------------------------------

export type SpineConnectionStatus = "disconnected" | "connecting" | "connected" | "demo";

export interface SpineConnectionState {
  status: SpineConnectionStatus;
  natsUrl?: string;
  error?: string;
  eventCount: number;
  /** Timestamp of last received event */
  lastEventAt?: string;
}

// ---------------------------------------------------------------------------
// Hubble flow types (for network map)
// ---------------------------------------------------------------------------

export interface HubbleFlow {
  id: string;
  timestamp: string;
  source: HubbleEndpoint;
  destination: HubbleEndpoint;
  verdict: "forwarded" | "dropped" | "error" | "audit";
  type: "L3_L4" | "L7";
  protocol: string;
  port: number;
  bytes: number;
  isReply: boolean;
}

export interface HubbleEndpoint {
  ip: string;
  port?: number;
  identity?: number;
  namespace?: string;
  podName?: string;
  labels?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Attack chain building types
// ---------------------------------------------------------------------------

export interface LiveAttackChain {
  id: string;
  name: string;
  /** Root exec_id that started this chain */
  rootExecId: string;
  status: "active" | "contained" | "remediated";
  firstSeen: string;
  lastSeen: string;
  events: SDREvent[];
  techniques: LiveTechnique[];
}

export interface LiveTechnique {
  id: string;
  name: string;
  tactic: string;
  detected: boolean;
  confidence: number;
  /** Events that contributed to this technique detection */
  eventIds: string[];
}
