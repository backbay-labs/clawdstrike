# Clawdstrike SIEM/SOAR Integration Overview

## Executive Summary

This specification defines the architecture and implementation plan for integrating Clawdstrike security telemetry with enterprise Security Information and Event Management (SIEM) and Security Orchestration, Automation and Response (SOAR) platforms.

Clawdstrike generates high-fidelity security events from AI agent execution including:
- Policy violations (forbidden path access, egress blocks, secret leaks)
- Guard decisions (allow/deny/warn with severity levels)
- IRM (Inline Reference Monitor) telemetry
- Audit trail for compliance

These events must flow to security operations centers for:
- Real-time threat detection and response
- Compliance auditing and reporting
- Incident investigation and forensics
- Correlation with traditional security events

## Problem Statement

### Current State

Clawdstrike currently provides:
1. Local audit logs (JSONL format in `.hush/audit.jsonl`)
2. In-memory event streaming via TypeScript/Rust APIs
3. Signed receipts for cryptographic verification

**Gaps:**
- No native SIEM connector framework
- No standardized event schema (ECS, CEF, OCSF)
- No webhook/streaming export capability
- No threat intelligence feed consumption
- No automated response orchestration

### Use Cases

| ID | Use Case | Priority |
|----|----------|----------|
| UC-1 | SOC analysts correlate agent violations with network events in Splunk | P0 |
| UC-2 | Automated PagerDuty alert on critical policy violations | P0 |
| UC-3 | Compliance team generates monthly audit reports from Elastic | P1 |
| UC-4 | Block known malicious domains via STIX/TAXII feeds | P1 |
| UC-5 | Slack notification to engineering on secret leak detection | P1 |
| UC-6 | Datadog dashboard for agent security posture | P2 |
| UC-7 | Sumo Logic aggregation across multi-tenant deployments | P2 |

## Proposed Architecture

### High-Level Design

```
+-------------------+     +---------------------------+     +-------------------+
|                   |     |    Clawdstrike Core       |     |                   |
|   AI Agent        |---->|  +-------------------+    |     |   SIEM/SOAR       |
|   Runtime         |     |  | HushEngine        |    |     |   Platforms       |
|                   |     |  | PolicyEngine      |    |     |                   |
+-------------------+     |  | IRM Router        |    |     | - Splunk          |
                          |  +--------+----------+    |     | - Elastic         |
                          |           |               |     | - Datadog         |
                          |           v               |     | - Sumo Logic      |
                          |  +-------------------+    |     | - PagerDuty       |
                          |  | Event Emitter     |    |     | - OpsGenie        |
                          |  | (EventBus)        |    |     | - Slack/Teams     |
                          |  +--------+----------+    |     +--------+----------+
                          |           |               |              ^
                          +-----------+---------------+              |
                                      |                              |
                                      v                              |
                          +---------------------------+              |
                          |    Exporter Framework     |              |
                          |  +-------------------+    |              |
                          |  | Schema Transform  |    |              |
                          |  | (ECS/CEF/OCSF)    |    |              |
                          |  +-------------------+    |              |
                          |  +-------------------+    |              |
                          |  | Batching/Retry    |    |              |
                          |  +-------------------+    |              |
                          |  +-------------------+    |              |
                          |  | Auth Provider     |    |              |
                          |  +-------------------+    +--------------+
                          +---------------------------+
```

### Component Architecture

```
+-----------------------------------------------------------------------+
|                         Exporter Framework                             |
+-----------------------------------------------------------------------+
|                                                                        |
|  +------------------+  +------------------+  +------------------+       |
|  |  EventBus        |  |  SchemaRegistry  |  |  CredentialStore |       |
|  |  - subscribe()   |  |  - ECS v8.x      |  |  - Vault         |       |
|  |  - emit()        |  |  - CEF           |  |  - K8s Secrets   |       |
|  |  - filter()      |  |  - OCSF v1.x     |  |  - Env vars      |       |
|  +------------------+  +------------------+  +------------------+       |
|                                                                        |
|  +---------------------------------------------------------------------+
|  |                        Exporter Trait                               |
|  +---------------------------------------------------------------------+
|  |  async fn export(&self, events: Vec<SecurityEvent>) -> Result<()>  |
|  |  fn name(&self) -> &str                                             |
|  |  fn schema(&self) -> SchemaFormat                                   |
|  +---------------------------------------------------------------------+
|                                                                        |
|  +------------------+  +------------------+  +------------------+       |
|  |  SplunkExporter  |  |  ElasticExporter |  |  DatadogExporter |       |
|  +------------------+  +------------------+  +------------------+       |
|  +------------------+  +------------------+  +------------------+       |
|  |  SumoLogicExp    |  |  PagerDutyExp    |  |  WebhookExporter |       |
|  +------------------+  +------------------+  +------------------+       |
|                                                                        |
+-----------------------------------------------------------------------+
```

## Core Data Model

### SecurityEvent Schema

```typescript
/**
 * Canonical security event for SIEM export.
 * Designed for compatibility with ECS, CEF, and OCSF.
 */
interface SecurityEvent {
  // Identity
  event_id: string;          // UUIDv7 for time-ordering
  event_type: SecurityEventType;
  event_category: EventCategory;

  // Timing
  timestamp: string;         // ISO 8601 with nanosecond precision
  ingested_at?: string;      // When received by SIEM

  // Source
  agent: {
    id: string;
    name: string;
    version: string;
    type: 'clawdstrike';
  };

  // Session context
  session: {
    id: string;
    user_id?: string;
    tenant_id?: string;
    environment?: string;    // dev/staging/prod
  };

  // Event data
  outcome: 'success' | 'failure' | 'unknown';
  action: string;            // Guard action that was evaluated

  // Security-specific
  threat: {
    indicator?: {
      type: 'domain' | 'file_path' | 'pattern';
      value: string;
    };
    tactic?: string;         // MITRE ATT&CK tactic
    technique?: string;      // MITRE ATT&CK technique
  };

  // Decision details
  decision: {
    allowed: boolean;
    guard: string;
    severity: Severity;
    reason: string;
    policy_hash?: string;
    ruleset?: string;
  };

  // Resource affected
  resource: {
    type: 'file' | 'network' | 'process' | 'tool';
    name: string;
    path?: string;
    host?: string;
    port?: number;
  };

  // Extensibility
  metadata: Record<string, unknown>;
  labels: Record<string, string>;
}

type SecurityEventType =
  | 'policy_violation'
  | 'policy_allow'
  | 'guard_block'
  | 'guard_warn'
  | 'secret_detected'
  | 'egress_blocked'
  | 'forbidden_path'
  | 'patch_rejected'
  | 'session_start'
  | 'session_end';

type EventCategory =
  | 'authentication'
  | 'authorization'
  | 'file'
  | 'network'
  | 'process'
  | 'configuration';
```

### Rust Equivalent

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Canonical security event for SIEM export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: Uuid,
    pub event_type: SecurityEventType,
    pub event_category: EventCategory,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingested_at: Option<DateTime<Utc>>,
    pub agent: AgentInfo,
    pub session: SessionInfo,
    pub outcome: Outcome,
    pub action: String,
    pub threat: ThreatInfo,
    pub decision: DecisionInfo,
    pub resource: ResourceInfo,
    #[serde(default)]
    pub metadata: serde_json::Value,
    #[serde(default)]
    pub labels: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    PolicyViolation,
    PolicyAllow,
    GuardBlock,
    GuardWarn,
    SecretDetected,
    EgressBlocked,
    ForbiddenPath,
    PatchRejected,
    SessionStart,
    SessionEnd,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Authentication,
    Authorization,
    File,
    Network,
    Process,
    Configuration,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Success,
    Failure,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(rename = "type")]
    pub agent_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indicator: Option<ThreatIndicator>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tactic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    #[serde(rename = "type")]
    pub indicator_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionInfo {
    pub allowed: bool,
    pub guard: String,
    pub severity: Severity,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
```

## Exporter Framework

### Trait Definition

```rust
use async_trait::async_trait;

/// Schema format for event transformation
#[derive(Debug, Clone, Copy)]
pub enum SchemaFormat {
    /// Elastic Common Schema
    Ecs,
    /// Common Event Format (ArcSight)
    Cef,
    /// Open Cybersecurity Schema Framework
    Ocsf,
    /// Raw Clawdstrike format
    Native,
}

/// Configuration for exporter behavior
#[derive(Debug, Clone)]
pub struct ExporterConfig {
    /// Maximum batch size before flush
    pub batch_size: usize,
    /// Maximum time to wait before flush (ms)
    pub flush_interval_ms: u64,
    /// Retry configuration
    pub retry: RetryConfig,
    /// Rate limiting
    pub rate_limit: Option<RateLimitConfig>,
}

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub backoff_multiplier: f64,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
}

/// Result of an export operation
#[derive(Debug)]
pub struct ExportResult {
    pub exported: usize,
    pub failed: usize,
    pub errors: Vec<ExportEventError>,
}

/// Error for individual event export failure
#[derive(Debug)]
pub struct ExportEventError {
    pub event_id: String,
    pub error: String,
    pub retryable: bool,
}

/// Error for complete export operation failure
#[derive(Debug, thiserror::Error)]
pub enum ExporterError {
    #[error("HTTP error: status {status}, body: {body}")]
    Http { status: u16, body: String },
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Authentication failed: {0}")]
    Auth(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Core trait for all SIEM/SOAR exporters
#[async_trait]
pub trait Exporter: Send + Sync {
    /// Unique name of this exporter
    fn name(&self) -> &str;

    /// Schema format this exporter uses
    fn schema(&self) -> SchemaFormat;

    /// Export a batch of events
    /// Returns ExportResult on success (may include partial failures in errors field)
    /// Returns ExporterError only for complete failures (auth, connection, etc.)
    async fn export(&self, events: Vec<SecurityEvent>) -> Result<ExportResult, ExporterError>;

    /// Health check
    async fn health_check(&self) -> Result<(), String>;

    /// Graceful shutdown
    async fn shutdown(&self) -> Result<(), String>;
}
```

### TypeScript Interface

```typescript
import { SecurityEvent } from './types';

export enum SchemaFormat {
  ECS = 'ecs',
  CEF = 'cef',
  OCSF = 'ocsf',
  Native = 'native',
}

export interface ExporterConfig {
  batchSize: number;
  flushIntervalMs: number;
  retry: RetryConfig;
  rateLimit?: RateLimitConfig;
}

export interface RetryConfig {
  maxRetries: number;
  initialBackoffMs: number;
  maxBackoffMs: number;
  backoffMultiplier: number;
}

export interface RateLimitConfig {
  requestsPerSecond: number;
  burstSize: number;
}

export interface ExportResult {
  exported: number;
  failed: number;
  errors: ExportError[];
}

export interface ExportError {
  eventId: string;
  error: string;
  retryable: boolean;
}

export interface Exporter {
  readonly name: string;
  readonly schema: SchemaFormat;

  export(events: SecurityEvent[]): Promise<ExportResult>;
  healthCheck(): Promise<void>;
  shutdown(): Promise<void>;
}

/**
 * Base class providing common exporter functionality
 */
export abstract class BaseExporter implements Exporter {
  abstract readonly name: string;
  abstract readonly schema: SchemaFormat;

  protected config: Required<ExporterConfig>;
  protected buffer: SecurityEvent[] = [];
  protected flushTimer: NodeJS.Timeout | null = null;

  constructor(config: Partial<ExporterConfig> = {}) {
    this.config = {
      batchSize: config.batchSize ?? 100,
      flushIntervalMs: config.flushIntervalMs ?? 5000,
      retry: config.retry ?? {
        maxRetries: 3,
        initialBackoffMs: 1000,
        maxBackoffMs: 30000,
        backoffMultiplier: 2,
      },
      rateLimit: config.rateLimit,
    };
  }

  async enqueue(event: SecurityEvent): Promise<void> {
    this.buffer.push(event);

    if (this.buffer.length >= this.config.batchSize) {
      await this.flush();
    } else if (!this.flushTimer) {
      this.flushTimer = setTimeout(
        () => this.flush(),
        this.config.flushIntervalMs
      );
    }
  }

  async flush(): Promise<ExportResult> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }

    const events = this.buffer.splice(0);
    if (events.length === 0) {
      return { exported: 0, failed: 0, errors: [] };
    }

    return this.exportWithRetry(events);
  }

  protected async exportWithRetry(
    events: SecurityEvent[]
  ): Promise<ExportResult> {
    let lastError: Error | null = null;
    let backoff = this.config.retry.initialBackoffMs;

    for (let attempt = 0; attempt <= this.config.retry.maxRetries; attempt++) {
      try {
        return await this.export(events);
      } catch (err) {
        lastError = err as Error;

        if (attempt < this.config.retry.maxRetries) {
          await this.sleep(backoff);
          backoff = Math.min(
            backoff * this.config.retry.backoffMultiplier,
            this.config.retry.maxBackoffMs
          );
        }
      }
    }

    return {
      exported: 0,
      failed: events.length,
      errors: events.map(e => ({
        eventId: e.event_id,
        error: lastError?.message ?? 'Unknown error',
        retryable: false,
      })),
    };
  }

  protected sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  abstract export(events: SecurityEvent[]): Promise<ExportResult>;
  abstract healthCheck(): Promise<void>;

  async shutdown(): Promise<void> {
    await this.flush();
  }
}
```

## Configuration

### Global Configuration

```yaml
# clawdstrike-siem.yaml
version: "1.0.0"

# Global settings
global:
  # Environment label for all events
  environment: production
  # Tenant identifier (for multi-tenant)
  tenant_id: acme-corp
  # Enable debug logging
  debug: false

# Schema transformation settings
schema:
  # Default format (ecs, cef, ocsf, native)
  default_format: ecs
  # Include raw event in transformed output
  include_raw: false
  # Custom field mappings
  field_mappings:
    agent.id: observer.name
    session.user_id: user.id

# Event filtering
filtering:
  # Minimum severity to export
  min_severity: low
  # Event types to include (empty = all)
  include_types: []
  # Event types to exclude
  exclude_types:
    - session_start
  # Guard names to include
  include_guards: []

# Credential management
credentials:
  # Provider: vault, k8s_secret, env, file
  provider: env
  # Vault configuration (if provider = vault)
  vault:
    address: https://vault.example.com
    path: secret/data/clawdstrike
    auth_method: kubernetes
  # Refresh interval for credentials (seconds)
  refresh_interval: 300

# Exporters configuration
exporters:
  splunk:
    enabled: true
    # See splunk.md for full config

  elastic:
    enabled: true
    # See elastic.md for full config

  datadog:
    enabled: false
    # See datadog.md for full config

  pagerduty:
    enabled: true
    # See pagerduty-opsgenie.md for full config

  slack:
    enabled: true
    # See slack-teams.md for full config

# Threat intelligence
threat_intel:
  # See stix-taxii.md for full config
  taxii:
    enabled: false
```

## Implementation Phases

### Phase 1: Foundation (4 weeks)

| Week | Deliverable | Owner |
|------|-------------|-------|
| 1 | SecurityEvent schema + validation | Core |
| 1 | EventBus implementation (Rust + TS) | Core |
| 2 | Exporter trait + BaseExporter | Core |
| 2 | Credential provider abstraction | Core |
| 3 | Splunk HEC exporter | Integration |
| 3 | PagerDuty exporter | Integration |
| 4 | E2E testing harness | QA |
| 4 | Documentation + examples | Docs |

### Phase 2: Enterprise SIEMs (4 weeks)

| Week | Deliverable | Owner |
|------|-------------|-------|
| 5 | Elastic ECS exporter | Integration |
| 5 | ECS schema transformation | Core |
| 6 | Datadog exporter | Integration |
| 6 | Sumo Logic exporter | Integration |
| 7 | CEF transformation (ArcSight) | Core |
| 7 | OCSF transformation | Core |
| 8 | Multi-exporter routing | Core |
| 8 | Performance benchmarks | Perf |

### Phase 3: SOAR & Intelligence (4 weeks)

| Week | Deliverable | Owner |
|------|-------------|-------|
| 9 | OpsGenie exporter | Integration |
| 9 | Slack webhook exporter | Integration |
| 10 | Microsoft Teams exporter | Integration |
| 10 | Generic webhook exporter | Integration |
| 11 | STIX/TAXII client | ThreatIntel |
| 11 | Threat feed integration | ThreatIntel |
| 12 | Response automation hooks | SOAR |
| 12 | Final testing + GA | All |

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Event latency (p99) | < 500ms | Time from guard decision to SIEM ingestion |
| Export success rate | > 99.9% | Successful exports / total attempts |
| Schema compliance | 100% | Events passing ECS/OCSF validation |
| Integration coverage | 8 platforms | Number of supported SIEM/SOAR platforms |
| Documentation coverage | 100% | All public APIs documented |

## Security Considerations

1. **Credential Protection**
   - Never log or expose API keys/tokens
   - Use credential rotation via Vault/K8s Secrets
   - Validate TLS certificates for all connections

2. **Data Privacy**
   - Support PII redaction before export
   - Configurable field exclusion
   - Audit log of all export operations

3. **Rate Limiting**
   - Respect SIEM API limits
   - Implement backpressure on buffer overflow
   - Alert on sustained export failures

4. **Access Control**
   - RBAC for exporter configuration
   - Audit trail for config changes
   - Separate credentials per exporter

## Related Documents

- [Splunk Integration](./splunk.md)
- [Elastic Integration](./elastic.md)
- [Datadog Integration](./datadog.md)
- [Sumo Logic Integration](./sumo-logic.md)
- [PagerDuty/OpsGenie Integration](./pagerduty-opsgenie.md)
- [Slack/Teams Integration](./slack-teams.md)
- [STIX/TAXII Integration](./stix-taxii.md)
