# PagerDuty and OpsGenie Alerting Integration

## Problem Statement

When Clawdstrike detects critical security policy violations, security teams need immediate notification through their existing incident management platforms. Without integrated alerting:

1. Critical violations go unnoticed during off-hours
2. No automated escalation for unacknowledged incidents
3. Manual correlation between security events and incidents
4. Inconsistent response times across severity levels
5. No feedback loop for policy tuning

## Use Cases

| ID | Use Case | Priority |
|----|----------|----------|
| PD-1 | Create PagerDuty incident on critical violation | P0 |
| PD-2 | Auto-resolve incident when threat is mitigated | P0 |
| PD-3 | Severity-based routing to on-call teams | P1 |
| PD-4 | Custom escalation policies per guard type | P1 |
| OG-1 | Create OpsGenie alert on critical violation | P0 |
| OG-2 | Tag-based routing to responder teams | P1 |
| OG-3 | Heartbeat monitoring for exporter health | P2 |

## Architecture

### Integration Pattern

```
+-------------------+     +-------------------------+     +------------------+
|                   |     |                         |     |                  |
|   Clawdstrike     |     |   Alerting Exporter     |     |   PagerDuty      |
|   Engine          |---->|                         |---->|   or OpsGenie    |
|                   |     |   +------------------+  |     |                  |
+-------------------+     |   | Alert Router     |  |     | - Incidents      |
                          |   +------------------+  |     | - Escalations    |
                          |   +------------------+  |     | - On-call        |
                          |   | Deduplication    |  |     | - Runbooks       |
                          |   +------------------+  |     +------------------+
                          |   +------------------+  |
                          |   | State Manager    |  |
                          |   | (resolve/ack)    |  |
                          |   +------------------+  |
                          +-------------------------+
```

### Component Design

```
+-------------------------------------------------------------------------+
|                          AlertingExporter                                |
+-------------------------------------------------------------------------+
|                                                                          |
|  +---------------------+  +---------------------+  +-------------------+ |
|  |   AlertRouter       |  |   DeduplicationMgr  |  |   StateTracker    | |
|  |   - Severity map    |  |   - Dedup key gen   |  |   - Open alerts   | |
|  |   - Guard routing   |  |   - Window mgmt     |  |   - Ack status    | |
|  |   - Team mapping    |  |   - Aggregation     |  |   - Auto-resolve  | |
|  +---------------------+  +---------------------+  +-------------------+ |
|                                                                          |
|  +---------------------+  +---------------------+  +-------------------+ |
|  |   PagerDutyClient   |  |   OpsGenieClient    |  |   RetryHandler    | |
|  |   - Events API v2   |  |   - Alert API       |  |   - Backoff       | |
|  |   - Change events   |  |   - Heartbeat API   |  |   - Circuit break | |
|  |   - Acknowledgment  |  |   - Team routing    |  |   - DLQ           | |
|  +---------------------+  +---------------------+  +-------------------+ |
|                                                                          |
+-------------------------------------------------------------------------+
```

## API Design

### TypeScript Implementation

```typescript
import {
  BaseExporter,
  ExporterConfig,
  SecurityEvent,
  ExportResult,
  SchemaFormat,
} from '../framework';

/**
 * Alert severity mapping
 */
export type AlertSeverity = 'critical' | 'error' | 'warning' | 'info';

/**
 * Alert action type
 */
export type AlertAction = 'trigger' | 'acknowledge' | 'resolve';

/**
 * PagerDuty configuration
 */
export interface PagerDutyConfig {
  /** PagerDuty Events API v2 routing key (integration key) */
  routingKey: string;

  /** API endpoint (default: events.pagerduty.com) */
  apiEndpoint?: string;

  /** Severity mapping from Clawdstrike to PagerDuty */
  severityMapping?: {
    critical?: AlertSeverity;
    high?: AlertSeverity;
    medium?: AlertSeverity;
    low?: AlertSeverity;
    info?: AlertSeverity;
  };

  /** Custom routing rules */
  routing?: {
    /** Route by guard to different services */
    byGuard?: Record<string, string>;
    /** Route by tenant */
    byTenant?: Record<string, string>;
  };

  /** Deduplication settings */
  deduplication?: {
    /** Key template (supports {guard}, {session_id}, {resource}) */
    keyTemplate?: string;
    /** Dedup window in seconds */
    windowSeconds?: number;
  };

  /** Include custom details */
  customDetails?: boolean;

  /** Auto-resolve settings */
  autoResolve?: {
    /** Enable auto-resolve */
    enabled?: boolean;
    /** Resolve after N minutes of no violations */
    afterMinutes?: number;
  };
}

/**
 * OpsGenie configuration
 */
export interface OpsGenieConfig {
  /** OpsGenie API key */
  apiKey: string;

  /** API endpoint (default: api.opsgenie.com) */
  apiEndpoint?: string;

  /** Responder teams */
  responders?: Array<{
    type: 'team' | 'user' | 'escalation' | 'schedule';
    id?: string;
    name?: string;
  }>;

  /** Priority mapping */
  priorityMapping?: {
    critical?: 'P1' | 'P2' | 'P3' | 'P4' | 'P5';
    high?: 'P1' | 'P2' | 'P3' | 'P4' | 'P5';
    medium?: 'P1' | 'P2' | 'P3' | 'P4' | 'P5';
    low?: 'P1' | 'P2' | 'P3' | 'P4' | 'P5';
    info?: 'P1' | 'P2' | 'P3' | 'P4' | 'P5';
  };

  /** Tags to add to alerts */
  tags?: string[];

  /** Routing rules */
  routing?: {
    byGuard?: Record<string, string[]>;  // guard -> team names
    bySeverity?: Record<string, string[]>;
  };

  /** Enable heartbeat */
  heartbeat?: {
    enabled?: boolean;
    name?: string;
    intervalMinutes?: number;
  };
}

/**
 * Combined alerting configuration
 */
export interface AlertingConfig extends ExporterConfig {
  /** PagerDuty configuration */
  pagerduty?: PagerDutyConfig;

  /** OpsGenie configuration */
  opsgenie?: OpsGenieConfig;

  /** Minimum severity to alert on */
  minSeverity?: 'info' | 'low' | 'medium' | 'high' | 'critical';

  /** Guards to include (empty = all) */
  includeGuards?: string[];

  /** Guards to exclude */
  excludeGuards?: string[];
}

/**
 * PagerDuty Events API v2 payload
 */
export interface PagerDutyEvent {
  routing_key: string;
  event_action: AlertAction;
  dedup_key?: string;
  payload: {
    summary: string;
    source: string;
    severity: AlertSeverity;
    timestamp?: string;
    component?: string;
    group?: string;
    class?: string;
    custom_details?: Record<string, unknown>;
  };
  links?: Array<{ href: string; text: string }>;
  images?: Array<{ src: string; href?: string; alt?: string }>;
}

/**
 * OpsGenie Alert payload
 */
export interface OpsGenieAlert {
  message: string;
  alias?: string;
  description?: string;
  responders?: Array<{
    type: string;
    id?: string;
    name?: string;
  }>;
  visibleTo?: Array<{
    type: string;
    id?: string;
    name?: string;
  }>;
  actions?: string[];
  tags?: string[];
  details?: Record<string, string>;
  entity?: string;
  source?: string;
  priority?: string;
  user?: string;
  note?: string;
}

/**
 * PagerDuty client
 */
export class PagerDutyClient {
  private config: Required<PagerDutyConfig>;
  private client: HttpClient;
  private openAlerts: Map<string, { eventId: string; createdAt: Date }> = new Map();

  constructor(config: PagerDutyConfig) {
    this.config = this.mergeDefaults(config);
    this.client = new HttpClient({
      baseUrl: this.config.apiEndpoint,
      timeout: 30000,
    });
  }

  private mergeDefaults(config: PagerDutyConfig): Required<PagerDutyConfig> {
    return {
      routingKey: config.routingKey,
      apiEndpoint: config.apiEndpoint ?? 'https://events.pagerduty.com',
      severityMapping: {
        critical: 'critical',
        high: 'error',
        medium: 'warning',
        low: 'info',
        info: 'info',
        ...config.severityMapping,
      },
      routing: config.routing ?? {},
      deduplication: {
        keyTemplate: config.deduplication?.keyTemplate ?? '{guard}:{session_id}',
        windowSeconds: config.deduplication?.windowSeconds ?? 300,
      },
      customDetails: config.customDetails ?? true,
      autoResolve: {
        enabled: config.autoResolve?.enabled ?? true,
        afterMinutes: config.autoResolve?.afterMinutes ?? 30,
      },
    };
  }

  /**
   * Generate deduplication key
   */
  private generateDedupKey(event: SecurityEvent): string {
    let key = this.config.deduplication.keyTemplate;
    key = key.replace('{guard}', event.decision.guard);
    key = key.replace('{session_id}', event.session.id);
    key = key.replace('{resource}', event.resource.name);
    key = key.replace('{tenant_id}', event.session.tenant_id ?? 'default');
    return key;
  }

  /**
   * Map severity to PagerDuty severity
   */
  private mapSeverity(severity: string): AlertSeverity {
    const mapping = this.config.severityMapping as Record<string, AlertSeverity>;
    return mapping[severity] ?? 'info';
  }

  /**
   * Get routing key for event
   */
  private getRoutingKey(event: SecurityEvent): string {
    // Check guard-based routing
    if (this.config.routing.byGuard?.[event.decision.guard]) {
      return this.config.routing.byGuard[event.decision.guard];
    }

    // Check tenant-based routing
    if (event.session.tenant_id && this.config.routing.byTenant?.[event.session.tenant_id]) {
      return this.config.routing.byTenant[event.session.tenant_id];
    }

    return this.config.routingKey;
  }

  /**
   * Build PagerDuty event payload
   */
  private buildPayload(
    event: SecurityEvent,
    action: AlertAction
  ): PagerDutyEvent {
    const summary = `[${event.decision.guard}] ${event.decision.reason}`;
    const dedupKey = this.generateDedupKey(event);

    const payload: PagerDutyEvent = {
      routing_key: this.getRoutingKey(event),
      event_action: action,
      dedup_key: dedupKey,
      payload: {
        summary: summary.slice(0, 1024), // PagerDuty limit
        source: `clawdstrike-${event.agent.id}`,
        severity: this.mapSeverity(event.decision.severity),
        timestamp: event.timestamp,
        component: event.decision.guard,
        group: event.session.tenant_id ?? 'default',
        class: event.event_type,
      },
    };

    if (this.config.customDetails) {
      payload.payload.custom_details = {
        event_id: event.event_id,
        event_type: event.event_type,
        session_id: event.session.id,
        user_id: event.session.user_id,
        resource_type: event.resource.type,
        resource_name: event.resource.name,
        resource_path: event.resource.path,
        resource_host: event.resource.host,
        allowed: event.decision.allowed,
        policy_hash: event.decision.policy_hash,
        ruleset: event.decision.ruleset,
      };
    }

    return payload;
  }

  /**
   * Trigger an alert
   */
  async trigger(event: SecurityEvent): Promise<void> {
    const payload = this.buildPayload(event, 'trigger');

    const response = await this.client.post('/v2/enqueue', payload);

    if (response.status !== 202) {
      throw new Error(`PagerDuty API error: ${response.status}`);
    }

    // Track open alert
    this.openAlerts.set(payload.dedup_key!, {
      eventId: event.event_id,
      createdAt: new Date(),
    });
  }

  /**
   * Resolve an alert
   */
  async resolve(dedupKey: string): Promise<void> {
    const payload: PagerDutyEvent = {
      routing_key: this.config.routingKey,
      event_action: 'resolve',
      dedup_key: dedupKey,
      payload: {
        summary: 'Resolved',
        source: 'clawdstrike',
        severity: 'info',
      },
    };

    await this.client.post('/v2/enqueue', payload);
    this.openAlerts.delete(dedupKey);
  }

  /**
   * Check for stale alerts and auto-resolve
   */
  async checkAutoResolve(): Promise<void> {
    if (!this.config.autoResolve.enabled) return;

    const now = new Date();
    const threshold = this.config.autoResolve.afterMinutes * 60 * 1000;

    for (const [dedupKey, info] of this.openAlerts) {
      if (now.getTime() - info.createdAt.getTime() > threshold) {
        await this.resolve(dedupKey);
      }
    }
  }
}

/**
 * OpsGenie client
 */
export class OpsGenieClient {
  private config: Required<OpsGenieConfig>;
  private client: HttpClient;
  private heartbeatTimer?: NodeJS.Timeout;

  constructor(config: OpsGenieConfig) {
    this.config = this.mergeDefaults(config);
    this.client = new HttpClient({
      baseUrl: this.config.apiEndpoint,
      timeout: 30000,
      headers: {
        'Authorization': `GenieKey ${this.config.apiKey}`,
        'Content-Type': 'application/json',
      },
    });

    if (this.config.heartbeat.enabled) {
      this.startHeartbeat();
    }
  }

  private mergeDefaults(config: OpsGenieConfig): Required<OpsGenieConfig> {
    return {
      apiKey: config.apiKey,
      apiEndpoint: config.apiEndpoint ?? 'https://api.opsgenie.com',
      responders: config.responders ?? [],
      priorityMapping: {
        critical: 'P1',
        high: 'P2',
        medium: 'P3',
        low: 'P4',
        info: 'P5',
        ...config.priorityMapping,
      },
      tags: config.tags ?? [],
      routing: config.routing ?? {},
      heartbeat: {
        enabled: config.heartbeat?.enabled ?? false,
        name: config.heartbeat?.name ?? 'clawdstrike',
        intervalMinutes: config.heartbeat?.intervalMinutes ?? 5,
      },
    };
  }

  /**
   * Start heartbeat ping
   */
  private startHeartbeat(): void {
    const intervalMs = this.config.heartbeat.intervalMinutes * 60 * 1000;

    this.heartbeatTimer = setInterval(async () => {
      try {
        await this.client.post(
          `/v2/heartbeats/${this.config.heartbeat.name}/ping`,
          {}
        );
      } catch (error) {
        console.error('OpsGenie heartbeat failed:', error);
      }
    }, intervalMs);

    // Initial ping
    this.client.post(`/v2/heartbeats/${this.config.heartbeat.name}/ping`, {});
  }

  /**
   * Get responders for event
   */
  private getResponders(event: SecurityEvent): OpsGenieAlert['responders'] {
    const responders = [...this.config.responders];

    // Add guard-based routing
    if (this.config.routing.byGuard?.[event.decision.guard]) {
      for (const teamName of this.config.routing.byGuard[event.decision.guard]) {
        responders.push({ type: 'team', name: teamName });
      }
    }

    // Add severity-based routing
    if (this.config.routing.bySeverity?.[event.decision.severity]) {
      for (const teamName of this.config.routing.bySeverity[event.decision.severity]) {
        responders.push({ type: 'team', name: teamName });
      }
    }

    return responders;
  }

  /**
   * Map severity to OpsGenie priority
   */
  private mapPriority(severity: string): string {
    const mapping = this.config.priorityMapping as Record<string, string>;
    return mapping[severity] ?? 'P5';
  }

  /**
   * Build alert payload
   */
  private buildPayload(event: SecurityEvent): OpsGenieAlert {
    const message = `[${event.decision.guard}] ${event.decision.reason}`;

    return {
      message: message.slice(0, 130), // OpsGenie limit
      alias: `clawdstrike-${event.decision.guard}-${event.session.id}`,
      description: this.buildDescription(event),
      responders: this.getResponders(event),
      tags: [
        ...this.config.tags,
        `guard:${event.decision.guard}`,
        `severity:${event.decision.severity}`,
        `event_type:${event.event_type}`,
      ],
      details: {
        event_id: event.event_id,
        event_type: event.event_type,
        session_id: event.session.id,
        user_id: event.session.user_id ?? '',
        resource_type: event.resource.type,
        resource_name: event.resource.name,
        resource_path: event.resource.path ?? '',
        allowed: String(event.decision.allowed),
      },
      entity: event.resource.name,
      source: `clawdstrike-${event.agent.id}`,
      priority: this.mapPriority(event.decision.severity),
    };
  }

  private buildDescription(event: SecurityEvent): string {
    return `
## Security Violation Details

**Guard:** ${event.decision.guard}
**Severity:** ${event.decision.severity}
**Reason:** ${event.decision.reason}

### Session Context
- **Session ID:** ${event.session.id}
- **User ID:** ${event.session.user_id ?? 'N/A'}
- **Tenant:** ${event.session.tenant_id ?? 'N/A'}
- **Environment:** ${event.session.environment ?? 'N/A'}

### Resource
- **Type:** ${event.resource.type}
- **Name:** ${event.resource.name}
- **Path:** ${event.resource.path ?? 'N/A'}
- **Host:** ${event.resource.host ?? 'N/A'}

### Policy
- **Ruleset:** ${event.decision.ruleset ?? 'N/A'}
- **Policy Hash:** ${event.decision.policy_hash ?? 'N/A'}

---
*Generated by Clawdstrike at ${event.timestamp}*
    `.trim();
  }

  /**
   * Create alert
   */
  async createAlert(event: SecurityEvent): Promise<void> {
    const payload = this.buildPayload(event);

    const response = await this.client.post('/v2/alerts', payload);

    if (response.status !== 202) {
      throw new Error(`OpsGenie API error: ${response.status}`);
    }
  }

  /**
   * Close alert
   */
  async closeAlert(alias: string): Promise<void> {
    await this.client.post(`/v2/alerts/${alias}/close`, {
      identifierType: 'alias',
      source: 'clawdstrike',
    });
  }

  /**
   * Stop heartbeat
   */
  stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
    }
  }
}

/**
 * Unified alerting exporter
 */
export class AlertingExporter extends BaseExporter {
  readonly name = 'alerting';
  readonly schema = SchemaFormat.Native;

  private config: Required<AlertingConfig>;
  private pagerduty?: PagerDutyClient;
  private opsgenie?: OpsGenieClient;

  private readonly severityOrder = ['info', 'low', 'medium', 'high', 'critical'];

  constructor(config: AlertingConfig) {
    super(config);
    this.config = this.mergeDefaults(config);

    if (this.config.pagerduty) {
      this.pagerduty = new PagerDutyClient(this.config.pagerduty);
    }

    if (this.config.opsgenie) {
      this.opsgenie = new OpsGenieClient(this.config.opsgenie);
    }
  }

  private mergeDefaults(config: AlertingConfig): Required<AlertingConfig> {
    return {
      pagerduty: config.pagerduty,
      opsgenie: config.opsgenie,
      minSeverity: config.minSeverity ?? 'high',
      includeGuards: config.includeGuards ?? [],
      excludeGuards: config.excludeGuards ?? [],
      ...this.config,
    };
  }

  /**
   * Check if event should trigger alert
   */
  private shouldAlert(event: SecurityEvent): boolean {
    // Check severity threshold
    const minIndex = this.severityOrder.indexOf(this.config.minSeverity);
    const eventIndex = this.severityOrder.indexOf(event.decision.severity);

    if (eventIndex < minIndex) {
      return false;
    }

    // Check guard inclusion
    if (this.config.includeGuards.length > 0) {
      if (!this.config.includeGuards.includes(event.decision.guard)) {
        return false;
      }
    }

    // Check guard exclusion
    if (this.config.excludeGuards.includes(event.decision.guard)) {
      return false;
    }

    // Only alert on denials
    if (event.decision.allowed) {
      return false;
    }

    return true;
  }

  async export(events: SecurityEvent[]): Promise<ExportResult> {
    const alertEvents = events.filter(e => this.shouldAlert(e));

    if (alertEvents.length === 0) {
      return { exported: 0, failed: 0, errors: [] };
    }

    const errors: ExportError[] = [];
    let exported = 0;

    for (const event of alertEvents) {
      try {
        await this.sendAlerts(event);
        exported++;
      } catch (error) {
        errors.push({
          eventId: event.event_id,
          error: (error as Error).message,
          retryable: true,
        });
      }
    }

    return {
      exported,
      failed: errors.length,
      errors,
    };
  }

  private async sendAlerts(event: SecurityEvent): Promise<void> {
    const promises: Promise<void>[] = [];

    if (this.pagerduty) {
      promises.push(this.pagerduty.trigger(event));
    }

    if (this.opsgenie) {
      promises.push(this.opsgenie.createAlert(event));
    }

    await Promise.all(promises);
  }

  async healthCheck(): Promise<void> {
    // PagerDuty doesn't have a health endpoint; check OpsGenie heartbeat
    if (this.opsgenie && this.config.opsgenie?.heartbeat?.enabled) {
      // Heartbeat is already running
    }
  }

  async shutdown(): Promise<void> {
    this.opsgenie?.stopHeartbeat();
  }
}
```

### Rust Implementation

```rust
use async_trait::async_trait;
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// PagerDuty configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutyConfig {
    /// Events API routing key
    pub routing_key: String,
    /// API endpoint
    #[serde(default = "default_pd_endpoint")]
    pub api_endpoint: String,
    /// Severity mapping
    #[serde(default)]
    pub severity_mapping: SeverityMapping,
    /// Deduplication settings
    #[serde(default)]
    pub deduplication: DeduplicationConfig,
    /// Auto-resolve settings
    #[serde(default)]
    pub auto_resolve: AutoResolveConfig,
}

fn default_pd_endpoint() -> String {
    "https://events.pagerduty.com".to_string()
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityMapping {
    #[serde(default = "critical")]
    pub critical: String,
    #[serde(default = "error")]
    pub high: String,
    #[serde(default = "warning")]
    pub medium: String,
    #[serde(default = "info")]
    pub low: String,
    #[serde(default = "info")]
    pub info: String,
}

fn critical() -> String { "critical".to_string() }
fn error() -> String { "error".to_string() }
fn warning() -> String { "warning".to_string() }
fn info() -> String { "info".to_string() }

impl Default for SeverityMapping {
    fn default() -> Self {
        Self {
            critical: critical(),
            high: error(),
            medium: warning(),
            low: info(),
            info: info(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationConfig {
    #[serde(default = "default_dedup_template")]
    pub key_template: String,
    #[serde(default = "default_dedup_window")]
    pub window_seconds: u64,
}

fn default_dedup_template() -> String { "{guard}:{session_id}".to_string() }
fn default_dedup_window() -> u64 { 300 }

impl Default for DeduplicationConfig {
    fn default() -> Self {
        Self {
            key_template: default_dedup_template(),
            window_seconds: default_dedup_window(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoResolveConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_resolve_minutes")]
    pub after_minutes: u64,
}

fn default_resolve_minutes() -> u64 { 30 }

impl Default for AutoResolveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            after_minutes: default_resolve_minutes(),
        }
    }
}

/// PagerDuty Events API v2 payload
#[derive(Debug, Serialize)]
struct PagerDutyEvent {
    routing_key: String,
    event_action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dedup_key: Option<String>,
    payload: PagerDutyPayload,
}

#[derive(Debug, Serialize)]
struct PagerDutyPayload {
    summary: String,
    source: String,
    severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    custom_details: Option<serde_json::Value>,
}

/// PagerDuty client
pub struct PagerDutyClient {
    config: PagerDutyConfig,
    client: Client,
    open_alerts: Arc<RwLock<HashMap<String, chrono::DateTime<chrono::Utc>>>>,
}

impl PagerDutyClient {
    pub fn new(config: PagerDutyConfig) -> Result<Self, ExporterError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            config,
            client,
            open_alerts: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    fn generate_dedup_key(&self, event: &SecurityEvent) -> String {
        self.config.deduplication.key_template
            .replace("{guard}", &event.decision.guard)
            .replace("{session_id}", &event.session.id)
            .replace("{resource}", &event.resource.name)
            .replace("{tenant_id}", event.session.tenant_id.as_deref().unwrap_or("default"))
    }

    fn map_severity(&self, severity: &Severity) -> &str {
        match severity {
            Severity::Critical => &self.config.severity_mapping.critical,
            Severity::High => &self.config.severity_mapping.high,
            Severity::Medium => &self.config.severity_mapping.medium,
            Severity::Low => &self.config.severity_mapping.low,
            Severity::Info => &self.config.severity_mapping.info,
        }
    }

    fn build_payload(&self, event: &SecurityEvent, action: &str) -> PagerDutyEvent {
        let summary = format!("[{}] {}", event.decision.guard, event.decision.reason);
        let dedup_key = self.generate_dedup_key(event);

        PagerDutyEvent {
            routing_key: self.config.routing_key.clone(),
            event_action: action.to_string(),
            dedup_key: Some(dedup_key),
            payload: PagerDutyPayload {
                summary: summary.chars().take(1024).collect(),
                source: format!("clawdstrike-{}", event.agent.id),
                severity: self.map_severity(&event.decision.severity).to_string(),
                timestamp: Some(event.timestamp.to_rfc3339()),
                component: Some(event.decision.guard.clone()),
                group: event.session.tenant_id.clone(),
                class: Some(format!("{:?}", event.event_type)),
                custom_details: Some(serde_json::json!({
                    "event_id": event.event_id.to_string(),
                    "session_id": event.session.id,
                    "user_id": event.session.user_id,
                    "resource_type": event.resource.resource_type,
                    "resource_name": event.resource.name,
                    "allowed": event.decision.allowed,
                })),
            },
        }
    }

    pub async fn trigger(&self, event: &SecurityEvent) -> Result<(), ExporterError> {
        let payload = self.build_payload(event, "trigger");
        let dedup_key = payload.dedup_key.clone().unwrap();

        let response = self.client
            .post(format!("{}/v2/enqueue", self.config.api_endpoint))
            .json(&payload)
            .send()
            .await?;

        if response.status() != 202 {
            return Err(ExporterError::Http {
                status: response.status().as_u16(),
                body: response.text().await.unwrap_or_default(),
            });
        }

        // Track open alert
        self.open_alerts.write().await.insert(dedup_key, chrono::Utc::now());

        Ok(())
    }

    pub async fn resolve(&self, dedup_key: &str) -> Result<(), ExporterError> {
        let payload = serde_json::json!({
            "routing_key": self.config.routing_key,
            "event_action": "resolve",
            "dedup_key": dedup_key,
        });

        self.client
            .post(format!("{}/v2/enqueue", self.config.api_endpoint))
            .json(&payload)
            .send()
            .await?;

        self.open_alerts.write().await.remove(dedup_key);

        Ok(())
    }

    pub async fn check_auto_resolve(&self) -> Result<(), ExporterError> {
        if !self.config.auto_resolve.enabled {
            return Ok(());
        }

        let threshold = chrono::Duration::minutes(self.config.auto_resolve.after_minutes as i64);
        let now = chrono::Utc::now();

        let keys_to_resolve: Vec<String> = {
            let alerts = self.open_alerts.read().await;
            alerts
                .iter()
                .filter(|(_, created_at)| now - **created_at > threshold)
                .map(|(key, _)| key.clone())
                .collect()
        };

        for key in keys_to_resolve {
            if let Err(e) = self.resolve(&key).await {
                warn!("Failed to auto-resolve alert {}: {}", key, e);
            }
        }

        Ok(())
    }
}

/// OpsGenie configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsGenieConfig {
    pub api_key: String,
    #[serde(default = "default_og_endpoint")]
    pub api_endpoint: String,
    #[serde(default)]
    pub responders: Vec<Responder>,
    #[serde(default)]
    pub priority_mapping: PriorityMapping,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
}

fn default_og_endpoint() -> String {
    "https://api.opsgenie.com".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Responder {
    #[serde(rename = "type")]
    pub responder_type: String,
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityMapping {
    #[serde(default = "p1")]
    pub critical: String,
    #[serde(default = "p2")]
    pub high: String,
    #[serde(default = "p3")]
    pub medium: String,
    #[serde(default = "p4")]
    pub low: String,
    #[serde(default = "p5")]
    pub info: String,
}

fn p1() -> String { "P1".to_string() }
fn p2() -> String { "P2".to_string() }
fn p3() -> String { "P3".to_string() }
fn p4() -> String { "P4".to_string() }
fn p5() -> String { "P5".to_string() }

impl Default for PriorityMapping {
    fn default() -> Self {
        Self {
            critical: p1(),
            high: p2(),
            medium: p3(),
            low: p4(),
            info: p5(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeartbeatConfig {
    pub enabled: bool,
    #[serde(default = "default_heartbeat_name")]
    pub name: String,
    #[serde(default = "default_heartbeat_interval")]
    pub interval_minutes: u64,
}

fn default_heartbeat_name() -> String { "clawdstrike".to_string() }
fn default_heartbeat_interval() -> u64 { 5 }

/// OpsGenie client
pub struct OpsGenieClient {
    config: OpsGenieConfig,
    client: Client,
}

impl OpsGenieClient {
    pub fn new(config: OpsGenieConfig) -> Result<Self, ExporterError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .default_headers({
                let mut headers = header::HeaderMap::new();
                headers.insert(
                    "Authorization",
                    format!("GenieKey {}", config.api_key).parse().unwrap(),
                );
                headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
                headers
            })
            .build()?;

        Ok(Self { config, client })
    }

    fn map_priority(&self, severity: &Severity) -> &str {
        match severity {
            Severity::Critical => &self.config.priority_mapping.critical,
            Severity::High => &self.config.priority_mapping.high,
            Severity::Medium => &self.config.priority_mapping.medium,
            Severity::Low => &self.config.priority_mapping.low,
            Severity::Info => &self.config.priority_mapping.info,
        }
    }

    pub async fn create_alert(&self, event: &SecurityEvent) -> Result<(), ExporterError> {
        let message = format!("[{}] {}", event.decision.guard, event.decision.reason);

        let mut tags = self.config.tags.clone();
        tags.push(format!("guard:{}", event.decision.guard));
        tags.push(format!("severity:{:?}", event.decision.severity));

        let payload = serde_json::json!({
            "message": &message[..message.len().min(130)],
            "alias": format!("clawdstrike-{}-{}", event.decision.guard, event.session.id),
            "description": format!(
                "## Security Violation\n\n**Guard:** {}\n**Severity:** {:?}\n**Reason:** {}\n\n**Session:** {}\n**Resource:** {}",
                event.decision.guard,
                event.decision.severity,
                event.decision.reason,
                event.session.id,
                event.resource.name
            ),
            "responders": self.config.responders,
            "tags": tags,
            "details": {
                "event_id": event.event_id.to_string(),
                "session_id": event.session.id,
                "resource_type": event.resource.resource_type,
                "allowed": event.decision.allowed.to_string(),
            },
            "priority": self.map_priority(&event.decision.severity),
            "source": format!("clawdstrike-{}", event.agent.id),
        });

        let response = self.client
            .post(format!("{}/v2/alerts", self.config.api_endpoint))
            .json(&payload)
            .send()
            .await?;

        if response.status() != 202 {
            return Err(ExporterError::Http {
                status: response.status().as_u16(),
                body: response.text().await.unwrap_or_default(),
            });
        }

        Ok(())
    }

    pub async fn ping_heartbeat(&self) -> Result<(), ExporterError> {
        if !self.config.heartbeat.enabled {
            return Ok(());
        }

        self.client
            .post(format!(
                "{}/v2/heartbeats/{}/ping",
                self.config.api_endpoint,
                self.config.heartbeat.name
            ))
            .send()
            .await?;

        Ok(())
    }
}

/// Alerting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingConfig {
    pub pagerduty: Option<PagerDutyConfig>,
    pub opsgenie: Option<OpsGenieConfig>,
    #[serde(default = "default_min_severity")]
    pub min_severity: String,
    #[serde(default)]
    pub include_guards: Vec<String>,
    #[serde(default)]
    pub exclude_guards: Vec<String>,
}

fn default_min_severity() -> String { "high".to_string() }

/// Alerting exporter
pub struct AlertingExporter {
    config: AlertingConfig,
    pagerduty: Option<PagerDutyClient>,
    opsgenie: Option<OpsGenieClient>,
}

impl AlertingExporter {
    pub fn new(config: AlertingConfig) -> Result<Self, ExporterError> {
        let pagerduty = config.pagerduty.as_ref()
            .map(|c| PagerDutyClient::new(c.clone()))
            .transpose()?;

        let opsgenie = config.opsgenie.as_ref()
            .map(|c| OpsGenieClient::new(c.clone()))
            .transpose()?;

        Ok(Self {
            config,
            pagerduty,
            opsgenie,
        })
    }

    fn should_alert(&self, event: &SecurityEvent) -> bool {
        // Only alert on denials
        if event.decision.allowed {
            return false;
        }

        // Check severity threshold
        let severity_order = ["info", "low", "medium", "high", "critical"];
        let min_idx = severity_order.iter()
            .position(|s| *s == self.config.min_severity)
            .unwrap_or(0);
        let event_idx = severity_order.iter()
            .position(|s| *s == format!("{:?}", event.decision.severity).to_lowercase())
            .unwrap_or(0);

        if event_idx < min_idx {
            return false;
        }

        // Check guard filters
        if !self.config.include_guards.is_empty()
            && !self.config.include_guards.contains(&event.decision.guard)
        {
            return false;
        }

        if self.config.exclude_guards.contains(&event.decision.guard) {
            return false;
        }

        true
    }
}

#[async_trait]
impl Exporter for AlertingExporter {
    fn name(&self) -> &str {
        "alerting"
    }

    fn schema(&self) -> SchemaFormat {
        SchemaFormat::Native
    }

    async fn export(&self, events: Vec<SecurityEvent>) -> Result<ExportResult, ExportError> {
        let alert_events: Vec<&SecurityEvent> = events
            .iter()
            .filter(|e| self.should_alert(e))
            .collect();

        if alert_events.is_empty() {
            return Ok(ExportResult {
                exported: 0,
                failed: 0,
                errors: vec![],
            });
        }

        let mut exported = 0;
        let mut errors = vec![];

        for event in alert_events {
            let mut event_errors = vec![];

            if let Some(pd) = &self.pagerduty {
                if let Err(e) = pd.trigger(event).await {
                    event_errors.push(format!("PagerDuty: {}", e));
                }
            }

            if let Some(og) = &self.opsgenie {
                if let Err(e) = og.create_alert(event).await {
                    event_errors.push(format!("OpsGenie: {}", e));
                }
            }

            if event_errors.is_empty() {
                exported += 1;
            } else {
                errors.push(ExportError {
                    event_id: event.event_id.to_string(),
                    error: event_errors.join("; "),
                    retryable: true,
                });
            }
        }

        info!("Sent {} alerts ({} failed)", exported, errors.len());

        Ok(ExportResult {
            exported,
            failed: errors.len(),
            errors,
        })
    }

    async fn health_check(&self) -> Result<(), String> {
        if let Some(og) = &self.opsgenie {
            og.ping_heartbeat().await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), String> {
        Ok(())
    }
}
```

## Configuration Examples

### PagerDuty Only

```yaml
exporters:
  alerting:
    enabled: true
    min_severity: high

    pagerduty:
      routing_key: ${PAGERDUTY_ROUTING_KEY}
      severity_mapping:
        critical: critical
        high: error
        medium: warning
      deduplication:
        key_template: "{guard}:{tenant_id}:{resource}"
        window_seconds: 600
      auto_resolve:
        enabled: true
        after_minutes: 60
```

### OpsGenie Only

```yaml
exporters:
  alerting:
    enabled: true
    min_severity: high

    opsgenie:
      api_key: ${OPSGENIE_API_KEY}
      responders:
        - type: team
          name: security-team
        - type: escalation
          name: security-escalation
      priority_mapping:
        critical: P1
        high: P2
        medium: P3
      tags:
        - source:clawdstrike
        - team:security
      heartbeat:
        enabled: true
        name: clawdstrike-prod
        interval_minutes: 5
```

### Both Platforms with Routing

```yaml
exporters:
  alerting:
    enabled: true
    min_severity: medium
    exclude_guards:
      - prompt_injection  # Handle separately

    pagerduty:
      routing_key: ${PAGERDUTY_DEFAULT_KEY}
      routing:
        by_guard:
          secret_leak: ${PAGERDUTY_DLP_KEY}
          egress_allowlist: ${PAGERDUTY_NETWORK_KEY}
        by_tenant:
          acme-corp: ${PAGERDUTY_ACME_KEY}

    opsgenie:
      api_key: ${OPSGENIE_API_KEY}
      routing:
        by_guard:
          secret_leak:
            - dlp-team
            - security-team
          forbidden_path:
            - compliance-team
        by_severity:
          critical:
            - security-oncall
```

## Implementation Phases

### Phase 1: Core Alerting (Week 9)

- [ ] Implement PagerDutyClient with Events API v2
- [ ] Implement OpsGenieClient with Alert API
- [ ] Severity mapping and filtering
- [ ] Deduplication key generation
- [ ] Unit tests with mock APIs

### Phase 2: Advanced Features (Week 9)

- [ ] Guard-based routing
- [ ] Tenant-based routing
- [ ] Auto-resolve functionality
- [ ] OpsGenie heartbeat

### Phase 3: Production (Week 9)

- [ ] Retry with exponential backoff
- [ ] Circuit breaker pattern
- [ ] Dead letter queue
- [ ] Documentation and examples
