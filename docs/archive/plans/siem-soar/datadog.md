# Datadog Integration for Security Monitoring

## Problem Statement

Organizations using Datadog for observability need unified visibility across infrastructure, application, and security telemetry. Clawdstrike security events must integrate with Datadog to enable:

1. Security dashboards alongside infrastructure metrics
2. Log-based alerting on policy violations
3. APM correlation with agent security context
4. Cloud SIEM integration for threat detection
5. Unified incident management workflow

## Use Cases

| ID | Use Case | Priority |
|----|----------|----------|
| DD-1 | Stream security events to Datadog Logs | P0 |
| DD-2 | Create security monitors for critical violations | P0 |
| DD-3 | Dashboard for agent security posture | P1 |
| DD-4 | APM trace correlation with security context | P1 |
| DD-5 | Cloud SIEM detection rules | P2 |
| DD-6 | Security Signals integration | P2 |

## Architecture

### Integration Pattern

```
+-------------------+     +-------------------------+     +------------------+
|                   |     |                         |     |                  |
|   Clawdstrike     |     |   Datadog Exporter      |     |   Datadog        |
|   Engine          |---->|                         |---->|   Platform       |
|                   |     |   +------------------+  |     |                  |
+-------------------+     |   | Log Formatter    |  |     | - Logs           |
                          |   +------------------+  |     | - Metrics        |
                          |   +------------------+  |     | - APM            |
                          |   | HTTP Client      |  |     | - Security       |
                          |   | (intake API)     |  |     |   Monitoring     |
                          |   +------------------+  |     +------------------+
                          +-------------------------+
```

### Component Design

```
+-------------------------------------------------------------------------+
|                          DatadogExporter                                 |
+-------------------------------------------------------------------------+
|                                                                          |
|  +---------------------+  +---------------------+  +-------------------+ |
|  |   LogFormatter      |  |   MetricsCollector  |  |   TraceInjector   | |
|  |   - JSON            |  |   - Counters        |  |   - Trace ID      | |
|  |   - Tags            |  |   - Histograms      |  |   - Span ID       | |
|  |   - Attributes      |  |   - Gauges          |  |   - Parent span   | |
|  +---------------------+  +---------------------+  +-------------------+ |
|                                                                          |
|  +---------------------+  +---------------------+  +-------------------+ |
|  |   IntakeClient      |  |   ApiKeyProvider    |  |   BatchProcessor  | |
|  |   - HTTP/2          |  |   - Rotation        |  |   - Compression   | |
|  |   - Multi-region    |  |   - Vault           |  |   - Retry         | |
|  |   - Site routing    |  |   - K8s Secret      |  |   - Backpressure  | |
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
 * Datadog configuration
 */
export interface DatadogConfig extends ExporterConfig {
  /** Datadog API key */
  apiKey: string;

  /** Datadog application key (for dashboards/monitors) */
  appKey?: string;

  /** Datadog site (datadoghq.com, datadoghq.eu, etc.) */
  site?: string;

  /** Log configuration */
  logs?: {
    /** Service name for logs */
    service?: string;
    /** Source identifier */
    source?: string;
    /** Default tags */
    tags?: string[];
    /** Hostname override */
    hostname?: string;
  };

  /** Metrics configuration */
  metrics?: {
    /** Enable metrics emission */
    enabled?: boolean;
    /** Metric prefix */
    prefix?: string;
    /** Default tags */
    tags?: string[];
  };

  /** APM trace correlation */
  apm?: {
    /** Enable trace correlation */
    enabled?: boolean;
    /** Service name */
    service?: string;
    /** Environment */
    env?: string;
  };

  /** Compression settings */
  compression?: {
    enabled?: boolean;
    level?: number;
  };
}

/**
 * Datadog log entry format
 */
export interface DatadogLog {
  /** Log message */
  message: string;
  /** Timestamp (ISO 8601 or Unix ms) */
  ddsource: string;
  /** Service name */
  service: string;
  /** Hostname */
  hostname: string;
  /** Log status */
  status: 'info' | 'warn' | 'error' | 'critical';
  /** Datadog tags */
  ddtags: string;
  /** Additional attributes */
  [key: string]: unknown;
}

/**
 * Datadog exporter implementation
 */
export class DatadogExporter extends BaseExporter {
  readonly name = 'datadog';
  readonly schema = SchemaFormat.Native;

  private config: Required<DatadogConfig>;
  private client: HttpClient;
  private metricsBuffer: Metric[] = [];

  constructor(config: DatadogConfig) {
    super(config);
    this.config = this.mergeDefaults(config);
    this.client = this.createClient();
  }

  private mergeDefaults(config: DatadogConfig): Required<DatadogConfig> {
    return {
      apiKey: config.apiKey,
      appKey: config.appKey ?? '',
      site: config.site ?? 'datadoghq.com',
      logs: {
        service: config.logs?.service ?? 'clawdstrike',
        source: config.logs?.source ?? 'clawdstrike',
        tags: config.logs?.tags ?? [],
        hostname: config.logs?.hostname ?? os.hostname(),
      },
      metrics: {
        enabled: config.metrics?.enabled ?? true,
        prefix: config.metrics?.prefix ?? 'clawdstrike',
        tags: config.metrics?.tags ?? [],
      },
      apm: {
        enabled: config.apm?.enabled ?? false,
        service: config.apm?.service ?? 'clawdstrike',
        env: config.apm?.env ?? 'production',
      },
      compression: {
        enabled: config.compression?.enabled ?? true,
        level: config.compression?.level ?? 6,
      },
      ...this.config,
    };
  }

  private createClient(): HttpClient {
    return new HttpClient({
      baseUrl: this.getIntakeUrl(),
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'DD-API-KEY': this.config.apiKey,
      },
    });
  }

  private getIntakeUrl(): string {
    const siteMap: Record<string, string> = {
      'datadoghq.com': 'https://http-intake.logs.datadoghq.com',
      'datadoghq.eu': 'https://http-intake.logs.datadoghq.eu',
      'us3.datadoghq.com': 'https://http-intake.logs.us3.datadoghq.com',
      'us5.datadoghq.com': 'https://http-intake.logs.us5.datadoghq.com',
      'ddog-gov.com': 'https://http-intake.logs.ddog-gov.com',
    };

    return siteMap[this.config.site] ?? siteMap['datadoghq.com'];
  }

  /**
   * Transform SecurityEvent to Datadog log format
   */
  private toDatadogLog(event: SecurityEvent): DatadogLog {
    const status = this.mapSeverityToStatus(event.decision.severity);
    const tags = this.buildTags(event);

    return {
      message: this.formatMessage(event),
      ddsource: this.config.logs.source,
      service: this.config.logs.service,
      hostname: this.config.logs.hostname,
      status,
      ddtags: tags.join(','),

      // Standard attributes
      timestamp: event.timestamp,
      event_id: event.event_id,
      event_type: event.event_type,
      event_category: event.event_category,

      // Security context
      security: {
        outcome: event.outcome,
        guard: event.decision.guard,
        severity: event.decision.severity,
        reason: event.decision.reason,
        allowed: event.decision.allowed,
      },

      // Agent context
      agent: {
        id: event.agent.id,
        name: event.agent.name,
        version: event.agent.version,
      },

      // Session context
      session: {
        id: event.session.id,
        user_id: event.session.user_id,
        tenant_id: event.session.tenant_id,
        environment: event.session.environment,
      },

      // Resource context
      resource: {
        type: event.resource.type,
        name: event.resource.name,
        path: event.resource.path,
        host: event.resource.host,
        port: event.resource.port,
      },

      // Threat context
      threat: event.threat,

      // APM correlation
      ...(this.config.apm.enabled && this.getTraceContext()),
    };
  }

  private mapSeverityToStatus(
    severity: string
  ): 'info' | 'warn' | 'error' | 'critical' {
    const mapping: Record<string, 'info' | 'warn' | 'error' | 'critical'> = {
      info: 'info',
      low: 'info',
      medium: 'warn',
      high: 'error',
      critical: 'critical',
    };
    return mapping[severity] ?? 'info';
  }

  private buildTags(event: SecurityEvent): string[] {
    const tags = [
      ...this.config.logs.tags,
      `event_type:${event.event_type}`,
      `guard:${event.decision.guard}`,
      `severity:${event.decision.severity}`,
      `outcome:${event.outcome}`,
      `allowed:${event.decision.allowed}`,
    ];

    if (event.session.environment) {
      tags.push(`env:${event.session.environment}`);
    }

    if (event.session.tenant_id) {
      tags.push(`tenant:${event.session.tenant_id}`);
    }

    if (event.resource.type) {
      tags.push(`resource_type:${event.resource.type}`);
    }

    // Add custom labels as tags
    for (const [key, value] of Object.entries(event.labels)) {
      tags.push(`${key}:${value}`);
    }

    return tags;
  }

  private formatMessage(event: SecurityEvent): string {
    const action = event.decision.allowed ? 'ALLOWED' : 'BLOCKED';
    return `[${event.decision.guard}] ${action}: ${event.decision.reason}`;
  }

  private getTraceContext(): Record<string, unknown> | undefined {
    // Integration with Datadog APM tracer
    try {
      const tracer = require('dd-trace');
      const span = tracer.scope().active();

      if (span) {
        const context = span.context();
        return {
          dd: {
            trace_id: context.toTraceId(),
            span_id: context.toSpanId(),
            service: this.config.apm.service,
            env: this.config.apm.env,
          },
        };
      }
    } catch {
      // dd-trace not available
    }
    return undefined;
  }

  /**
   * Export events to Datadog Logs
   */
  async export(events: SecurityEvent[]): Promise<ExportResult> {
    const logs = events.map(e => this.toDatadogLog(e));

    try {
      let body: string | Buffer = JSON.stringify(logs);

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'DD-API-KEY': this.config.apiKey,
      };

      if (this.config.compression.enabled) {
        body = await gzip(body, { level: this.config.compression.level });
        headers['Content-Encoding'] = 'gzip';
      }

      const response = await this.client.post('/api/v2/logs', body, { headers });

      if (response.status >= 400) {
        throw new Error(`Datadog API error: ${response.status}`);
      }

      // Emit metrics
      if (this.config.metrics.enabled) {
        await this.emitMetrics(events);
      }

      return {
        exported: events.length,
        failed: 0,
        errors: [],
      };
    } catch (error) {
      return {
        exported: 0,
        failed: events.length,
        errors: events.map(e => ({
          eventId: e.event_id,
          error: (error as Error).message,
          retryable: this.isRetryable(error),
        })),
      };
    }
  }

  /**
   * Emit security metrics to Datadog
   */
  private async emitMetrics(events: SecurityEvent[]): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const prefix = this.config.metrics.prefix;

    // Aggregate metrics
    const byGuard = new Map<string, number>();
    const bySeverity = new Map<string, number>();
    const byOutcome = new Map<string, number>();

    for (const event of events) {
      // By guard
      const guardCount = byGuard.get(event.decision.guard) ?? 0;
      byGuard.set(event.decision.guard, guardCount + 1);

      // By severity
      const severityCount = bySeverity.get(event.decision.severity) ?? 0;
      bySeverity.set(event.decision.severity, severityCount + 1);

      // By outcome
      const outcome = event.decision.allowed ? 'allowed' : 'denied';
      const outcomeCount = byOutcome.get(outcome) ?? 0;
      byOutcome.set(outcome, outcomeCount + 1);
    }

    const series: MetricSeries[] = [];

    // Events by guard
    for (const [guard, count] of byGuard) {
      series.push({
        metric: `${prefix}.events.by_guard`,
        type: 'count',
        points: [[now, count]],
        tags: [...this.config.metrics.tags, `guard:${guard}`],
      });
    }

    // Events by severity
    for (const [severity, count] of bySeverity) {
      series.push({
        metric: `${prefix}.events.by_severity`,
        type: 'count',
        points: [[now, count]],
        tags: [...this.config.metrics.tags, `severity:${severity}`],
      });
    }

    // Events by outcome
    for (const [outcome, count] of byOutcome) {
      series.push({
        metric: `${prefix}.events.by_outcome`,
        type: 'count',
        points: [[now, count]],
        tags: [...this.config.metrics.tags, `outcome:${outcome}`],
      });
    }

    // Total events
    series.push({
      metric: `${prefix}.events.total`,
      type: 'count',
      points: [[now, events.length]],
      tags: this.config.metrics.tags,
    });

    // Send metrics
    await this.sendMetrics(series);
  }

  private async sendMetrics(series: MetricSeries[]): Promise<void> {
    const metricsUrl = `https://api.${this.config.site}/api/v1/series`;

    await this.client.post(metricsUrl, JSON.stringify({ series }), {
      headers: {
        'Content-Type': 'application/json',
        'DD-API-KEY': this.config.apiKey,
      },
    });
  }

  private isRetryable(error: unknown): boolean {
    if (error instanceof HttpError) {
      return [429, 503, 502, 504].includes(error.statusCode);
    }
    return false;
  }

  async healthCheck(): Promise<void> {
    const response = await this.client.get(
      `https://api.${this.config.site}/api/v1/validate`,
      {
        headers: {
          'DD-API-KEY': this.config.apiKey,
        },
      }
    );

    if (response.status !== 200) {
      throw new Error(`Datadog API validation failed: ${response.status}`);
    }
  }

  async shutdown(): Promise<void> {
    await this.flush();
  }
}

interface MetricSeries {
  metric: string;
  type: 'count' | 'gauge' | 'rate';
  points: [number, number][];
  tags: string[];
}
```

### Rust Implementation

```rust
use async_trait::async_trait;
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info};

/// Datadog configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatadogConfig {
    /// API key
    #[serde(skip_serializing)]
    pub api_key: String,
    /// Application key (optional)
    #[serde(skip_serializing)]
    pub app_key: Option<String>,
    /// Datadog site
    #[serde(default = "default_site")]
    pub site: String,
    /// Log configuration
    #[serde(default)]
    pub logs: LogConfig,
    /// Metrics configuration
    #[serde(default)]
    pub metrics: MetricsConfig,
}

fn default_site() -> String {
    "datadoghq.com".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_service")]
    pub service: String,
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_service() -> String { "clawdstrike".to_string() }
fn default_source() -> String { "clawdstrike".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_prefix")]
    pub prefix: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_prefix() -> String { "clawdstrike".to_string() }
fn default_true() -> bool { true }

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefix: default_prefix(),
            tags: vec![],
        }
    }
}

/// Datadog log entry
#[derive(Debug, Serialize)]
struct DatadogLog {
    message: String,
    ddsource: String,
    service: String,
    hostname: String,
    status: String,
    ddtags: String,
    #[serde(flatten)]
    attributes: serde_json::Value,
}

/// Datadog exporter
pub struct DatadogExporter {
    config: DatadogConfig,
    client: Client,
    hostname: String,
}

impl DatadogExporter {
    pub fn new(config: DatadogConfig) -> Result<Self, ExporterError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        Ok(Self {
            config,
            client,
            hostname,
        })
    }

    fn get_intake_url(&self) -> String {
        match self.config.site.as_str() {
            "datadoghq.eu" => "https://http-intake.logs.datadoghq.eu".to_string(),
            "us3.datadoghq.com" => "https://http-intake.logs.us3.datadoghq.com".to_string(),
            "us5.datadoghq.com" => "https://http-intake.logs.us5.datadoghq.com".to_string(),
            "ddog-gov.com" => "https://http-intake.logs.ddog-gov.com".to_string(),
            _ => "https://http-intake.logs.datadoghq.com".to_string(),
        }
    }

    fn to_datadog_log(&self, event: &SecurityEvent) -> DatadogLog {
        let status = match event.decision.severity {
            Severity::Info | Severity::Low => "info",
            Severity::Medium => "warn",
            Severity::High => "error",
            Severity::Critical => "critical",
        };

        let mut tags = self.config.logs.tags.clone();
        tags.push(format!("event_type:{:?}", event.event_type));
        tags.push(format!("guard:{}", event.decision.guard));
        tags.push(format!("severity:{:?}", event.decision.severity));
        tags.push(format!("outcome:{}", event.outcome));
        tags.push(format!("allowed:{}", event.decision.allowed));

        if let Some(env) = &event.session.environment {
            tags.push(format!("env:{}", env));
        }

        let action = if event.decision.allowed { "ALLOWED" } else { "BLOCKED" };
        let message = format!(
            "[{}] {}: {}",
            event.decision.guard, action, event.decision.reason
        );

        let attributes = serde_json::json!({
            "timestamp": event.timestamp.to_rfc3339(),
            "event_id": event.event_id.to_string(),
            "event_type": format!("{:?}", event.event_type),
            "security": {
                "outcome": event.outcome,
                "guard": event.decision.guard,
                "severity": format!("{:?}", event.decision.severity),
                "reason": event.decision.reason,
                "allowed": event.decision.allowed,
            },
            "agent": {
                "id": event.agent.id,
                "name": event.agent.name,
                "version": event.agent.version,
            },
            "session": {
                "id": event.session.id,
                "user_id": event.session.user_id,
                "tenant_id": event.session.tenant_id,
            },
            "resource": {
                "type": event.resource.resource_type,
                "name": event.resource.name,
                "path": event.resource.path,
                "host": event.resource.host,
            },
        });

        DatadogLog {
            message,
            ddsource: self.config.logs.source.clone(),
            service: self.config.logs.service.clone(),
            hostname: self.hostname.clone(),
            status: status.to_string(),
            ddtags: tags.join(","),
            attributes,
        }
    }

    async fn emit_metrics(&self, events: &[SecurityEvent]) -> Result<(), ExporterError> {
        if !self.config.metrics.enabled {
            return Ok(());
        }

        let now = chrono::Utc::now().timestamp();
        let prefix = &self.config.metrics.prefix;

        let mut by_guard: HashMap<String, i64> = HashMap::new();
        let mut by_severity: HashMap<String, i64> = HashMap::new();
        let mut allowed_count: i64 = 0;
        let mut denied_count: i64 = 0;

        for event in events {
            *by_guard.entry(event.decision.guard.clone()).or_insert(0) += 1;
            *by_severity
                .entry(format!("{:?}", event.decision.severity))
                .or_insert(0) += 1;

            if event.decision.allowed {
                allowed_count += 1;
            } else {
                denied_count += 1;
            }
        }

        let mut series: Vec<serde_json::Value> = vec![];

        for (guard, count) in by_guard {
            series.push(serde_json::json!({
                "metric": format!("{}.events.by_guard", prefix),
                "type": "count",
                "points": [[now, count]],
                "tags": [format!("guard:{}", guard)]
            }));
        }

        for (severity, count) in by_severity {
            series.push(serde_json::json!({
                "metric": format!("{}.events.by_severity", prefix),
                "type": "count",
                "points": [[now, count]],
                "tags": [format!("severity:{}", severity)]
            }));
        }

        series.push(serde_json::json!({
            "metric": format!("{}.events.allowed", prefix),
            "type": "count",
            "points": [[now, allowed_count]],
            "tags": self.config.metrics.tags
        }));

        series.push(serde_json::json!({
            "metric": format!("{}.events.denied", prefix),
            "type": "count",
            "points": [[now, denied_count]],
            "tags": self.config.metrics.tags
        }));

        let metrics_url = format!("https://api.{}/api/v1/series", self.config.site);

        self.client
            .post(&metrics_url)
            .header("DD-API-KEY", &self.config.api_key)
            .json(&serde_json::json!({ "series": series }))
            .send()
            .await?;

        Ok(())
    }
}

#[async_trait]
impl Exporter for DatadogExporter {
    fn name(&self) -> &str {
        "datadog"
    }

    fn schema(&self) -> SchemaFormat {
        SchemaFormat::Native
    }

    async fn export(&self, events: Vec<SecurityEvent>) -> Result<ExportResult, ExportError> {
        if events.is_empty() {
            return Ok(ExportResult {
                exported: 0,
                failed: 0,
                errors: vec![],
            });
        }

        let logs: Vec<DatadogLog> = events.iter().map(|e| self.to_datadog_log(e)).collect();

        let intake_url = format!("{}/api/v2/logs", self.get_intake_url());

        let response = self
            .client
            .post(&intake_url)
            .header("DD-API-KEY", &self.config.api_key)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&logs)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Datadog API error: {} - {}", status, body);

            return Ok(ExportResult {
                exported: 0,
                failed: events.len(),
                errors: events
                    .iter()
                    .map(|e| ExportError {
                        event_id: e.event_id.to_string(),
                        error: format!("HTTP {}: {}", status, body),
                        retryable: status.as_u16() >= 500 || status.as_u16() == 429,
                    })
                    .collect(),
            });
        }

        // Emit metrics
        if let Err(e) = self.emit_metrics(&events).await {
            error!("Failed to emit metrics: {}", e);
        }

        info!("Exported {} events to Datadog", events.len());
        Ok(ExportResult {
            exported: events.len(),
            failed: 0,
            errors: vec![],
        })
    }

    async fn health_check(&self) -> Result<(), String> {
        let validate_url = format!("https://api.{}/api/v1/validate", self.config.site);

        let response = self
            .client
            .get(&validate_url)
            .header("DD-API-KEY", &self.config.api_key)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Validation failed: {}", response.status()))
        }
    }

    async fn shutdown(&self) -> Result<(), String> {
        Ok(())
    }
}
```

## Configuration Examples

### Basic Configuration

```yaml
exporters:
  datadog:
    enabled: true
    api_key: ${DD_API_KEY}
    site: datadoghq.com
    logs:
      service: clawdstrike
      source: clawdstrike
      tags:
        - team:security
        - product:ai-agents
```

### Full Configuration

```yaml
exporters:
  datadog:
    enabled: true
    api_key: ${DD_API_KEY}
    app_key: ${DD_APP_KEY}
    site: datadoghq.com

    logs:
      service: clawdstrike-prod
      source: clawdstrike
      tags:
        - env:production
        - team:security
        - service:ai-agents

    metrics:
      enabled: true
      prefix: clawdstrike.security
      tags:
        - env:production

    apm:
      enabled: true
      service: clawdstrike
      env: production

    compression:
      enabled: true
      level: 6

    batch:
      size: 500
      flush_interval_ms: 5000

    retry:
      max_retries: 3
      initial_backoff_ms: 1000
```

### Multi-Region Configuration

```yaml
exporters:
  datadog_us:
    enabled: true
    api_key: ${DD_US_API_KEY}
    site: datadoghq.com
    logs:
      service: clawdstrike
      tags:
        - region:us

  datadog_eu:
    enabled: true
    api_key: ${DD_EU_API_KEY}
    site: datadoghq.eu
    logs:
      service: clawdstrike
      tags:
        - region:eu
```

## Datadog Dashboard

### Dashboard JSON

```json
{
  "title": "Clawdstrike Security Dashboard",
  "description": "AI Agent Security Posture",
  "widgets": [
    {
      "definition": {
        "title": "Policy Violations (24h)",
        "type": "query_value",
        "requests": [
          {
            "q": "sum:clawdstrike.security.events.denied{*}.as_count()",
            "aggregator": "sum"
          }
        ],
        "precision": 0,
        "custom_unit": "violations"
      }
    },
    {
      "definition": {
        "title": "Events by Severity",
        "type": "toplist",
        "requests": [
          {
            "q": "top(sum:clawdstrike.security.events.by_severity{*} by {severity}.as_count(), 5, 'sum', 'desc')"
          }
        ]
      }
    },
    {
      "definition": {
        "title": "Events by Guard",
        "type": "pie",
        "requests": [
          {
            "q": "sum:clawdstrike.security.events.by_guard{*} by {guard}.as_count()"
          }
        ]
      }
    },
    {
      "definition": {
        "title": "Event Timeline",
        "type": "timeseries",
        "requests": [
          {
            "q": "sum:clawdstrike.security.events.total{*}.as_count()",
            "display_type": "bars"
          }
        ]
      }
    },
    {
      "definition": {
        "title": "Recent Critical Events",
        "type": "log_stream",
        "query": "service:clawdstrike status:critical",
        "columns": ["timestamp", "message", "security.guard", "security.reason"]
      }
    }
  ],
  "layout_type": "ordered"
}
```

## Datadog Monitors

### Critical Violation Monitor

```json
{
  "name": "Clawdstrike Critical Policy Violation",
  "type": "log alert",
  "query": "logs(\"service:clawdstrike status:critical\").index(\"*\").rollup(\"count\").last(\"5m\") > 0",
  "message": "@pagerduty-security Critical policy violation detected by Clawdstrike.\n\nGuard: {{security.guard}}\nReason: {{security.reason}}\nSession: {{session.id}}",
  "tags": ["team:security", "source:clawdstrike"],
  "options": {
    "thresholds": {
      "critical": 0
    },
    "notify_audit": true,
    "include_tags": true,
    "escalation_message": "Critical violation unacknowledged after 15 minutes"
  }
}
```

### High Volume Denial Monitor

```json
{
  "name": "Clawdstrike High Denial Rate",
  "type": "metric alert",
  "query": "sum(last_5m):sum:clawdstrike.security.events.denied{*}.as_count() > 100",
  "message": "@slack-security High number of policy denials detected.\n\nThis may indicate:\n- Misconfigured policy\n- Potential attack\n- Misbehaving agent",
  "tags": ["team:security", "source:clawdstrike"],
  "options": {
    "thresholds": {
      "warning": 50,
      "critical": 100
    }
  }
}
```

## Implementation Phases

### Phase 1: Core Logging (Week 6)

- [ ] Implement DatadogExporter with Logs API v2
- [ ] Add proper tag formatting
- [ ] Gzip compression support
- [ ] Health check via validate endpoint
- [ ] Unit tests with mock API

### Phase 2: Metrics & APM (Week 6)

- [ ] Metrics emission via Series API
- [ ] APM trace correlation
- [ ] Custom metrics aggregation
- [ ] Integration tests

### Phase 3: Dashboards & Monitors (Week 6)

- [ ] Export dashboard JSON template
- [ ] Export monitor JSON templates
- [ ] Documentation for Datadog setup
- [ ] Multi-region support
