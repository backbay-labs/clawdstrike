# Sumo Logic Exporter Design

## Problem Statement

Organizations using Sumo Logic for centralized log management and security analytics need Clawdstrike events to integrate with their existing security monitoring infrastructure. Without native integration, security teams face:

1. Manual log collection and parsing overhead
2. Inconsistent field naming across data sources
3. Inability to correlate AI agent events with other security data
4. Limited real-time alerting capabilities
5. Compliance gaps in audit trail coverage

## Use Cases

| ID | Use Case | Priority |
|----|----------|----------|
| SL-1 | Stream security events via HTTP Source | P0 |
| SL-2 | Categorize events using Source Category hierarchy | P0 |
| SL-3 | Build scheduled searches for violation trends | P1 |
| SL-4 | Real-time alerts via Webhook connections | P1 |
| SL-5 | Cloud SIEM integration for threat detection | P2 |
| SL-6 | Multi-tenant partitioning | P2 |

## Architecture

### Integration Pattern

```
+-------------------+     +-------------------------+     +------------------+
|                   |     |                         |     |                  |
|   Clawdstrike     |     |   Sumo Logic Exporter   |     |   Sumo Logic     |
|   Engine          |---->|                         |---->|   Cloud          |
|                   |     |   +------------------+  |     |                  |
+-------------------+     |   | HTTPSourceClient |  |     | - Collectors     |
                          |   +------------------+  |     | - Partitions     |
                          |   +------------------+  |     | - Dashboards     |
                          |   | FieldExtractor   |  |     | - Alerts         |
                          |   +------------------+  |     +------------------+
                          |   +------------------+  |
                          |   | BatchProcessor   |  |
                          |   +------------------+  |
                          +-------------------------+
```

### Component Design

```
+-------------------------------------------------------------------------+
|                          SumoLogicExporter                               |
+-------------------------------------------------------------------------+
|                                                                          |
|  +---------------------+  +---------------------+  +-------------------+ |
|  |   HTTPSourceClient  |  |   MessageFormatter  |  |   MetadataManager | |
|  |   - HTTPS POST      |  |   - JSON            |  |   - Source Cat    | |
|  |   - Compression     |  |   - Text            |  |   - Source Name   | |
|  |   - Timestamps      |  |   - Key-Value       |  |   - Source Host   | |
|  +---------------------+  +---------------------+  +-------------------+ |
|                                                                          |
|  +---------------------+  +---------------------+  +-------------------+ |
|  |   BatchManager      |  |   RetryHandler      |  |   PartitionRouter | |
|  |   - Size limits     |  |   - Exponential     |  |   - By tenant     | |
|  |   - Time windows    |  |   - Circuit break   |  |   - By severity   | |
|  |   - Backpressure    |  |   - DLQ             |  |   - By guard      | |
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
 * Sumo Logic configuration
 */
export interface SumoLogicConfig extends ExporterConfig {
  /** HTTP Source URL (from Sumo Logic) */
  httpSourceUrl: string;

  /** Source category (hierarchical, e.g., "prod/security/clawdstrike") */
  sourceCategory?: string;

  /** Source name */
  sourceName?: string;

  /** Source host override */
  sourceHost?: string;

  /** Message format */
  format?: 'json' | 'text' | 'key_value';

  /** Timestamp field name */
  timestampField?: string;

  /** Enable gzip compression */
  compression?: boolean;

  /** Fields to include in logs */
  fields?: {
    /** Include all fields */
    includeAll?: boolean;
    /** Specific fields to include */
    include?: string[];
    /** Fields to exclude */
    exclude?: string[];
  };

  /** Partitioning configuration */
  partitioning?: {
    /** Enable partition routing */
    enabled?: boolean;
    /** Route by tenant */
    byTenant?: boolean;
    /** Route by severity */
    bySeverity?: boolean;
  };
}

/**
 * Sumo Logic message with metadata headers
 */
export interface SumoLogicMessage {
  /** Message body */
  body: string;
  /** HTTP headers for metadata */
  headers: {
    'X-Sumo-Category'?: string;
    'X-Sumo-Name'?: string;
    'X-Sumo-Host'?: string;
    'X-Sumo-Timestamp'?: string;
    'X-Sumo-Fields'?: string;
  };
}

/**
 * Sumo Logic exporter implementation
 */
export class SumoLogicExporter extends BaseExporter {
  readonly name = 'sumo-logic';
  readonly schema = SchemaFormat.Native;

  private config: Required<SumoLogicConfig>;
  private client: HttpClient;

  constructor(config: SumoLogicConfig) {
    super(config);
    this.config = this.mergeDefaults(config);
    this.client = this.createClient();
  }

  private mergeDefaults(config: SumoLogicConfig): Required<SumoLogicConfig> {
    return {
      httpSourceUrl: config.httpSourceUrl,
      sourceCategory: config.sourceCategory ?? 'security/clawdstrike',
      sourceName: config.sourceName ?? 'clawdstrike',
      sourceHost: config.sourceHost ?? os.hostname(),
      format: config.format ?? 'json',
      timestampField: config.timestampField ?? 'timestamp',
      compression: config.compression ?? true,
      fields: {
        includeAll: config.fields?.includeAll ?? true,
        include: config.fields?.include ?? [],
        exclude: config.fields?.exclude ?? [],
      },
      partitioning: {
        enabled: config.partitioning?.enabled ?? false,
        byTenant: config.partitioning?.byTenant ?? false,
        bySeverity: config.partitioning?.bySeverity ?? false,
      },
      ...this.config,
    };
  }

  private createClient(): HttpClient {
    return new HttpClient({
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  /**
   * Format event based on configured format
   */
  private formatEvent(event: SecurityEvent): string {
    switch (this.config.format) {
      case 'json':
        return this.formatJson(event);
      case 'text':
        return this.formatText(event);
      case 'key_value':
        return this.formatKeyValue(event);
      default:
        return this.formatJson(event);
    }
  }

  private formatJson(event: SecurityEvent): string {
    const data = this.filterFields(event);
    return JSON.stringify(data);
  }

  private formatText(event: SecurityEvent): string {
    const action = event.decision.allowed ? 'ALLOWED' : 'BLOCKED';
    return `${event.timestamp} [${event.decision.severity.toUpperCase()}] ` +
      `${event.decision.guard}: ${action} - ${event.decision.reason} ` +
      `| event_id=${event.event_id} session_id=${event.session.id}`;
  }

  private formatKeyValue(event: SecurityEvent): string {
    const pairs: string[] = [
      `timestamp="${event.timestamp}"`,
      `event_id="${event.event_id}"`,
      `event_type="${event.event_type}"`,
      `guard="${event.decision.guard}"`,
      `severity="${event.decision.severity}"`,
      `allowed="${event.decision.allowed}"`,
      `reason="${event.decision.reason}"`,
      `session_id="${event.session.id}"`,
    ];

    if (event.session.user_id) {
      pairs.push(`user_id="${event.session.user_id}"`);
    }

    if (event.resource.path) {
      pairs.push(`resource_path="${event.resource.path}"`);
    }

    if (event.resource.host) {
      pairs.push(`resource_host="${event.resource.host}"`);
    }

    return pairs.join(' ');
  }

  private filterFields(event: SecurityEvent): Record<string, unknown> {
    if (this.config.fields.includeAll) {
      const data = { ...event } as Record<string, unknown>;
      for (const field of this.config.fields.exclude) {
        delete data[field];
      }
      return data;
    }

    const data: Record<string, unknown> = {};
    for (const field of this.config.fields.include) {
      const value = this.getNestedField(event, field);
      if (value !== undefined) {
        this.setNestedField(data, field, value);
      }
    }
    return data;
  }

  private getNestedField(obj: any, path: string): unknown {
    return path.split('.').reduce((o, k) => o?.[k], obj);
  }

  private setNestedField(obj: any, path: string, value: unknown): void {
    const keys = path.split('.');
    const last = keys.pop()!;
    const target = keys.reduce((o, k) => (o[k] = o[k] || {}), obj);
    target[last] = value;
  }

  /**
   * Build metadata headers for Sumo Logic
   */
  private buildHeaders(event: SecurityEvent): Record<string, string> {
    const headers: Record<string, string> = {};

    // Source category with optional partitioning
    let category = this.config.sourceCategory;
    if (this.config.partitioning.enabled) {
      if (this.config.partitioning.byTenant && event.session.tenant_id) {
        category += `/${event.session.tenant_id}`;
      }
      if (this.config.partitioning.bySeverity) {
        category += `/${event.decision.severity}`;
      }
    }
    headers['X-Sumo-Category'] = category;
    headers['X-Sumo-Name'] = this.config.sourceName;
    headers['X-Sumo-Host'] = this.config.sourceHost;

    // Timestamp in milliseconds
    const timestamp = new Date(event.timestamp).getTime();
    headers['X-Sumo-Timestamp'] = timestamp.toString();

    // Custom fields for faceted search
    const fields: string[] = [
      `event_type=${event.event_type}`,
      `guard=${event.decision.guard}`,
      `severity=${event.decision.severity}`,
      `outcome=${event.outcome}`,
    ];

    if (event.session.tenant_id) {
      fields.push(`tenant_id=${event.session.tenant_id}`);
    }

    if (event.session.environment) {
      fields.push(`environment=${event.session.environment}`);
    }

    headers['X-Sumo-Fields'] = fields.join(',');

    return headers;
  }

  /**
   * Export events to Sumo Logic HTTP Source
   */
  async export(events: SecurityEvent[]): Promise<ExportResult> {
    if (events.length === 0) {
      return { exported: 0, failed: 0, errors: [] };
    }

    // Group events by partition if enabled
    const batches = this.partitionEvents(events);
    const results: ExportResult[] = [];

    for (const [category, batchEvents] of batches) {
      const result = await this.sendBatch(batchEvents, category);
      results.push(result);
    }

    // Aggregate results
    return results.reduce(
      (acc, r) => ({
        exported: acc.exported + r.exported,
        failed: acc.failed + r.failed,
        errors: [...acc.errors, ...r.errors],
      }),
      { exported: 0, failed: 0, errors: [] }
    );
  }

  private partitionEvents(
    events: SecurityEvent[]
  ): Map<string, SecurityEvent[]> {
    const batches = new Map<string, SecurityEvent[]>();

    if (!this.config.partitioning.enabled) {
      batches.set(this.config.sourceCategory, events);
      return batches;
    }

    for (const event of events) {
      let category = this.config.sourceCategory;

      if (this.config.partitioning.byTenant && event.session.tenant_id) {
        category += `/${event.session.tenant_id}`;
      }

      if (this.config.partitioning.bySeverity) {
        category += `/${event.decision.severity}`;
      }

      if (!batches.has(category)) {
        batches.set(category, []);
      }
      batches.get(category)!.push(event);
    }

    return batches;
  }

  private async sendBatch(
    events: SecurityEvent[],
    category: string
  ): Promise<ExportResult> {
    // Format messages
    const messages = events.map(e => this.formatEvent(e));
    let body = messages.join('\n');

    // Build headers
    const headers: Record<string, string> = {
      'Content-Type': this.config.format === 'json'
        ? 'application/json'
        : 'text/plain',
      'X-Sumo-Category': category,
      'X-Sumo-Name': this.config.sourceName,
      'X-Sumo-Host': this.config.sourceHost,
    };

    // Compress if enabled
    if (this.config.compression) {
      body = await gzip(body);
      headers['Content-Encoding'] = 'gzip';
    }

    try {
      const response = await this.client.post(
        this.config.httpSourceUrl,
        body,
        { headers }
      );

      if (response.status >= 400) {
        throw new Error(`Sumo Logic error: ${response.status}`);
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

  private isRetryable(error: unknown): boolean {
    if (error instanceof HttpError) {
      return [429, 503, 502, 504].includes(error.statusCode);
    }
    return true; // Network errors are retryable
  }

  async healthCheck(): Promise<void> {
    // Sumo Logic HTTP Sources don't have a dedicated health endpoint
    // Send a test message with special category
    const testMessage = JSON.stringify({
      _type: 'health_check',
      timestamp: new Date().toISOString(),
      source: 'clawdstrike',
    });

    const response = await this.client.post(this.config.httpSourceUrl, testMessage, {
      headers: {
        'Content-Type': 'application/json',
        'X-Sumo-Category': `${this.config.sourceCategory}/healthcheck`,
      },
    });

    if (response.status >= 400) {
      throw new Error(`Sumo Logic health check failed: ${response.status}`);
    }
  }

  async shutdown(): Promise<void> {
    await this.flush();
  }
}
```

### Rust Implementation

```rust
use async_trait::async_trait;
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info};

/// Sumo Logic configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SumoLogicConfig {
    /// HTTP Source URL
    pub http_source_url: String,
    /// Source category
    #[serde(default = "default_category")]
    pub source_category: String,
    /// Source name
    #[serde(default = "default_name")]
    pub source_name: String,
    /// Message format
    #[serde(default)]
    pub format: MessageFormat,
    /// Enable compression
    #[serde(default = "default_true")]
    pub compression: bool,
    /// Partitioning config
    #[serde(default)]
    pub partitioning: PartitionConfig,
    /// Batch settings
    #[serde(default)]
    pub batch: BatchConfig,
}

fn default_category() -> String { "security/clawdstrike".to_string() }
fn default_name() -> String { "clawdstrike".to_string() }
fn default_true() -> bool { true }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageFormat {
    #[default]
    Json,
    Text,
    KeyValue,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PartitionConfig {
    pub enabled: bool,
    pub by_tenant: bool,
    pub by_severity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    #[serde(default = "default_batch_size")]
    pub size: usize,
    #[serde(default = "default_flush_ms")]
    pub flush_interval_ms: u64,
}

fn default_batch_size() -> usize { 100 }
fn default_flush_ms() -> u64 { 5000 }

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            size: default_batch_size(),
            flush_interval_ms: default_flush_ms(),
        }
    }
}

/// Sumo Logic exporter
pub struct SumoLogicExporter {
    config: SumoLogicConfig,
    client: Client,
    hostname: String,
}

impl SumoLogicExporter {
    pub fn new(config: SumoLogicConfig) -> Result<Self, ExporterError> {
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

    fn format_event(&self, event: &SecurityEvent) -> String {
        match self.config.format {
            MessageFormat::Json => self.format_json(event),
            MessageFormat::Text => self.format_text(event),
            MessageFormat::KeyValue => self.format_kv(event),
        }
    }

    fn format_json(&self, event: &SecurityEvent) -> String {
        serde_json::to_string(event).unwrap_or_default()
    }

    fn format_text(&self, event: &SecurityEvent) -> String {
        let action = if event.decision.allowed { "ALLOWED" } else { "BLOCKED" };
        format!(
            "{} [{:?}] {}: {} - {} | event_id={} session_id={}",
            event.timestamp.to_rfc3339(),
            event.decision.severity,
            event.decision.guard,
            action,
            event.decision.reason,
            event.event_id,
            event.session.id
        )
    }

    fn format_kv(&self, event: &SecurityEvent) -> String {
        let mut pairs = vec![
            format!("timestamp=\"{}\"", event.timestamp.to_rfc3339()),
            format!("event_id=\"{}\"", event.event_id),
            format!("event_type=\"{:?}\"", event.event_type),
            format!("guard=\"{}\"", event.decision.guard),
            format!("severity=\"{:?}\"", event.decision.severity),
            format!("allowed=\"{}\"", event.decision.allowed),
            format!("session_id=\"{}\"", event.session.id),
        ];

        if let Some(user_id) = &event.session.user_id {
            pairs.push(format!("user_id=\"{}\"", user_id));
        }

        pairs.join(" ")
    }

    fn build_category(&self, event: &SecurityEvent) -> String {
        let mut category = self.config.source_category.clone();

        if self.config.partitioning.enabled {
            if self.config.partitioning.by_tenant {
                if let Some(tenant) = &event.session.tenant_id {
                    category = format!("{}/{}", category, tenant);
                }
            }
            if self.config.partitioning.by_severity {
                category = format!("{}/{:?}", category, event.decision.severity);
            }
        }

        category
    }

    fn build_fields(&self, event: &SecurityEvent) -> String {
        let mut fields = vec![
            format!("event_type={:?}", event.event_type),
            format!("guard={}", event.decision.guard),
            format!("severity={:?}", event.decision.severity),
            format!("outcome={}", event.outcome),
        ];

        if let Some(tenant) = &event.session.tenant_id {
            fields.push(format!("tenant_id={}", tenant));
        }

        if let Some(env) = &event.session.environment {
            fields.push(format!("environment={}", env));
        }

        fields.join(",")
    }

    async fn send_batch(
        &self,
        events: &[SecurityEvent],
        category: &str,
    ) -> Result<usize, ExporterError> {
        let messages: Vec<String> = events
            .iter()
            .map(|e| self.format_event(e))
            .collect();

        let body = messages.join("\n");

        let mut request = self.client
            .post(&self.config.http_source_url)
            .header("X-Sumo-Category", category)
            .header("X-Sumo-Name", &self.config.source_name)
            .header("X-Sumo-Host", &self.hostname);

        // Set content type based on format
        request = match self.config.format {
            MessageFormat::Json => request.header(header::CONTENT_TYPE, "application/json"),
            _ => request.header(header::CONTENT_TYPE, "text/plain"),
        };

        // Compress if enabled
        let body = if self.config.compression {
            request = request.header(header::CONTENT_ENCODING, "gzip");
            compress_gzip(body.as_bytes())?
        } else {
            body.into_bytes()
        };

        let response = request.body(body).send().await?;

        if !response.status().is_success() {
            return Err(ExporterError::Http {
                status: response.status().as_u16(),
                body: response.text().await.unwrap_or_default(),
            });
        }

        Ok(events.len())
    }
}

#[async_trait]
impl Exporter for SumoLogicExporter {
    fn name(&self) -> &str {
        "sumo-logic"
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

        // Partition events by category
        let mut batches: HashMap<String, Vec<&SecurityEvent>> = HashMap::new();

        for event in &events {
            let category = self.build_category(event);
            batches.entry(category).or_default().push(event);
        }

        let mut total_exported = 0;
        let mut total_failed = 0;
        let mut errors = vec![];

        for (category, batch_events) in batches {
            let batch: Vec<SecurityEvent> = batch_events.into_iter().cloned().collect();

            match self.send_batch(&batch, &category).await {
                Ok(count) => {
                    total_exported += count;
                }
                Err(e) => {
                    total_failed += batch.len();
                    for event in &batch {
                        errors.push(ExportError {
                            event_id: event.event_id.to_string(),
                            error: e.to_string(),
                            retryable: e.is_retryable(),
                        });
                    }
                }
            }
        }

        info!(
            "Exported {} events to Sumo Logic ({} failed)",
            total_exported, total_failed
        );

        Ok(ExportResult {
            exported: total_exported,
            failed: total_failed,
            errors,
        })
    }

    async fn health_check(&self) -> Result<(), String> {
        let test_message = serde_json::json!({
            "_type": "health_check",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "source": "clawdstrike"
        });

        let response = self.client
            .post(&self.config.http_source_url)
            .header("X-Sumo-Category", format!("{}/healthcheck", self.config.source_category))
            .header(header::CONTENT_TYPE, "application/json")
            .json(&test_message)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Health check failed: {}", response.status()))
        }
    }

    async fn shutdown(&self) -> Result<(), String> {
        Ok(())
    }
}

fn compress_gzip(data: &[u8]) -> Result<Vec<u8>, ExporterError> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish().map_err(ExporterError::from)
}
```

## Configuration Examples

### Basic Configuration

```yaml
exporters:
  sumo_logic:
    enabled: true
    http_source_url: ${SUMO_HTTP_SOURCE_URL}
    source_category: prod/security/clawdstrike
    source_name: clawdstrike
```

### Multi-Tenant Configuration

```yaml
exporters:
  sumo_logic:
    enabled: true
    http_source_url: ${SUMO_HTTP_SOURCE_URL}
    source_category: security/clawdstrike
    source_name: clawdstrike-prod

    format: json
    compression: true

    partitioning:
      enabled: true
      by_tenant: true
      by_severity: false

    batch:
      size: 200
      flush_interval_ms: 3000

    retry:
      max_retries: 3
      initial_backoff_ms: 1000
```

### High-Volume Configuration

```yaml
exporters:
  sumo_logic:
    enabled: true
    http_source_url: ${SUMO_HTTP_SOURCE_URL}
    source_category: prod/security/clawdstrike

    format: text  # Smaller payload
    compression: true

    batch:
      size: 1000
      flush_interval_ms: 1000

    rate_limit:
      requests_per_second: 50
      burst_size: 100

    retry:
      max_retries: 5
      initial_backoff_ms: 500
      max_backoff_ms: 30000
```

## Sumo Logic Field Extraction Rules

### JSON FER

```
| json field=_raw "event_id", "event_type", "timestamp", "decision.guard" as guard,
    "decision.severity" as severity, "decision.allowed" as allowed,
    "decision.reason" as reason, "session.id" as session_id,
    "session.user_id" as user_id, "session.tenant_id" as tenant_id,
    "resource.type" as resource_type, "resource.path" as resource_path,
    "resource.host" as resource_host
```

### Parse Expression for Key-Value Format

```
| parse "timestamp=\"*\" event_id=\"*\" event_type=\"*\" guard=\"*\" severity=\"*\" allowed=\"*\""
    as timestamp, event_id, event_type, guard, severity, allowed
```

## Sumo Logic Queries

### Security Violations Summary

```sql
_sourceCategory=*/security/clawdstrike
| json field=_raw "decision.allowed" as allowed, "decision.guard" as guard,
    "decision.severity" as severity
| where allowed = "false"
| count by guard, severity
| sort by _count desc
```

### Critical Events Last Hour

```sql
_sourceCategory=*/security/clawdstrike
| json field=_raw "decision.severity" as severity, "decision.reason" as reason,
    "session.id" as session_id
| where severity = "critical"
| count by session_id, reason
| order by _count desc
| limit 20
```

### Events by Tenant

```sql
_sourceCategory=*/security/clawdstrike
| json field=_raw "session.tenant_id" as tenant, "decision.allowed" as allowed
| count by tenant, allowed
| transpose row tenant column allowed
```

### Guard Performance

```sql
_sourceCategory=*/security/clawdstrike
| json field=_raw "decision.guard" as guard, "decision.allowed" as allowed
| count by guard, allowed
| where allowed = "false"
| sort by _count desc
```

## Sumo Logic Alerts

### Critical Violation Alert

```json
{
  "type": "SavedSearchWithScheduleSyncDefinition",
  "name": "Clawdstrike Critical Violation",
  "description": "Alert on critical policy violations",
  "search": {
    "queryText": "_sourceCategory=*/security/clawdstrike | json field=_raw \"decision.severity\" as severity | where severity = \"critical\" | count",
    "defaultTimeRange": "-5m",
    "byReceiptTime": false
  },
  "schedule": {
    "cronExpression": "0 0/5 * * * ? *",
    "muteErrorEmails": false,
    "scheduleType": "Custom",
    "timezone": "America/Los_Angeles",
    "threshold": {
      "thresholdType": "GreaterThan",
      "count": 0
    },
    "notification": {
      "taskType": "EmailSearchNotificationSyncDefinition",
      "toList": ["security@example.com"],
      "subjectTemplate": "Critical Clawdstrike Violation Detected",
      "includeQuery": true,
      "includeResultSet": true
    }
  }
}
```

### High Volume Denial Alert

```json
{
  "type": "SavedSearchWithScheduleSyncDefinition",
  "name": "Clawdstrike High Denial Rate",
  "search": {
    "queryText": "_sourceCategory=*/security/clawdstrike | json field=_raw \"decision.allowed\" as allowed | where allowed = \"false\" | count",
    "defaultTimeRange": "-5m"
  },
  "schedule": {
    "cronExpression": "0 0/5 * * * ? *",
    "threshold": {
      "thresholdType": "GreaterThan",
      "count": 100
    },
    "notification": {
      "taskType": "WebhookSearchNotificationSyncDefinition",
      "webhookId": "xxx-webhook-id",
      "payload": "{\"text\": \"High denial rate: {{ResultsCount}} violations in 5 minutes\"}"
    }
  }
}
```

## Dashboard Panels

### Security Posture Dashboard

```json
{
  "type": "DashboardV2SyncDefinition",
  "name": "Clawdstrike Security Posture",
  "panels": [
    {
      "panelType": "SumoSearchPanel",
      "title": "Violations by Guard",
      "queryString": "_sourceCategory=*/security/clawdstrike | json \"decision.guard\" as guard, \"decision.allowed\" as allowed | where allowed = \"false\" | count by guard",
      "visualSettings": "{\"general\":{\"type\":\"pie\"}}"
    },
    {
      "panelType": "SumoSearchPanel",
      "title": "Event Timeline",
      "queryString": "_sourceCategory=*/security/clawdstrike | json \"decision.allowed\" as allowed | timeslice 5m | count by _timeslice, allowed",
      "visualSettings": "{\"general\":{\"type\":\"area\"}}"
    },
    {
      "panelType": "SumoSearchPanel",
      "title": "Top Blocked Resources",
      "queryString": "_sourceCategory=*/security/clawdstrike | json \"decision.allowed\" as allowed, \"resource.name\" as resource | where allowed = \"false\" | count by resource | top 10 resource",
      "visualSettings": "{\"general\":{\"type\":\"bar\"}}"
    }
  ]
}
```

## Implementation Phases

### Phase 1: Core Integration (Week 6)

- [ ] Implement SumoLogicExporter with HTTP Source
- [ ] Support JSON, text, and key-value formats
- [ ] Gzip compression
- [ ] Metadata headers (category, name, host)
- [ ] Unit tests with mock endpoints

### Phase 2: Enterprise Features (Week 6)

- [ ] Multi-tenant partitioning
- [ ] Severity-based routing
- [ ] Retry with exponential backoff
- [ ] Dead letter queue

### Phase 3: Sumo Logic Artifacts (Week 6)

- [ ] Field extraction rules
- [ ] Saved search templates
- [ ] Alert configurations
- [ ] Dashboard JSON exports
- [ ] Documentation
