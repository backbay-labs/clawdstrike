# Splunk Integration Architecture

## Problem Statement

Security operations teams using Splunk need real-time visibility into Clawdstrike policy violations and agent security events. Without native Splunk integration, SOC analysts must:

1. Manually export and import audit logs
2. Build custom parsing for Clawdstrike JSON format
3. Lack correlation with other security telemetry
4. Miss real-time alerting on critical violations

## Use Cases

| ID | Use Case | Priority |
|----|----------|----------|
| SPL-1 | Stream policy violations to Splunk in real-time | P0 |
| SPL-2 | Search and correlate agent events with network logs | P0 |
| SPL-3 | Build dashboards for agent security posture | P1 |
| SPL-4 | Alert on critical severity events | P1 |
| SPL-5 | Generate compliance reports from Splunk | P2 |

## Architecture

### HTTP Event Collector (HEC) Integration

```
+-------------------+     +-----------------------+     +------------------+
|                   |     |                       |     |                  |
|   Clawdstrike     |     |   Splunk HEC          |     |   Splunk         |
|   Engine          |---->|   Exporter            |---->|   Indexer        |
|                   |     |                       |     |                  |
+-------------------+     +-----------------------+     +------------------+
                                    |
                                    | HTTPS POST
                                    | /services/collector/event
                                    |
                          +-----------------------+
                          |   HEC Endpoint        |
                          |   - Load balanced     |
                          |   - Token auth        |
                          |   - Acknowledgment    |
                          +-----------------------+
```

### Component Design

```
+-----------------------------------------------------------------------+
|                       SplunkExporter                                   |
+-----------------------------------------------------------------------+
|                                                                        |
|  +------------------+  +------------------+  +------------------+       |
|  |  HecClient       |  |  EventFormatter  |  |  AckTracker      |       |
|  |  - HTTP/2        |  |  - JSON          |  |  - Channel mgmt  |       |
|  |  - Connection    |  |  - Raw           |  |  - Retry queue   |       |
|  |    pooling       |  |  - Metric        |  |  - Delivery      |       |
|  +------------------+  +------------------+  |    guarantee     |       |
|                                             +------------------+       |
|                                                                        |
|  +------------------+  +------------------+  +------------------+       |
|  |  BatchManager    |  |  TokenRotator    |  |  HealthChecker   |       |
|  |  - Size-based    |  |  - Vault sync    |  |  - /health       |       |
|  |  - Time-based    |  |  - Refresh       |  |  - Connectivity  |       |
|  |  - Compression   |  |  - Failover      |  |  - Latency       |       |
|  +------------------+  +------------------+  +------------------+       |
|                                                                        |
+-----------------------------------------------------------------------+
```

## API Design

### TypeScript Interface

```typescript
import { BaseExporter, ExporterConfig, SecurityEvent, ExportResult, SchemaFormat } from '../framework';

/**
 * Splunk HEC configuration
 */
export interface SplunkConfig extends ExporterConfig {
  /** HEC endpoint URL (e.g., https://splunk.example.com:8088) */
  hecUrl: string;

  /** HEC token for authentication */
  hecToken: string;

  /** Target index (optional, uses token default) */
  index?: string;

  /** Source type for events */
  sourceType?: string;

  /** Source identifier */
  source?: string;

  /** Host override (defaults to hostname) */
  host?: string;

  /** Enable acknowledgment tracking */
  useAck?: boolean;

  /** Acknowledgment channel */
  ackChannel?: string;

  /** Enable gzip compression */
  compression?: boolean;

  /** TLS configuration */
  tls?: {
    /** Skip certificate verification (NOT for production) */
    insecureSkipVerify?: boolean;
    /** Custom CA certificate path */
    caCertPath?: string;
    /** Client certificate for mTLS */
    clientCertPath?: string;
    /** Client key for mTLS */
    clientKeyPath?: string;
  };

  /** Connection settings */
  connection?: {
    /** Connection timeout (ms) */
    timeoutMs?: number;
    /** Keep-alive interval (ms) */
    keepAliveMs?: number;
    /** Maximum concurrent connections */
    maxConnections?: number;
  };
}

/**
 * Splunk HEC event format
 */
export interface SplunkEvent {
  /** Event timestamp (epoch seconds with milliseconds) */
  time: number;
  /** Target index */
  index?: string;
  /** Source type */
  sourcetype: string;
  /** Source */
  source: string;
  /** Host */
  host: string;
  /** Event data */
  event: Record<string, unknown>;
  /** Field extractions */
  fields?: Record<string, string>;
}

/**
 * Splunk HEC response
 */
export interface SplunkResponse {
  text: string;
  code: number;
  ackId?: number;
}

/**
 * Splunk HEC exporter implementation
 */
export class SplunkExporter extends BaseExporter {
  readonly name = 'splunk';
  readonly schema = SchemaFormat.Native;

  private config: Required<SplunkConfig>;
  private client: HttpClient;
  private ackTracker?: AckTracker;

  constructor(config: SplunkConfig) {
    super(config);
    this.config = this.mergeDefaults(config);
    this.client = this.createClient();

    if (this.config.useAck) {
      this.ackTracker = new AckTracker(this.client, this.config.ackChannel);
    }
  }

  private mergeDefaults(config: SplunkConfig): Required<SplunkConfig> {
    return {
      hecUrl: config.hecUrl,
      hecToken: config.hecToken,
      index: config.index ?? 'main',
      sourceType: config.sourceType ?? 'clawdstrike:security',
      source: config.source ?? 'clawdstrike',
      host: config.host ?? os.hostname(),
      useAck: config.useAck ?? true,
      ackChannel: config.ackChannel ?? crypto.randomUUID(),
      compression: config.compression ?? true,
      tls: config.tls ?? {},
      connection: {
        timeoutMs: config.connection?.timeoutMs ?? 30000,
        keepAliveMs: config.connection?.keepAliveMs ?? 60000,
        maxConnections: config.connection?.maxConnections ?? 10,
      },
      ...this.config,
    };
  }

  /**
   * Transform SecurityEvent to Splunk HEC format
   */
  private toSplunkEvent(event: SecurityEvent): SplunkEvent {
    return {
      time: new Date(event.timestamp).getTime() / 1000,
      index: this.config.index,
      sourcetype: this.config.sourceType,
      source: this.config.source,
      host: this.config.host,
      event: {
        event_id: event.event_id,
        event_type: event.event_type,
        event_category: event.event_category,
        outcome: event.outcome,
        action: event.action,
        agent: event.agent,
        session: event.session,
        threat: event.threat,
        decision: event.decision,
        resource: event.resource,
        metadata: event.metadata,
      },
      fields: {
        severity: event.decision.severity,
        guard: event.decision.guard,
        environment: event.session.environment ?? 'unknown',
        tenant_id: event.session.tenant_id ?? 'default',
      },
    };
  }

  /**
   * Export events to Splunk HEC
   */
  async export(events: SecurityEvent[]): Promise<ExportResult> {
    const splunkEvents = events.map(e => this.toSplunkEvent(e));
    const body = this.formatBody(splunkEvents);

    const headers: Record<string, string> = {
      'Authorization': `Splunk ${this.config.hecToken}`,
      'Content-Type': 'application/json',
    };

    if (this.config.useAck) {
      headers['X-Splunk-Request-Channel'] = this.config.ackChannel;
    }

    if (this.config.compression) {
      headers['Content-Encoding'] = 'gzip';
    }

    try {
      const response = await this.client.post<SplunkResponse>(
        `${this.config.hecUrl}/services/collector/event`,
        this.config.compression ? await gzip(body) : body,
        { headers }
      );

      if (response.code !== 0) {
        throw new Error(`HEC error: ${response.text} (code: ${response.code})`);
      }

      // Track acknowledgment if enabled
      if (this.config.useAck && response.ackId !== undefined) {
        await this.ackTracker?.track(response.ackId, events);
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
   * Format multiple events for HEC batch endpoint
   */
  private formatBody(events: SplunkEvent[]): string {
    // HEC expects newline-delimited JSON for batches
    return events.map(e => JSON.stringify(e)).join('\n');
  }

  /**
   * Check if error is retryable
   */
  private isRetryable(error: unknown): boolean {
    if (error instanceof HttpError) {
      // 429 Too Many Requests, 503 Service Unavailable
      return [429, 503, 502, 504].includes(error.statusCode);
    }
    return false;
  }

  /**
   * Health check via HEC health endpoint
   */
  async healthCheck(): Promise<void> {
    const response = await this.client.get(
      `${this.config.hecUrl}/services/collector/health`,
      {
        headers: {
          'Authorization': `Splunk ${this.config.hecToken}`,
        },
      }
    );

    if (response.status !== 200) {
      throw new Error(`Splunk HEC health check failed: ${response.status}`);
    }
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    // Flush pending events
    await super.shutdown();

    // Wait for acknowledgments
    if (this.ackTracker) {
      await this.ackTracker.waitForPending(30000);
    }

    // Close connections
    await this.client.close();
  }
}

/**
 * Acknowledgment tracker for delivery guarantee
 */
class AckTracker {
  private pending: Map<number, { events: SecurityEvent[]; timestamp: number }> = new Map();
  private pollInterval: NodeJS.Timeout | null = null;

  constructor(
    private client: HttpClient,
    private channel: string
  ) {
    this.startPolling();
  }

  async track(ackId: number, events: SecurityEvent[]): Promise<void> {
    this.pending.set(ackId, { events, timestamp: Date.now() });
  }

  private startPolling(): void {
    this.pollInterval = setInterval(() => this.pollAcks(), 1000);
  }

  private async pollAcks(): Promise<void> {
    if (this.pending.size === 0) return;

    const ackIds = Array.from(this.pending.keys());
    const response = await this.client.post('/services/collector/ack', {
      acks: ackIds,
    }, {
      headers: {
        'X-Splunk-Request-Channel': this.channel,
      },
    });

    for (const [ackId, success] of Object.entries(response.acks)) {
      if (success) {
        this.pending.delete(Number(ackId));
      }
    }
  }

  async waitForPending(timeoutMs: number): Promise<void> {
    const start = Date.now();
    while (this.pending.size > 0 && Date.now() - start < timeoutMs) {
      await this.pollAcks();
      await new Promise(r => setTimeout(r, 100));
    }
  }

  stop(): void {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
    }
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

/// Splunk HEC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplunkConfig {
    /// HEC endpoint URL
    pub hec_url: String,
    /// HEC token (loaded from credential provider)
    #[serde(skip_serializing)]
    pub hec_token: String,
    /// Target index
    #[serde(default = "default_index")]
    pub index: String,
    /// Source type
    #[serde(default = "default_sourcetype")]
    pub sourcetype: String,
    /// Source
    #[serde(default = "default_source")]
    pub source: String,
    /// Enable acknowledgment
    #[serde(default = "default_true")]
    pub use_ack: bool,
    /// Enable compression
    #[serde(default = "default_true")]
    pub compression: bool,
    /// Batch configuration
    #[serde(default)]
    pub batch: BatchConfig,
    /// TLS configuration
    #[serde(default)]
    pub tls: TlsConfig,
}

fn default_index() -> String { "main".to_string() }
fn default_sourcetype() -> String { "clawdstrike:security".to_string() }
fn default_source() -> String { "clawdstrike".to_string() }
fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    #[serde(default = "default_batch_size")]
    pub size: usize,
    #[serde(default = "default_flush_interval")]
    pub flush_interval_ms: u64,
}

fn default_batch_size() -> usize { 100 }
fn default_flush_interval() -> u64 { 5000 }

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            size: default_batch_size(),
            flush_interval_ms: default_flush_interval(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    pub insecure_skip_verify: bool,
    pub ca_cert_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
}

/// Splunk HEC event format
#[derive(Debug, Serialize)]
struct SplunkEvent {
    time: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<String>,
    sourcetype: String,
    source: String,
    host: String,
    event: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<HashMap<String, String>>,
}

/// Splunk HEC response
#[derive(Debug, Deserialize)]
struct HecResponse {
    text: String,
    code: i32,
    #[serde(rename = "ackId")]
    ack_id: Option<u64>,
}

/// Splunk HEC exporter
pub struct SplunkExporter {
    config: SplunkConfig,
    client: Client,
    channel: String,
    buffer: Arc<RwLock<Vec<SecurityEvent>>>,
    pending_acks: Arc<RwLock<HashMap<u64, Vec<String>>>>,
}

impl SplunkExporter {
    /// Create a new Splunk exporter
    pub fn new(config: SplunkConfig) -> Result<Self, ExporterError> {
        let client = Self::build_client(&config)?;
        let channel = uuid::Uuid::new_v4().to_string();

        Ok(Self {
            config,
            client,
            channel,
            buffer: Arc::new(RwLock::new(Vec::new())),
            pending_acks: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    fn build_client(config: &SplunkConfig) -> Result<Client, ExporterError> {
        let mut builder = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(10);

        if config.tls.insecure_skip_verify {
            warn!("TLS verification disabled - NOT FOR PRODUCTION");
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(ca_path) = &config.tls.ca_cert_path {
            let cert = std::fs::read(ca_path)?;
            let cert = reqwest::Certificate::from_pem(&cert)?;
            builder = builder.add_root_certificate(cert);
        }

        builder.build().map_err(ExporterError::from)
    }

    /// Transform SecurityEvent to Splunk format
    fn to_splunk_event(&self, event: &SecurityEvent) -> SplunkEvent {
        let timestamp = event.timestamp.timestamp_millis() as f64 / 1000.0;

        let mut fields = HashMap::new();
        fields.insert("severity".to_string(), format!("{:?}", event.decision.severity));
        fields.insert("guard".to_string(), event.decision.guard.clone());

        if let Some(env) = &event.session.environment {
            fields.insert("environment".to_string(), env.clone());
        }

        SplunkEvent {
            time: timestamp,
            index: Some(self.config.index.clone()),
            sourcetype: self.config.sourcetype.clone(),
            source: self.config.source.clone(),
            host: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            event: serde_json::to_value(event).unwrap_or_default(),
            fields: Some(fields),
        }
    }

    /// Send batch to HEC endpoint
    async fn send_batch(&self, events: &[SecurityEvent]) -> Result<HecResponse, ExporterError> {
        let splunk_events: Vec<SplunkEvent> = events
            .iter()
            .map(|e| self.to_splunk_event(e))
            .collect();

        // Build newline-delimited JSON
        let body: String = splunk_events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n");

        let mut request = self.client
            .post(format!("{}/services/collector/event", self.config.hec_url))
            .header(header::AUTHORIZATION, format!("Splunk {}", self.config.hec_token))
            .header(header::CONTENT_TYPE, "application/json");

        if self.config.use_ack {
            request = request.header("X-Splunk-Request-Channel", &self.channel);
        }

        let body = if self.config.compression {
            request = request.header(header::CONTENT_ENCODING, "gzip");
            compress_gzip(body.as_bytes())?
        } else {
            body.into_bytes()
        };

        let response = request.body(body).send().await?;
        let status = response.status();

        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(ExporterError::Http {
                status: status.as_u16(),
                body: text,
            });
        }

        let hec_response: HecResponse = response.json().await?;

        if hec_response.code != 0 {
            return Err(ExporterError::Hec {
                code: hec_response.code,
                text: hec_response.text,
            });
        }

        Ok(hec_response)
    }

    /// Poll for acknowledgments
    async fn poll_acks(&self) -> Result<Vec<u64>, ExporterError> {
        let pending = self.pending_acks.read().await;
        if pending.is_empty() {
            return Ok(vec![]);
        }

        let ack_ids: Vec<u64> = pending.keys().copied().collect();
        drop(pending);

        let response = self.client
            .post(format!("{}/services/collector/ack", self.config.hec_url))
            .header(header::AUTHORIZATION, format!("Splunk {}", self.config.hec_token))
            .header("X-Splunk-Request-Channel", &self.channel)
            .json(&serde_json::json!({ "acks": ack_ids }))
            .send()
            .await?;

        #[derive(Deserialize)]
        struct AckResponse {
            acks: HashMap<String, bool>,
        }

        let ack_response: AckResponse = response.json().await?;
        let mut confirmed = vec![];

        let mut pending = self.pending_acks.write().await;
        for (ack_id_str, success) in ack_response.acks {
            if success {
                if let Ok(ack_id) = ack_id_str.parse::<u64>() {
                    pending.remove(&ack_id);
                    confirmed.push(ack_id);
                }
            }
        }

        Ok(confirmed)
    }
}

#[async_trait]
impl Exporter for SplunkExporter {
    fn name(&self) -> &str {
        "splunk"
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

        debug!("Exporting {} events to Splunk", events.len());

        match self.send_batch(&events).await {
            Ok(response) => {
                if self.config.use_ack {
                    if let Some(ack_id) = response.ack_id {
                        let event_ids: Vec<String> = events.iter()
                            .map(|e| e.event_id.to_string())
                            .collect();
                        self.pending_acks.write().await.insert(ack_id, event_ids);
                    }
                }

                info!("Exported {} events to Splunk", events.len());
                Ok(ExportResult {
                    exported: events.len(),
                    failed: 0,
                    errors: vec![],
                })
            }
            Err(e) => {
                error!("Failed to export to Splunk: {}", e);
                Ok(ExportResult {
                    exported: 0,
                    failed: events.len(),
                    errors: events.iter().map(|ev| ExportError {
                        event_id: ev.event_id.to_string(),
                        error: e.to_string(),
                        retryable: e.is_retryable(),
                    }).collect(),
                })
            }
        }
    }

    async fn health_check(&self) -> Result<(), String> {
        let response = self.client
            .get(format!("{}/services/collector/health", self.config.hec_url))
            .header(header::AUTHORIZATION, format!("Splunk {}", self.config.hec_token))
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
        // Flush buffer
        let events = {
            let mut buffer = self.buffer.write().await;
            std::mem::take(&mut *buffer)
        };

        if !events.is_empty() {
            let _ = self.export(events).await;
        }

        // Wait for acks with timeout
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(30);

        while !self.pending_acks.read().await.is_empty() {
            if start.elapsed() > timeout {
                warn!("Timeout waiting for Splunk acknowledgments");
                break;
            }

            let _ = self.poll_acks().await;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        Ok(())
    }
}

/// Gzip compression helper
fn compress_gzip(data: &[u8]) -> Result<Vec<u8>, ExporterError> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish().map_err(ExporterError::from)
}
```

## Data Model

### Splunk Field Mappings

| Clawdstrike Field | Splunk Field | Type | Indexed |
|-------------------|--------------|------|---------|
| event_id | event_id | string | yes |
| timestamp | _time | epoch | auto |
| event_type | event_type | string | yes |
| event_category | event_category | string | yes |
| outcome | outcome | string | yes |
| agent.id | agent_id | string | yes |
| session.id | session_id | string | yes |
| session.user_id | user | string | yes |
| session.tenant_id | tenant_id | string | yes |
| decision.allowed | decision_allowed | bool | yes |
| decision.guard | guard | string | yes |
| decision.severity | severity | string | yes |
| decision.reason | reason | string | no |
| resource.type | resource_type | string | yes |
| resource.name | resource_name | string | yes |
| resource.path | resource_path | string | yes |
| resource.host | dest_host | string | yes |
| resource.port | dest_port | number | yes |
| threat.tactic | mitre_tactic | string | yes |
| threat.technique | mitre_technique | string | yes |

### props.conf

```ini
[clawdstrike:security]
DATETIME_CONFIG =
TIME_FORMAT = %s.%3N
TIME_PREFIX = "time":
MAX_TIMESTAMP_LOOKAHEAD = 32
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
KV_MODE = json
TRUNCATE = 999999

# Field extractions
EXTRACT-event_id = "event_id"\s*:\s*"(?<event_id>[^"]+)"
EXTRACT-event_type = "event_type"\s*:\s*"(?<event_type>[^"]+)"
EXTRACT-severity = "severity"\s*:\s*"(?<severity>[^"]+)"
EXTRACT-guard = "guard"\s*:\s*"(?<guard>[^"]+)"
EXTRACT-outcome = "outcome"\s*:\s*"(?<outcome>[^"]+)"

# Lookups
LOOKUP-severity_level = clawdstrike_severity severity OUTPUT severity_level severity_color
LOOKUP-mitre_enrichment = mitre_attack_techniques technique_id AS mitre_technique OUTPUT technique_name tactic_name
```

### transforms.conf

```ini
[clawdstrike_severity]
filename = clawdstrike_severity.csv

[mitre_attack_techniques]
filename = mitre_attack_techniques.csv
```

### clawdstrike_severity.csv

```csv
severity,severity_level,severity_color
info,1,green
low,2,yellow
medium,3,orange
high,4,red
critical,5,purple
```

## Configuration Examples

### Basic Configuration

```yaml
exporters:
  splunk:
    enabled: true
    hec_url: https://splunk.example.com:8088
    hec_token: ${SPLUNK_HEC_TOKEN}
    index: security
    sourcetype: clawdstrike:security
    source: clawdstrike-prod
```

### High-Availability Configuration

```yaml
exporters:
  splunk:
    enabled: true
    # Load-balanced HEC endpoint
    hec_url: https://hec-lb.example.com:8088
    hec_token: ${SPLUNK_HEC_TOKEN}
    index: security_agents
    sourcetype: clawdstrike:security
    source: clawdstrike

    # Enable indexer acknowledgment
    use_ack: true

    # Compression for efficiency
    compression: true

    # Batching
    batch:
      size: 500
      flush_interval_ms: 2000

    # TLS with custom CA
    tls:
      ca_cert_path: /etc/ssl/splunk-ca.pem

    # Retry configuration
    retry:
      max_retries: 5
      initial_backoff_ms: 500
      max_backoff_ms: 60000
      backoff_multiplier: 2.0

    # Rate limiting
    rate_limit:
      requests_per_second: 100
      burst_size: 200
```

### Multi-Index Configuration

```yaml
exporters:
  splunk:
    enabled: true
    hec_url: https://splunk.example.com:8088
    hec_token: ${SPLUNK_HEC_TOKEN}

    # Route events by severity
    routing:
      - condition: severity == 'critical'
        index: security_critical
        sourcetype: clawdstrike:critical
      - condition: severity == 'high'
        index: security_high
        sourcetype: clawdstrike:high
      - condition: default
        index: security_agents
        sourcetype: clawdstrike:security
```

## Authentication & Credential Management

### Token Rotation

```typescript
/**
 * Splunk HEC token rotator with Vault integration
 */
export class SplunkTokenRotator {
  private currentToken: string;
  private refreshInterval: NodeJS.Timeout | null = null;

  constructor(
    private vault: VaultClient,
    private secretPath: string,
    private refreshIntervalMs: number = 300000 // 5 minutes
  ) {}

  async start(): Promise<void> {
    await this.refresh();
    this.refreshInterval = setInterval(
      () => this.refresh(),
      this.refreshIntervalMs
    );
  }

  async refresh(): Promise<void> {
    try {
      const secret = await this.vault.read(this.secretPath);
      this.currentToken = secret.data.hec_token;
    } catch (error) {
      console.error('Failed to refresh Splunk token:', error);
      // Keep using existing token
    }
  }

  getToken(): string {
    return this.currentToken;
  }

  stop(): void {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
    }
  }
}
```

### Kubernetes Secret Integration

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: clawdstrike-splunk
  namespace: security
type: Opaque
data:
  hec_token: <base64-encoded-token>
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: clawdstrike-config
  namespace: security
data:
  siem-config.yaml: |
    exporters:
      splunk:
        enabled: true
        hec_url: https://splunk.example.com:8088
        hec_token: ${SPLUNK_HEC_TOKEN}
```

## Rate Limiting & Batching

### Adaptive Rate Limiting

```typescript
/**
 * Adaptive rate limiter that adjusts based on 429 responses
 */
export class AdaptiveRateLimiter {
  private currentRate: number;
  private minRate: number;
  private maxRate: number;
  private tokens: number;
  private lastRefill: number;

  constructor(config: {
    initialRate: number;
    minRate: number;
    maxRate: number;
    burstSize: number;
  }) {
    this.currentRate = config.initialRate;
    this.minRate = config.minRate;
    this.maxRate = config.maxRate;
    this.tokens = config.burstSize;
    this.lastRefill = Date.now();
  }

  async acquire(): Promise<void> {
    this.refill();

    while (this.tokens < 1) {
      const waitTime = (1 / this.currentRate) * 1000;
      await new Promise(r => setTimeout(r, waitTime));
      this.refill();
    }

    this.tokens -= 1;
  }

  onSuccess(): void {
    // Gradually increase rate on success
    this.currentRate = Math.min(
      this.currentRate * 1.05,
      this.maxRate
    );
  }

  onRateLimited(): void {
    // Halve rate on 429
    this.currentRate = Math.max(
      this.currentRate * 0.5,
      this.minRate
    );
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(
      this.tokens + elapsed * this.currentRate,
      this.currentRate * 2 // burst
    );
    this.lastRefill = now;
  }
}
```

## Error Handling & Retry Logic

### Error Categories

| Error Type | HTTP Status | Retryable | Action |
|------------|-------------|-----------|--------|
| Invalid Token | 401, 403 | No | Refresh token, alert |
| Rate Limited | 429 | Yes | Exponential backoff |
| Server Error | 500, 502, 503, 504 | Yes | Exponential backoff |
| Invalid Data | 400 | No | Log, drop event |
| Network Error | N/A | Yes | Exponential backoff |
| Timeout | N/A | Yes | Retry with backoff |

### Dead Letter Queue

```typescript
/**
 * Dead letter queue for failed events
 */
export class SplunkDeadLetterQueue {
  private queue: FailedEvent[] = [];
  private maxSize: number;
  private persistPath: string;

  constructor(config: { maxSize: number; persistPath: string }) {
    this.maxSize = config.maxSize;
    this.persistPath = config.persistPath;
    this.loadFromDisk();
  }

  async enqueue(event: SecurityEvent, error: string): Promise<void> {
    const failed: FailedEvent = {
      event,
      error,
      failedAt: new Date().toISOString(),
      attempts: 1,
    };

    this.queue.push(failed);

    if (this.queue.length > this.maxSize) {
      // Remove oldest
      this.queue.shift();
    }

    await this.persistToDisk();
  }

  async retry(exporter: SplunkExporter): Promise<number> {
    const toRetry = this.queue.splice(0, 100);
    let succeeded = 0;

    for (const failed of toRetry) {
      try {
        await exporter.export([failed.event]);
        succeeded++;
      } catch (error) {
        failed.attempts++;
        if (failed.attempts < 5) {
          this.queue.push(failed);
        } else {
          console.error('Permanently failed event:', failed.event.event_id);
        }
      }
    }

    await this.persistToDisk();
    return succeeded;
  }

  private async loadFromDisk(): Promise<void> {
    try {
      const data = await fs.readFile(this.persistPath, 'utf-8');
      this.queue = JSON.parse(data);
    } catch {
      // File doesn't exist or is invalid
      this.queue = [];
    }
  }

  private async persistToDisk(): Promise<void> {
    await fs.writeFile(
      this.persistPath,
      JSON.stringify(this.queue, null, 2)
    );
  }
}

interface FailedEvent {
  event: SecurityEvent;
  error: string;
  failedAt: string;
  attempts: number;
}
```

## Implementation Phases

### Phase 1: Core HEC Integration (Week 3)

- [ ] Implement SplunkExporter with basic HEC support
- [ ] Add batch processing with configurable size/interval
- [ ] Implement gzip compression
- [ ] Add health check endpoint
- [ ] Unit tests with mock HEC server

### Phase 2: Reliability (Week 3-4)

- [ ] Implement indexer acknowledgment tracking
- [ ] Add exponential backoff retry logic
- [ ] Implement dead letter queue
- [ ] Add adaptive rate limiting
- [ ] Integration tests with Splunk instance

### Phase 3: Production Hardening (Week 4)

- [ ] Vault token rotation integration
- [ ] Kubernetes secret support
- [ ] mTLS configuration
- [ ] Prometheus metrics exposure
- [ ] Documentation and examples

## Splunk Searches & Dashboards

### Example Searches

```spl
# Critical violations in last 24h
index=security sourcetype=clawdstrike:security severity=critical
| stats count by guard, resource_name, session_id
| sort -count

# Top blocked domains
index=security sourcetype=clawdstrike:security event_type=egress_blocked
| stats count by resource_host
| sort -count
| head 20

# Agent activity timeline
index=security sourcetype=clawdstrike:security
| timechart span=1h count by outcome

# MITRE ATT&CK coverage
index=security sourcetype=clawdstrike:security mitre_technique=*
| stats count by mitre_tactic, mitre_technique
| lookup mitre_attack_techniques technique_id AS mitre_technique OUTPUT technique_name
```

### Dashboard Panel: Security Posture

```xml
<dashboard version="1.1">
  <label>Clawdstrike Security Posture</label>
  <row>
    <panel>
      <single>
        <title>Critical Violations (24h)</title>
        <search>
          <query>index=security sourcetype=clawdstrike:security severity=critical | stats count</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="colorBy">value</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xf1813f","0xdc4e41"]</option>
        <option name="rangeValues">[0,5,20]</option>
      </single>
    </panel>
    <panel>
      <chart>
        <title>Violations by Guard</title>
        <search>
          <query>
            index=security sourcetype=clawdstrike:security outcome=failure
            | stats count by guard
            | sort -count
          </query>
          <earliest>-24h</earliest>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>
</dashboard>
```
