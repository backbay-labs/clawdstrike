# Elastic SIEM Integration with ECS Mapping

## Problem Statement

Organizations using the Elastic Stack for security monitoring need Clawdstrike events to integrate seamlessly with their existing security data. Elastic Common Schema (ECS) provides a standardized field naming convention that enables:

1. Unified search across heterogeneous security data
2. Out-of-the-box detection rules and dashboards
3. Correlation with network, endpoint, and cloud security events
4. Machine learning anomaly detection on standardized fields

Without ECS-compliant event formatting, security teams must:
- Create custom field mappings manually
- Maintain separate dashboards for Clawdstrike data
- Build custom detection rules that don't leverage existing templates
- Lose correlation capabilities with other security sources

## Use Cases

| ID | Use Case | Priority |
|----|----------|----------|
| ELK-1 | Index Clawdstrike events in ECS format for unified search | P0 |
| ELK-2 | Leverage Elastic Security detection rules for agent violations | P0 |
| ELK-3 | Correlate agent events with network/endpoint data | P1 |
| ELK-4 | Build ML jobs for anomalous agent behavior | P1 |
| ELK-5 | Generate compliance reports from Kibana | P2 |
| ELK-6 | Stream events via Elastic Agent integration | P2 |

## Architecture

### Integration Pattern

```
+-------------------+     +-------------------------+     +------------------+
|                   |     |                         |     |                  |
|   Clawdstrike     |     |   Elastic Exporter      |     |   Elasticsearch  |
|   Engine          |---->|                         |---->|   Cluster        |
|                   |     |   +------------------+  |     |                  |
+-------------------+     |   | ECS Transformer  |  |     +------------------+
                          |   +------------------+  |             |
                          |   +------------------+  |             v
                          |   | Bulk API Client  |  |     +------------------+
                          |   +------------------+  |     |   Kibana         |
                          |   +------------------+  |     |   - Dashboards   |
                          |   | ILM Manager      |  |     |   - Alerts       |
                          |   +------------------+  |     |   - ML Jobs      |
                          +-------------------------+     +------------------+
```

### Component Architecture

```
+-------------------------------------------------------------------------+
|                          ElasticExporter                                 |
+-------------------------------------------------------------------------+
|                                                                          |
|  +---------------------+  +---------------------+  +-------------------+ |
|  |   EcsTransformer    |  |   BulkProcessor     |  |   IndexManager    | |
|  |   - Field mapping   |  |   - Batching        |  |   - Template      | |
|  |   - Enrichment      |  |   - Backpressure    |  |   - ILM policy    | |
|  |   - Validation      |  |   - Error handling  |  |   - Rollover      | |
|  +---------------------+  +---------------------+  +-------------------+ |
|                                                                          |
|  +---------------------+  +---------------------+  +-------------------+ |
|  |   ConnectionPool    |  |   AuthProvider      |  |   RetryHandler    | |
|  |   - HTTP/2          |  |   - API key         |  |   - Circuit break | |
|  |   - Load balance    |  |   - Cloud ID        |  |   - Backoff       | |
|  |   - Health check    |  |   - mTLS            |  |   - DLQ           | |
|  +---------------------+  +---------------------+  +-------------------+ |
|                                                                          |
+-------------------------------------------------------------------------+
```

## ECS Field Mapping

### Core ECS Mapping

| Clawdstrike Field | ECS Field | ECS Type | Notes |
|-------------------|-----------|----------|-------|
| event_id | event.id | keyword | Unique event identifier |
| timestamp | @timestamp | date | Event timestamp |
| event_type | event.type | keyword | ECS event type |
| event_category | event.category | keyword | ECS category array |
| outcome | event.outcome | keyword | success/failure/unknown |
| action | event.action | keyword | Guard action evaluated |
| agent.id | agent.id | keyword | Clawdstrike agent ID |
| agent.name | agent.name | keyword | Agent name |
| agent.version | agent.version | keyword | Agent version |
| agent.type | agent.type | keyword | Always "clawdstrike" |
| session.id | session.id | keyword | Session identifier |
| session.user_id | user.id | keyword | User identifier |
| session.tenant_id | organization.id | keyword | Tenant/org identifier |
| decision.allowed | event.outcome | keyword | Mapped to success/failure |
| decision.guard | rule.name | keyword | Guard that made decision |
| decision.severity | event.severity | long | Numeric severity (0-4) |
| decision.reason | message | text | Human-readable reason |
| decision.ruleset | rule.ruleset | keyword | Policy ruleset name |
| resource.type | event.category | keyword | Maps to ECS category |
| resource.name | file.name / process.name | keyword | Depends on resource type |
| resource.path | file.path | keyword | File path if applicable |
| resource.host | destination.domain | keyword | Target host |
| resource.port | destination.port | long | Target port |
| threat.tactic | threat.tactic.name | keyword | MITRE ATT&CK tactic |
| threat.technique | threat.technique.id | keyword | MITRE technique ID |

### ECS Event Categories

| Clawdstrike Event Type | ECS event.category | ECS event.type |
|------------------------|-------------------|----------------|
| policy_violation | intrusion_detection | denied |
| policy_allow | intrusion_detection | allowed |
| guard_block | intrusion_detection | denied |
| guard_warn | intrusion_detection | info |
| secret_detected | intrusion_detection | indicator |
| egress_blocked | network | denied |
| forbidden_path | file | denied |
| patch_rejected | file | denied |
| session_start | session | start |
| session_end | session | end |

### ECS Severity Mapping

| Clawdstrike Severity | ECS event.severity | Numeric Value |
|---------------------|-------------------|---------------|
| info | informational | 1 |
| low | low | 2 |
| medium | medium | 3 |
| high | high | 4 |
| critical | critical | 5 |

## API Design

### TypeScript Implementation

```typescript
import { Client } from '@elastic/elasticsearch';
import {
  BaseExporter,
  ExporterConfig,
  SecurityEvent,
  ExportResult,
  SchemaFormat,
} from '../framework';

/**
 * Elastic exporter configuration
 */
export interface ElasticConfig extends ExporterConfig {
  /** Elasticsearch node URLs or cloud ID */
  nodes?: string[];
  cloudId?: string;

  /** Authentication */
  auth: {
    apiKey?: string;
    username?: string;
    password?: string;
  };

  /** Index configuration */
  index: {
    /** Index name pattern (supports date math) */
    name: string;
    /** Enable ILM (Index Lifecycle Management) */
    ilm?: boolean;
    /** ILM policy name */
    ilmPolicy?: string;
    /** Number of shards */
    shards?: number;
    /** Number of replicas */
    replicas?: number;
  };

  /** TLS configuration */
  tls?: {
    ca?: string;
    cert?: string;
    key?: string;
    rejectUnauthorized?: boolean;
  };

  /** Bulk operation settings */
  bulk?: {
    /** Flush threshold (number of operations) */
    flushThreshold?: number;
    /** Flush interval (ms) */
    flushIntervalMs?: number;
    /** Maximum retries per document */
    maxRetries?: number;
    /** Concurrent requests limit */
    concurrency?: number;
  };
}

/**
 * ECS-formatted event
 */
export interface EcsEvent {
  '@timestamp': string;
  event: {
    id: string;
    kind: string;
    category: string[];
    type: string[];
    outcome: string;
    action: string;
    severity: number;
    original?: string;
  };
  agent: {
    id: string;
    name: string;
    type: string;
    version: string;
  };
  user?: {
    id: string;
  };
  organization?: {
    id: string;
  };
  rule?: {
    name: string;
    ruleset?: string;
  };
  message: string;
  file?: {
    path: string;
    name: string;
  };
  destination?: {
    domain: string;
    port: number;
  };
  process?: {
    name: string;
    command_line: string;
  };
  threat?: {
    tactic: {
      name: string[];
    };
    technique: {
      id: string[];
      name: string[];
    };
  };
  labels: Record<string, string>;
  clawdstrike: {
    session_id: string;
    environment?: string;
    guard: string;
    policy_hash?: string;
    metadata: Record<string, unknown>;
  };
}

/**
 * Elastic SIEM exporter with ECS transformation
 */
export class ElasticExporter extends BaseExporter {
  readonly name = 'elastic';
  readonly schema = SchemaFormat.Ecs;

  private client: Client;
  private config: Required<ElasticConfig>;
  private transformer: EcsTransformer;
  private bulkHelper: BulkHelper;

  constructor(config: ElasticConfig) {
    super(config);
    this.config = this.mergeDefaults(config);
    this.client = this.createClient();
    this.transformer = new EcsTransformer();
    this.bulkHelper = new BulkHelper(this.client, {
      flushThreshold: this.config.bulk.flushThreshold,
      flushIntervalMs: this.config.bulk.flushIntervalMs,
      maxRetries: this.config.bulk.maxRetries,
      concurrency: this.config.bulk.concurrency,
    });
  }

  private mergeDefaults(config: ElasticConfig): Required<ElasticConfig> {
    return {
      nodes: config.nodes ?? ['http://localhost:9200'],
      cloudId: config.cloudId ?? '',
      auth: config.auth,
      index: {
        name: config.index.name ?? 'clawdstrike-security',
        ilm: config.index.ilm ?? true,
        ilmPolicy: config.index.ilmPolicy ?? 'clawdstrike-policy',
        shards: config.index.shards ?? 1,
        replicas: config.index.replicas ?? 1,
      },
      tls: config.tls ?? {},
      bulk: {
        flushThreshold: config.bulk?.flushThreshold ?? 500,
        flushIntervalMs: config.bulk?.flushIntervalMs ?? 5000,
        maxRetries: config.bulk?.maxRetries ?? 3,
        concurrency: config.bulk?.concurrency ?? 5,
      },
      ...this.config,
    };
  }

  private createClient(): Client {
    const clientConfig: any = {};

    if (this.config.cloudId) {
      clientConfig.cloud = { id: this.config.cloudId };
    } else {
      clientConfig.nodes = this.config.nodes;
    }

    if (this.config.auth.apiKey) {
      clientConfig.auth = { apiKey: this.config.auth.apiKey };
    } else if (this.config.auth.username) {
      clientConfig.auth = {
        username: this.config.auth.username,
        password: this.config.auth.password,
      };
    }

    if (this.config.tls.ca) {
      clientConfig.tls = {
        ca: this.config.tls.ca,
        cert: this.config.tls.cert,
        key: this.config.tls.key,
        rejectUnauthorized: this.config.tls.rejectUnauthorized ?? true,
      };
    }

    return new Client(clientConfig);
  }

  /**
   * Initialize index template and ILM policy
   */
  async initialize(): Promise<void> {
    // Create ILM policy if enabled
    if (this.config.index.ilm) {
      await this.createIlmPolicy();
    }

    // Create index template
    await this.createIndexTemplate();
  }

  private async createIlmPolicy(): Promise<void> {
    const policy = {
      policy: {
        phases: {
          hot: {
            min_age: '0ms',
            actions: {
              rollover: {
                max_age: '1d',
                max_primary_shard_size: '50gb',
              },
              set_priority: {
                priority: 100,
              },
            },
          },
          warm: {
            min_age: '7d',
            actions: {
              shrink: {
                number_of_shards: 1,
              },
              forcemerge: {
                max_num_segments: 1,
              },
              set_priority: {
                priority: 50,
              },
            },
          },
          cold: {
            min_age: '30d',
            actions: {
              set_priority: {
                priority: 0,
              },
            },
          },
          delete: {
            min_age: '90d',
            actions: {
              delete: {},
            },
          },
        },
      },
    };

    await this.client.ilm.putLifecycle({
      name: this.config.index.ilmPolicy,
      body: policy,
    });
  }

  private async createIndexTemplate(): Promise<void> {
    const template = {
      index_patterns: [`${this.config.index.name}-*`],
      template: {
        settings: {
          number_of_shards: this.config.index.shards,
          number_of_replicas: this.config.index.replicas,
          'index.lifecycle.name': this.config.index.ilmPolicy,
          'index.lifecycle.rollover_alias': this.config.index.name,
        },
        mappings: this.getEcsMappings(),
      },
      priority: 200,
      composed_of: ['ecs@mappings'],
      _meta: {
        description: 'Clawdstrike security events in ECS format',
        managed_by: 'clawdstrike',
      },
    };

    await this.client.indices.putIndexTemplate({
      name: `${this.config.index.name}-template`,
      body: template,
    });
  }

  private getEcsMappings(): Record<string, any> {
    return {
      properties: {
        '@timestamp': { type: 'date' },
        event: {
          properties: {
            id: { type: 'keyword' },
            kind: { type: 'keyword' },
            category: { type: 'keyword' },
            type: { type: 'keyword' },
            outcome: { type: 'keyword' },
            action: { type: 'keyword' },
            severity: { type: 'long' },
            original: { type: 'keyword', index: false },
          },
        },
        agent: {
          properties: {
            id: { type: 'keyword' },
            name: { type: 'keyword' },
            type: { type: 'keyword' },
            version: { type: 'keyword' },
          },
        },
        user: {
          properties: {
            id: { type: 'keyword' },
          },
        },
        organization: {
          properties: {
            id: { type: 'keyword' },
          },
        },
        rule: {
          properties: {
            name: { type: 'keyword' },
            ruleset: { type: 'keyword' },
          },
        },
        message: { type: 'text' },
        file: {
          properties: {
            path: { type: 'keyword' },
            name: { type: 'keyword' },
          },
        },
        destination: {
          properties: {
            domain: { type: 'keyword' },
            port: { type: 'long' },
          },
        },
        process: {
          properties: {
            name: { type: 'keyword' },
            command_line: { type: 'keyword' },
          },
        },
        threat: {
          properties: {
            tactic: {
              properties: {
                name: { type: 'keyword' },
              },
            },
            technique: {
              properties: {
                id: { type: 'keyword' },
                name: { type: 'keyword' },
              },
            },
          },
        },
        labels: { type: 'object', dynamic: true },
        clawdstrike: {
          properties: {
            session_id: { type: 'keyword' },
            environment: { type: 'keyword' },
            guard: { type: 'keyword' },
            policy_hash: { type: 'keyword' },
            metadata: { type: 'object', dynamic: true },
          },
        },
      },
    };
  }

  /**
   * Export events to Elasticsearch
   */
  async export(events: SecurityEvent[]): Promise<ExportResult> {
    const operations: BulkOperation[] = [];

    for (const event of events) {
      const ecsEvent = this.transformer.transform(event);
      const indexName = this.resolveIndexName(event.timestamp);

      operations.push({
        index: { _index: indexName, _id: event.event_id },
      });
      operations.push(ecsEvent);
    }

    try {
      const response = await this.bulkHelper.execute(operations);
      return this.processResponse(events, response);
    } catch (error) {
      return {
        exported: 0,
        failed: events.length,
        errors: events.map(e => ({
          eventId: e.event_id,
          error: (error as Error).message,
          retryable: true,
        })),
      };
    }
  }

  private resolveIndexName(timestamp: string): string {
    const date = new Date(timestamp);
    const suffix = date.toISOString().slice(0, 10).replace(/-/g, '.');
    return `${this.config.index.name}-${suffix}`;
  }

  private processResponse(
    events: SecurityEvent[],
    response: BulkResponse
  ): ExportResult {
    const errors: ExportError[] = [];
    let failed = 0;

    if (response.errors) {
      for (let i = 0; i < response.items.length; i++) {
        const item = response.items[i].index;
        if (item?.error) {
          failed++;
          errors.push({
            eventId: events[i].event_id,
            error: item.error.reason ?? 'Unknown error',
            retryable: item.status >= 500 || item.status === 429,
          });
        }
      }
    }

    return {
      exported: events.length - failed,
      failed,
      errors,
    };
  }

  async healthCheck(): Promise<void> {
    const response = await this.client.cluster.health();
    if (response.status === 'red') {
      throw new Error('Elasticsearch cluster health is red');
    }
  }

  async shutdown(): Promise<void> {
    await this.bulkHelper.flush();
    await this.client.close();
  }
}

/**
 * ECS field transformer
 */
class EcsTransformer {
  private severityMap: Map<string, number> = new Map([
    ['info', 1],
    ['low', 2],
    ['medium', 3],
    ['high', 4],
    ['critical', 5],
  ]);

  private categoryMap: Map<string, string[]> = new Map([
    ['policy_violation', ['intrusion_detection']],
    ['guard_block', ['intrusion_detection']],
    ['egress_blocked', ['network']],
    ['forbidden_path', ['file']],
    ['secret_detected', ['intrusion_detection']],
    ['session_start', ['session']],
    ['session_end', ['session']],
  ]);

  private typeMap: Map<string, string[]> = new Map([
    ['policy_violation', ['denied']],
    ['policy_allow', ['allowed']],
    ['guard_block', ['denied']],
    ['guard_warn', ['info']],
    ['egress_blocked', ['denied']],
    ['forbidden_path', ['denied']],
    ['session_start', ['start']],
    ['session_end', ['end']],
  ]);

  transform(event: SecurityEvent): EcsEvent {
    const severity = this.severityMap.get(event.decision.severity) ?? 1;
    const categories = this.categoryMap.get(event.event_type) ?? ['intrusion_detection'];
    const types = this.typeMap.get(event.event_type) ?? ['info'];

    const ecs: EcsEvent = {
      '@timestamp': event.timestamp,
      event: {
        id: event.event_id,
        kind: 'event',
        category: categories,
        type: types,
        outcome: event.decision.allowed ? 'success' : 'failure',
        action: event.action,
        severity,
      },
      agent: {
        id: event.agent.id,
        name: event.agent.name,
        type: event.agent.agent_type,
        version: event.agent.version,
      },
      message: event.decision.reason,
      rule: {
        name: event.decision.guard,
        ruleset: event.decision.ruleset,
      },
      labels: event.labels,
      clawdstrike: {
        session_id: event.session.id,
        environment: event.session.environment,
        guard: event.decision.guard,
        policy_hash: event.decision.policy_hash,
        metadata: event.metadata,
      },
    };

    // Add user if present
    if (event.session.user_id) {
      ecs.user = { id: event.session.user_id };
    }

    // Add organization if present
    if (event.session.tenant_id) {
      ecs.organization = { id: event.session.tenant_id };
    }

    // Add resource-specific fields
    this.addResourceFields(ecs, event);

    // Add threat fields if present
    this.addThreatFields(ecs, event);

    return ecs;
  }

  private addResourceFields(ecs: EcsEvent, event: SecurityEvent): void {
    if (event.resource.path) {
      ecs.file = {
        path: event.resource.path,
        name: event.resource.name,
      };
    }

    if (event.resource.host) {
      ecs.destination = {
        domain: event.resource.host,
        port: event.resource.port ?? 0,
      };
    }

    if (event.resource.type === 'process') {
      ecs.process = {
        name: event.resource.name,
        command_line: event.resource.path ?? '',
      };
    }
  }

  private addThreatFields(ecs: EcsEvent, event: SecurityEvent): void {
    if (event.threat.tactic || event.threat.technique) {
      ecs.threat = {
        tactic: {
          name: event.threat.tactic ? [event.threat.tactic] : [],
        },
        technique: {
          id: event.threat.technique ? [event.threat.technique] : [],
          name: [],
        },
      };
    }
  }
}

/**
 * Bulk operation helper with automatic batching and retry
 */
class BulkHelper {
  private buffer: any[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private inFlight: number = 0;

  constructor(
    private client: Client,
    private config: {
      flushThreshold: number;
      flushIntervalMs: number;
      maxRetries: number;
      concurrency: number;
    }
  ) {}

  async execute(operations: any[]): Promise<BulkResponse> {
    const responses: BulkResponse = { errors: false, items: [] };

    // Process in chunks
    for (let i = 0; i < operations.length; i += this.config.flushThreshold * 2) {
      const chunk = operations.slice(i, i + this.config.flushThreshold * 2);

      // Wait for concurrency slot
      while (this.inFlight >= this.config.concurrency) {
        await new Promise(r => setTimeout(r, 10));
      }

      this.inFlight++;
      try {
        const response = await this.sendBulk(chunk);
        responses.errors = responses.errors || response.errors;
        responses.items.push(...response.items);
      } finally {
        this.inFlight--;
      }
    }

    return responses;
  }

  private async sendBulk(operations: any[], attempt = 0): Promise<BulkResponse> {
    try {
      const response = await this.client.bulk({
        operations,
        refresh: false,
      });
      return response;
    } catch (error) {
      if (attempt < this.config.maxRetries && this.isRetryable(error)) {
        const backoff = Math.pow(2, attempt) * 1000;
        await new Promise(r => setTimeout(r, backoff));
        return this.sendBulk(operations, attempt + 1);
      }
      throw error;
    }
  }

  private isRetryable(error: any): boolean {
    return (
      error.statusCode === 429 ||
      error.statusCode === 503 ||
      error.code === 'ECONNREFUSED'
    );
  }

  async flush(): Promise<void> {
    while (this.inFlight > 0) {
      await new Promise(r => setTimeout(r, 100));
    }
  }
}

interface BulkOperation {
  index: { _index: string; _id?: string };
}

interface BulkResponse {
  errors: boolean;
  items: Array<{
    index?: {
      _id: string;
      status: number;
      error?: { reason: string };
    };
  }>;
}
```

### Rust Implementation

```rust
use async_trait::async_trait;
use elasticsearch::{
    auth::Credentials,
    http::transport::{SingleNodeConnectionPool, TransportBuilder},
    BulkOperation, BulkParts, Elasticsearch, IndexParts,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use tracing::{debug, error, info};

/// Elastic exporter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElasticConfig {
    /// Elasticsearch nodes
    #[serde(default)]
    pub nodes: Vec<String>,
    /// Elastic Cloud ID
    pub cloud_id: Option<String>,
    /// Authentication
    pub auth: ElasticAuth,
    /// Index settings
    pub index: IndexConfig,
    /// Bulk settings
    #[serde(default)]
    pub bulk: BulkConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ElasticAuth {
    #[serde(rename = "api_key")]
    ApiKey { api_key: String },
    #[serde(rename = "basic")]
    Basic { username: String, password: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexConfig {
    pub name: String,
    #[serde(default = "default_true")]
    pub ilm: bool,
    #[serde(default = "default_ilm_policy")]
    pub ilm_policy: String,
}

fn default_ilm_policy() -> String {
    "clawdstrike-policy".to_string()
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkConfig {
    #[serde(default = "default_bulk_size")]
    pub flush_threshold: usize,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
}

fn default_bulk_size() -> usize { 500 }
fn default_concurrency() -> usize { 5 }

impl Default for BulkConfig {
    fn default() -> Self {
        Self {
            flush_threshold: default_bulk_size(),
            concurrency: default_concurrency(),
        }
    }
}

/// ECS-formatted event
#[derive(Debug, Clone, Serialize)]
pub struct EcsEvent {
    #[serde(rename = "@timestamp")]
    pub timestamp: String,
    pub event: EcsEventData,
    pub agent: EcsAgent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<EcsUser>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<EcsOrganization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<EcsRule>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<EcsFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<EcsDestination>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat: Option<EcsThreat>,
    pub labels: HashMap<String, String>,
    pub clawdstrike: ClawdstrikeFields,
}

#[derive(Debug, Clone, Serialize)]
pub struct EcsEventData {
    pub id: String,
    pub kind: String,
    pub category: Vec<String>,
    #[serde(rename = "type")]
    pub event_type: Vec<String>,
    pub outcome: String,
    pub action: String,
    pub severity: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct EcsAgent {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub agent_type: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EcsUser {
    pub id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EcsOrganization {
    pub id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EcsRule {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EcsFile {
    pub path: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EcsDestination {
    pub domain: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct EcsThreat {
    pub tactic: EcsTactic,
    pub technique: EcsTechnique,
}

#[derive(Debug, Clone, Serialize)]
pub struct EcsTactic {
    pub name: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EcsTechnique {
    pub id: Vec<String>,
    pub name: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClawdstrikeFields {
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    pub guard: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    pub metadata: serde_json::Value,
}

/// Elastic SIEM exporter
pub struct ElasticExporter {
    config: ElasticConfig,
    client: Elasticsearch,
    transformer: EcsTransformer,
}

impl ElasticExporter {
    /// Create a new Elastic exporter
    pub async fn new(config: ElasticConfig) -> Result<Self, ExporterError> {
        let client = Self::create_client(&config)?;
        let transformer = EcsTransformer::new();

        let exporter = Self {
            config,
            client,
            transformer,
        };

        // Initialize index template
        exporter.initialize().await?;

        Ok(exporter)
    }

    fn create_client(config: &ElasticConfig) -> Result<Elasticsearch, ExporterError> {
        let url = if let Some(cloud_id) = &config.cloud_id {
            // Parse cloud ID
            cloud_id.clone()
        } else {
            config.nodes.first()
                .cloned()
                .unwrap_or_else(|| "http://localhost:9200".to_string())
        };

        let conn_pool = SingleNodeConnectionPool::new(url.parse()?);
        let mut transport_builder = TransportBuilder::new(conn_pool);

        match &config.auth {
            ElasticAuth::ApiKey { api_key } => {
                transport_builder = transport_builder.auth(Credentials::ApiKey(
                    api_key.clone(),
                    String::new(),
                ));
            }
            ElasticAuth::Basic { username, password } => {
                transport_builder = transport_builder.auth(Credentials::Basic(
                    username.clone(),
                    password.clone(),
                ));
            }
        }

        let transport = transport_builder.build()?;
        Ok(Elasticsearch::new(transport))
    }

    async fn initialize(&self) -> Result<(), ExporterError> {
        // Create ILM policy
        if self.config.index.ilm {
            self.create_ilm_policy().await?;
        }

        // Create index template
        self.create_index_template().await?;

        Ok(())
    }

    async fn create_ilm_policy(&self) -> Result<(), ExporterError> {
        let policy = json!({
            "policy": {
                "phases": {
                    "hot": {
                        "min_age": "0ms",
                        "actions": {
                            "rollover": {
                                "max_age": "1d",
                                "max_primary_shard_size": "50gb"
                            }
                        }
                    },
                    "warm": {
                        "min_age": "7d",
                        "actions": {
                            "shrink": { "number_of_shards": 1 },
                            "forcemerge": { "max_num_segments": 1 }
                        }
                    },
                    "delete": {
                        "min_age": "90d",
                        "actions": { "delete": {} }
                    }
                }
            }
        });

        self.client
            .ilm()
            .put_lifecycle(elasticsearch::ilm::IlmPutLifecycleParts::Policy(
                &self.config.index.ilm_policy,
            ))
            .body(policy)
            .send()
            .await?;

        Ok(())
    }

    async fn create_index_template(&self) -> Result<(), ExporterError> {
        let template = json!({
            "index_patterns": [format!("{}-*", self.config.index.name)],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1,
                    "index.lifecycle.name": self.config.index.ilm_policy,
                    "index.lifecycle.rollover_alias": self.config.index.name
                },
                "mappings": {
                    "properties": {
                        "@timestamp": { "type": "date" },
                        "event": {
                            "properties": {
                                "id": { "type": "keyword" },
                                "kind": { "type": "keyword" },
                                "category": { "type": "keyword" },
                                "type": { "type": "keyword" },
                                "outcome": { "type": "keyword" },
                                "severity": { "type": "long" }
                            }
                        },
                        "agent": {
                            "properties": {
                                "id": { "type": "keyword" },
                                "name": { "type": "keyword" }
                            }
                        },
                        "rule": {
                            "properties": {
                                "name": { "type": "keyword" }
                            }
                        },
                        "message": { "type": "text" },
                        "clawdstrike": { "type": "object", "dynamic": true }
                    }
                }
            }
        });

        self.client
            .indices()
            .put_index_template(elasticsearch::indices::IndicesPutIndexTemplateParts::Name(
                &format!("{}-template", self.config.index.name),
            ))
            .body(template)
            .send()
            .await?;

        Ok(())
    }

    fn resolve_index_name(&self, timestamp: &str) -> String {
        let date = chrono::DateTime::parse_from_rfc3339(timestamp)
            .map(|dt| dt.format("%Y.%m.%d").to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        format!("{}-{}", self.config.index.name, date)
    }
}

#[async_trait]
impl Exporter for ElasticExporter {
    fn name(&self) -> &str {
        "elastic"
    }

    fn schema(&self) -> SchemaFormat {
        SchemaFormat::Ecs
    }

    async fn export(&self, events: Vec<SecurityEvent>) -> Result<ExportResult, ExportError> {
        if events.is_empty() {
            return Ok(ExportResult {
                exported: 0,
                failed: 0,
                errors: vec![],
            });
        }

        let mut operations: Vec<BulkOperation<_>> = Vec::with_capacity(events.len());

        for event in &events {
            let ecs_event = self.transformer.transform(event);
            let index_name = self.resolve_index_name(&event.timestamp.to_rfc3339());

            operations.push(
                BulkOperation::index(ecs_event)
                    .id(&event.event_id.to_string())
                    .index(&index_name)
                    .into(),
            );
        }

        let response = self.client
            .bulk(BulkParts::None)
            .body(operations)
            .send()
            .await?;

        let response_body = response.json::<serde_json::Value>().await?;
        let has_errors = response_body["errors"].as_bool().unwrap_or(false);

        if has_errors {
            let items = response_body["items"].as_array();
            let mut errors = vec![];
            let mut failed = 0;

            if let Some(items) = items {
                for (i, item) in items.iter().enumerate() {
                    if let Some(error) = item["index"]["error"].as_object() {
                        failed += 1;
                        errors.push(ExportError {
                            event_id: events[i].event_id.to_string(),
                            error: error["reason"].as_str().unwrap_or("Unknown").to_string(),
                            retryable: item["index"]["status"].as_u64().unwrap_or(0) >= 500,
                        });
                    }
                }
            }

            return Ok(ExportResult {
                exported: events.len() - failed,
                failed,
                errors,
            });
        }

        info!("Exported {} events to Elasticsearch", events.len());
        Ok(ExportResult {
            exported: events.len(),
            failed: 0,
            errors: vec![],
        })
    }

    async fn health_check(&self) -> Result<(), String> {
        let response = self.client.cluster().health(
            elasticsearch::cluster::ClusterHealthParts::None,
        ).send().await.map_err(|e| e.to_string())?;

        let body: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
        let status = body["status"].as_str().unwrap_or("unknown");

        if status == "red" {
            return Err("Cluster health is red".to_string());
        }

        Ok(())
    }

    async fn shutdown(&self) -> Result<(), String> {
        Ok(())
    }
}

/// ECS transformer
struct EcsTransformer {
    severity_map: HashMap<String, u8>,
    category_map: HashMap<String, Vec<String>>,
    type_map: HashMap<String, Vec<String>>,
}

impl EcsTransformer {
    fn new() -> Self {
        let mut severity_map = HashMap::new();
        severity_map.insert("info".to_string(), 1);
        severity_map.insert("low".to_string(), 2);
        severity_map.insert("medium".to_string(), 3);
        severity_map.insert("high".to_string(), 4);
        severity_map.insert("critical".to_string(), 5);

        let mut category_map = HashMap::new();
        category_map.insert("policy_violation".to_string(), vec!["intrusion_detection".to_string()]);
        category_map.insert("egress_blocked".to_string(), vec!["network".to_string()]);
        category_map.insert("forbidden_path".to_string(), vec!["file".to_string()]);

        let mut type_map = HashMap::new();
        type_map.insert("policy_violation".to_string(), vec!["denied".to_string()]);
        type_map.insert("policy_allow".to_string(), vec!["allowed".to_string()]);

        Self {
            severity_map,
            category_map,
            type_map,
        }
    }

    fn transform(&self, event: &SecurityEvent) -> EcsEvent {
        let severity = self.severity_map
            .get(&format!("{:?}", event.decision.severity).to_lowercase())
            .copied()
            .unwrap_or(1);

        let event_type_str = format!("{:?}", event.event_type).to_lowercase();
        let categories = self.category_map
            .get(&event_type_str)
            .cloned()
            .unwrap_or_else(|| vec!["intrusion_detection".to_string()]);

        let types = self.type_map
            .get(&event_type_str)
            .cloned()
            .unwrap_or_else(|| vec!["info".to_string()]);

        EcsEvent {
            timestamp: event.timestamp.to_rfc3339(),
            event: EcsEventData {
                id: event.event_id.to_string(),
                kind: "event".to_string(),
                category: categories,
                event_type: types,
                outcome: if event.decision.allowed { "success" } else { "failure" }.to_string(),
                action: event.action.clone(),
                severity,
            },
            agent: EcsAgent {
                id: event.agent.id.clone(),
                name: event.agent.name.clone(),
                agent_type: event.agent.agent_type.clone(),
                version: event.agent.version.clone(),
            },
            user: event.session.user_id.as_ref().map(|id| EcsUser { id: id.clone() }),
            organization: event.session.tenant_id.as_ref().map(|id| EcsOrganization { id: id.clone() }),
            rule: Some(EcsRule {
                name: event.decision.guard.clone(),
                ruleset: event.decision.ruleset.clone(),
            }),
            message: event.decision.reason.clone(),
            file: event.resource.path.as_ref().map(|path| EcsFile {
                path: path.clone(),
                name: event.resource.name.clone(),
            }),
            destination: event.resource.host.as_ref().map(|host| EcsDestination {
                domain: host.clone(),
                port: event.resource.port.unwrap_or(0),
            }),
            threat: None, // TODO: Implement threat mapping
            labels: event.labels.clone(),
            clawdstrike: ClawdstrikeFields {
                session_id: event.session.id.clone(),
                environment: event.session.environment.clone(),
                guard: event.decision.guard.clone(),
                policy_hash: event.decision.policy_hash.clone(),
                metadata: event.metadata.clone(),
            },
        }
    }
}
```

## Configuration Examples

### Basic Configuration

```yaml
exporters:
  elastic:
    enabled: true
    nodes:
      - https://elasticsearch.example.com:9200
    auth:
      type: api_key
      api_key: ${ELASTIC_API_KEY}
    index:
      name: clawdstrike-security
```

### Elastic Cloud Configuration

```yaml
exporters:
  elastic:
    enabled: true
    cloud_id: ${ELASTIC_CLOUD_ID}
    auth:
      type: api_key
      api_key: ${ELASTIC_API_KEY}
    index:
      name: clawdstrike-security
      ilm: true
      ilm_policy: clawdstrike-90d
```

### High-Volume Production Configuration

```yaml
exporters:
  elastic:
    enabled: true
    nodes:
      - https://es-node-1.example.com:9200
      - https://es-node-2.example.com:9200
      - https://es-node-3.example.com:9200
    auth:
      type: api_key
      api_key: ${ELASTIC_API_KEY}
    index:
      name: clawdstrike-security
      ilm: true
      ilm_policy: clawdstrike-policy
      shards: 3
      replicas: 2
    bulk:
      flush_threshold: 1000
      flush_interval_ms: 2000
      max_retries: 5
      concurrency: 10
    tls:
      ca: /etc/ssl/elastic-ca.pem
```

## Elastic Security Detection Rules

### Example Detection Rule: Critical Policy Violation

```json
{
  "name": "Clawdstrike Critical Policy Violation",
  "description": "Detects critical severity policy violations from Clawdstrike",
  "risk_score": 73,
  "severity": "high",
  "type": "query",
  "query": "event.severity >= 5 and agent.type:clawdstrike and event.outcome:failure",
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0005",
        "name": "Defense Evasion"
      }
    }
  ],
  "actions": [
    {
      "action_type_id": ".pagerduty",
      "params": {
        "severity": "critical",
        "summary": "Critical Clawdstrike policy violation detected"
      }
    }
  ]
}
```

### Example Detection Rule: Secret Leak Attempt

```json
{
  "name": "Clawdstrike Secret Leak Detection",
  "description": "Detects attempts to leak secrets through AI agent",
  "risk_score": 85,
  "severity": "critical",
  "type": "query",
  "query": "clawdstrike.guard:secret_leak and event.outcome:failure",
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0010",
        "name": "Exfiltration"
      },
      "technique": [
        {
          "id": "T1048",
          "name": "Exfiltration Over Alternative Protocol"
        }
      ]
    }
  ]
}
```

## Implementation Phases

### Phase 1: Core Integration (Week 5)

- [ ] Implement ElasticExporter with bulk API support
- [ ] ECS transformation for all event types
- [ ] Index template and ILM policy creation
- [ ] Unit tests with mock Elasticsearch

### Phase 2: Production Features (Week 5-6)

- [ ] Connection pooling and load balancing
- [ ] Retry logic with exponential backoff
- [ ] Dead letter queue for failed events
- [ ] Health check endpoint

### Phase 3: Enterprise Features (Week 6)

- [ ] Elastic Cloud integration
- [ ] mTLS authentication
- [ ] Cross-cluster replication support
- [ ] Detection rule templates
- [ ] Kibana dashboard exports
