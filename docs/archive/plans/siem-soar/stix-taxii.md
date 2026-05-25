# STIX/TAXII Threat Intelligence Feed Consumption

## Problem Statement

Clawdstrike's egress allowlist and policy guards can benefit from external threat intelligence feeds to dynamically block known malicious indicators. Without threat intelligence integration:

1. Static allowlists become stale as threats evolve
2. Manual updates create lag between threat discovery and protection
3. No automated correlation with threat actor TTPs
4. Missing context for SOC analysts during incident investigation
5. Compliance gaps for threat-informed defense requirements

## Use Cases

| ID | Use Case | Priority |
|----|----------|----------|
| TI-1 | Subscribe to TAXII feeds for malicious domains/IPs | P0 |
| TI-2 | Auto-update egress blocklist from STIX indicators | P0 |
| TI-3 | Enrich security events with threat context | P1 |
| TI-4 | Support STIX 2.1 indicator patterns | P1 |
| TI-5 | Cache and deduplicate indicators | P1 |
| TI-6 | Publish Clawdstrike detections as STIX | P2 |

## Architecture

### Integration Pattern

```
+-------------------+     +-------------------------+     +------------------+
|                   |     |                         |     |                  |
|   TAXII Server    |     |   ThreatIntel Client    |     |   Clawdstrike    |
|   (External)      |<----|                         |---->|   Engine         |
|                   |     |   +------------------+  |     |                  |
| - AlienVault OTX  |     |   | TAXII 2.1 Client |  |     | - EgressGuard    |
| - MISP            |     |   +------------------+  |     | - PolicyEngine   |
| - OpenCTI         |     |   +------------------+  |     | - EventEnricher  |
| - CISA            |     |   | STIX Parser      |  |     +------------------+
|                   |     |   +------------------+  |
+-------------------+     |   +------------------+  |
                          |   | Indicator Cache  |  |
                          |   +------------------+  |
                          +-------------------------+
```

### Component Design

```
+-------------------------------------------------------------------------+
|                          ThreatIntelClient                               |
+-------------------------------------------------------------------------+
|                                                                          |
|  +---------------------+  +---------------------+  +-------------------+ |
|  |   TaxiiClient       |  |   StixParser        |  |   IndicatorCache  | |
|  |   - TAXII 2.0/2.1   |  |   - STIX 2.0/2.1    |  |   - TTL-based     | |
|  |   - Pagination      |  |   - Indicator types |  |   - Deduplication | |
|  |   - Auth (basic,    |  |   - Pattern parse   |  |   - Persistence   | |
|  |     cert, api key)  |  |   - Validation      |  |   - Bloom filter  | |
|  +---------------------+  +---------------------+  +-------------------+ |
|                                                                          |
|  +---------------------+  +---------------------+  +-------------------+ |
|  |   FeedManager       |  |   IndicatorMatcher  |  |   EventEnricher   | |
|  |   - Polling         |  |   - Domain match    |  |   - TTP context   | |
|  |   - Incremental     |  |   - IP/CIDR match   |  |   - Actor attrib  | |
|  |   - Rate limiting   |  |   - Pattern match   |  |   - Confidence    | |
|  +---------------------+  +---------------------+  +-------------------+ |
|                                                                          |
+-------------------------------------------------------------------------+
```

## STIX 2.1 Data Model

### Supported Indicator Types

| STIX Type | Clawdstrike Use |
|-----------|-----------------|
| `indicator` | Block/alert on pattern match |
| `malware` | Context enrichment |
| `attack-pattern` | MITRE ATT&CK mapping |
| `threat-actor` | Attribution context |
| `campaign` | Campaign correlation |
| `intrusion-set` | Group attribution |
| `infrastructure` | C2 infrastructure blocking |
| `observed-data` | Historical correlation |

### Indicator Pattern Types

| Pattern Type | Example | Guard |
|--------------|---------|-------|
| `domain-name:value` | `[domain-name:value = 'evil.com']` | EgressGuard |
| `ipv4-addr:value` | `[ipv4-addr:value = '192.0.2.1']` | EgressGuard |
| `ipv6-addr:value` | `[ipv6-addr:value = '2001:db8::1']` | EgressGuard |
| `url:value` | `[url:value = 'http://evil.com/malware']` | EgressGuard |
| `file:hashes.SHA-256` | `[file:hashes.SHA-256 = '...']` | PatchIntegrityGuard |
| `file:name` | `[file:name = 'malware.exe']` | ForbiddenPathGuard |

## API Design

### TypeScript Implementation

```typescript
import { EventEmitter } from 'events';

/**
 * TAXII server configuration
 */
export interface TaxiiServerConfig {
  /** TAXII server URL */
  url: string;

  /** API root path */
  apiRoot: string;

  /** Collection ID to subscribe */
  collectionId: string;

  /** Authentication */
  auth?: {
    type: 'basic' | 'api_key' | 'certificate';
    username?: string;
    password?: string;
    apiKey?: string;
    certPath?: string;
    keyPath?: string;
  };

  /** TAXII version */
  version?: '2.0' | '2.1';

  /** Custom headers */
  headers?: Record<string, string>;
}

/**
 * Feed polling configuration
 */
export interface FeedConfig {
  /** Polling interval in minutes */
  intervalMinutes?: number;

  /** Maximum indicators to fetch per poll */
  pageSize?: number;

  /** Indicator types to include */
  includeTypes?: string[];

  /** Minimum confidence score (0-100) */
  minConfidence?: number;

  /** Only fetch indicators added after this date */
  addedAfter?: string;

  /** Cache TTL in hours */
  cacheTtlHours?: number;
}

/**
 * Threat intelligence configuration
 */
export interface ThreatIntelConfig {
  /** Enable threat intelligence */
  enabled: boolean;

  /** TAXII servers to subscribe */
  servers: TaxiiServerConfig[];

  /** Feed configuration */
  feed?: FeedConfig;

  /** Cache configuration */
  cache?: {
    /** Enable persistent cache */
    persistent?: boolean;
    /** Cache file path */
    path?: string;
    /** Maximum cache size (indicators) */
    maxSize?: number;
  };

  /** Indicator actions */
  actions?: {
    /** Add to egress blocklist */
    blockEgress?: boolean;
    /** Add to path blocklist */
    blockPaths?: boolean;
    /** Enrich events with context */
    enrichEvents?: boolean;
  };
}

/**
 * STIX 2.1 Indicator
 */
export interface StixIndicator {
  type: 'indicator';
  spec_version: '2.1';
  id: string;
  created: string;
  modified: string;
  name?: string;
  description?: string;
  indicator_types?: string[];
  pattern: string;
  pattern_type: 'stix';
  pattern_version?: string;
  valid_from: string;
  valid_until?: string;
  kill_chain_phases?: KillChainPhase[];
  confidence?: number;
  lang?: string;
  external_references?: ExternalReference[];
  object_marking_refs?: string[];
  granular_markings?: GranularMarking[];
  labels?: string[];
}

export interface KillChainPhase {
  kill_chain_name: string;
  phase_name: string;
}

export interface ExternalReference {
  source_name: string;
  description?: string;
  url?: string;
  hashes?: Record<string, string>;
  external_id?: string;
}

export interface GranularMarking {
  marking_ref: string;
  selectors: string[];
}

/**
 * STIX Bundle
 */
export interface StixBundle {
  type: 'bundle';
  id: string;
  objects: StixObject[];
}

export type StixObject =
  | StixIndicator
  | StixMalware
  | StixAttackPattern
  | StixThreatActor
  | StixRelationship;

/**
 * Parsed indicator for matching
 */
export interface ParsedIndicator {
  id: string;
  type: 'domain' | 'ipv4' | 'ipv6' | 'url' | 'file_hash' | 'file_name';
  value: string;
  confidence: number;
  validFrom: Date;
  validUntil?: Date;
  source: string;
  context: {
    name?: string;
    description?: string;
    killChainPhases?: KillChainPhase[];
    labels?: string[];
    externalRefs?: ExternalReference[];
  };
}

/**
 * TAXII 2.1 client
 */
export class TaxiiClient {
  private config: TaxiiServerConfig;
  private client: HttpClient;
  private lastModified?: string;

  constructor(config: TaxiiServerConfig) {
    this.config = config;
    this.client = this.createClient();
  }

  private createClient(): HttpClient {
    const headers: Record<string, string> = {
      'Accept': 'application/taxii+json;version=2.1',
      'Content-Type': 'application/taxii+json;version=2.1',
      ...this.config.headers,
    };

    if (this.config.auth?.type === 'api_key') {
      headers['Authorization'] = `Bearer ${this.config.auth.apiKey}`;
    }

    return new HttpClient({
      baseUrl: this.config.url,
      headers,
      auth: this.config.auth?.type === 'basic' ? {
        username: this.config.auth.username!,
        password: this.config.auth.password!,
      } : undefined,
    });
  }

  /**
   * Get server discovery document
   */
  async getDiscovery(): Promise<TaxiiDiscovery> {
    const response = await this.client.get('/taxii2/');
    return response.json();
  }

  /**
   * Get API root information
   */
  async getApiRoot(): Promise<TaxiiApiRoot> {
    const response = await this.client.get(`/${this.config.apiRoot}/`);
    return response.json();
  }

  /**
   * Get collection information
   */
  async getCollection(): Promise<TaxiiCollection> {
    const response = await this.client.get(
      `/${this.config.apiRoot}/collections/${this.config.collectionId}/`
    );
    return response.json();
  }

  /**
   * Get objects from collection
   */
  async getObjects(options: {
    addedAfter?: string;
    limit?: number;
    type?: string[];
    next?: string;
  } = {}): Promise<TaxiiObjectsResponse> {
    const params = new URLSearchParams();

    if (options.addedAfter) {
      params.set('added_after', options.addedAfter);
    }
    if (options.limit) {
      params.set('limit', options.limit.toString());
    }
    if (options.type?.length) {
      params.set('match[type]', options.type.join(','));
    }
    if (options.next) {
      params.set('next', options.next);
    }

    const url = `/${this.config.apiRoot}/collections/${this.config.collectionId}/objects/?${params}`;
    const response = await this.client.get(url);

    // Extract pagination info from headers
    const more = response.headers.get('X-TAXII-Date-Added-Last');
    const nextUrl = response.headers.get('X-TAXII-More') === 'true'
      ? response.headers.get('X-TAXII-Next')
      : undefined;

    const body = await response.json();

    return {
      objects: body.objects || [],
      more: !!nextUrl,
      next: nextUrl ?? undefined,
    };
  }

  /**
   * Get all objects with pagination
   */
  async *getAllObjects(options: {
    addedAfter?: string;
    type?: string[];
    pageSize?: number;
  } = {}): AsyncGenerator<StixObject[]> {
    let next: string | undefined;

    do {
      const response = await this.getObjects({
        addedAfter: options.addedAfter,
        limit: options.pageSize ?? 100,
        type: options.type,
        next,
      });

      if (response.objects.length > 0) {
        yield response.objects;
      }

      next = response.next;
    } while (next);
  }
}

interface TaxiiDiscovery {
  title: string;
  description?: string;
  contact?: string;
  default?: string;
  api_roots?: string[];
}

interface TaxiiApiRoot {
  title: string;
  description?: string;
  versions: string[];
  max_content_length: number;
}

interface TaxiiCollection {
  id: string;
  title: string;
  description?: string;
  can_read: boolean;
  can_write: boolean;
  media_types?: string[];
}

interface TaxiiObjectsResponse {
  objects: StixObject[];
  more: boolean;
  next?: string;
}

/**
 * STIX pattern parser
 */
export class StixPatternParser {
  /**
   * Parse STIX pattern to indicator values
   */
  parse(pattern: string): ParsedIndicator['type'] | null {
    // Simple patterns: [object-type:property = 'value']
    const simpleMatch = pattern.match(
      /\[(\w+-?\w+):(\w+(?:\.\w+)*)\s*=\s*'([^']+)'\]/
    );

    if (!simpleMatch) {
      return null;
    }

    const [, objectType, property, value] = simpleMatch;

    return this.mapToIndicatorType(objectType, property, value);
  }

  private mapToIndicatorType(
    objectType: string,
    property: string,
    value: string
  ): { type: ParsedIndicator['type']; value: string } | null {
    switch (objectType) {
      case 'domain-name':
        if (property === 'value') {
          return { type: 'domain', value };
        }
        break;

      case 'ipv4-addr':
        if (property === 'value') {
          return { type: 'ipv4', value };
        }
        break;

      case 'ipv6-addr':
        if (property === 'value') {
          return { type: 'ipv6', value };
        }
        break;

      case 'url':
        if (property === 'value') {
          return { type: 'url', value };
        }
        break;

      case 'file':
        if (property.startsWith('hashes.')) {
          return { type: 'file_hash', value };
        }
        if (property === 'name') {
          return { type: 'file_name', value };
        }
        break;
    }

    return null;
  }

  /**
   * Extract all indicators from a pattern
   */
  extractIndicators(
    indicator: StixIndicator,
    source: string
  ): ParsedIndicator[] {
    const parsed = this.parse(indicator.pattern);

    if (!parsed) {
      return [];
    }

    return [{
      id: indicator.id,
      type: parsed.type,
      value: parsed.value,
      confidence: indicator.confidence ?? 50,
      validFrom: new Date(indicator.valid_from),
      validUntil: indicator.valid_until
        ? new Date(indicator.valid_until)
        : undefined,
      source,
      context: {
        name: indicator.name,
        description: indicator.description,
        killChainPhases: indicator.kill_chain_phases,
        labels: indicator.labels,
        externalRefs: indicator.external_references,
      },
    }];
  }
}

/**
 * Indicator cache with TTL
 */
export class IndicatorCache {
  private cache: Map<string, { indicator: ParsedIndicator; expiresAt: number }>;
  private maxSize: number;
  private persistPath?: string;

  constructor(config: {
    maxSize?: number;
    persistPath?: string;
  } = {}) {
    this.cache = new Map();
    this.maxSize = config.maxSize ?? 100000;
    this.persistPath = config.persistPath;

    if (this.persistPath) {
      this.loadFromDisk();
    }
  }

  /**
   * Add indicator to cache
   */
  add(indicator: ParsedIndicator, ttlMs: number): void {
    if (this.cache.size >= this.maxSize) {
      this.evictOldest();
    }

    const key = this.getKey(indicator);
    this.cache.set(key, {
      indicator,
      expiresAt: Date.now() + ttlMs,
    });
  }

  /**
   * Check if value matches any indicator
   */
  match(type: ParsedIndicator['type'], value: string): ParsedIndicator | null {
    const key = `${type}:${value.toLowerCase()}`;
    const entry = this.cache.get(key);

    if (!entry) {
      return null;
    }

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }

    // Check validity period
    const now = new Date();
    if (now < entry.indicator.validFrom) {
      return null;
    }
    if (entry.indicator.validUntil && now > entry.indicator.validUntil) {
      this.cache.delete(key);
      return null;
    }

    return entry.indicator;
  }

  /**
   * Get all indicators of a type
   */
  getByType(type: ParsedIndicator['type']): ParsedIndicator[] {
    const results: ParsedIndicator[] = [];
    const now = Date.now();

    for (const [key, entry] of this.cache) {
      if (key.startsWith(`${type}:`) && now < entry.expiresAt) {
        results.push(entry.indicator);
      }
    }

    return results;
  }

  /**
   * Get domains for egress blocking
   */
  getBlockedDomains(): string[] {
    return this.getByType('domain').map(i => i.value);
  }

  /**
   * Get IPs for egress blocking
   */
  getBlockedIPs(): string[] {
    return [
      ...this.getByType('ipv4').map(i => i.value),
      ...this.getByType('ipv6').map(i => i.value),
    ];
  }

  private getKey(indicator: ParsedIndicator): string {
    return `${indicator.type}:${indicator.value.toLowerCase()}`;
  }

  private evictOldest(): void {
    const now = Date.now();

    // First, evict expired
    for (const [key, entry] of this.cache) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
      }
    }

    // If still over limit, evict oldest
    if (this.cache.size >= this.maxSize) {
      const oldest = [...this.cache.entries()]
        .sort((a, b) => a[1].expiresAt - b[1].expiresAt)
        .slice(0, Math.floor(this.maxSize * 0.1));

      for (const [key] of oldest) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Persist cache to disk
   */
  async persist(): Promise<void> {
    if (!this.persistPath) return;

    const data = JSON.stringify([...this.cache.entries()]);
    await fs.writeFile(this.persistPath, data);
  }

  /**
   * Load cache from disk
   */
  private async loadFromDisk(): Promise<void> {
    if (!this.persistPath) return;

    try {
      const data = await fs.readFile(this.persistPath, 'utf-8');
      const entries = JSON.parse(data);
      this.cache = new Map(entries);

      // Remove expired entries
      const now = Date.now();
      for (const [key, entry] of this.cache) {
        if (now > entry.expiresAt) {
          this.cache.delete(key);
        }
      }
    } catch {
      // File doesn't exist or is invalid
    }
  }

  /**
   * Get cache statistics
   */
  stats(): { total: number; byType: Record<string, number> } {
    const byType: Record<string, number> = {};

    for (const key of this.cache.keys()) {
      const type = key.split(':')[0];
      byType[type] = (byType[type] ?? 0) + 1;
    }

    return {
      total: this.cache.size,
      byType,
    };
  }
}

/**
 * Feed manager for TAXII subscriptions
 */
export class FeedManager extends EventEmitter {
  private config: ThreatIntelConfig;
  private clients: Map<string, TaxiiClient> = new Map();
  private parser: StixPatternParser;
  private cache: IndicatorCache;
  private pollTimer?: NodeJS.Timeout;
  private lastPoll: Map<string, string> = new Map();

  constructor(config: ThreatIntelConfig) {
    super();
    this.config = config;
    this.parser = new StixPatternParser();
    this.cache = new IndicatorCache({
      maxSize: config.cache?.maxSize,
      persistPath: config.cache?.path,
    });

    // Initialize clients
    for (const server of config.servers) {
      const id = `${server.url}/${server.apiRoot}/${server.collectionId}`;
      this.clients.set(id, new TaxiiClient(server));
    }
  }

  /**
   * Start polling feeds
   */
  start(): void {
    const intervalMs = (this.config.feed?.intervalMinutes ?? 60) * 60 * 1000;

    // Initial poll
    this.pollAll();

    // Schedule recurring polls
    this.pollTimer = setInterval(() => this.pollAll(), intervalMs);
  }

  /**
   * Stop polling
   */
  stop(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
    }
  }

  /**
   * Poll all configured feeds
   */
  async pollAll(): Promise<void> {
    for (const [id, client] of this.clients) {
      try {
        await this.pollFeed(id, client);
      } catch (error) {
        this.emit('error', { feedId: id, error });
      }
    }

    // Persist cache after polling
    if (this.config.cache?.persistent) {
      await this.cache.persist();
    }

    this.emit('poll-complete', this.cache.stats());
  }

  private async pollFeed(feedId: string, client: TaxiiClient): Promise<void> {
    const addedAfter = this.lastPoll.get(feedId) ?? this.config.feed?.addedAfter;
    let indicatorCount = 0;

    for await (const objects of client.getAllObjects({
      addedAfter,
      type: this.config.feed?.includeTypes ?? ['indicator'],
      pageSize: this.config.feed?.pageSize,
    })) {
      for (const obj of objects) {
        if (obj.type === 'indicator') {
          const indicators = this.parser.extractIndicators(
            obj as StixIndicator,
            feedId
          );

          for (const indicator of indicators) {
            // Filter by confidence
            if (
              this.config.feed?.minConfidence &&
              indicator.confidence < this.config.feed.minConfidence
            ) {
              continue;
            }

            // Add to cache
            const ttlMs = (this.config.feed?.cacheTtlHours ?? 24) * 60 * 60 * 1000;
            this.cache.add(indicator, ttlMs);
            indicatorCount++;

            this.emit('indicator', indicator);
          }
        }
      }
    }

    this.lastPoll.set(feedId, new Date().toISOString());
    this.emit('feed-polled', { feedId, indicatorCount });
  }

  /**
   * Get the indicator cache
   */
  getCache(): IndicatorCache {
    return this.cache;
  }

  /**
   * Check if a domain/IP is in threat intel
   */
  checkThreat(
    type: 'domain' | 'ipv4' | 'ipv6',
    value: string
  ): ParsedIndicator | null {
    return this.cache.match(type, value);
  }
}

/**
 * Event enricher for adding threat context
 */
export class EventEnricher {
  private feedManager: FeedManager;

  constructor(feedManager: FeedManager) {
    this.feedManager = feedManager;
  }

  /**
   * Enrich security event with threat intelligence
   */
  enrich(event: SecurityEvent): SecurityEvent & { threatIntel?: ThreatContext } {
    const threatContext: ThreatContext = {
      indicators: [],
      ttps: [],
      confidence: 0,
    };

    // Check domain
    if (event.resource.host) {
      const indicator = this.feedManager.checkThreat(
        'domain',
        event.resource.host
      );
      if (indicator) {
        threatContext.indicators.push({
          type: 'domain',
          value: indicator.value,
          source: indicator.source,
          confidence: indicator.confidence,
        });

        // Add kill chain phases as TTPs
        if (indicator.context.killChainPhases) {
          for (const phase of indicator.context.killChainPhases) {
            threatContext.ttps.push({
              framework: phase.kill_chain_name,
              phase: phase.phase_name,
            });
          }
        }

        threatContext.confidence = Math.max(
          threatContext.confidence,
          indicator.confidence
        );
      }
    }

    if (threatContext.indicators.length === 0) {
      return event;
    }

    return {
      ...event,
      threatIntel: threatContext,
    };
  }
}

interface ThreatContext {
  indicators: Array<{
    type: string;
    value: string;
    source: string;
    confidence: number;
  }>;
  ttps: Array<{
    framework: string;
    phase: string;
  }>;
  confidence: number;
}
```

### Rust Implementation

```rust
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// TAXII server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiServerConfig {
    pub url: String,
    pub api_root: String,
    pub collection_id: String,
    #[serde(default)]
    pub auth: Option<TaxiiAuth>,
    #[serde(default = "default_version")]
    pub version: String,
}

fn default_version() -> String { "2.1".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TaxiiAuth {
    #[serde(rename = "basic")]
    Basic { username: String, password: String },
    #[serde(rename = "api_key")]
    ApiKey { api_key: String },
}

/// Feed configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    #[serde(default = "default_interval")]
    pub interval_minutes: u64,
    #[serde(default = "default_page_size")]
    pub page_size: usize,
    #[serde(default)]
    pub include_types: Vec<String>,
    #[serde(default)]
    pub min_confidence: Option<u8>,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_hours: u64,
}

fn default_interval() -> u64 { 60 }
fn default_page_size() -> usize { 100 }
fn default_cache_ttl() -> u64 { 24 }

impl Default for FeedConfig {
    fn default() -> Self {
        Self {
            interval_minutes: default_interval(),
            page_size: default_page_size(),
            include_types: vec!["indicator".to_string()],
            min_confidence: None,
            cache_ttl_hours: default_cache_ttl(),
        }
    }
}

/// Threat intel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    pub enabled: bool,
    pub servers: Vec<TaxiiServerConfig>,
    #[serde(default)]
    pub feed: FeedConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub actions: ThreatActions,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheConfig {
    pub persistent: bool,
    pub path: Option<String>,
    #[serde(default = "default_cache_size")]
    pub max_size: usize,
}

fn default_cache_size() -> usize { 100000 }
fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActions {
    #[serde(default = "default_true")]
    pub block_egress: bool,
    #[serde(default)]
    pub block_paths: bool,
    #[serde(default = "default_true")]
    pub enrich_events: bool,
}

impl Default for ThreatActions {
    fn default() -> Self {
        Self {
            block_egress: true,
            block_paths: false,
            enrich_events: true,
        }
    }
}

/// STIX 2.1 Indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixIndicator {
    #[serde(rename = "type")]
    pub object_type: String,
    pub spec_version: String,
    pub id: String,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub indicator_types: Option<Vec<String>>,
    pub pattern: String,
    pub pattern_type: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
    pub confidence: Option<u8>,
    pub labels: Option<Vec<String>>,
    pub external_references: Option<Vec<ExternalReference>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainPhase {
    pub kill_chain_name: String,
    pub phase_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReference {
    pub source_name: String,
    pub description: Option<String>,
    pub url: Option<String>,
    pub external_id: Option<String>,
}

/// Parsed indicator
#[derive(Debug, Clone)]
pub struct ParsedIndicator {
    pub id: String,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: u8,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub source: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub kill_chain_phases: Vec<KillChainPhase>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndicatorType {
    Domain,
    IPv4,
    IPv6,
    Url,
    FileHash,
    FileName,
}

impl std::fmt::Display for IndicatorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IndicatorType::Domain => write!(f, "domain"),
            IndicatorType::IPv4 => write!(f, "ipv4"),
            IndicatorType::IPv6 => write!(f, "ipv6"),
            IndicatorType::Url => write!(f, "url"),
            IndicatorType::FileHash => write!(f, "file_hash"),
            IndicatorType::FileName => write!(f, "file_name"),
        }
    }
}

/// STIX pattern parser
pub struct StixPatternParser;

impl StixPatternParser {
    pub fn parse(pattern: &str) -> Option<(IndicatorType, String)> {
        // Simple pattern: [object-type:property = 'value']
        let re = regex::Regex::new(
            r"\[(\w+-?\w+):(\w+(?:\.\w+)*)\s*=\s*'([^']+)'\]"
        ).ok()?;

        let caps = re.captures(pattern)?;
        let object_type = caps.get(1)?.as_str();
        let property = caps.get(2)?.as_str();
        let value = caps.get(3)?.as_str().to_string();

        let indicator_type = match (object_type, property) {
            ("domain-name", "value") => IndicatorType::Domain,
            ("ipv4-addr", "value") => IndicatorType::IPv4,
            ("ipv6-addr", "value") => IndicatorType::IPv6,
            ("url", "value") => IndicatorType::Url,
            ("file", prop) if prop.starts_with("hashes.") => IndicatorType::FileHash,
            ("file", "name") => IndicatorType::FileName,
            _ => return None,
        };

        Some((indicator_type, value))
    }

    pub fn extract_indicator(
        indicator: &StixIndicator,
        source: &str,
    ) -> Option<ParsedIndicator> {
        let (indicator_type, value) = Self::parse(&indicator.pattern)?;

        Some(ParsedIndicator {
            id: indicator.id.clone(),
            indicator_type,
            value,
            confidence: indicator.confidence.unwrap_or(50),
            valid_from: indicator.valid_from,
            valid_until: indicator.valid_until,
            source: source.to_string(),
            name: indicator.name.clone(),
            description: indicator.description.clone(),
            kill_chain_phases: indicator.kill_chain_phases.clone().unwrap_or_default(),
        })
    }
}

/// Indicator cache
pub struct IndicatorCache {
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    max_size: usize,
}

struct CacheEntry {
    indicator: ParsedIndicator,
    expires_at: DateTime<Utc>,
}

impl IndicatorCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_size,
        }
    }

    pub async fn add(&self, indicator: ParsedIndicator, ttl: chrono::Duration) {
        let key = format!("{}:{}", indicator.indicator_type, indicator.value.to_lowercase());
        let expires_at = Utc::now() + ttl;

        let mut cache = self.cache.write().await;

        // Evict if at capacity
        if cache.len() >= self.max_size {
            self.evict_expired(&mut cache);
        }

        cache.insert(key, CacheEntry { indicator, expires_at });
    }

    pub async fn check(&self, indicator_type: IndicatorType, value: &str) -> Option<ParsedIndicator> {
        let key = format!("{}:{}", indicator_type, value.to_lowercase());
        let cache = self.cache.read().await;

        let entry = cache.get(&key)?;

        if Utc::now() > entry.expires_at {
            return None;
        }

        let now = Utc::now();
        if now < entry.indicator.valid_from {
            return None;
        }
        if let Some(valid_until) = entry.indicator.valid_until {
            if now > valid_until {
                return None;
            }
        }

        Some(entry.indicator.clone())
    }

    pub async fn get_blocked_domains(&self) -> Vec<String> {
        let cache = self.cache.read().await;
        let now = Utc::now();

        cache.iter()
            .filter(|(k, v)| k.starts_with("domain:") && now < v.expires_at)
            .map(|(_, v)| v.indicator.value.clone())
            .collect()
    }

    pub async fn get_blocked_ips(&self) -> Vec<String> {
        let cache = self.cache.read().await;
        let now = Utc::now();

        cache.iter()
            .filter(|(k, v)| {
                (k.starts_with("ipv4:") || k.starts_with("ipv6:")) && now < v.expires_at
            })
            .map(|(_, v)| v.indicator.value.clone())
            .collect()
    }

    fn evict_expired(&self, cache: &mut HashMap<String, CacheEntry>) {
        let now = Utc::now();
        cache.retain(|_, v| now < v.expires_at);
    }

    pub async fn stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        let mut by_type: HashMap<String, usize> = HashMap::new();

        for key in cache.keys() {
            let type_str = key.split(':').next().unwrap_or("unknown");
            *by_type.entry(type_str.to_string()).or_insert(0) += 1;
        }

        CacheStats {
            total: cache.len(),
            by_type,
        }
    }
}

#[derive(Debug)]
pub struct CacheStats {
    pub total: usize,
    pub by_type: HashMap<String, usize>,
}

/// TAXII 2.1 client
pub struct TaxiiClient {
    config: TaxiiServerConfig,
    client: Client,
}

impl TaxiiClient {
    pub fn new(config: TaxiiServerConfig) -> Result<Self, ExporterError> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            "application/taxii+json;version=2.1".parse().unwrap(),
        );
        headers.insert(
            header::CONTENT_TYPE,
            "application/taxii+json;version=2.1".parse().unwrap(),
        );

        let mut builder = Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(60));

        if let Some(auth) = &config.auth {
            match auth {
                TaxiiAuth::Basic { username, password } => {
                    // Basic auth will be added per-request
                }
                TaxiiAuth::ApiKey { api_key } => {
                    let mut auth_headers = header::HeaderMap::new();
                    auth_headers.insert(
                        header::AUTHORIZATION,
                        format!("Bearer {}", api_key).parse().unwrap(),
                    );
                    builder = builder.default_headers(auth_headers);
                }
            }
        }

        let client = builder.build()?;

        Ok(Self { config, client })
    }

    pub async fn get_objects(
        &self,
        added_after: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<serde_json::Value>, ExporterError> {
        let mut url = format!(
            "{}/{}/collections/{}/objects/",
            self.config.url, self.config.api_root, self.config.collection_id
        );

        let mut params = vec![];
        if let Some(after) = added_after {
            params.push(format!("added_after={}", after));
        }
        if let Some(l) = limit {
            params.push(format!("limit={}", l));
        }
        params.push("match[type]=indicator".to_string());

        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        let mut request = self.client.get(&url);

        if let Some(TaxiiAuth::Basic { username, password }) = &self.config.auth {
            request = request.basic_auth(username, Some(password));
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(ExporterError::Http {
                status: response.status().as_u16(),
                body: response.text().await.unwrap_or_default(),
            });
        }

        let body: serde_json::Value = response.json().await?;
        let objects = body["objects"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        Ok(objects)
    }
}

/// Feed manager
pub struct FeedManager {
    config: ThreatIntelConfig,
    clients: HashMap<String, TaxiiClient>,
    cache: Arc<IndicatorCache>,
    last_poll: Arc<RwLock<HashMap<String, String>>>,
}

impl FeedManager {
    pub fn new(config: ThreatIntelConfig) -> Result<Self, ExporterError> {
        let mut clients = HashMap::new();

        for server in &config.servers {
            let id = format!(
                "{}/{}/{}",
                server.url, server.api_root, server.collection_id
            );
            clients.insert(id, TaxiiClient::new(server.clone())?);
        }

        let cache = Arc::new(IndicatorCache::new(config.cache.max_size));

        Ok(Self {
            config,
            clients,
            cache,
            last_poll: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn poll_all(&self) -> Result<usize, ExporterError> {
        let mut total_indicators = 0;

        for (id, client) in &self.clients {
            match self.poll_feed(id, client).await {
                Ok(count) => {
                    total_indicators += count;
                    info!("Polled {} indicators from {}", count, id);
                }
                Err(e) => {
                    error!("Failed to poll {}: {}", id, e);
                }
            }
        }

        Ok(total_indicators)
    }

    async fn poll_feed(&self, feed_id: &str, client: &TaxiiClient) -> Result<usize, ExporterError> {
        let added_after = {
            let last = self.last_poll.read().await;
            last.get(feed_id).cloned()
        };

        let objects = client
            .get_objects(added_after.as_deref(), Some(self.config.feed.page_size))
            .await?;

        let mut count = 0;
        let ttl = chrono::Duration::hours(self.config.feed.cache_ttl_hours as i64);

        for obj in objects {
            if obj["type"] == "indicator" {
                let indicator: StixIndicator = serde_json::from_value(obj)?;

                if let Some(parsed) = StixPatternParser::extract_indicator(&indicator, feed_id) {
                    // Filter by confidence
                    if let Some(min_conf) = self.config.feed.min_confidence {
                        if parsed.confidence < min_conf {
                            continue;
                        }
                    }

                    self.cache.add(parsed, ttl).await;
                    count += 1;
                }
            }
        }

        // Update last poll timestamp
        {
            let mut last = self.last_poll.write().await;
            last.insert(feed_id.to_string(), Utc::now().to_rfc3339());
        }

        Ok(count)
    }

    pub fn get_cache(&self) -> Arc<IndicatorCache> {
        Arc::clone(&self.cache)
    }

    pub async fn check_threat(
        &self,
        indicator_type: IndicatorType,
        value: &str,
    ) -> Option<ParsedIndicator> {
        self.cache.check(indicator_type, value).await
    }
}

/// Integration with EgressGuard
pub struct ThreatIntelEgressIntegration {
    feed_manager: Arc<FeedManager>,
}

impl ThreatIntelEgressIntegration {
    pub fn new(feed_manager: Arc<FeedManager>) -> Self {
        Self { feed_manager }
    }

    pub async fn is_blocked(&self, host: &str) -> Option<ParsedIndicator> {
        // Check domain
        if let Some(indicator) = self.feed_manager
            .check_threat(IndicatorType::Domain, host)
            .await
        {
            return Some(indicator);
        }

        // Check if it's an IP
        if host.parse::<std::net::Ipv4Addr>().is_ok() {
            return self.feed_manager
                .check_threat(IndicatorType::IPv4, host)
                .await;
        }

        if host.parse::<std::net::Ipv6Addr>().is_ok() {
            return self.feed_manager
                .check_threat(IndicatorType::IPv6, host)
                .await;
        }

        None
    }
}
```

## Configuration Examples

### Basic TAXII Feed

```yaml
threat_intel:
  enabled: true
  servers:
    - url: https://taxii.example.com
      api_root: api/v1
      collection_id: threat-indicators
      auth:
        type: api_key
        api_key: ${TAXII_API_KEY}

  feed:
    interval_minutes: 60
    page_size: 500
    min_confidence: 70
    cache_ttl_hours: 24

  actions:
    block_egress: true
    enrich_events: true
```

### Multiple Feeds

```yaml
threat_intel:
  enabled: true
  servers:
    # CISA Known Exploited Vulnerabilities
    - url: https://cisa.gov/taxii
      api_root: api
      collection_id: known-exploited-vulnerabilities
      version: "2.1"

    # AlienVault OTX
    - url: https://otx.alienvault.com/taxii
      api_root: api/v1
      collection_id: public-indicators
      auth:
        type: api_key
        api_key: ${OTX_API_KEY}

    # Internal MISP
    - url: https://misp.internal.example.com/taxii2
      api_root: api
      collection_id: ioc-feed
      auth:
        type: basic
        username: ${MISP_USER}
        password: ${MISP_PASSWORD}

  feed:
    interval_minutes: 30
    include_types:
      - indicator
      - malware
    min_confidence: 60
    cache_ttl_hours: 48

  cache:
    persistent: true
    path: /var/lib/clawdstrike/threat-cache.json
    max_size: 500000

  actions:
    block_egress: true
    block_paths: true
    enrich_events: true
```

## Implementation Phases

### Phase 1: TAXII Client (Week 11)

- [ ] Implement TAXII 2.1 client with pagination
- [ ] Support basic, API key, and certificate auth
- [ ] STIX 2.1 indicator parsing
- [ ] Unit tests with mock TAXII server

### Phase 2: Feed Management (Week 11)

- [ ] Feed polling with configurable intervals
- [ ] Indicator cache with TTL
- [ ] Persistence to disk
- [ ] Deduplication and eviction

### Phase 3: Guard Integration (Week 11-12)

- [ ] Integration with EgressGuard
- [ ] Event enrichment with threat context
- [ ] Metrics for cache stats
- [ ] Documentation and examples

### Phase 4: Production (Week 12)

- [ ] Multiple feed support
- [ ] Rate limiting for polling
- [ ] Health monitoring
- [ ] Example TAXII server configs
