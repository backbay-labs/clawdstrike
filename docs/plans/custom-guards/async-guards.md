# Async Guards: External Service Integration

## Document Information

| Field | Value |
|-------|-------|
| **Status** | Draft |
| **Version** | 0.1.0 |
| **Authors** | Clawdstrike Architecture Team |
| **Last Updated** | 2026-02-02 |
| **Prerequisites** | overview.md, plugin-system.md |

---

## 1. Problem Statement

### 1.1 The Need for External Services

Many security decisions require data that isn't available locally:

1. **Threat Intelligence**: Is this file hash known malicious? (VirusTotal)
2. **Vulnerability Scanning**: Does this dependency have CVEs? (Snyk, Dependabot)
3. **URL Reputation**: Is this domain safe? (Google Safe Browsing, URLhaus)
4. **Identity Verification**: Is this user authorized? (LDAP, Okta)
5. **Compliance Checking**: Does this action comply with policy? (External policy engines)

### 1.2 Challenges

| Challenge | Impact |
|-----------|--------|
| **Latency** | External calls add 100-5000ms latency |
| **Availability** | External services may be down |
| **Rate Limits** | APIs have quotas (e.g., VirusTotal: 4 req/min free) |
| **Cost** | Paid APIs charge per request |
| **Security** | Sending data externally is itself a risk |
| **Privacy** | Some data shouldn't leave the network |

### 1.3 Design Goals

1. **Non-blocking by default**: Sync guards shouldn't wait for async guards
2. **Configurable timeout behavior**: Allow, deny, or warn on timeout
3. **Caching**: Minimize redundant external calls
4. **Rate limiting**: Respect API quotas
5. **Circuit breaking**: Gracefully handle service outages
6. **Audit logging**: Track all external calls

---

## 2. Architecture

### 2.1 Async Guard Execution Model

```
+------------------------------------------------------------------+
|                    Policy Engine                                  |
+------------------------------------------------------------------+
|                                                                    |
|  Event arrives                                                     |
|       │                                                            |
|       v                                                            |
|  ┌─────────────────────────────────────────────────────────────┐  |
|  │                    Guard Orchestrator                        │  |
|  └─────────────────────────────────────────────────────────────┘  |
|       │                                                            |
|       ├──────────────────┬──────────────────┐                     |
|       v                  v                  v                     |
|  ┌──────────┐      ┌──────────┐      ┌──────────┐               |
|  │  Sync    │      │  Sync    │      │  Async   │               |
|  │ Guard 1  │      │ Guard 2  │      │ Guard 3  │               |
|  └────┬─────┘      └────┬─────┘      └────┬─────┘               |
|       │                  │                  │                     |
|       │ (immediate)      │ (immediate)      │                     |
|       v                  v                  v                     |
|  ┌──────────┐      ┌──────────┐      ┌──────────────────────┐   |
|  │ Result A │      │ Result B │      │  Async Executor      │   |
|  └──────────┘      └──────────┘      │  ┌───────────────┐   │   |
|       │                  │            │  │ Cache Check   │   │   |
|       │                  │            │  └───────┬───────┘   │   |
|       │                  │            │          │           │   |
|       │                  │            │  ┌───────v───────┐   │   |
|       │                  │            │  │ Rate Limiter  │   │   |
|       │                  │            │  └───────┬───────┘   │   |
|       │                  │            │          │           │   |
|       │                  │            │  ┌───────v───────┐   │   |
|       │                  │            │  │Circuit Breaker│   │   |
|       │                  │            │  └───────┬───────┘   │   |
|       │                  │            │          │           │   |
|       │                  │            │  ┌───────v───────┐   │   |
|       │                  │            │  │ HTTP Client   │──────> External API
|       │                  │            │  └───────────────┘   │   |
|       │                  │            │          │           │   |
|       │                  │            │  ┌───────v───────┐   │   |
|       │                  │            │  │ Result C      │   │   |
|       │                  │            │  └───────────────┘   │   |
|       │                  │            └──────────────────────┘   |
|       │                  │                       │                |
|       v                  v                       v                |
|  ┌──────────────────────────────────────────────────────────┐    |
|  │                   Result Aggregator                       │    |
|  │   (applies timeout policy, aggregates results)           │    |
|  └──────────────────────────────────────────────────────────┘    |
|                              │                                    |
|                              v                                    |
|                        Final Decision                             |
|                                                                    |
+------------------------------------------------------------------+
```

### 2.2 Execution Modes

```typescript
/**
 * How async guards are executed relative to sync guards
 */
export type AsyncExecutionMode =
  | 'parallel'      // Run async guards in parallel with sync guards
  | 'sequential'    // Run async guards after sync guards
  | 'background';   // Run async guards in background, don't wait

/**
 * What to do when async guard times out
 */
export type TimeoutBehavior =
  | 'allow'         // Allow the action (optimistic)
  | 'deny'          // Deny the action (pessimistic)
  | 'warn'          // Allow but log warning
  | 'defer';        // Use cached result or default

/**
 * Async guard execution configuration
 */
export interface AsyncGuardConfig {
  /**
   * Maximum time to wait for async guard
   */
  timeoutMs: number;

  /**
   * Behavior on timeout
   */
  onTimeout: TimeoutBehavior;

  /**
   * Execution mode
   */
  executionMode: AsyncExecutionMode;

  /**
   * Whether to cache results
   */
  cacheEnabled: boolean;

  /**
   * Cache TTL in seconds
   */
  cacheTtlSeconds: number;

  /**
   * Rate limit (requests per second)
   */
  rateLimit?: number;

  /**
   * Circuit breaker configuration
   */
  circuitBreaker?: CircuitBreakerConfig;

  /**
   * Retry configuration
   */
  retry?: RetryConfig;
}
```

---

## 3. API Design

### 3.1 Async Guard Interface (TypeScript)

```typescript
// @clawdstrike/guard-sdk

import { Guard, GuardResult, PolicyEvent, Policy, GuardContext } from './types';

/**
 * Extended interface for async guards that call external services
 */
export interface AsyncGuard extends Guard {
  /**
   * Async guards must implement check() (not checkSync)
   */
  check(event: PolicyEvent, policy: Policy): Promise<GuardResult>;

  /**
   * Async configuration
   */
  getAsyncConfig(): AsyncGuardConfig;

  /**
   * Generate cache key for result caching
   */
  getCacheKey(event: PolicyEvent): string;

  /**
   * Called when circuit breaker opens
   */
  onCircuitOpen?(): void;

  /**
   * Called when circuit breaker closes
   */
  onCircuitClose?(): void;
}

/**
 * Base class for async guards with built-in functionality
 */
export abstract class BaseAsyncGuard implements AsyncGuard {
  protected config: AsyncGuardConfig;
  protected httpClient: HttpClient;
  protected cache: CacheClient;
  protected rateLimiter: RateLimiter;
  protected circuitBreaker: CircuitBreaker;

  constructor(config: Partial<AsyncGuardConfig> = {}) {
    this.config = {
      timeoutMs: 5000,
      onTimeout: 'warn',
      executionMode: 'parallel',
      cacheEnabled: true,
      cacheTtlSeconds: 3600,
      ...config,
    };
  }

  abstract name(): string;
  abstract handles(): EventType[];
  abstract check(event: PolicyEvent, policy: Policy): Promise<GuardResult>;

  /**
   * Make HTTP request with all protections
   */
  protected async makeRequest<T>(
    url: string,
    options: RequestOptions = {}
  ): Promise<T> {
    // Check rate limit
    await this.rateLimiter.acquire();

    // Check circuit breaker
    if (this.circuitBreaker.isOpen()) {
      throw new CircuitOpenError('Circuit breaker is open');
    }

    try {
      const response = await this.httpClient.request(url, {
        ...options,
        timeout: this.config.timeoutMs,
      });

      this.circuitBreaker.recordSuccess();
      return response.json();
    } catch (error) {
      this.circuitBreaker.recordFailure();
      throw error;
    }
  }

  /**
   * Check cache before making request
   */
  protected async checkCache<T>(key: string): Promise<T | null> {
    if (!this.config.cacheEnabled) return null;
    return this.cache.get<T>(key);
  }

  /**
   * Store result in cache
   */
  protected async setCache<T>(key: string, value: T): Promise<void> {
    if (!this.config.cacheEnabled) return;
    await this.cache.set(key, value, this.config.cacheTtlSeconds);
  }

  getAsyncConfig(): AsyncGuardConfig {
    return this.config;
  }

  getCacheKey(event: PolicyEvent): string {
    return `${this.name()}:${event.eventId}`;
  }

  isEnabled(): boolean {
    return true;
  }
}
```

### 3.2 Async Guard Interface (Rust)

```rust
// clawdstrike-guard-sdk

use async_trait::async_trait;
use std::time::Duration;

/// Extended trait for async guards that call external services
#[async_trait]
pub trait AsyncGuard: Guard {
    /// Async configuration
    fn async_config(&self) -> &AsyncGuardConfig;

    /// Generate cache key for result caching
    fn cache_key(&self, event: &PolicyEvent) -> String;

    /// Called when circuit breaker opens
    fn on_circuit_open(&self) {}

    /// Called when circuit breaker closes
    fn on_circuit_close(&self) {}
}

/// Async guard execution configuration
#[derive(Clone, Debug)]
pub struct AsyncGuardConfig {
    /// Maximum time to wait for async guard
    pub timeout: Duration,

    /// Behavior on timeout
    pub on_timeout: TimeoutBehavior,

    /// Execution mode
    pub execution_mode: AsyncExecutionMode,

    /// Whether to cache results
    pub cache_enabled: bool,

    /// Cache TTL
    pub cache_ttl: Duration,

    /// Rate limit (requests per second)
    pub rate_limit: Option<f64>,

    /// Circuit breaker configuration
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Retry configuration
    pub retry: Option<RetryConfig>,
}

impl Default for AsyncGuardConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            on_timeout: TimeoutBehavior::Warn,
            execution_mode: AsyncExecutionMode::Parallel,
            cache_enabled: true,
            cache_ttl: Duration::from_secs(3600),
            rate_limit: None,
            circuit_breaker: None,
            retry: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimeoutBehavior {
    Allow,
    Deny,
    Warn,
    Defer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsyncExecutionMode {
    Parallel,
    Sequential,
    Background,
}

/// Circuit breaker configuration
#[derive(Clone, Debug)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening
    pub failure_threshold: u32,

    /// Time to wait before attempting to close
    pub reset_timeout: Duration,

    /// Number of successes needed to close
    pub success_threshold: u32,
}

/// Retry configuration
#[derive(Clone, Debug)]
pub struct RetryConfig {
    /// Maximum number of retries
    pub max_retries: u32,

    /// Initial backoff duration
    pub initial_backoff: Duration,

    /// Maximum backoff duration
    pub max_backoff: Duration,

    /// Backoff multiplier
    pub multiplier: f64,
}
```

---

## 4. Reference Implementations

### 4.1 VirusTotal Scanner Guard

```typescript
// @clawdstrike-guard/virustotal

import {
  BaseAsyncGuard,
  PolicyEvent,
  Policy,
  GuardResult,
  EventType,
} from '@clawdstrike/guard-sdk';
import * as crypto from 'crypto';

interface VirusTotalConfig {
  apiKey: string;
  scanFiles: boolean;
  scanUrls: boolean;
  minDetections: number;
  timeoutMs?: number;
}

interface VTFileReport {
  data: {
    attributes: {
      last_analysis_stats: {
        malicious: number;
        suspicious: number;
        harmless: number;
        undetected: number;
      };
      last_analysis_results: Record<string, {
        category: string;
        result: string | null;
      }>;
    };
  };
}

export class VirusTotalGuard extends BaseAsyncGuard {
  private vtConfig: VirusTotalConfig;

  constructor(config: VirusTotalConfig) {
    super({
      timeoutMs: config.timeoutMs ?? 30000,
      onTimeout: 'warn',
      cacheEnabled: true,
      cacheTtlSeconds: 86400, // 24 hours
      rateLimit: 4 / 60, // VirusTotal free tier: 4 requests/minute
      circuitBreaker: {
        failure_threshold: 5,
        reset_timeout_ms: 60000,
        success_threshold: 2,
      },
    });

    this.vtConfig = config;
  }

  name(): string {
    return 'virustotal';
  }

  handles(): EventType[] {
    const types: EventType[] = [];
    if (this.vtConfig.scanFiles) {
      types.push('file_write', 'patch_apply');
    }
    if (this.vtConfig.scanUrls) {
      types.push('network_egress');
    }
    return types;
  }

  async check(event: PolicyEvent, _policy: Policy): Promise<GuardResult> {
    // Handle file events
    if (event.data.type === 'file' || event.data.type === 'patch') {
      return this.checkFile(event);
    }

    // Handle network events
    if (event.data.type === 'network') {
      return this.checkUrl(event);
    }

    return this.allow();
  }

  private async checkFile(event: PolicyEvent): Promise<GuardResult> {
    // Get file content hash
    const content = this.getFileContent(event);
    if (!content) return this.allow();

    const hash = crypto.createHash('sha256').update(content).digest('hex');

    // Check cache
    const cacheKey = `vt:file:${hash}`;
    const cached = await this.checkCache<VTFileReport>(cacheKey);
    if (cached) {
      return this.analyzeFileReport(cached, hash);
    }

    try {
      // Query VirusTotal
      const report = await this.makeRequest<VTFileReport>(
        `https://www.virustotal.com/api/v3/files/${hash}`,
        {
          headers: {
            'x-apikey': this.vtConfig.apiKey,
          },
        }
      );

      await this.setCache(cacheKey, report);
      return this.analyzeFileReport(report, hash);
    } catch (error) {
      if (this.isNotFoundError(error)) {
        // File not in VT database - could be new malware or benign
        return this.warn(`File ${hash} not found in VirusTotal database`);
      }
      throw error;
    }
  }

  private async checkUrl(event: PolicyEvent): Promise<GuardResult> {
    if (event.data.type !== 'network') return this.allow();

    const url = event.data.url ?? `https://${event.data.host}`;
    const urlId = Buffer.from(url).toString('base64url');

    // Check cache
    const cacheKey = `vt:url:${urlId}`;
    const cached = await this.checkCache<any>(cacheKey);
    if (cached) {
      return this.analyzeUrlReport(cached, url);
    }

    try {
      const report = await this.makeRequest<any>(
        `https://www.virustotal.com/api/v3/urls/${urlId}`,
        {
          headers: {
            'x-apikey': this.vtConfig.apiKey,
          },
        }
      );

      await this.setCache(cacheKey, report);
      return this.analyzeUrlReport(report, url);
    } catch (error) {
      if (this.isNotFoundError(error)) {
        return this.warn(`URL ${url} not found in VirusTotal database`);
      }
      throw error;
    }
  }

  private analyzeFileReport(report: VTFileReport, hash: string): GuardResult {
    const stats = report.data.attributes.last_analysis_stats;
    const totalMalicious = stats.malicious + stats.suspicious;

    if (totalMalicious >= this.vtConfig.minDetections) {
      return this.deny(
        `File ${hash} flagged by ${totalMalicious} engines`,
        'critical'
      );
    }

    if (stats.malicious > 0) {
      return this.warn(
        `File ${hash} flagged by ${stats.malicious} engines (below threshold)`
      );
    }

    return this.allow();
  }

  private analyzeUrlReport(report: any, url: string): GuardResult {
    const stats = report.data.attributes.last_analysis_stats;
    const totalMalicious = stats.malicious + stats.suspicious;

    if (totalMalicious >= this.vtConfig.minDetections) {
      return this.deny(
        `URL ${url} flagged by ${totalMalicious} engines`,
        'high'
      );
    }

    return this.allow();
  }

  getCacheKey(event: PolicyEvent): string {
    if (event.data.type === 'file' || event.data.type === 'patch') {
      const content = this.getFileContent(event);
      if (content) {
        const hash = crypto.createHash('sha256').update(content).digest('hex');
        return `virustotal:file:${hash}`;
      }
    }

    if (event.data.type === 'network') {
      return `virustotal:url:${event.data.host}`;
    }

    return `virustotal:${event.eventId}`;
  }

  private getFileContent(event: PolicyEvent): Buffer | null {
    // Implementation depends on event structure
    if (event.data.type === 'patch') {
      return Buffer.from(event.data.patchContent);
    }
    return null;
  }

  private isNotFoundError(error: unknown): boolean {
    return (error as any)?.status === 404;
  }
}
```

### 4.2 Snyk Vulnerability Guard

```typescript
// @clawdstrike-guard/snyk

import {
  BaseAsyncGuard,
  PolicyEvent,
  Policy,
  GuardResult,
  EventType,
} from '@clawdstrike/guard-sdk';

interface SnykConfig {
  apiToken: string;
  orgId: string;
  severityThreshold: 'low' | 'medium' | 'high' | 'critical';
  failOnUpgradable: boolean;
}

interface SnykTestResult {
  ok: boolean;
  vulnerabilities: SnykVulnerability[];
  dependencyCount: number;
}

interface SnykVulnerability {
  id: string;
  title: string;
  severity: string;
  isUpgradable: boolean;
  isPatched: boolean;
  packageName: string;
  version: string;
}

export class SnykGuard extends BaseAsyncGuard {
  private snykConfig: SnykConfig;

  constructor(config: SnykConfig) {
    super({
      timeoutMs: 60000, // Snyk tests can take a while
      onTimeout: 'warn',
      cacheEnabled: true,
      cacheTtlSeconds: 3600, // 1 hour
      rateLimit: 10, // Snyk has generous rate limits
    });

    this.snykConfig = config;
  }

  name(): string {
    return 'snyk';
  }

  handles(): EventType[] {
    return ['file_write', 'patch_apply'];
  }

  async check(event: PolicyEvent, _policy: Policy): Promise<GuardResult> {
    // Only check package manifest files
    if (!this.isPackageManifest(event)) {
      return this.allow();
    }

    const manifest = this.extractManifest(event);
    if (!manifest) {
      return this.allow();
    }

    // Check cache
    const cacheKey = this.getCacheKey(event);
    const cached = await this.checkCache<SnykTestResult>(cacheKey);
    if (cached) {
      return this.analyzeResult(cached);
    }

    try {
      const result = await this.testManifest(manifest);
      await this.setCache(cacheKey, result);
      return this.analyzeResult(result);
    } catch (error) {
      // Log error but don't block
      console.error('Snyk test failed:', error);
      return this.warn('Snyk vulnerability test failed');
    }
  }

  private isPackageManifest(event: PolicyEvent): boolean {
    if (event.data.type !== 'file') return false;

    const manifestPatterns = [
      'package.json',
      'package-lock.json',
      'Cargo.toml',
      'Cargo.lock',
      'requirements.txt',
      'Pipfile.lock',
      'go.mod',
      'pom.xml',
      'build.gradle',
    ];

    return manifestPatterns.some(p => event.data.path.endsWith(p));
  }

  private extractManifest(event: PolicyEvent): string | null {
    // Extract manifest content from event
    if (event.data.type === 'file') {
      return event.data.contentHash ?? null;
    }
    if (event.data.type === 'patch') {
      return event.data.patchContent;
    }
    return null;
  }

  private async testManifest(manifest: string): Promise<SnykTestResult> {
    // Snyk API test endpoint
    const response = await this.makeRequest<SnykTestResult>(
      `https://snyk.io/api/v1/test/npm`,
      {
        method: 'POST',
        headers: {
          'Authorization': `token ${this.snykConfig.apiToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          encoding: 'plain',
          files: {
            'package.json': manifest,
          },
        }),
      }
    );

    return response;
  }

  private analyzeResult(result: SnykTestResult): GuardResult {
    if (result.ok) {
      return this.allow();
    }

    const severityOrder = ['low', 'medium', 'high', 'critical'];
    const thresholdIndex = severityOrder.indexOf(this.snykConfig.severityThreshold);

    const criticalVulns = result.vulnerabilities.filter(v => {
      const vulnIndex = severityOrder.indexOf(v.severity);
      return vulnIndex >= thresholdIndex;
    });

    if (criticalVulns.length === 0) {
      return this.allow();
    }

    // Check if any are upgradable
    const upgradable = criticalVulns.filter(v => v.isUpgradable);

    if (this.snykConfig.failOnUpgradable && upgradable.length > 0) {
      return this.deny(
        `${upgradable.length} vulnerabilities with available upgrades: ` +
        upgradable.map(v => `${v.packageName}@${v.version} (${v.title})`).join(', '),
        'high'
      );
    }

    // Warn about vulnerabilities
    return this.warn(
      `${criticalVulns.length} vulnerabilities found at or above ${this.snykConfig.severityThreshold} severity`
    );
  }

  getCacheKey(event: PolicyEvent): string {
    if (event.data.type === 'file') {
      return `snyk:${event.data.path}:${event.data.contentHash ?? 'unknown'}`;
    }
    return `snyk:${event.eventId}`;
  }
}
```

### 4.3 Google Safe Browsing Guard

```typescript
// @clawdstrike-guard/safe-browsing

import {
  BaseAsyncGuard,
  PolicyEvent,
  Policy,
  GuardResult,
  EventType,
} from '@clawdstrike/guard-sdk';

interface SafeBrowsingConfig {
  apiKey: string;
  clientId: string;
  threatTypes?: ThreatType[];
}

type ThreatType =
  | 'MALWARE'
  | 'SOCIAL_ENGINEERING'
  | 'UNWANTED_SOFTWARE'
  | 'POTENTIALLY_HARMFUL_APPLICATION';

interface SafeBrowsingResponse {
  matches?: SafeBrowsingMatch[];
}

interface SafeBrowsingMatch {
  threatType: ThreatType;
  platformType: string;
  threatEntryType: string;
  threat: { url: string };
}

export class SafeBrowsingGuard extends BaseAsyncGuard {
  private sbConfig: SafeBrowsingConfig;

  constructor(config: SafeBrowsingConfig) {
    super({
      timeoutMs: 5000,
      onTimeout: 'warn',
      cacheEnabled: true,
      cacheTtlSeconds: 300, // 5 minutes (Safe Browsing updates frequently)
      rateLimit: 100, // Safe Browsing is generous
    });

    this.sbConfig = {
      ...config,
      threatTypes: config.threatTypes ?? [
        'MALWARE',
        'SOCIAL_ENGINEERING',
        'UNWANTED_SOFTWARE',
      ],
    };
  }

  name(): string {
    return 'safe_browsing';
  }

  handles(): EventType[] {
    return ['network_egress'];
  }

  async check(event: PolicyEvent, _policy: Policy): Promise<GuardResult> {
    if (event.data.type !== 'network') {
      return this.allow();
    }

    const url = event.data.url ?? `https://${event.data.host}`;

    // Check cache
    const cacheKey = `safebrowsing:${url}`;
    const cached = await this.checkCache<SafeBrowsingResponse>(cacheKey);
    if (cached) {
      return this.analyzeResponse(cached, url);
    }

    try {
      const response = await this.lookupUrl(url);
      await this.setCache(cacheKey, response);
      return this.analyzeResponse(response, url);
    } catch (error) {
      console.error('Safe Browsing lookup failed:', error);
      return this.warn('Safe Browsing check failed');
    }
  }

  private async lookupUrl(url: string): Promise<SafeBrowsingResponse> {
    const response = await this.makeRequest<SafeBrowsingResponse>(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${this.sbConfig.apiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          client: {
            clientId: this.sbConfig.clientId,
            clientVersion: '1.0.0',
          },
          threatInfo: {
            threatTypes: this.sbConfig.threatTypes,
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }],
          },
        }),
      }
    );

    return response;
  }

  private analyzeResponse(response: SafeBrowsingResponse, url: string): GuardResult {
    if (!response.matches || response.matches.length === 0) {
      return this.allow();
    }

    const threats = response.matches.map(m => m.threatType).join(', ');

    return this.deny(
      `URL ${url} flagged by Google Safe Browsing: ${threats}`,
      'critical'
    );
  }

  getCacheKey(event: PolicyEvent): string {
    if (event.data.type === 'network') {
      const url = event.data.url ?? `https://${event.data.host}`;
      return `safe_browsing:${url}`;
    }
    return `safe_browsing:${event.eventId}`;
  }
}
```

---

## 5. Configuration Schema

### 5.1 Async Guard Policy Configuration

> **Note on naming conventions:** YAML/JSON configuration files use `snake_case` for property names, while TypeScript interfaces use `camelCase`. The SDK automatically converts between these conventions at the boundary. Rust uses `snake_case` natively.

```yaml
# policy.yaml
version: "1.1.0"

guards:
  custom:
    # VirusTotal integration
    - package: "@clawdstrike-guard/virustotal"
      config:
        api_key: ${VT_API_KEY}
        scan_files: true
        scan_urls: true
        min_detections: 3
      async:
        timeout_ms: 30000
        on_timeout: warn
        execution_mode: parallel
        cache:
          enabled: true
          ttl_seconds: 86400
        rate_limit:
          requests_per_minute: 4
        circuit_breaker:
          failure_threshold: 5
          reset_timeout_ms: 60000

    # Snyk integration
    - package: "@clawdstrike-guard/snyk"
      config:
        api_token: ${SNYK_TOKEN}
        org_id: ${SNYK_ORG_ID}
        severity_threshold: high
        fail_on_upgradable: true
      async:
        timeout_ms: 60000
        on_timeout: warn
        execution_mode: background  # Don't block on vulnerability checks
        cache:
          enabled: true
          ttl_seconds: 3600

    # Safe Browsing integration
    - package: "@clawdstrike-guard/safe-browsing"
      config:
        api_key: ${GOOGLE_API_KEY}
        client_id: "clawdstrike"
      async:
        timeout_ms: 5000
        on_timeout: allow  # Don't block network on timeout
        execution_mode: parallel
```

### 5.2 Async Configuration JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://clawdstrike.dev/schemas/async-guard.json",
  "title": "Async Guard Configuration",
  "type": "object",
  "properties": {
    "timeout_ms": {
      "type": "integer",
      "minimum": 100,
      "maximum": 300000,
      "default": 5000,
      "description": "Maximum time to wait for async guard (milliseconds)"
    },
    "on_timeout": {
      "type": "string",
      "enum": ["allow", "deny", "warn", "defer"],
      "default": "warn",
      "description": "Behavior when guard times out"
    },
    "execution_mode": {
      "type": "string",
      "enum": ["parallel", "sequential", "background"],
      "default": "parallel",
      "description": "How async guards are executed"
    },
    "cache": {
      "type": "object",
      "properties": {
        "enabled": {
          "type": "boolean",
          "default": true
        },
        "ttl_seconds": {
          "type": "integer",
          "minimum": 1,
          "default": 3600
        },
        "max_size_mb": {
          "type": "number",
          "minimum": 1,
          "default": 100
        }
      }
    },
    "rate_limit": {
      "type": "object",
      "properties": {
        "requests_per_second": {
          "type": "number",
          "minimum": 0.001
        },
        "requests_per_minute": {
          "type": "number",
          "minimum": 0.001
        },
        "burst": {
          "type": "integer",
          "minimum": 1,
          "default": 1
        }
      }
    },
    "circuit_breaker": {
      "type": "object",
      "properties": {
        "failure_threshold": {
          "type": "integer",
          "minimum": 1,
          "default": 5
        },
        "reset_timeout_ms": {
          "type": "integer",
          "minimum": 1000,
          "default": 30000
        },
        "success_threshold": {
          "type": "integer",
          "minimum": 1,
          "default": 2
        }
      }
    },
    "retry": {
      "type": "object",
      "properties": {
        "max_retries": {
          "type": "integer",
          "minimum": 0,
          "default": 3
        },
        "initial_backoff_ms": {
          "type": "integer",
          "minimum": 100,
          "default": 1000
        },
        "max_backoff_ms": {
          "type": "integer",
          "minimum": 100,
          "default": 30000
        },
        "multiplier": {
          "type": "number",
          "minimum": 1,
          "default": 2
        }
      }
    }
  }
}
```

---

## 6. Testing Framework

### 6.1 Async Guard Test Utilities

```typescript
// @clawdstrike/guard-sdk/testing

import { AsyncGuard, PolicyEvent, GuardResult } from '../types';

/**
 * Test harness for async guards
 */
export class AsyncGuardTestHarness {
  private guard: AsyncGuard;
  private mockServer: MockServer;
  private clock: FakeClock;

  constructor(guard: AsyncGuard) {
    this.guard = guard;
    this.mockServer = new MockServer();
    this.clock = new FakeClock();
  }

  /**
   * Mock an external API endpoint
   */
  mockEndpoint(url: string, response: MockResponse): this {
    this.mockServer.mock(url, response);
    return this;
  }

  /**
   * Simulate slow response
   */
  mockSlowEndpoint(url: string, delayMs: number, response: MockResponse): this {
    this.mockServer.mock(url, {
      ...response,
      delay: delayMs,
    });
    return this;
  }

  /**
   * Simulate endpoint failure
   */
  mockFailingEndpoint(url: string, error: MockError): this {
    this.mockServer.mockError(url, error);
    return this;
  }

  /**
   * Test with timeout
   */
  async testWithTimeout(
    event: PolicyEvent,
    expectedBehavior: 'allow' | 'deny' | 'warn'
  ): Promise<void> {
    this.mockSlowEndpoint('*', this.guard.getAsyncConfig().timeoutMs + 1000, {
      status: 200,
      body: {},
    });

    const result = await this.guard.check(event, {});

    expect(result.status).toBe(expectedBehavior);
  }

  /**
   * Test cache behavior
   */
  async testCaching(event: PolicyEvent): Promise<void> {
    let callCount = 0;
    this.mockEndpoint('*', {
      status: 200,
      body: {},
      onCall: () => callCount++,
    });

    // First call
    await this.guard.check(event, {});
    expect(callCount).toBe(1);

    // Second call should use cache
    await this.guard.check(event, {});
    expect(callCount).toBe(1);
  }

  /**
   * Test rate limiting
   */
  async testRateLimiting(event: PolicyEvent): Promise<void> {
    const config = this.guard.getAsyncConfig();
    if (!config.rateLimit) {
      throw new Error('Guard does not have rate limiting configured');
    }

    this.mockEndpoint('*', { status: 200, body: {} });

    const requests: Promise<GuardResult>[] = [];
    for (let i = 0; i < config.rateLimit * 2; i++) {
      requests.push(this.guard.check(event, {}));
    }

    // Some requests should be delayed due to rate limiting
    const results = await Promise.all(requests);
    // All should eventually complete
    expect(results.length).toBe(config.rateLimit * 2);
  }

  /**
   * Test circuit breaker
   */
  async testCircuitBreaker(event: PolicyEvent): Promise<void> {
    const config = this.guard.getAsyncConfig();
    const cb = config.circuitBreaker;
    if (!cb) {
      throw new Error('Guard does not have circuit breaker configured');
    }

    // Fail enough times to open circuit
    this.mockFailingEndpoint('*', { status: 500 });

    for (let i = 0; i < cb.failureThreshold; i++) {
      try {
        await this.guard.check(event, {});
      } catch {
        // Expected
      }
    }

    // Circuit should be open now
    const result = await this.guard.check(event, {});
    expect(result.reason).toContain('circuit');
  }
}

interface MockResponse {
  status: number;
  body: unknown;
  delay?: number;
  onCall?: () => void;
}

interface MockError {
  status?: number;
  message?: string;
}
```

### 6.2 Async Guard Test Example

```typescript
// tests/virustotal-guard.test.ts

import { describe, it, expect, beforeEach } from 'vitest';
import { AsyncGuardTestHarness, fileWriteEvent } from '@clawdstrike/guard-sdk/testing';
import { VirusTotalGuard } from '../src/guard';

describe('VirusTotalGuard', () => {
  let harness: AsyncGuardTestHarness;
  let guard: VirusTotalGuard;

  beforeEach(() => {
    guard = new VirusTotalGuard({
      apiKey: 'test-api-key',
      scanFiles: true,
      scanUrls: true,
      minDetections: 3,
    });
    harness = new AsyncGuardTestHarness(guard);
  });

  it('should allow clean files', async () => {
    harness.mockEndpoint('https://www.virustotal.com/api/v3/files/*', {
      status: 200,
      body: {
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 0,
              suspicious: 0,
              harmless: 60,
              undetected: 10,
            },
          },
        },
      },
    });

    const event = fileWriteEvent('/app/file.txt', 'safe content');
    const result = await guard.check(event, {});

    expect(result.status).toBe('allow');
  });

  it('should deny malicious files', async () => {
    harness.mockEndpoint('https://www.virustotal.com/api/v3/files/*', {
      status: 200,
      body: {
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 15,
              suspicious: 5,
              harmless: 40,
              undetected: 10,
            },
          },
        },
      },
    });

    const event = fileWriteEvent('/app/malware.exe', 'malicious content');
    const result = await guard.check(event, {});

    expect(result.status).toBe('deny');
    expect(result.severity).toBe('critical');
  });

  it('should warn on timeout', async () => {
    await harness.testWithTimeout(
      fileWriteEvent('/app/file.txt', 'content'),
      'warn' // Expected behavior on timeout
    );
  });

  it('should use cache for repeated checks', async () => {
    await harness.testCaching(fileWriteEvent('/app/file.txt', 'content'));
  });

  it('should respect rate limits', async () => {
    await harness.testRateLimiting(fileWriteEvent('/app/file.txt', 'content'));
  });

  it('should open circuit breaker on failures', async () => {
    await harness.testCircuitBreaker(fileWriteEvent('/app/file.txt', 'content'));
  });
});
```

---

## 7. Security Considerations

### 7.1 Data Exfiltration Risk

Async guards send data to external services. This is itself a security risk:

| Risk | Mitigation |
|------|------------|
| Sending sensitive file contents | Hash files instead of sending content |
| Exposing internal URLs | Redact internal domains before lookup |
| API key exposure | Use environment variables, rotate keys |
| Man-in-the-middle | Require TLS, verify certificates |

### 7.2 Capability Restrictions

Async guards require the `network` capability:

```json
{
  "capabilities": {
    "network": {
      "allowedHosts": ["www.virustotal.com"],
      "allowedMethods": ["GET", "POST"],
      "maxRequestSizeBytes": 1048576,
      "maxResponseSizeBytes": 10485760
    }
  }
}
```

### 7.3 Audit Logging

All external calls must be logged:

```typescript
interface AsyncGuardAuditEvent {
  timestamp: string;
  guard: string;
  action: 'request' | 'response' | 'timeout' | 'error';
  details: {
    url: string;
    method: string;
    requestSizeBytes?: number;
    responseSizeBytes?: number;
    durationMs?: number;
    statusCode?: number;
    error?: string;
  };
}
```

### 7.4 Secrets Management

API keys for external services should be:

1. Stored in secret manager (not policy files)
2. Rotated regularly
3. Scoped to minimum required permissions
4. Audited for access

```yaml
# policy.yaml - reference secrets by name
guards:
  custom:
    - package: "@clawdstrike-guard/virustotal"
      config:
        api_key: ${secrets.VT_API_KEY}  # Resolved at runtime
```

---

## 8. Implementation Phases

### Phase 1: Core Infrastructure (Weeks 1-3)

- [ ] Async guard execution model
- [ ] HTTP client with timeout support
- [ ] Basic caching layer
- [ ] Audit logging

### Phase 2: Resilience (Weeks 4-6)

- [ ] Rate limiting implementation
- [ ] Circuit breaker implementation
- [ ] Retry with backoff
- [ ] Timeout handling

### Phase 3: Reference Guards (Weeks 7-9)

- [ ] VirusTotal guard
- [ ] Snyk guard
- [ ] Safe Browsing guard
- [ ] Custom webhook guard

### Phase 4: Testing & Documentation (Weeks 10-12)

- [ ] Async test harness
- [ ] Mock server utilities
- [ ] Integration tests
- [ ] Documentation and examples

---

## 9. Open Questions

1. **Q: Should async guards be able to run in background mode permanently?**
   - Current: Background mode returns default result, logs actual result later
   - Alternative: Background guards never affect decision, only audit

2. **Q: How do we handle async guard dependencies?**
   - Example: Guard B needs result from Guard A
   - Proposed: Sequential execution mode, or composition DSL

3. **Q: Should we provide a caching service or require guards to implement?**
   - Current: Base class provides caching
   - Alternative: Central cache service with shared eviction

4. **Q: How do we handle API versioning for external services?**
   - External APIs change; guards may break
   - Proposed: Guards declare minimum API version, warn on unknown versions

---

*Next: See guard-sdk.md for the complete SDK documentation.*
