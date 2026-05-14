/**
 * Threat Intelligence Types
 *
 * Runtime types for the threat intelligence enrichment pipeline. These define
 * the contract between threat intel source plugins and the workbench enrichment
 * orchestrator.
 *
 * Note: These are RUNTIME types used by plugin activate() code and the
 * orchestrator. They are separate from ThreatIntelSourceContribution in types.ts,
 * which is a MANIFEST type declaring that a plugin provides a threat intel source.
 */


/**
 * The type of indicator being enriched.
 * Maps to standard IOC taxonomy used by threat intelligence feeds.
 */
export type IndicatorType = "hash" | "ip" | "domain" | "url" | "email";

/**
 * An indicator to be enriched by threat intelligence sources.
 * Extracted from findings/signals by the indicator extraction pipeline.
 */
export interface Indicator {
  /** The indicator type (hash, ip, domain, url, email). */
  type: IndicatorType;
  /** The indicator value (e.g., "1.2.3.4", "evil.com", "abc123..."). */
  value: string;
  /** Hash algorithm, only relevant when type is "hash". */
  hashAlgorithm?: "md5" | "sha1" | "sha256";
  /** Optional context linking back to the originating finding/signals. */
  context?: {
    findingId?: string;
    signalIds?: string[];
  };
}


/**
 * Threat verdict from a single intelligence source.
 * Classifies the indicator with a confidence score.
 */
export interface ThreatVerdict {
  /** Threat classification. */
  classification: "malicious" | "benign" | "suspicious" | "unknown";
  /** Confidence score from 0.0 (no confidence) to 1.0 (certain). */
  confidence: number;
  /** Human-readable one-liner summarizing the verdict. */
  summary: string;
}


/**
 * Result of enriching an indicator against a single threat intelligence source.
 * Contains the verdict, raw data, and optional MITRE/related context.
 */
export interface EnrichmentResult {
  /** ID of the source that produced this result. */
  sourceId: string;
  /** Display name of the source. */
  sourceName: string;
  /** The threat verdict for the indicator. */
  verdict: ThreatVerdict;
  /** Raw response data from the source API. */
  rawData: Record<string, unknown>;
  /** Optional MITRE ATT&CK technique mappings. */
  mitreTechniques?: Array<{
    techniqueId: string;
    techniqueName: string;
    tactic: string;
  }>;
  /** Optional related indicators discovered during enrichment. */
  relatedIndicators?: Indicator[];
  /** Optional permalink to the source's detail page for this indicator. */
  permalink?: string;
  /** When this result was fetched (Unix milliseconds). */
  fetchedAt: number;
  /** How long this result may be cached (milliseconds). */
  cacheTtlMs: number;
}


/**
 * Runtime interface for a threat intelligence source plugin.
 *
 * Plugins implement this interface and register instances via the
 * ThreatIntelSourceRegistry at activation time. The enrichment orchestrator
 * calls enrich() for matching indicator types.
 */
export interface ThreatIntelSource {
  /** Unique source identifier. */
  id: string;
  /** Human-readable display name (e.g., "VirusTotal", "AbuseIPDB"). */
  name: string;
  /** Indicator types this source can enrich. */
  supportedIndicatorTypes: IndicatorType[];
  /** Rate limiting configuration. */
  rateLimit: { maxPerMinute: number };
  /** Enrich an indicator. Called by the orchestrator. */
  enrich(indicator: Indicator): Promise<EnrichmentResult>;
  /** Optional health check. Called by the orchestrator for source status. */
  healthCheck?(): Promise<{ healthy: boolean; message?: string }>;
}
