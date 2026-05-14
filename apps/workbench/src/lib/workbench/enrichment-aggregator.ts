import type { Finding, Enrichment } from "./finding-engine";

// Types
/** An indicator that appears across one or more findings. */
export interface IndicatorAggregation {
  /** The indicator value (e.g. "1.2.3.4", "evil.com"). */
  indicator: string;
  /** The IOC type (e.g. "ip", "domain", "sha256"). */
  iocType: string;
  /** IDs of findings containing this indicator. */
  findingIds: string[];
  /** Titles of findings containing this indicator. */
  findingTitles: string[];
  /** Number of findings this indicator appears in. */
  count: number;
  /** Most recent addedAt timestamp across all enrichments containing this indicator. */
  lastSeenAt: number;
}

/** Verdict counts for a single enrichment source. */
export interface VerdictSummary {
  /** Source identifier (from enrichment.source). */
  sourceId: string;
  /** Human-readable source name (same as sourceId for now). */
  sourceName: string;
  /** Total number of enrichments from this source. */
  total: number;
  /** Count of enrichments classified as malicious. */
  malicious: number;
  /** Count of enrichments classified as benign. */
  benign: number;
  /** Count of enrichments classified as unknown. */
  unknown: number;
  /** Count of enrichments classified as suspicious. */
  suspicious: number;
}

export interface SourceHealthInput {
  id: string;
  name: string;
  rateLimit: { maxPerMinute: number };
  quotaUsed: number;
  quotaTotal: number;
  lastSuccessAt: number | null;
  lastErrorAt: number | null;
  lastErrorMessage?: string;
}

export interface SourceHealthStatus {
  id: string;
  name: string;
  health: "healthy" | "degraded" | "unhealthy";
  quotaPercent: number;
  quotaUsed: number;
  quotaTotal: number;
  rateLimit: { maxPerMinute: number };
  lastSuccessAt: number | null;
  lastErrorAt: number | null;
  lastErrorMessage?: string;
}

// Public API
/**
 * Aggregate indicators across all findings, identifying IOCs that appear
 * in multiple findings. Results are sorted by count descending (most
 * cross-referenced first).
 */
export function aggregateIndicators(findings: Finding[]): IndicatorAggregation[] {
  const map = new Map<
    string,
    {
      indicator: string;
      iocType: string;
      findingIds: Set<string>;
      findingTitles: Set<string>;
      lastSeenAt: number;
    }
  >();

  for (const finding of findings) {
    for (const enrichment of finding.enrichments) {
      if (enrichment.type !== "ioc_extraction") continue;

      const indicators = enrichment.data.indicators;
      if (!Array.isArray(indicators)) continue;

      for (const item of indicators) {
        const typed = item as { indicator?: string; iocType?: string };
        if (typeof typed.indicator !== "string" || typeof typed.iocType !== "string") continue;

        const key = `${typed.iocType}:${typed.indicator}`;
        const existing = map.get(key);

        if (existing) {
          existing.findingIds.add(finding.id);
          existing.findingTitles.add(finding.title);
          existing.lastSeenAt = Math.max(existing.lastSeenAt, enrichment.addedAt);
        } else {
          map.set(key, {
            indicator: typed.indicator,
            iocType: typed.iocType,
            findingIds: new Set([finding.id]),
            findingTitles: new Set([finding.title]),
            lastSeenAt: enrichment.addedAt,
          });
        }
      }
    }
  }

  const result: IndicatorAggregation[] = [];
  for (const entry of map.values()) {
    result.push({
      indicator: entry.indicator,
      iocType: entry.iocType,
      findingIds: Array.from(entry.findingIds),
      findingTitles: Array.from(entry.findingTitles),
      count: entry.findingIds.size,
      lastSeenAt: entry.lastSeenAt,
    });
  }

  result.sort((a, b) => b.count - a.count);
  return result;
}

/**
 * Aggregate enrichment verdicts by source across all findings.
 * Groups enrichments by their source and counts verdicts into
 * malicious/benign/unknown/suspicious buckets.
 * Results sorted by total desc.
 */
export function aggregateVerdictsBySource(findings: Finding[]): VerdictSummary[] {
  const map = new Map<
    string,
    { malicious: number; benign: number; unknown: number; suspicious: number; total: number }
  >();

  for (const finding of findings) {
    for (const enrichment of finding.enrichments) {
      const sourceId = enrichment.source;
      if (!map.has(sourceId)) {
        map.set(sourceId, { malicious: 0, benign: 0, unknown: 0, suspicious: 0, total: 0 });
      }

      const bucket = map.get(sourceId)!;
      bucket.total++;

      const verdict = classifyVerdict(enrichment);
      bucket[verdict]++;
    }
  }

  const result: VerdictSummary[] = [];
  for (const [sourceId, counts] of map.entries()) {
    result.push({
      sourceId,
      sourceName: sourceId,
      ...counts,
    });
  }

  result.sort((a, b) => b.total - a.total);
  return result;
}

/**
 * Compute health status for each configured threat intel source.
 *
 * Health thresholds:
 * - "unhealthy": quota > 95% OR (error in last hour AND no success since error)
 * - "degraded": quota > 80% OR error in last hour
 * - "healthy": otherwise
 */
export function getSourceHealthSummary(sources: SourceHealthInput[]): SourceHealthStatus[] {
  const now = Date.now();
  const ONE_HOUR = 60 * 60 * 1000;

  return sources.map((source) => {
    const quotaPercent =
      source.quotaTotal > 0
        ? Math.round((source.quotaUsed / source.quotaTotal) * 100)
        : 0;

    const errorInLastHour =
      source.lastErrorAt !== null && now - source.lastErrorAt < ONE_HOUR;

    const noSuccessSinceError =
      source.lastSuccessAt === null ||
      (source.lastErrorAt !== null && source.lastSuccessAt < source.lastErrorAt);

    let health: "healthy" | "degraded" | "unhealthy";

    if (quotaPercent > 95 || (errorInLastHour && noSuccessSinceError)) {
      health = "unhealthy";
    } else if (quotaPercent > 80 || errorInLastHour) {
      health = "degraded";
    } else {
      health = "healthy";
    }

    return {
      id: source.id,
      name: source.name,
      health,
      quotaPercent,
      quotaUsed: source.quotaUsed,
      quotaTotal: source.quotaTotal,
      rateLimit: source.rateLimit,
      lastSuccessAt: source.lastSuccessAt,
      lastErrorAt: source.lastErrorAt,
      lastErrorMessage: source.lastErrorMessage,
    };
  });
}

// Internals
function classifyVerdict(
  enrichment: Enrichment,
): "malicious" | "benign" | "unknown" | "suspicious" {
  const raw =
    (enrichment.data.verdict as string | undefined) ??
    (enrichment.data.classification as string | undefined);

  if (!raw) return "unknown";

  const normalized = raw.toLowerCase().trim();

  if (normalized === "malicious") return "malicious";
  if (normalized === "benign") return "benign";
  if (normalized === "suspicious") return "suspicious";
  return "unknown";
}
