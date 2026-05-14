import type { Enrichment } from "./finding-engine";

// Types
export interface RelatedIndicator {
  /** Indicator type (e.g. "ip", "domain", "sha256"). */
  type: string;
  /** Indicator value (e.g. "1.2.3.4", "evil.com"). */
  value: string;
  /** Optional context about the relationship. */
  context?: string;
  /** ID of the enrichment that surfaced this indicator. */
  sourceEnrichmentId: string;
}

// Public API
/**
 * Extract related indicators from a list of enrichments.
 *
 * Scans each enrichment's `data.relatedIndicators` array, maps entries to
 * RelatedIndicator objects, and deduplicates by `${type}:${value}` tuple.
 * First occurrence wins for deduplication.
 */
export function extractRelatedIndicators(
  enrichments: Enrichment[],
): RelatedIndicator[] {
  const seen = new Set<string>();
  const result: RelatedIndicator[] = [];

  for (const enrichment of enrichments) {
    const raw = enrichment.data.relatedIndicators;
    if (!Array.isArray(raw)) continue;

    for (const item of raw) {
      if (
        typeof item !== "object" ||
        item === null ||
        typeof (item as Record<string, unknown>).type !== "string" ||
        typeof (item as Record<string, unknown>).value !== "string"
      ) {
        continue;
      }

      const typed = item as { type: string; value: string; context?: string };
      const key = `${typed.type}:${typed.value}`;

      if (!seen.has(key)) {
        seen.add(key);
        const indicator: RelatedIndicator = {
          type: typed.type,
          value: typed.value,
          sourceEnrichmentId: enrichment.id,
        };
        if (typed.context !== undefined) {
          indicator.context = typed.context;
        }
        result.push(indicator);
      }
    }
  }

  return result;
}

/**
 * Trigger follow-on enrichment for a related indicator.
 *
 * Thin wrapper that calls the provided enrich function with the
 * indicator's type and value.
 */
export function triggerPivotEnrichment(
  indicator: RelatedIndicator,
  enrichFn: (type: string, value: string) => void,
): void {
  enrichFn(indicator.type, indicator.value);
}
