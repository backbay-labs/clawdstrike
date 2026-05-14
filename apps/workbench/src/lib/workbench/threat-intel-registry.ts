import type { ThreatIntelSource, IndicatorType } from "@clawdstrike/plugin-sdk";

const sourceMap = new Map<string, ThreatIntelSource>();

/**
 * Register a threat intelligence source. Returns a dispose function to unregister.
 * Throws if a source with the same ID is already registered.
 */
export function registerThreatIntelSource(source: ThreatIntelSource): () => void {
  if (sourceMap.has(source.id)) {
    throw new Error(`Threat intel source "${source.id}" is already registered`);
  }
  sourceMap.set(source.id, source);
  return () => {
    sourceMap.delete(source.id);
  };
}

export function unregisterThreatIntelSource(id: string): void {
  sourceMap.delete(id);
}

/** Returns a registered source by ID, or undefined if not registered. */
export function getThreatIntelSource(id: string): ThreatIntelSource | undefined {
  return sourceMap.get(id);
}

/** Returns all registered threat intel sources as an array. */
export function getAllThreatIntelSources(): ThreatIntelSource[] {
  return Array.from(sourceMap.values());
}

/**
 * Returns all registered sources that support the given indicator type.
 * Filters by each source's declared supportedIndicatorTypes array.
 */
export function getThreatIntelSourcesForIndicator(type: IndicatorType): ThreatIntelSource[] {
  return Array.from(sourceMap.values()).filter((source) =>
    source.supportedIndicatorTypes.includes(type),
  );
}

/** Reset the registry. Only exported for test teardown. */
export function _resetForTesting(): void {
  sourceMap.clear();
}
