import type { Finding } from "./finding-engine";
import type { Indicator } from "@clawdstrike/plugin-sdk";

export interface AutoEnrichmentConfig {
  /** Whether auto-enrichment is enabled. Default: false. */
  enabled: boolean;
  /** Minimum confidence (0.0-1.0) for auto-enrichment to trigger. */
  confidenceThreshold: number;
  /** Source IDs to auto-enrich with. Empty = all configured sources. */
  enabledSources: string[];
  /** Sentinel IDs whose findings auto-enrich. "all" = all sentinels. */
  enabledSentinels: string[] | "all";
}

const DEFAULT_CONFIG: AutoEnrichmentConfig = {
  enabled: false,
  confidenceThreshold: 0.5,
  enabledSources: [],
  enabledSentinels: "all",
};

const STORAGE_KEY = "clawdstrike:auto-enrichment-config";
const DEBOUNCE_MS = 100;

export interface EnrichmentOrchestratorLike {
  enrich(
    indicator: Indicator,
    options?: { sourceIds?: string[] },
  ): Promise<unknown>;
}

interface AutoEnrichmentManagerOptions {
  orchestrator: EnrichmentOrchestratorLike;
  extractIndicators: (finding: Finding) => Indicator[];
  config?: AutoEnrichmentConfig;
}

export class AutoEnrichmentManager {
  private config: AutoEnrichmentConfig;
  private readonly orchestrator: EnrichmentOrchestratorLike;
  private readonly extractIndicators: (finding: Finding) => Indicator[];
  private readonly recentlyProcessed = new Map<string, number>();

  constructor(options: AutoEnrichmentManagerOptions) {
    this.orchestrator = options.orchestrator;
    this.extractIndicators = options.extractIndicators;

    // Load persisted config, fallback to provided config, fallback to defaults
    const persisted = this.loadFromStorage();
    this.config = persisted ?? options.config ?? { ...DEFAULT_CONFIG };
  }

  /**
   * Process a newly added finding for auto-enrichment.
   *
   * Guards:
   * - Not enabled -> skip
   * - Below confidence threshold -> skip
   * - Sentinel not in enabledSentinels -> skip
   * - Finding ID recently processed (debounce) -> skip
   * - All applicable sources already enriched -> skip
   *
   * Fire-and-forget: enrichment results flow back via store dispatch.
   */
  processNewFinding(finding: Finding): void {
    if (!this.config.enabled) return;

    if (finding.confidence < this.config.confidenceThreshold) return;

    if (this.config.enabledSentinels !== "all") {
      if (!this.config.enabledSentinels.includes(finding.createdBy)) return;
    }

    const now = Date.now();
    const lastProcessed = this.recentlyProcessed.get(finding.id);
    if (lastProcessed !== undefined && now - lastProcessed < DEBOUNCE_MS) {
      return;
    }
    this.recentlyProcessed.set(finding.id, now);

    const alreadyEnrichedSources = new Set(
      finding.enrichments.map((e) => e.source),
    );

    let sourceIds: string[] | undefined;
    if (this.config.enabledSources.length > 0) {
      const remaining = this.config.enabledSources.filter(
        (s) => !alreadyEnrichedSources.has(s),
      );
      if (remaining.length === 0) return; // All sources already enriched
      sourceIds = remaining;
    }

    const indicators = this.extractIndicators(finding);
    if (indicators.length === 0) return;

    const enrichOptions = sourceIds ? { sourceIds } : {};
    for (const indicator of indicators) {
      // Intentionally not awaited -- results flow back via store dispatch
      this.orchestrator.enrich(indicator, enrichOptions).catch((err: unknown) => {
        console.error(
          `[AutoEnrichment] Failed to enrich ${indicator.type}:${indicator.value}:`,
          err instanceof Error ? err.message : String(err),
        );
      });
    }
  }

  /** Returns the current auto-enrichment configuration. */
  getConfig(): AutoEnrichmentConfig {
    return { ...this.config };
  }

  /** Merges partial config updates and persists to localStorage. */
  updateConfig(partial: Partial<AutoEnrichmentConfig>): void {
    this.config = { ...this.config, ...partial };
    this.saveToStorage();
  }

  /** Cleans up debounce state. */
  destroy(): void {
    this.recentlyProcessed.clear();
  }

  private loadFromStorage(): AutoEnrichmentConfig | null {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        typeof parsed.enabled === "boolean" &&
        typeof parsed.confidenceThreshold === "number"
      ) {
        return parsed as AutoEnrichmentConfig;
      }
      return null;
    } catch {
      return null;
    }
  }

  private saveToStorage(): void {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.config));
    } catch {
      // Storage unavailable -- silently ignore
    }
  }
}
