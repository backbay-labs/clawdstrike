import { SpiderSenseDetector, type SpiderSenseDetectorConfig } from "../spider-sense.js";
import { type Guard, GuardAction, type GuardContext, GuardResult, Severity } from "./types";

export interface SpiderSenseGuardConfig extends SpiderSenseDetectorConfig {
  enabled?: boolean;
}

export class SpiderSenseGuard implements Guard {
  readonly name = "spider_sense";
  private readonly enabled: boolean;
  private readonly detector: SpiderSenseDetector;

  constructor(config: SpiderSenseGuardConfig = {}) {
    this.enabled = config.enabled !== false;
    this.detector = new SpiderSenseDetector(config);
  }

  /**
   * Load a pattern database into the underlying detector.
   * Must be called before `check()` can produce meaningful results.
   */
  loadPatterns(patterns: import("../spider-sense.js").PatternEntry[]): void {
    this.detector.loadPatterns(patterns);
  }

  handles(_action: GuardAction): boolean {
    return true;
  }

  check(action: GuardAction, _context: GuardContext): GuardResult {
    if (!this.enabled) {
      return GuardResult.allow(this.name);
    }

    const embedding = this.extractEmbedding(action.customData);
    if (!embedding) {
      return GuardResult.allow(this.name);
    }

    const result = this.detector.screen(embedding);

    const details = {
      verdict: result.verdict,
      top_score: result.topScore,
      threshold: result.threshold,
      ambiguity_band: result.ambiguityBand,
      top_matches_count: result.topMatches.length,
    };

    if (result.verdict === "deny") {
      return GuardResult.block(
        this.name,
        Severity.ERROR,
        "Spider-Sense threat detected",
      ).withDetails(details);
    }

    if (result.verdict === "ambiguous") {
      return GuardResult.warn(
        this.name,
        "Spider-Sense ambiguous match detected",
      ).withDetails(details);
    }

    return GuardResult.allow(this.name);
  }

  private extractEmbedding(data?: Record<string, unknown>): number[] | null {
    if (!data) return null;
    const value = data.embedding;
    if (Array.isArray(value) && value.every((v) => typeof v === "number")) {
      return value as number[];
    }
    return null;
  }
}
