import { Guard, GuardAction, GuardContext, GuardResult, Severity } from "./types";

const DEFAULT_FORBIDDEN_PATTERNS = [
  // Disable security features
  /disable[ _\-]?(security|auth|ssl|tls)/i,
  /skip[ _\-]?(verify|validation|check)/i,
  // Dangerous operations
  /rm\s+-rf\s+\//i,
  /chmod\s+777/i,
  /eval\s*\(/i,
  /exec\s*\(/i,
  // Backdoor indicators
  /reverse[_\-]?shell/i,
  /bind[_\-]?shell/i,
  /base64[_\-]?decode.*exec/i,
];

export interface PatchIntegrityConfig {
  /** Enable/disable this guard */
  enabled?: boolean;
  /** Maximum lines added in a single patch */
  maxAdditions?: number;
  /** Maximum lines deleted in a single patch */
  maxDeletions?: number;
  /** Regex patterns that are forbidden in patches */
  forbiddenPatterns?: RegExp[];
  /** Require patches to have balanced additions/deletions */
  requireBalance?: boolean;
  /** Maximum imbalance ratio (additions/deletions) */
  maxImbalanceRatio?: number;
}

export interface PatchAnalysis {
  additions: number;
  deletions: number;
  imbalanceRatio: number;
  forbiddenMatches: ForbiddenMatch[];
  exceedsMaxAdditions: boolean;
  exceedsMaxDeletions: boolean;
  exceedsImbalance: boolean;
}

export interface ForbiddenMatch {
  line: string;
  pattern: string;
}

/**
 * Guard that validates patch safety.
 *
 * Checks for:
 * - Forbidden patterns (security disabling, dangerous commands, backdoors)
 * - Size limits (max additions/deletions)
 * - Balance (additions vs deletions ratio)
 */
export class PatchIntegrityGuard implements Guard {
  readonly name = "patch_integrity";
  private enabled: boolean;
  private maxAdditions: number;
  private maxDeletions: number;
  private forbiddenPatterns: RegExp[];
  private requireBalance: boolean;
  private maxImbalanceRatio: number;

  constructor(config: PatchIntegrityConfig = {}) {
    this.enabled = config.enabled ?? true;
    this.maxAdditions = config.maxAdditions ?? 1000;
    this.maxDeletions = config.maxDeletions ?? 500;
    this.forbiddenPatterns = config.forbiddenPatterns ?? DEFAULT_FORBIDDEN_PATTERNS;
    this.requireBalance = config.requireBalance ?? false;
    this.maxImbalanceRatio = config.maxImbalanceRatio ?? 10.0;
  }

  handles(action: GuardAction): boolean {
    return this.enabled && action.actionType === "patch";
  }

  check(action: GuardAction, _context: GuardContext): GuardResult {
    if (!this.enabled) {
      return GuardResult.allow(this.name);
    }
    if (!this.handles(action)) {
      return GuardResult.allow(this.name);
    }

    const diff = action.diff;
    if (!diff) {
      return GuardResult.allow(this.name);
    }

    const analysis = this.analyze(diff);

    if (this.isSafe(analysis)) {
      return GuardResult.allow(this.name);
    }

    const issues: string[] = [];

    if (analysis.forbiddenMatches.length > 0) {
      const patterns = analysis.forbiddenMatches.map((m) => m.pattern).join(", ");
      issues.push(`Contains forbidden patterns: ${patterns}`);
    }

    if (analysis.exceedsMaxAdditions) {
      issues.push(`Too many additions: ${analysis.additions} (max: ${this.maxAdditions})`);
    }

    if (analysis.exceedsMaxDeletions) {
      issues.push(`Too many deletions: ${analysis.deletions} (max: ${this.maxDeletions})`);
    }

    if (analysis.exceedsImbalance) {
      issues.push(
        `Imbalanced patch: ratio ${analysis.imbalanceRatio.toFixed(2)} (max: ${this.maxImbalanceRatio.toFixed(2)})`
      );
    }

    const severity = analysis.forbiddenMatches.length > 0 ? Severity.CRITICAL : Severity.ERROR;

    return GuardResult.block(this.name, severity, issues.join("; ")).withDetails({
      path: action.path,
      additions: analysis.additions,
      deletions: analysis.deletions,
      imbalanceRatio: analysis.imbalanceRatio,
      forbiddenMatches: analysis.forbiddenMatches.length,
    });
  }

  /**
   * Analyze a unified diff.
   */
  analyze(diff: string): PatchAnalysis {
    let additions = 0;
    let deletions = 0;
    const forbiddenMatches: ForbiddenMatch[] = [];

    for (const line of diff.split("\n")) {
      if (line.startsWith("+") && !line.startsWith("+++")) {
        additions++;

        // Check for forbidden patterns in added lines
        for (const pattern of this.forbiddenPatterns) {
          if (pattern.test(line)) {
            forbiddenMatches.push({
              line,
              pattern: pattern.source,
            });
          }
        }
      } else if (line.startsWith("-") && !line.startsWith("---")) {
        deletions++;
      }
    }

    const imbalanceRatio =
      deletions > 0 ? additions / deletions : additions > 0 ? Infinity : 1.0;

    return {
      additions,
      deletions,
      imbalanceRatio,
      forbiddenMatches,
      exceedsMaxAdditions: additions > this.maxAdditions,
      exceedsMaxDeletions: deletions > this.maxDeletions,
      exceedsImbalance: this.requireBalance && imbalanceRatio > this.maxImbalanceRatio,
    };
  }

  private isSafe(analysis: PatchAnalysis): boolean {
    return (
      analysis.forbiddenMatches.length === 0 &&
      !analysis.exceedsMaxAdditions &&
      !analysis.exceedsMaxDeletions &&
      !analysis.exceedsImbalance
    );
  }
}
