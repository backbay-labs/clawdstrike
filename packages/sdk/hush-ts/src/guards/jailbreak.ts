import { JailbreakDetector, type JailbreakDetectorConfig } from "../jailbreak.js";
import { type Guard, GuardAction, type GuardContext, GuardResult, Severity } from "./types";

export interface JailbreakGuardConfig extends JailbreakDetectorConfig {
  enabled?: boolean;
  /** Alias kept for backward compatibility with snake_case policy YAML. */
  warn_threshold?: number;
  /** Alias kept for backward compatibility with snake_case policy YAML. */
  block_threshold?: number;
  /** Alias kept for backward compatibility with snake_case policy YAML. */
  max_scan_bytes?: number;
}

export class JailbreakGuard implements Guard {
  readonly name = "jailbreak_detection";
  private readonly enabled: boolean;
  private readonly detector: JailbreakDetector;
  private readonly blockThreshold: number;
  private readonly warnThreshold: number;

  constructor(config: JailbreakGuardConfig = {}) {
    this.enabled = config.enabled !== false;

    // Merge snake_case aliases into the canonical camelCase fields expected
    // by JailbreakDetectorConfig before forwarding to the WASM detector.
    const mergedConfig: JailbreakDetectorConfig = {
      ...config,
      blockThreshold:
        config.blockThreshold ??
        (Number.isFinite(config.block_threshold) ? Number(config.block_threshold) : undefined),
      warnThreshold:
        config.warnThreshold ??
        (Number.isFinite(config.warn_threshold) ? Number(config.warn_threshold) : undefined),
      maxInputBytes:
        config.maxInputBytes ??
        (Number.isInteger(config.max_scan_bytes) && (config.max_scan_bytes ?? 0) > 0
          ? Number(config.max_scan_bytes)
          : undefined),
    };

    this.detector = new JailbreakDetector(mergedConfig);
    this.blockThreshold = mergedConfig.blockThreshold ?? 70;
    this.warnThreshold = mergedConfig.warnThreshold ?? 30;
  }

  handles(action: GuardAction): boolean {
    return (
      action.actionType === "custom" &&
      (action.customType === "user_input" ||
        action.customType === "clawdstrike.user_input" ||
        action.customType === "hushclaw.user_input")
    );
  }

  check(action: GuardAction, _context: GuardContext): GuardResult {
    if (!this.enabled || !this.handles(action)) {
      return GuardResult.allow(this.name);
    }

    const text = this.extractText(action.customData);
    if (!text) {
      return GuardResult.allow(this.name);
    }

    const result = this.detector.detect(text, _context.sessionId);

    const details = {
      risk_score: result.riskScore,
      severity: result.severity,
      signals: result.signals.map((s) => s.id),
      fingerprint: result.fingerprint,
      truncated: result.canonicalization.truncated,
      scanned_bytes: result.canonicalization.scannedBytes,
    };

    if (result.riskScore >= this.blockThreshold) {
      const severity = result.riskScore >= 100 ? Severity.CRITICAL : Severity.ERROR;
      return GuardResult.block(this.name, severity, "Jailbreak attempt detected").withDetails(
        details,
      );
    }
    if (result.riskScore >= this.warnThreshold) {
      return GuardResult.warn(this.name, "Potential jailbreak attempt detected").withDetails(
        details,
      );
    }

    return GuardResult.allow(this.name);
  }

  private extractText(data?: Record<string, unknown>): string {
    if (!data) return "";
    const value = data.text;
    return typeof value === "string" ? value : "";
  }
}
