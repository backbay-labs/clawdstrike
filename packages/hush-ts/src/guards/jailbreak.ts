import { Guard, GuardAction, GuardContext, GuardResult, Severity } from "./types";

export interface JailbreakGuardConfig {
  enabled?: boolean;
  warn_threshold?: number;
  block_threshold?: number;
  max_scan_bytes?: number;
}

const JB_PATTERNS: Array<{ id: string; re: RegExp; score: number }> = [
  { id: "ignore_safety", re: /\b(ignore|bypass|disable)\b.{0,48}\b(safety|policy|guardrails?)\b/ims, score: 40 },
  { id: "dan", re: /\b(dan|jailbreak|unfiltered|unrestricted)\b/ims, score: 35 },
  { id: "prompt_extraction", re: /\b(reveal|show|print)\b.{0,48}\b(system prompt|hidden instructions)\b/ims, score: 35 },
  { id: "role_play", re: /\b(you are now|act as|pretend to be)\b/ims, score: 20 },
];

export class JailbreakGuard implements Guard {
  readonly name = "jailbreak_detection";
  private readonly enabled: boolean;
  private readonly warnThreshold: number;
  private readonly blockThreshold: number;
  private readonly maxScanBytes: number;

  constructor(config: JailbreakGuardConfig = {}) {
    this.enabled = config.enabled !== false;
    this.warnThreshold = Number.isFinite(config.warn_threshold) ? Number(config.warn_threshold) : 30;
    this.blockThreshold = Number.isFinite(config.block_threshold) ? Number(config.block_threshold) : 70;
    this.maxScanBytes = Number.isInteger(config.max_scan_bytes) && (config.max_scan_bytes ?? 0) > 0
      ? Number(config.max_scan_bytes)
      : 100_000;
  }

  handles(action: GuardAction): boolean {
    return (
      action.actionType === "custom"
      && (action.customType === "user_input" || action.customType === "hushclaw.user_input")
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

    const bytes = Buffer.from(text, "utf8");
    const truncated = bytes.length > this.maxScanBytes;
    const content = truncated ? bytes.subarray(0, this.maxScanBytes).toString("utf8") : text;

    let riskScore = 0;
    const signals: string[] = [];
    for (const p of JB_PATTERNS) {
      if (p.re.test(content)) {
        riskScore += p.score;
        signals.push(p.id);
      }
    }
    if (riskScore > 100) riskScore = 100;

    const details = {
      risk_score: riskScore,
      signals,
      truncated,
      scanned_bytes: bytes.length,
    };

    if (riskScore >= this.blockThreshold) {
      const severity = riskScore >= 90 ? Severity.CRITICAL : Severity.ERROR;
      return GuardResult.block(this.name, severity, "Jailbreak attempt detected")
        .withDetails(details);
    }
    if (riskScore >= this.warnThreshold) {
      return GuardResult.warn(this.name, "Potential jailbreak attempt detected")
        .withDetails(details);
    }

    return GuardResult.allow(this.name);
  }

  private extractText(data?: Record<string, unknown>): string {
    if (!data) return "";
    const value = data.text;
    return typeof value === "string" ? value : "";
  }
}
