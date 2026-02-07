import { Guard, GuardAction, GuardContext, GuardResult, Severity } from "./types";

export type PromptInjectionLevel = "safe" | "suspicious" | "high" | "critical";

export interface PromptInjectionConfig {
  enabled?: boolean;
  warn_at_or_above?: Exclude<PromptInjectionLevel, "safe">;
  block_at_or_above?: Exclude<PromptInjectionLevel, "safe">;
  max_scan_bytes?: number;
}

const PROMPT_PATTERNS: Array<{ id: string; re: RegExp; score: number }> = [
  { id: "ignore_previous", re: /\b(ignore|disregard|override)\b.{0,48}\b(previous|system|developer)\b/ims, score: 2 },
  { id: "reveal_prompt", re: /\b(reveal|show|print|dump)\b.{0,48}\b(system prompt|developer prompt|hidden instructions)\b/ims, score: 2 },
  { id: "policy_bypass", re: /\b(ignore|bypass|disable|turn off)\b.{0,48}\b(safety|guardrails?|policies|policy|filters)\b/ims, score: 3 },
  {
    id: "credential_exfiltration",
    re: /(?:\b(api key|secret|secrets|token|password|private key)\b.{0,96}\b(send|post|upload|exfiltrat(?:e|ion|ing|ed)?|leak|reveal|print|dump)\b|\b(send|post|upload|exfiltrat(?:e|ion|ing|ed)?|leak|reveal|print|dump)\b.{0,96}\b(api key|secret|secrets|token|password|private key)\b)/ims,
    score: 5,
  },
  { id: "role_override", re: /\b(you are now|act as|pretend to be)\b/ims, score: 1 },
];

function levelOrd(level: PromptInjectionLevel): number {
  switch (level) {
    case "safe":
      return 0;
    case "suspicious":
      return 1;
    case "high":
      return 2;
    case "critical":
      return 3;
  }
}

function classifyLevel(score: number): PromptInjectionLevel {
  if (score >= 5) return "critical";
  if (score >= 3) return "high";
  if (score >= 1) return "suspicious";
  return "safe";
}

function severityForBlock(level: PromptInjectionLevel): Severity {
  if (level === "critical") return Severity.CRITICAL;
  return Severity.ERROR;
}

export class PromptInjectionGuard implements Guard {
  readonly name = "prompt_injection";
  private readonly enabled: boolean;
  private readonly warnAt: Exclude<PromptInjectionLevel, "safe">;
  private readonly blockAt: Exclude<PromptInjectionLevel, "safe">;
  private readonly maxScanBytes: number;

  constructor(config: PromptInjectionConfig = {}) {
    this.enabled = config.enabled !== false;
    this.warnAt = config.warn_at_or_above ?? "suspicious";
    this.blockAt = config.block_at_or_above ?? "high";
    this.maxScanBytes = Number.isInteger(config.max_scan_bytes) && (config.max_scan_bytes ?? 0) > 0
      ? Number(config.max_scan_bytes)
      : 200_000;
  }

  handles(action: GuardAction): boolean {
    return (
      action.actionType === "custom"
      && (action.customType === "untrusted_text" || action.customType === "hushclaw.untrusted_text")
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

    const scanned = Buffer.from(text, "utf8");
    const truncated = scanned.length > this.maxScanBytes;
    const content = truncated ? scanned.subarray(0, this.maxScanBytes).toString("utf8") : text;

    let score = 0;
    const signals: string[] = [];
    for (const p of PROMPT_PATTERNS) {
      if (p.re.test(content)) {
        score += p.score;
        signals.push(p.id);
      }
    }

    const level = classifyLevel(score);
    const details = {
      level,
      score,
      signals,
      truncated,
      scanned_bytes: scanned.length,
    };

    if (levelOrd(level) >= levelOrd(this.blockAt)) {
      return GuardResult
        .block(this.name, severityForBlock(level), "Untrusted text contains prompt-injection signals")
        .withDetails(details);
    }
    if (levelOrd(level) >= levelOrd(this.warnAt)) {
      return GuardResult.warn(this.name, "Untrusted text contains prompt-injection signals")
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
