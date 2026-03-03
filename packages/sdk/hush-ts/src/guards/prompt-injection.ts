import { getWasmModule } from "../crypto/backend.js";
import { Guard, GuardAction, GuardContext, GuardResult, Severity } from "./types";

export type PromptInjectionLevel = "safe" | "suspicious" | "high" | "critical";

export interface PromptInjectionConfig {
  enabled?: boolean;
  warn_at_or_above?: Exclude<PromptInjectionLevel, "safe">;
  block_at_or_above?: Exclude<PromptInjectionLevel, "safe">;
  max_scan_bytes?: number;
}

interface WasmPromptInjectionResult {
  level: PromptInjectionLevel;
  score: number;
  fingerprint: string;
  signals: string[];
  canonicalization?: {
    scannedBytes: number;
    truncated: boolean;
    nfkcChanged: boolean;
    casefoldChanged: boolean;
    zeroWidthStripped: number;
    whitespaceCollapsed: boolean;
    canonicalBytes: number;
  };
}

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
    this.maxScanBytes =
      Number.isInteger(config.max_scan_bytes) && (config.max_scan_bytes ?? 0) > 0
        ? Number(config.max_scan_bytes)
        : 200_000;

    const wasm = getWasmModule();
    if (!wasm?.detect_prompt_injection) {
      throw new Error(
        "WASM not initialized. Call initWasm() before using PromptInjectionGuard.",
      );
    }
  }

  handles(action: GuardAction): boolean {
    return (
      action.actionType === "custom" &&
      (action.customType === "untrusted_text" ||
        action.customType === "clawdstrike.untrusted_text" ||
        action.customType === "hushclaw.untrusted_text")
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

    const wasm = getWasmModule();
    const resultJson: string = wasm.detect_prompt_injection(text, this.maxScanBytes);
    const result: WasmPromptInjectionResult = JSON.parse(resultJson);

    const details = {
      level: result.level,
      score: result.score,
      signals: result.signals,
      fingerprint: result.fingerprint,
      truncated: result.canonicalization?.truncated ?? false,
      scanned_bytes: result.canonicalization?.scannedBytes ?? 0,
    };

    if (levelOrd(result.level) >= levelOrd(this.blockAt)) {
      return GuardResult.block(
        this.name,
        severityForBlock(result.level),
        "Untrusted text contains prompt-injection signals",
      ).withDetails(details);
    }
    if (levelOrd(result.level) >= levelOrd(this.warnAt)) {
      return GuardResult.warn(
        this.name,
        "Untrusted text contains prompt-injection signals",
      ).withDetails(details);
    }

    return GuardResult.allow(this.name);
  }

  private extractText(data?: Record<string, unknown>): string {
    if (!data) return "";
    const value = data.text;
    return typeof value === "string" ? value : "";
  }
}
