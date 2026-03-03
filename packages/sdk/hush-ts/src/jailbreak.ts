import { getWasmModule } from "./crypto/backend.js";
import { toSnakeCaseKeys } from "./case-convert.js";

export type JailbreakSeverity = "safe" | "suspicious" | "likely" | "confirmed";

export type JailbreakCategory =
  | "role_play"
  | "authority_confusion"
  | "encoding_attack"
  | "hypothetical_framing"
  | "adversarial_suffix"
  | "system_impersonation"
  | "instruction_extraction"
  | "multi_turn_grooming"
  | "payload_splitting";

export interface JailbreakSignal {
  id: string;
  category: JailbreakCategory;
  weight: number;
  matchSpan?: [number, number];
}

export interface LayerResult {
  layer: string;
  score: number;
  signals: string[];
  latencyMs?: number;
}

export interface JailbreakDetectionResult {
  severity: JailbreakSeverity;
  confidence: number;
  riskScore: number;
  blocked: boolean;
  fingerprint: string;
  signals: JailbreakSignal[];
  layerResults: {
    heuristic: LayerResult;
    statistical: LayerResult;
    ml?: LayerResult;
    llmJudge?: LayerResult;
  };
  canonicalization: {
    scannedBytes: number;
    truncated: boolean;
    nfkcChanged: boolean;
    casefoldChanged: boolean;
    zeroWidthStripped: number;
    whitespaceCollapsed: boolean;
    canonicalBytes: number;
  };
  session?: {
    sessionId: string;
    messagesSeen: number;
    suspiciousCount: number;
    cumulativeRisk: number;
    rollingRisk?: number;
    lastSeenMs?: number;
  };
  latencyMs?: number;
}

export interface JailbreakDetectorConfig {
  layers?: {
    heuristic?: boolean;
    statistical?: boolean;
    ml?: boolean;
    llmJudge?: boolean;
  };
  linearModel?: JailbreakLinearModelConfig;
  blockThreshold?: number;
  warnThreshold?: number;
  maxInputBytes?: number;
  sessionAggregation?: boolean;
  sessionMaxEntries?: number;
  sessionTtlSeconds?: number;
  sessionHalfLifeSeconds?: number;
}

export interface JailbreakLinearModelConfig {
  bias?: number;
  wIgnorePolicy?: number;
  wDan?: number;
  wRoleChange?: number;
  wPromptExtraction?: number;
  wEncoded?: number;
  wPunct?: number;
  wSymbolRun?: number;
}

/**
 * Jailbreak detector backed by Rust compiled to WASM.
 * Requires `initWasm()` before construction.
 */
export class JailbreakDetector {
  // biome-ignore lint/suspicious/noExplicitAny: WasmJailbreakDetector is untyped
  private readonly inner: any;

  constructor(config?: JailbreakDetectorConfig) {
    const wasm = getWasmModule();
    if (!wasm?.WasmJailbreakDetector) {
      throw new Error(
        "WASM not initialized. Call initWasm() before using JailbreakDetector.",
      );
    }
    // Only pass Rust-known config fields; strip JS-only and guard-level options.
    const RUST_FIELDS = new Set([
      "layers", "linearModel", "blockThreshold", "warnThreshold",
      "maxInputBytes", "sessionAggregation", "sessionMaxEntries",
      "sessionTtlSeconds", "sessionHalfLifeSeconds",
    ]);
    const filtered: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(config ?? {})) {
      if (RUST_FIELDS.has(k) && v !== undefined) filtered[k] = v;
    }
    const hasConfig = Object.keys(filtered).length > 0;
    this.inner = new wasm.WasmJailbreakDetector(
      hasConfig ? JSON.stringify(toSnakeCaseKeys(filtered)) : undefined,
    );
  }

  /**
   * Run jailbreak detection on the given input text.
   *
   * @param input  - The text to analyse.
   * @param sessionId - Optional session identifier for cross-message aggregation.
   * @returns Structured detection result (camelCase keys from WASM).
   */
  detect(input: string, sessionId?: string): JailbreakDetectionResult {
    const json: string = this.inner.detect(input, sessionId ?? undefined);
    return JSON.parse(json) as JailbreakDetectionResult;
  }
}
