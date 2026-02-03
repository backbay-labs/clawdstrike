import { sha256, toHex } from "./crypto/hash";

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
}

export interface LayerResult {
  layer: string;
  score: number; // 0..1-ish
  signals: string[]; // IDs only
}

export interface JailbreakDetectionResult {
  severity: JailbreakSeverity;
  confidence: number; // 0..1
  riskScore: number; // 0..100
  blocked: boolean;
  fingerprint: string; // sha256 hex
  signals: JailbreakSignal[];
  layers: {
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
  };
}

export interface JailbreakDetectorConfig {
  layers?: {
    heuristic?: boolean;
    statistical?: boolean;
    ml?: boolean;
    llmJudge?: boolean;
  };
  blockThreshold?: number;
  warnThreshold?: number;
  maxInputBytes?: number;
  sessionAggregation?: boolean;
  llmJudge?: (input: string) => Promise<number>;
}

const DEFAULT_CFG: Required<Omit<JailbreakDetectorConfig, "llmJudge">> = {
  layers: { heuristic: true, statistical: true, ml: true, llmJudge: false },
  blockThreshold: 70,
  warnThreshold: 30,
  maxInputBytes: 100_000,
  sessionAggregation: true,
};

const ZW_RE = /[\u00AD\u180E\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/g;

function truncateToBytes(s: string, maxBytes: number): { slice: string; truncated: boolean } {
  const bytes = Buffer.from(s, "utf8");
  if (bytes.length <= maxBytes) return { slice: s, truncated: false };
  // Keep a prefix by bytes, then re-decode.
  const truncatedBytes = bytes.subarray(0, maxBytes);
  return { slice: truncatedBytes.toString("utf8"), truncated: true };
}

function canonicalizeForDetection(input: string): { canonical: string; stats: JailbreakDetectionResult["canonicalization"] } {
  const scannedBytes = Buffer.from(input, "utf8").length;
  const nfkc = input.normalize("NFKC");
  const nfkcChanged = nfkc !== input;
  const folded = nfkc.toLowerCase();
  const casefoldChanged = folded !== nfkc;
  const beforeZw = folded;
  const stripped = beforeZw.replace(ZW_RE, "");
  const zeroWidthStripped = beforeZw.length - stripped.length;
  const collapsed = stripped.split(/\s+/).filter(Boolean).join(" ");
  const whitespaceCollapsed = collapsed !== stripped;
  return {
    canonical: collapsed,
    stats: {
      scannedBytes,
      truncated: false,
      nfkcChanged,
      casefoldChanged,
      zeroWidthStripped: Math.max(0, zeroWidthStripped),
      whitespaceCollapsed,
      canonicalBytes: Buffer.from(collapsed, "utf8").length,
    },
  };
}

const HEURISTIC_PATTERNS: Array<{ id: string; category: JailbreakCategory; weight: number; re: RegExp }> = [
  {
    id: "jb_ignore_policy",
    category: "authority_confusion",
    weight: 0.9,
    re: /\b(ignore|disregard|bypass|override|disable)\b.{0,64}\b(policy|policies|rules|safety|guardrails?)\b/ims,
  },
  {
    id: "jb_dan_unfiltered",
    category: "role_play",
    weight: 0.9,
    re: /\b(dan|jailbreak|unfiltered|unrestricted)\b/ims,
  },
  {
    id: "jb_system_prompt_extraction",
    category: "instruction_extraction",
    weight: 0.95,
    re: /\b(reveal|show|tell\s+me|repeat|print|output)\b.{0,64}\b(system prompt|developer (message|instructions|prompt)|hidden (instructions|prompt)|system instructions)\b/ims,
  },
  {
    id: "jb_role_change",
    category: "role_play",
    weight: 0.7,
    re: /\b(you are now|act as|pretend to be|roleplay)\b/ims,
  },
  {
    id: "jb_encoded_payload",
    category: "encoding_attack",
    weight: 0.6,
    re: /\b(base64|rot13|url[-_ ]?encode|decode)\b/ims,
  },
];

function punctuationRatio(s: string): number {
  let punct = 0;
  let total = 0;
  for (const ch of s) {
    if (/\s/.test(ch)) continue;
    total += 1;
    if (!/[A-Za-z0-9]/.test(ch)) punct += 1;
  }
  return total === 0 ? 0 : punct / total;
}

function longRunOfSymbols(s: string): boolean {
  let run = 0;
  for (const ch of s) {
    if (/[A-Za-z0-9]/.test(ch) || /\s/.test(ch)) {
      run = 0;
      continue;
    }
    run += 1;
    if (run >= 12) return true;
  }
  return false;
}

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

export class JailbreakDetector {
  private readonly cfg: Required<JailbreakDetectorConfig>;
  private readonly judge?: (input: string) => Promise<number>;
  private readonly sessions = new Map<string, { messagesSeen: number; suspiciousCount: number; cumulativeRisk: number }>();

  constructor(config: JailbreakDetectorConfig = {}) {
    this.cfg = {
      ...DEFAULT_CFG,
      ...config,
      layers: { ...DEFAULT_CFG.layers, ...(config.layers ?? {}) },
    };
    this.judge = config.llmJudge;
  }

  async detect(input: string, sessionId?: string): Promise<JailbreakDetectionResult> {
    const fingerprint = toHex(sha256(input));
    const { slice, truncated } = truncateToBytes(input, this.cfg.maxInputBytes);
    const { canonical, stats } = canonicalizeForDetection(slice);
    stats.truncated = truncated;

    // Heuristic
    const heuristicSignals: string[] = [];
    let heuristicScore = 0;
    if (this.cfg.layers.heuristic) {
      for (const p of HEURISTIC_PATTERNS) {
        p.re.lastIndex = 0;
        if (p.re.test(canonical)) {
          heuristicSignals.push(p.id);
          heuristicScore += p.weight;
        }
        p.re.lastIndex = 0;
      }
    }

    // Statistical
    const statSignals: string[] = [];
    if (this.cfg.layers.statistical) {
      const pr = punctuationRatio(canonical);
      if (pr >= 0.35) statSignals.push("stat_punctuation_ratio_high");
      if (stats.zeroWidthStripped > 0) statSignals.push("stat_zero_width_obfuscation");
      if (longRunOfSymbols(canonical)) statSignals.push("stat_long_symbol_run");
    }
    const statScore = Math.min(1, statSignals.length * 0.2);

    // ML (linear model)
    let ml: LayerResult | undefined;
    let mlScore = 0;
    if (this.cfg.layers.ml) {
      const has = (id: string) => heuristicSignals.includes(id);
      const xIgnore = has("jb_ignore_policy") ? 1 : 0;
      const xDan = has("jb_dan_unfiltered") ? 1 : 0;
      const xRole = has("jb_role_change") ? 1 : 0;
      const xLeak = has("jb_system_prompt_extraction") ? 1 : 0;
      const xEnc = has("jb_encoded_payload") ? 1 : 0;
      const xPunct = Math.min(1, punctuationRatio(canonical) * 2);
      const xRun = longRunOfSymbols(canonical) ? 1 : 0;

      const z =
        -2.0 +
        2.5 * xIgnore +
        2.0 * xDan +
        1.5 * xRole +
        2.2 * xLeak +
        1.0 * xEnc +
        2.0 * xPunct +
        1.5 * xRun;
      mlScore = sigmoid(z);
      ml = { layer: "ml", score: mlScore, signals: ["ml_linear_model"] };
    }

    // Optional LLM judge (caller-provided callback)
    let judgeLayer: LayerResult | undefined;
    let judgeScore = 0;
    if (this.cfg.layers.llmJudge && this.judge) {
      try {
        judgeScore = Math.max(0, Math.min(1, await this.judge(slice)));
        judgeLayer = { layer: "llm_judge", score: judgeScore, signals: ["llm_judge_score"] };
      } catch {
        // Ignore judge failures; keep baseline.
      }
    }

    const heuristicNorm = Math.min(1, heuristicScore / 3);
    let combined =
      (this.cfg.layers.heuristic ? 0.55 * heuristicNorm : 0) +
      (this.cfg.layers.statistical ? 0.2 * statScore : 0) +
      (this.cfg.layers.ml ? 0.25 * mlScore : 0);
    if (judgeLayer) combined = 0.9 * combined + 0.1 * judgeScore;
    combined = Math.max(0, Math.min(1, combined));

    const riskScore = Math.max(0, Math.min(100, Math.round(combined * 100)));
    const severity: JailbreakSeverity =
      riskScore >= 85 ? "confirmed" :
        riskScore >= 60 ? "likely" :
          riskScore >= 25 ? "suspicious" :
            "safe";
    const blocked = riskScore >= this.cfg.blockThreshold;

    const signals: JailbreakSignal[] = [];
    for (const p of HEURISTIC_PATTERNS) {
      if (heuristicSignals.includes(p.id)) {
        signals.push({ id: p.id, category: p.category, weight: p.weight });
      }
    }
    for (const id of statSignals) {
      signals.push({ id, category: "adversarial_suffix", weight: 0.2 });
    }

    let session: JailbreakDetectionResult["session"] | undefined;
    if (this.cfg.sessionAggregation && sessionId) {
      const s = this.sessions.get(sessionId) ?? { messagesSeen: 0, suspiciousCount: 0, cumulativeRisk: 0 };
      s.messagesSeen += 1;
      s.cumulativeRisk += riskScore;
      if (riskScore >= this.cfg.warnThreshold) s.suspiciousCount += 1;
      this.sessions.set(sessionId, s);
      session = { sessionId, ...s };
    }

    return {
      severity,
      confidence: combined,
      riskScore,
      blocked,
      fingerprint,
      signals,
      layers: {
        heuristic: { layer: "heuristic", score: heuristicNorm, signals: heuristicSignals },
        statistical: { layer: "statistical", score: statScore, signals: statSignals },
        ml,
        llmJudge: judgeLayer,
      },
      canonicalization: stats,
      session,
    };
  }
}

