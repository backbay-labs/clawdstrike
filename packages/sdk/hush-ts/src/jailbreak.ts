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
    rollingRisk?: number;
    lastSeenMs?: number;
  };
}

export interface JailbreakSessionState {
  sessionId: string;
  messagesSeen: number;
  suspiciousCount: number;
  cumulativeRisk: number;
  rollingRisk: number;
  lastSeenMs: number;
}

export interface JailbreakSessionStore {
  load(sessionId: string): Promise<JailbreakSessionState | undefined>;
  save(sessionId: string, state: JailbreakSessionState): Promise<void>;
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
  sessionTtlMs?: number;
  sessionHalfLifeMs?: number;
  sessionStore?: JailbreakSessionStore;
  llmJudge?: (input: string) => Promise<number>;
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

type ResolvedJailbreakLayers = {
  heuristic: boolean;
  statistical: boolean;
  ml: boolean;
  llmJudge: boolean;
};

type ResolvedJailbreakDetectorConfig = {
  layers: ResolvedJailbreakLayers;
  blockThreshold: number;
  warnThreshold: number;
  maxInputBytes: number;
  sessionAggregation: boolean;
  sessionMaxEntries: number;
  sessionTtlMs: number;
  sessionHalfLifeMs: number;
};

const DEFAULT_CFG: ResolvedJailbreakDetectorConfig = {
  layers: { heuristic: true, statistical: true, ml: true, llmJudge: false },
  blockThreshold: 70,
  warnThreshold: 30,
  maxInputBytes: 100_000,
  sessionAggregation: true,
  sessionMaxEntries: 1024,
  sessionTtlMs: 60 * 60 * 1000,
  sessionHalfLifeMs: 15 * 60 * 1000,
};

type LinearModel = Required<{
  bias: number;
  wIgnorePolicy: number;
  wDan: number;
  wRoleChange: number;
  wPromptExtraction: number;
  wEncoded: number;
  wPunct: number;
  wSymbolRun: number;
}>;

const DEFAULT_LINEAR_MODEL: LinearModel = {
  bias: -2.0,
  wIgnorePolicy: 2.5,
  wDan: 2.0,
  wRoleChange: 1.5,
  wPromptExtraction: 2.2,
  wEncoded: 1.0,
  wPunct: 2.0,
  wSymbolRun: 1.5,
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

function shannonEntropyAsciiNonWs(s: string): number {
  const counts = new Array<number>(128).fill(0);
  let total = 0;
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code >= 128) continue;
    const ch = s[i] ?? "";
    if (/\s/.test(ch)) continue;
    counts[code] += 1;
    total += 1;
  }
  if (total <= 0) return 0;

  let entropy = 0;
  for (const c of counts) {
    if (c <= 0) continue;
    const p = c / total;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

export class JailbreakDetector {
  private readonly cfg: ResolvedJailbreakDetectorConfig;
  private readonly model: LinearModel;
  private readonly judge?: (input: string) => Promise<number>;
  private readonly store?: JailbreakSessionStore;
  private readonly sessions = new Map<string, JailbreakSessionState>();

  constructor(config: JailbreakDetectorConfig = {}) {
    this.cfg = {
      layers: { ...DEFAULT_CFG.layers, ...(config.layers ?? {}) },
      blockThreshold: config.blockThreshold ?? DEFAULT_CFG.blockThreshold,
      warnThreshold: config.warnThreshold ?? DEFAULT_CFG.warnThreshold,
      maxInputBytes: config.maxInputBytes ?? DEFAULT_CFG.maxInputBytes,
      sessionAggregation: config.sessionAggregation ?? DEFAULT_CFG.sessionAggregation,
      sessionMaxEntries: config.sessionMaxEntries ?? DEFAULT_CFG.sessionMaxEntries,
      sessionTtlMs: config.sessionTtlMs ?? DEFAULT_CFG.sessionTtlMs,
      sessionHalfLifeMs: config.sessionHalfLifeMs ?? DEFAULT_CFG.sessionHalfLifeMs,
    };
    this.model = { ...DEFAULT_LINEAR_MODEL, ...(config.linearModel ?? {}) };
    this.judge = config.llmJudge;
    this.store = config.sessionStore;
  }

  private decayFactor(elapsedMs: number): number {
    if (this.cfg.sessionHalfLifeMs <= 0) return 1;
    return Math.pow(0.5, elapsedMs / this.cfg.sessionHalfLifeMs);
  }

  private pruneSessions(nowMs: number): void {
    if (this.cfg.sessionTtlMs <= 0) return;
    for (const [sid, st] of this.sessions) {
      if (nowMs - st.lastSeenMs > this.cfg.sessionTtlMs) {
        this.sessions.delete(sid);
      }
    }
  }

  private evictForCapacity(): void {
    const maxEntries = Math.max(1, this.cfg.sessionMaxEntries);
    while (this.sessions.size > maxEntries) {
      let oldestId: string | undefined;
      let oldestTs = Number.POSITIVE_INFINITY;
      for (const [sid, st] of this.sessions) {
        if (st.lastSeenMs < oldestTs) {
          oldestTs = st.lastSeenMs;
          oldestId = sid;
        }
      }
      if (!oldestId) return;
      this.sessions.delete(oldestId);
    }
  }

  private async maybeLoadSession(sessionId: string): Promise<void> {
    if (!this.store) return;
    if (this.sessions.has(sessionId)) return;
    try {
      const loaded = await this.store.load(sessionId);
      if (loaded) this.sessions.set(sessionId, loaded);
    } catch {
      // ignore store failures; session aggregation is best-effort
    }
  }

  private async maybePersistSession(sessionId: string): Promise<void> {
    if (!this.store) return;
    const st = this.sessions.get(sessionId);
    if (!st) return;
    try {
      await this.store.save(sessionId, st);
    } catch {
      // ignore store failures; session aggregation is best-effort
    }
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
      const ent = shannonEntropyAsciiNonWs(canonical);
      if (ent >= 4.8) statSignals.push("stat_char_entropy_high");
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
        this.model.bias +
        this.model.wIgnorePolicy * xIgnore +
        this.model.wDan * xDan +
        this.model.wRoleChange * xRole +
        this.model.wPromptExtraction * xLeak +
        this.model.wEncoded * xEnc +
        this.model.wPunct * xPunct +
        this.model.wSymbolRun * xRun;
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
      const nowMs = Date.now();
      this.pruneSessions(nowMs);
      await this.maybeLoadSession(sessionId);

      // Ensure room if inserting a new session.
      if (!this.sessions.has(sessionId)) {
        const maxEntries = Math.max(1, this.cfg.sessionMaxEntries);
        while (this.sessions.size + 1 > maxEntries) {
          this.evictForCapacity();
          if (this.sessions.size + 1 <= maxEntries) break;
        }
      }

      const st: JailbreakSessionState =
        this.sessions.get(sessionId) ?? {
          sessionId,
          messagesSeen: 0,
          suspiciousCount: 0,
          cumulativeRisk: 0,
          rollingRisk: 0,
          lastSeenMs: nowMs,
        };

      const elapsedMs = Math.max(0, nowMs - st.lastSeenMs);
      st.rollingRisk *= this.decayFactor(elapsedMs);
      st.lastSeenMs = nowMs;

      st.messagesSeen += 1;
      st.cumulativeRisk += riskScore;
      st.rollingRisk += riskScore;
      if (riskScore >= this.cfg.warnThreshold) st.suspiciousCount += 1;

      this.sessions.set(sessionId, st);
      this.evictForCapacity();
      await this.maybePersistSession(sessionId);

      session = {
        sessionId,
        messagesSeen: st.messagesSeen,
        suspiciousCount: st.suspiciousCount,
        cumulativeRisk: st.cumulativeRisk,
        rollingRisk: st.rollingRisk,
        lastSeenMs: st.lastSeenMs,
      };
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
