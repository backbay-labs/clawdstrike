import { readFile } from "node:fs/promises";
import { fromHex, sha256, toHex } from "../crypto/hash.js";
import { verifySignature } from "../crypto/sign.js";
import { type PatternEntry, type SpiderSenseDetectorConfig } from "../spider-sense.js";
import { type Guard, GuardAction, type GuardContext, GuardResult, Severity } from "./types";

const DEFAULT_SIMILARITY_THRESHOLD = 0.85;
const DEFAULT_AMBIGUITY_BAND = 0.1;
const DEFAULT_TOP_K = 5;
const DEFAULT_EMBEDDING_TIMEOUT_MS = 15_000;
const MAX_EMBEDDING_RESPONSE_BYTES = 2 * 1024 * 1024;

type SpiderSenseVerdict = "deny" | "ambiguous" | "allow";

interface PatternMatch {
  entry: PatternEntry;
  score: number;
}

interface ScreeningResult {
  verdict: SpiderSenseVerdict;
  topScore: number;
  threshold: number;
  ambiguityBand: number;
  topMatches: PatternMatch[];
}

interface PatternDb {
  entries: PatternEntry[];
  expectedDim: number;
}

type SpiderSenseProvider = "openai" | "cohere" | "voyage";

export interface SpiderSenseMetrics {
  verdict: SpiderSenseVerdict;
  top_score: number;
  severity: Severity;
  db_source: string;
  db_version: string;
  allow_count: number;
  ambiguous_count: number;
  deny_count: number;
  total_count: number;
  ambiguity_rate: number;
  screened: boolean;
  skip_reason?: string;
  embedding_source?: "action" | "provider";
}

export type SpiderSenseMetricsHook = (event: SpiderSenseMetrics) => void;

export interface SpiderSenseGuardConfig extends SpiderSenseDetectorConfig {
  enabled?: boolean;
  patterns?: PatternEntry[];
  patternDbPath?: string;
  patternDbVersion?: string;
  patternDbChecksum?: string;
  patternDbSignature?: string;
  patternDbPublicKey?: string;
  embeddingApiUrl?: string;
  embeddingApiKey?: string;
  embeddingModel?: string;
  embeddingTimeoutMs?: number;
  metricsHook?: SpiderSenseMetricsHook;
  fetchFn?: typeof fetch;
}

function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) {
    return 0.0;
  }

  let dot = 0.0;
  let normA = 0.0;
  let normB = 0.0;
  for (let i = 0; i < a.length; i += 1) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }

  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  if (!Number.isFinite(denom) || denom === 0) {
    return 0.0;
  }
  const result = dot / denom;
  if (!Number.isFinite(result)) {
    return 0.0;
  }
  return result;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function coerceEmbedding(value: unknown): number[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const out: number[] = [];
  for (const item of value) {
    if (!isFiniteNumber(item)) {
      return null;
    }
    out.push(item);
  }
  return out;
}

function truncate(value: string, maxChars = 512): string {
  const trimmed = value.trim();
  if (trimmed.length <= maxChars) {
    return trimmed;
  }
  return trimmed.slice(0, maxChars);
}

function parsePatternDbJson(json: string): PatternDb {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (err) {
    throw new Error(`failed to parse pattern DB: ${err instanceof Error ? err.message : String(err)}`);
  }

  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error("pattern DB must contain at least one entry");
  }

  const entries: PatternEntry[] = [];
  for (let i = 0; i < parsed.length; i += 1) {
    const raw = parsed[i];
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      throw new Error(`pattern DB entry ${i} must be an object`);
    }
    const embedding = coerceEmbedding((raw as Record<string, unknown>).embedding);
    if (!embedding) {
      throw new Error(`pattern DB entry ${i} has invalid embedding values (must be finite numbers)`);
    }
    entries.push({
      id: String((raw as Record<string, unknown>).id ?? ""),
      category: String((raw as Record<string, unknown>).category ?? ""),
      stage: String((raw as Record<string, unknown>).stage ?? ""),
      label: String((raw as Record<string, unknown>).label ?? ""),
      embedding,
    });
  }

  const expectedDim = entries[0].embedding.length;
  if (expectedDim === 0) {
    throw new Error("pattern DB entries must have non-empty embeddings");
  }
  for (let i = 0; i < entries.length; i += 1) {
    if (entries[i].embedding.length !== expectedDim) {
      throw new Error(
        `pattern DB dimension mismatch at index ${i}: expected ${expectedDim}, got ${entries[i].embedding.length}`,
      );
    }
  }

  return { entries, expectedDim };
}

function parseProviderFromUrl(url: string): SpiderSenseProvider {
  const host = new URL(url).host.toLowerCase();
  if (host.includes("cohere")) {
    return "cohere";
  }
  if (host.includes("voyage")) {
    return "voyage";
  }
  return "openai";
}

export class SpiderSenseGuard implements Guard {
  readonly name = "spider_sense";
  private readonly enabled: boolean;
  private readonly threshold: number;
  private readonly ambiguityBand: number;
  private readonly topK: number;
  private readonly upperBound: number;
  private readonly lowerBound: number;

  private readonly embeddingEnabled: boolean;
  private readonly embeddingApiUrl: string;
  private readonly embeddingApiKey: string;
  private readonly embeddingModel: string;
  private readonly embeddingProvider: SpiderSenseProvider;
  private readonly embeddingTimeoutMs: number;
  private readonly fetchFn: typeof fetch;

  private readonly metricsHook?: SpiderSenseMetricsHook;
  private allowCount = 0;
  private ambiguousCount = 0;
  private denyCount = 0;
  private totalCount = 0;

  private patternDb: PatternDb | null = null;
  private dbSource = "";
  private dbVersion = "";
  private loadPromise: Promise<void> | null = null;
  private pendingPatternConfig: SpiderSenseGuardConfig | null = null;

  constructor(config: SpiderSenseGuardConfig = {}) {
    this.enabled = config.enabled !== false;
    this.threshold = config.similarityThreshold ?? DEFAULT_SIMILARITY_THRESHOLD;
    this.ambiguityBand = config.ambiguityBand ?? DEFAULT_AMBIGUITY_BAND;
    this.topK = config.topK ?? DEFAULT_TOP_K;
    this.upperBound = this.threshold + this.ambiguityBand;
    this.lowerBound = this.threshold - this.ambiguityBand;
    this.validateThresholdConfig();

    const embeddingApiUrl = (config.embeddingApiUrl ?? "").trim();
    const embeddingApiKey = (config.embeddingApiKey ?? "").trim();
    const embeddingModel = (config.embeddingModel ?? "").trim();
    const hasUrl = embeddingApiUrl.length > 0;
    const hasKey = embeddingApiKey.length > 0;
    const hasModel = embeddingModel.length > 0;

    if (hasUrl || hasKey || hasModel) {
      if (!hasUrl || !hasKey || !hasModel) {
        throw new Error(
          "spider_sense: embedding_api_url, embedding_api_key, and embedding_model must all be set when any is provided",
        );
      }
      const parsed = new URL(embeddingApiUrl);
      if (!parsed.protocol || !parsed.host) {
        throw new Error("spider_sense: embedding_api_url must be absolute and include host");
      }
      this.embeddingEnabled = true;
      this.embeddingApiUrl = embeddingApiUrl;
      this.embeddingApiKey = embeddingApiKey;
      this.embeddingModel = embeddingModel;
      this.embeddingProvider = parseProviderFromUrl(embeddingApiUrl);
    } else {
      this.embeddingEnabled = false;
      this.embeddingApiUrl = "";
      this.embeddingApiKey = "";
      this.embeddingModel = "";
      this.embeddingProvider = "openai";
    }

    this.embeddingTimeoutMs = Number.isFinite(config.embeddingTimeoutMs)
      ? Math.max(1, config.embeddingTimeoutMs ?? DEFAULT_EMBEDDING_TIMEOUT_MS)
      : DEFAULT_EMBEDDING_TIMEOUT_MS;
    this.fetchFn = config.fetchFn ?? fetch;
    this.metricsHook = config.metricsHook;

    if (config.patterns) {
      if (config.patterns.length === 0) {
        throw new Error("spider_sense: patterns must contain at least one entry when set");
      }
      this.patternDb = parsePatternDbJson(JSON.stringify(config.patterns));
      this.dbSource = "inline";
      this.dbVersion = "inline";
    } else if (config.patternDbPath?.trim()) {
      this.pendingPatternConfig = { ...config };
    }
  }

  loadPatterns(patterns: PatternEntry[]): void {
    if (patterns.length === 0) {
      throw new Error("spider_sense: patterns must contain at least one entry when set");
    }
    this.patternDb = parsePatternDbJson(JSON.stringify(patterns));
    this.dbSource = "inline";
    this.dbVersion = "inline";
    this.loadPromise = null;
  }

  handles(_action: GuardAction): boolean {
    return true;
  }

  async check(action: GuardAction, context: GuardContext): Promise<GuardResult> {
    if (!this.enabled) {
      const result = GuardResult.allow(this.name);
      this.emitMetrics("allow", 0, result.severity, false, "disabled");
      return result;
    }

    await this.ensurePatternDbLoaded();
    if (!this.patternDb) {
      const result = GuardResult.allow(this.name);
      this.emitMetrics("allow", 0, result.severity, false, "pattern_db_missing");
      return result;
    }

    let embedding = this.extractEmbedding(action.customData);
    let embeddingSource: "action" | "provider" = "action";

    if (!embedding) {
      if (!this.embeddingEnabled) {
        const result = GuardResult.allow(this.name);
        this.emitMetrics("allow", 0, result.severity, false, "embedding_missing");
        return result;
      }
      try {
        embedding = await this.fetchEmbedding(this.actionToText(action), context);
        embeddingSource = "provider";
      } catch (err) {
        const details = {
          analysis: "provider",
          error: err instanceof Error ? err.message : String(err),
          db_source: this.dbSource,
          db_version: this.dbVersion,
          embedding_from: "provider",
        };
        const result = GuardResult.block(
          this.name,
          Severity.ERROR,
          "Spider-Sense embedding provider error (fail-closed)",
        ).withDetails(details);
        this.emitMetrics("deny", 0, result.severity, true, "provider_error", "provider");
        return result;
      }
    }

    if (embedding.length !== this.patternDb.expectedDim) {
      const details = {
        analysis: "validation",
        error: `embedding dimension mismatch: got ${embedding.length}, expected ${this.patternDb.expectedDim}`,
        db_source: this.dbSource,
        db_version: this.dbVersion,
        embedding_from: embeddingSource,
      };
      const result = GuardResult.block(
        this.name,
        Severity.ERROR,
        "Spider-Sense embedding dimension mismatch (fail-closed)",
      ).withDetails(details);
      this.emitMetrics("deny", 0, result.severity, true, "dimension_mismatch", embeddingSource);
      return result;
    }

    const screening = this.screen(embedding);
    const details = this.resultDetails(screening, embeddingSource);

    if (screening.verdict === "deny") {
      const topLabel = screening.topMatches[0]?.entry.label ?? "";
      const result = GuardResult.block(
        this.name,
        Severity.ERROR,
        `Spider-Sense threat detected (score=${screening.topScore.toFixed(3)}, label="${topLabel}")`,
      ).withDetails(details);
      this.emitMetrics("deny", screening.topScore, result.severity, true, undefined, embeddingSource);
      return result;
    }

    if (screening.verdict === "ambiguous") {
      const result = GuardResult.warn(
        this.name,
        `Spider-Sense ambiguous match detected (score=${screening.topScore.toFixed(3)})`,
      ).withDetails(details);
      this.emitMetrics(
        "ambiguous",
        screening.topScore,
        result.severity,
        true,
        undefined,
        embeddingSource,
      );
      return result;
    }

    const result = GuardResult.allow(this.name).withDetails(details);
    this.emitMetrics("allow", screening.topScore, result.severity, true, undefined, embeddingSource);
    return result;
  }

  private validateThresholdConfig(): void {
    if (!Number.isFinite(this.threshold)) {
      throw new Error("spider_sense: similarity_threshold must be a finite number");
    }
    if (this.threshold < 0 || this.threshold > 1) {
      throw new Error(
        `spider_sense: similarity_threshold must be in [0.0, 1.0], got ${this.threshold}`,
      );
    }
    if (!Number.isFinite(this.ambiguityBand)) {
      throw new Error("spider_sense: ambiguity_band must be a finite number");
    }
    if (this.ambiguityBand < 0 || this.ambiguityBand > 1) {
      throw new Error(
        `spider_sense: ambiguity_band must be in [0.0, 1.0], got ${this.ambiguityBand}`,
      );
    }
    if (this.lowerBound < 0 || this.lowerBound > 1 || this.upperBound < 0 || this.upperBound > 1) {
      throw new Error(
        `spider_sense: threshold/band produce invalid decision range: lower=${this.lowerBound.toFixed(3)}, upper=${this.upperBound.toFixed(3)}; expected both in [0.0, 1.0]`,
      );
    }
    if (!Number.isInteger(this.topK) || this.topK < 1) {
      throw new Error("spider_sense: top_k must be at least 1");
    }
  }

  private async ensurePatternDbLoaded(): Promise<void> {
    if (!this.loadPromise && this.pendingPatternConfig) {
      this.loadPromise = this.loadPatternDbFromPath(this.pendingPatternConfig);
      this.pendingPatternConfig = null;
    }
    if (!this.loadPromise) {
      return;
    }
    const current = this.loadPromise;
    this.loadPromise = null;
    await current;
  }

  private async loadPatternDbFromPath(config: SpiderSenseGuardConfig): Promise<void> {
    const path = (config.patternDbPath ?? "").trim();
    if (!path) {
      throw new Error("spider_sense: pattern_db_path cannot be empty");
    }

    const version = (config.patternDbVersion ?? "").trim();
    const checksum = (config.patternDbChecksum ?? "").trim();
    const signature = (config.patternDbSignature ?? "").trim();
    const publicKey = (config.patternDbPublicKey ?? "").trim();

    if (!version || !checksum) {
      throw new Error(
        "spider_sense: pattern_db_version and pattern_db_checksum are required when pattern_db_path is set",
      );
    }
    if ((signature.length > 0) !== (publicKey.length > 0)) {
      throw new Error(
        "spider_sense: pattern_db_signature and pattern_db_public_key must either both be set or both be omitted",
      );
    }

    let bytes: Uint8Array;
    let source = path;
    if (path === "builtin:s2bench-v1") {
      const builtinUrl = new URL("../../../hush-go/guards/patterns/s2bench-v1.json", import.meta.url);
      bytes = await readFile(builtinUrl);
      source = "builtin:s2bench-v1";
    } else {
      bytes = await readFile(path);
    }

    const actualChecksum = toHex(sha256(bytes)).toLowerCase();
    const normalizedExpected = checksum.toLowerCase().replace(/^0x/, "");
    if (actualChecksum !== normalizedExpected) {
      throw new Error(
        `spider_sense: pattern DB checksum mismatch: expected ${normalizedExpected}, got ${actualChecksum}`,
      );
    }

    if (signature && publicKey) {
      const message = new TextEncoder().encode(
        `spider_sense_db:v1:${version}:${normalizedExpected}`,
      );
      let valid = false;
      try {
        valid = await verifySignature(message, fromHex(signature), fromHex(publicKey));
      } catch (err) {
        throw new Error(
          `spider_sense: invalid pattern DB signature material: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      if (!valid) {
        throw new Error("spider_sense: pattern DB signature verification failed");
      }
    }

    const db = parsePatternDbJson(new TextDecoder().decode(bytes));
    this.patternDb = db;
    this.dbSource = source;
    this.dbVersion = version;
  }

  private extractEmbedding(data?: Record<string, unknown>): number[] | null {
    if (!data) {
      return null;
    }
    return coerceEmbedding(data.embedding);
  }

  private actionToText(action: GuardAction): string {
    switch (action.actionType) {
      case "custom": {
        const label = (action.customType ?? "custom").trim() || "custom";
        return `[custom:${label}] ${JSON.stringify(action.customData ?? null)}`;
      }
      case "mcp_tool": {
        const name = (action.tool ?? "tool").trim() || "tool";
        return `[mcp_tool:${name}] ${JSON.stringify(action.args ?? {})}`;
      }
      case "shell_command":
        return `[shell_command] ${(action.command ?? "").trim()}`;
      case "file_write": {
        const preview = action.content
          ? truncate(new TextDecoder().decode(action.content))
          : "";
        return `[file_write:${(action.path ?? "").trim()}] ${preview}`;
      }
      case "network_egress":
        return `[network_egress:${(action.host ?? "").trim()}:${action.port ?? 0}]`;
      case "file_access":
        return `[file_access] ${(action.path ?? "").trim()}`;
      case "patch":
        return `[patch:${(action.path ?? "").trim()}] ${truncate(action.diff ?? "")}`;
      default:
        return `[action:${action.actionType}]`;
    }
  }

  private async fetchEmbedding(
    text: string,
    _context: GuardContext,
  ): Promise<number[]> {
    const payload =
      this.embeddingProvider === "cohere"
        ? {
            texts: [text],
            model: this.embeddingModel,
            embedding_types: ["float"],
            input_type: "classification",
          }
        : this.embeddingProvider === "voyage"
          ? {
              input: [text],
              model: this.embeddingModel,
            }
          : {
              input: text,
              model: this.embeddingModel,
            };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.embeddingTimeoutMs);
    let response: Response;
    try {
      response = await this.fetchFn(this.embeddingApiUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          authorization: `Bearer ${this.embeddingApiKey}`,
          ...(this.embeddingProvider === "cohere"
            ? { "x-client-name": "clawdstrike-ts" }
            : {}),
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }

    const rawBody = await response.text();
    if (!response.ok) {
      throw new Error(
        `embedding API returned HTTP ${response.status}: ${rawBody.trim() || "empty response body"}`,
      );
    }
    if (rawBody.length > MAX_EMBEDDING_RESPONSE_BYTES) {
      throw new Error("embedding API response exceeds size limit");
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(rawBody);
    } catch (err) {
      throw new Error(
        `parse embedding response: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    let embedding: number[] | null = null;
    if (this.embeddingProvider === "cohere") {
      const embeddings = (parsed as Record<string, unknown>).embeddings;
      if (Array.isArray(embeddings) && embeddings.length > 0) {
        embedding = coerceEmbedding(embeddings[0]);
      } else if (typeof embeddings === "object" && embeddings !== null) {
        const floatEmbeddings = (embeddings as { float?: unknown }).float;
        if (Array.isArray(floatEmbeddings) && floatEmbeddings.length > 0) {
          embedding = coerceEmbedding(floatEmbeddings[0]);
        }
      }
    } else {
      const data = (parsed as Record<string, unknown>).data;
      if (Array.isArray(data) && data.length > 0) {
        const first = data[0];
        if (typeof first === "object" && first !== null) {
          embedding = coerceEmbedding((first as Record<string, unknown>).embedding);
        }
      }
    }

    if (!embedding || embedding.length === 0) {
      throw new Error("embedding API returned an empty or invalid embedding");
    }
    return embedding;
  }

  private screen(embedding: number[]): ScreeningResult {
    if (!this.patternDb) {
      return {
        verdict: "allow",
        topScore: 0,
        threshold: this.threshold,
        ambiguityBand: this.ambiguityBand,
        topMatches: [],
      };
    }

    const scored: PatternMatch[] = this.patternDb.entries.map((entry) => ({
      entry,
      score: cosineSimilarity(embedding, entry.embedding),
    }));
    scored.sort((a, b) => b.score - a.score);
    const topMatches = scored.slice(0, this.topK);
    const topScore = topMatches[0]?.score ?? 0;

    let verdict: SpiderSenseVerdict;
    if (topScore >= this.upperBound) {
      verdict = "deny";
    } else if (topScore <= this.lowerBound) {
      verdict = "allow";
    } else {
      verdict = "ambiguous";
    }

    return {
      verdict,
      topScore,
      threshold: this.threshold,
      ambiguityBand: this.ambiguityBand,
      topMatches,
    };
  }

  private resultDetails(
    result: ScreeningResult,
    embeddingSource: "action" | "provider",
  ): Record<string, unknown> {
    const matches = result.topMatches.map((match) => ({
      id: match.entry.id,
      category: match.entry.category,
      stage: match.entry.stage,
      label: match.entry.label,
      score: match.score,
    }));
    return {
      analysis: "fast_path",
      verdict: result.verdict,
      top_score: result.topScore,
      threshold: result.threshold,
      ambiguity_band: result.ambiguityBand,
      top_matches: matches,
      top_match: matches[0],
      db_source: this.dbSource,
      db_version: this.dbVersion,
      embedding_from: embeddingSource,
    };
  }

  private emitMetrics(
    verdict: SpiderSenseVerdict,
    topScore: number,
    severity: Severity,
    screened: boolean,
    skipReason?: string,
    embeddingSource?: "action" | "provider",
  ): void {
    if (!this.metricsHook) {
      return;
    }
    this.totalCount += 1;
    if (verdict === "deny") {
      this.denyCount += 1;
    } else if (verdict === "ambiguous") {
      this.ambiguousCount += 1;
    } else {
      this.allowCount += 1;
    }

    const ambiguityRate = this.totalCount === 0 ? 0 : this.ambiguousCount / this.totalCount;
    const event: SpiderSenseMetrics = {
      verdict,
      top_score: topScore,
      severity,
      db_source: this.dbSource,
      db_version: this.dbVersion,
      allow_count: this.allowCount,
      ambiguous_count: this.ambiguousCount,
      deny_count: this.denyCount,
      total_count: this.totalCount,
      ambiguity_rate: ambiguityRate,
      screened,
      skip_reason: skipReason,
      embedding_source: embeddingSource,
    };
    try {
      this.metricsHook(event);
    } catch {
      // Hooks are best-effort only.
    }
  }
}
