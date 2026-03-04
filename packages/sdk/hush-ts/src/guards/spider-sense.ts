import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve as resolvePath } from "node:path";
import { fromHex, sha256, toHex } from "../crypto/hash.js";
import { verifySignature } from "../crypto/sign.js";
import { type PatternEntry, type SpiderSenseDetectorConfig } from "../spider-sense.js";
import { type Guard, GuardAction, type GuardContext, GuardResult, Severity } from "./types";

const DEFAULT_SIMILARITY_THRESHOLD = 0.85;
const DEFAULT_AMBIGUITY_BAND = 0.1;
const DEFAULT_TOP_K = 5;
const DEFAULT_EMBEDDING_TIMEOUT_MS = 15_000;
const MAX_EMBEDDING_RESPONSE_BYTES = 2 * 1024 * 1024;

const DEFAULT_CACHE_TTL_MS = 60 * 60 * 1000;
const DEFAULT_CACHE_MAX_SIZE_BYTES = 64 * 1024 * 1024;
const DEFAULT_RETRY_INITIAL_BACKOFF_MS = 250;
const DEFAULT_RETRY_MAX_BACKOFF_MS = 2_000;
const DEFAULT_RETRY_MULTIPLIER = 2;
const DEFAULT_RETRY_AFTER_CAP_MS = 10_000;
const DEFAULT_RATE_LIMIT_RESET_GRACE_MS = 250;
const DEFAULT_LLM_TIMEOUT_MS = 1_500;
const DEFAULT_LLM_OPENAI_MODEL = "gpt-4.1-mini";
const DEFAULT_LLM_ANTHROPIC_MODEL = "claude-haiku-4-5-20251001";
const DEFAULT_PROMPT_TEMPLATE_ID = "spider_sense.deep_path.json_classifier";
const DEFAULT_PROMPT_TEMPLATE_VERSION = "1.0.0";

type SpiderSenseVerdict = "deny" | "ambiguous" | "allow";
type SpiderSenseProvider = "openai" | "cohere" | "voyage";
type SpiderSenseLLMProvider = "openai" | "anthropic";
type SpiderSenseCircuitState = "closed" | "open" | "half_open";
type SpiderSenseCircuitOpenAction = "deny" | "warn" | "allow";
type SpiderSenseDeepPathFailMode = "warn" | "deny" | "allow";
type SpiderSenseTrustedKeyStatus = "active" | "deprecated" | "revoked";

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
  cache_hit?: boolean;
  provider_attempts?: number;
  retry_count?: number;
  circuit_state?: string;
  deep_path_used?: boolean;
  deep_path_verdict?: string;
  trust_key_id?: string;
  embedding_latency_ms?: number;
  deep_path_latency_ms?: number;
}

export type SpiderSenseMetricsHook = (event: SpiderSenseMetrics) => void;

export interface SpiderSenseTrustedKeyConfig {
  key_id?: string;
  public_key: string;
  not_before?: string;
  not_after?: string;
  status?: string;
}

export interface SpiderSenseAsyncConfig {
  timeout_ms?: number;
  cache?: {
    enabled?: boolean;
    ttl_seconds?: number;
    max_size_mb?: number;
  };
  retry?: {
    max_retries?: number;
    initial_backoff_ms?: number;
    max_backoff_ms?: number;
    multiplier?: number;
    honor_retry_after?: boolean;
    retry_after_cap_ms?: number;
    honor_rate_limit_reset?: boolean;
    rate_limit_reset_grace_ms?: number;
  };
  circuit_breaker?: {
    failure_threshold?: number;
    reset_timeout_ms?: number;
    success_threshold?: number;
    on_open?: string;
  };
}

export interface SpiderSenseGuardConfig extends SpiderSenseDetectorConfig {
  enabled?: boolean;
  patterns?: PatternEntry[];
  patternDbPath?: string;
  patternDbVersion?: string;
  patternDbChecksum?: string;
  patternDbSignature?: string;
  patternDbSignatureKeyId?: string;
  patternDbPublicKey?: string;
  patternDbTrustStorePath?: string;
  patternDbTrustedKeys?: SpiderSenseTrustedKeyConfig[];
  patternDbManifestPath?: string;
  patternDbManifestTrustStorePath?: string;
  patternDbManifestTrustedKeys?: SpiderSenseTrustedKeyConfig[];

  embeddingApiUrl?: string;
  embeddingApiKey?: string;
  embeddingModel?: string;
  embeddingTimeoutMs?: number;

  llmApiUrl?: string;
  llmApiKey?: string;
  llmModel?: string;
  llmPromptTemplateId?: string;
  llmPromptTemplateVersion?: string;
  llmTimeoutMs?: number;
  llmFailMode?: string;

  async?: SpiderSenseAsyncConfig | Record<string, unknown>;

  metricsHook?: SpiderSenseMetricsHook;
  fetchFn?: typeof fetch;
  deepPathFetchFn?: typeof fetch;
}

interface SpiderSenseRetryRuntimeConfig {
  enabled: boolean;
  maxRetries: number;
  initialBackoffMs: number;
  maxBackoffMs: number;
  multiplier: number;
  honorRetryAfter: boolean;
  retryAfterCapMs: number;
  honorRateLimitReset: boolean;
  rateLimitResetGraceMs: number;
}

interface SpiderSenseCircuitRuntimeConfig {
  failureThreshold: number;
  resetTimeoutMs: number;
  successThreshold: number;
}

interface SpiderSenseRuntimeConfig {
  timeoutMs: number;
  hasTimeout: boolean;
  cacheEnabled: boolean;
  cacheTtlMs: number;
  cacheMaxSizeBytes: number;
  retry: SpiderSenseRetryRuntimeConfig;
  circuitBreaker: SpiderSenseCircuitRuntimeConfig | null;
  onCircuitOpen: SpiderSenseCircuitOpenAction;
}

interface SpiderSenseDeepPathConfig {
  enabled: boolean;
  apiUrl: string;
  apiKey: string;
  model: string;
  provider: SpiderSenseLLMProvider;
  timeoutMs: number;
  failMode: SpiderSenseDeepPathFailMode;
  templateId: string;
  templateVersion: string;
  templateRenderer: (actionText: string) => string;
}

interface SpiderSenseProviderStats {
  attempts: number;
  retries: number;
  circuitState: SpiderSenseCircuitState;
  latencyMs: number;
  circuitOpened: boolean;
}

interface SpiderSenseDeepPathStats {
  used: boolean;
  attempts: number;
  retries: number;
  circuitState: SpiderSenseCircuitState;
  latencyMs: number;
  verdict: string;
}

interface SpiderSenseMetricRuntime {
  cacheHit?: boolean;
  providerAttempts?: number;
  retryCount?: number;
  circuitState?: string;
  deepPathUsed?: boolean;
  deepPathVerdict?: string;
  trustKeyId?: string;
  embeddingLatencyMs?: number;
  deepPathLatencyMs?: number;
}

interface SpiderSenseLLMVerdict {
  verdict: string;
  reason: string;
}

interface SpiderSenseTrustedKey {
  keyId: string;
  publicKey: string;
  status: SpiderSenseTrustedKeyStatus;
  notBefore?: Date;
  notAfter?: Date;
}

interface SpiderSensePatternManifest {
  pattern_db_path?: string;
  pattern_db_version?: string;
  pattern_db_checksum?: string;
  pattern_db_signature?: string;
  pattern_db_public_key?: string;
  pattern_db_signature_key_id?: string;
  pattern_db_trust_store_path?: string;
  pattern_db_trusted_keys?: SpiderSenseTrustedKeyConfig[];
  manifest_signature?: string;
  manifest_signature_key_id?: string;
  not_before?: string;
  not_after?: string;
}

class SpiderSenseProviderError extends Error {
  readonly retryable: boolean;
  readonly status?: number;
  readonly retryAfterMs?: number;

  constructor(message: string, retryable: boolean, status?: number, retryAfterMs?: number) {
    super(message);
    this.name = "SpiderSenseProviderError";
    this.retryable = retryable;
    this.status = status;
    this.retryAfterMs = retryAfterMs;
  }
}

class SpiderSenseCircuitBreaker {
  private state: SpiderSenseCircuitState = "closed";
  private failures = 0;
  private successes = 0;
  private openUntil = 0;

  constructor(private readonly config: SpiderSenseCircuitRuntimeConfig) {}

  allow(now = Date.now()): { allowed: boolean; state: SpiderSenseCircuitState } {
    if (this.state === "open") {
      if (now < this.openUntil) {
        return { allowed: false, state: this.state };
      }
      this.state = "half_open";
      this.failures = 0;
      this.successes = 0;
      return { allowed: true, state: this.state };
    }
    return { allowed: true, state: this.state };
  }

  recordSuccess(): void {
    if (this.state === "half_open") {
      this.successes += 1;
      if (this.successes >= this.config.successThreshold) {
        this.state = "closed";
        this.failures = 0;
        this.successes = 0;
      }
      return;
    }
    this.state = "closed";
    this.failures = 0;
    this.successes = 0;
  }

  recordFailure(now = Date.now()): void {
    if (this.state === "half_open") {
      this.state = "open";
      this.openUntil = now + this.config.resetTimeoutMs;
      this.failures = 0;
      this.successes = 0;
      return;
    }
    this.failures += 1;
    if (this.failures >= this.config.failureThreshold) {
      this.state = "open";
      this.openUntil = now + this.config.resetTimeoutMs;
      this.failures = 0;
      this.successes = 0;
    }
  }

  currentState(): SpiderSenseCircuitState {
    return this.state;
  }
}

interface SpiderSenseCacheEntry {
  embedding: number[];
  expiresAt: number;
  sizeBytes: number;
}

class SpiderSenseEmbeddingCache {
  private readonly entries = new Map<string, SpiderSenseCacheEntry>();
  private currentSizeBytes = 0;

  constructor(
    private readonly enabled: boolean,
    private readonly ttlMs: number,
    private readonly maxSizeBytes: number,
  ) {}

  get(key: string): number[] | null {
    if (!this.enabled) {
      return null;
    }
    const entry = this.entries.get(key);
    if (!entry) {
      return null;
    }
    if (entry.expiresAt <= Date.now()) {
      this.delete(key);
      return null;
    }
    this.entries.delete(key);
    this.entries.set(key, entry);
    return [...entry.embedding];
  }

  set(key: string, embedding: number[]): void {
    if (!this.enabled || embedding.length === 0) {
      return;
    }
    const sizeBytes = key.length + embedding.length * 8 + 64;
    if (sizeBytes > this.maxSizeBytes) {
      return;
    }

    const existing = this.entries.get(key);
    if (existing) {
      this.delete(key);
    }

    while (this.currentSizeBytes + sizeBytes > this.maxSizeBytes && this.entries.size > 0) {
      const oldestKey = this.entries.keys().next().value as string;
      this.delete(oldestKey);
    }

    this.entries.set(key, {
      embedding: [...embedding],
      expiresAt: Date.now() + this.ttlMs,
      sizeBytes,
    });
    this.currentSizeBytes += sizeBytes;
  }

  private delete(key: string): void {
    const entry = this.entries.get(key);
    if (!entry) {
      return;
    }
    this.entries.delete(key);
    this.currentSizeBytes -= entry.sizeBytes;
    if (this.currentSizeBytes < 0) {
      this.currentSizeBytes = 0;
    }
  }
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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

function toInt(value: unknown): number | undefined {
  if (!isFiniteNumber(value)) {
    return undefined;
  }
  return Math.trunc(value);
}

function toPositiveInt(value: unknown): number | undefined {
  const parsed = toInt(value);
  if (parsed === undefined || parsed <= 0) {
    return undefined;
  }
  return parsed;
}

function toPositiveNumber(value: unknown): number | undefined {
  if (!isFiniteNumber(value) || value <= 0) {
    return undefined;
  }
  return value;
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
    if (!isRecord(raw)) {
      throw new Error(`pattern DB entry ${i} must be an object`);
    }
    const embedding = coerceEmbedding(raw.embedding);
    if (!embedding) {
      throw new Error(`pattern DB entry ${i} has invalid embedding values (must be finite numbers)`);
    }
    entries.push({
      id: String(raw.id ?? ""),
      category: String(raw.category ?? ""),
      stage: String(raw.stage ?? ""),
      label: String(raw.label ?? ""),
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

function parseLlmProviderFromUrl(url: string): SpiderSenseLLMProvider {
  const host = new URL(url).host.toLowerCase();
  return host.includes("anthropic") ? "anthropic" : "openai";
}

function parseRuntimeConfig(raw: SpiderSenseGuardConfig["async"]): SpiderSenseRuntimeConfig {
  const cfg = isRecord(raw) ? raw : {};
  const out: SpiderSenseRuntimeConfig = {
    timeoutMs: DEFAULT_EMBEDDING_TIMEOUT_MS,
    hasTimeout: false,
    cacheEnabled: true,
    cacheTtlMs: DEFAULT_CACHE_TTL_MS,
    cacheMaxSizeBytes: DEFAULT_CACHE_MAX_SIZE_BYTES,
    retry: {
      enabled: false,
      maxRetries: 0,
      initialBackoffMs: DEFAULT_RETRY_INITIAL_BACKOFF_MS,
      maxBackoffMs: DEFAULT_RETRY_MAX_BACKOFF_MS,
      multiplier: DEFAULT_RETRY_MULTIPLIER,
      honorRetryAfter: true,
      retryAfterCapMs: DEFAULT_RETRY_AFTER_CAP_MS,
      honorRateLimitReset: true,
      rateLimitResetGraceMs: DEFAULT_RATE_LIMIT_RESET_GRACE_MS,
    },
    circuitBreaker: null,
    onCircuitOpen: "deny",
  };

  const timeoutMs = toPositiveInt(cfg.timeout_ms);
  if (timeoutMs) {
    out.timeoutMs = timeoutMs;
    out.hasTimeout = true;
  }

  if (isRecord(cfg.cache)) {
    if (typeof cfg.cache.enabled === "boolean") {
      out.cacheEnabled = cfg.cache.enabled;
    }
    const ttlSeconds = toPositiveInt(cfg.cache.ttl_seconds);
    if (ttlSeconds) {
      out.cacheTtlMs = ttlSeconds * 1_000;
    }
    const maxSizeMb = toPositiveInt(cfg.cache.max_size_mb);
    if (maxSizeMb) {
      out.cacheMaxSizeBytes = maxSizeMb * 1024 * 1024;
    }
  }

  if (isRecord(cfg.retry)) {
    out.retry.enabled = true;
    out.retry.maxRetries = 2;
    const retries = toInt(cfg.retry.max_retries);
    if (retries !== undefined && retries >= 0) {
      out.retry.maxRetries = retries;
    }
    const initialBackoffMs = toPositiveInt(cfg.retry.initial_backoff_ms);
    if (initialBackoffMs) {
      out.retry.initialBackoffMs = initialBackoffMs;
    }
    const maxBackoffMs = toPositiveInt(cfg.retry.max_backoff_ms);
    if (maxBackoffMs) {
      out.retry.maxBackoffMs = maxBackoffMs;
    }
    const multiplier = toPositiveNumber(cfg.retry.multiplier);
    if (multiplier !== undefined && multiplier >= 1) {
      out.retry.multiplier = multiplier;
    }
    if (typeof cfg.retry.honor_retry_after === "boolean") {
      out.retry.honorRetryAfter = cfg.retry.honor_retry_after;
    }
    const retryAfterCapMs = toPositiveInt(cfg.retry.retry_after_cap_ms);
    if (retryAfterCapMs) {
      out.retry.retryAfterCapMs = retryAfterCapMs;
    }
    if (typeof cfg.retry.honor_rate_limit_reset === "boolean") {
      out.retry.honorRateLimitReset = cfg.retry.honor_rate_limit_reset;
    }
    const resetGraceMs = toInt(cfg.retry.rate_limit_reset_grace_ms);
    if (resetGraceMs !== undefined && resetGraceMs >= 0) {
      out.retry.rateLimitResetGraceMs = resetGraceMs;
    }
    if (out.retry.maxBackoffMs < out.retry.initialBackoffMs) {
      out.retry.maxBackoffMs = out.retry.initialBackoffMs;
    }
    if (out.retry.retryAfterCapMs <= 0) {
      out.retry.retryAfterCapMs = out.retry.maxBackoffMs;
    }
  }

  if (isRecord(cfg.circuit_breaker)) {
    const circuit: SpiderSenseCircuitRuntimeConfig = {
      failureThreshold: 5,
      resetTimeoutMs: 30_000,
      successThreshold: 2,
    };
    const failureThreshold = toPositiveInt(cfg.circuit_breaker.failure_threshold);
    if (failureThreshold) {
      circuit.failureThreshold = failureThreshold;
    }
    const resetTimeoutMs = toPositiveInt(cfg.circuit_breaker.reset_timeout_ms);
    if (resetTimeoutMs) {
      circuit.resetTimeoutMs = resetTimeoutMs;
    }
    const successThreshold = toPositiveInt(cfg.circuit_breaker.success_threshold);
    if (successThreshold) {
      circuit.successThreshold = successThreshold;
    }
    const mode = typeof cfg.circuit_breaker.on_open === "string"
      ? cfg.circuit_breaker.on_open.trim().toLowerCase()
      : "";
    switch (mode) {
      case "":
      case "deny":
        out.onCircuitOpen = "deny";
        break;
      case "warn":
        out.onCircuitOpen = "warn";
        break;
      case "allow":
        out.onCircuitOpen = "allow";
        break;
      default:
        throw new Error("spider_sense: async.circuit_breaker.on_open must be one of allow|warn|deny");
    }
    out.circuitBreaker = circuit;
  }

  return out;
}

function parseDeepPathConfig(
  config: SpiderSenseGuardConfig,
  runtime: SpiderSenseRuntimeConfig,
): SpiderSenseDeepPathConfig {
  const out: SpiderSenseDeepPathConfig = {
    enabled: false,
    apiUrl: "",
    apiKey: "",
    model: "",
    provider: "openai",
    timeoutMs: runtime.hasTimeout ? runtime.timeoutMs : DEFAULT_LLM_TIMEOUT_MS,
    failMode: "warn",
    templateId: "",
    templateVersion: "",
    templateRenderer: defaultPromptTemplate,
  };

  const url = (config.llmApiUrl ?? "").trim();
  const key = (config.llmApiKey ?? "").trim();
  const model = (config.llmModel ?? "").trim();
  const templateId = (config.llmPromptTemplateId ?? "").trim();
  const templateVersion = (config.llmPromptTemplateVersion ?? "").trim();
  const hasUrl = url.length > 0;
  const hasKey = key.length > 0;
  const hasModel = model.length > 0;
  const hasTemplateId = templateId.length > 0;
  const hasTemplateVersion = templateVersion.length > 0;
  if (hasTemplateId !== hasTemplateVersion) {
    throw new Error(
      "spider_sense: llm_prompt_template_id and llm_prompt_template_version must be set together",
    );
  }
  if (!hasUrl && !hasKey && !hasModel) {
    if (hasTemplateId || hasTemplateVersion) {
      throw new Error(
        "spider_sense: llm_prompt_template_id/version require llm_api_url and llm_api_key",
      );
    }
    return out;
  }
  if (!hasUrl || !hasKey) {
    throw new Error("spider_sense: llm_api_url and llm_api_key must both be set when deep path is configured");
  }

  const parsed = new URL(url);
  if (!parsed.protocol || !parsed.host) {
    throw new Error("spider_sense: llm_api_url must be absolute and include host");
  }

  let renderer = defaultPromptTemplate;
  if (hasTemplateId && hasTemplateVersion) {
    const templateKey = deepPathPromptTemplateKey(templateId, templateVersion);
    const selected = DEEP_PATH_PROMPT_TEMPLATES.get(templateKey);
    if (!selected) {
      throw new Error(
        `spider_sense: unsupported llm prompt template "${templateId}" version "${templateVersion}"`,
      );
    }
    renderer = selected;
    out.templateId = templateId;
    out.templateVersion = templateVersion;
  }

  out.enabled = true;
  out.apiUrl = url;
  out.apiKey = key;
  out.provider = parseLlmProviderFromUrl(url);
  out.templateRenderer = renderer;
  out.model = hasModel
    ? model
    : out.provider === "anthropic"
      ? DEFAULT_LLM_ANTHROPIC_MODEL
      : DEFAULT_LLM_OPENAI_MODEL;

  const timeoutMs = toPositiveInt(config.llmTimeoutMs);
  if (timeoutMs) {
    out.timeoutMs = timeoutMs;
  }

  const failMode = (config.llmFailMode ?? "").trim().toLowerCase();
  switch (failMode) {
    case "":
    case "warn":
      out.failMode = "warn";
      break;
    case "deny":
      out.failMode = "deny";
      break;
    case "allow":
      out.failMode = "allow";
      break;
    default:
      throw new Error("spider_sense: llm_fail_mode must be one of allow|warn|deny");
  }

  return out;
}

function normalizeHex(value: string): string {
  return value.trim().toLowerCase().replace(/^0x/, "");
}

function deriveKeyId(publicKeyHex: string): string {
  const normalized = normalizeHex(publicKeyHex);
  return toHex(sha256(normalized)).slice(0, 16);
}

function parseDateStrict(value: string, label: string): Date {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error(label);
  }
  return parsed;
}

function normalizeTrustedKey(entry: SpiderSenseTrustedKeyConfig): SpiderSenseTrustedKey {
  const publicKey = normalizeHex(entry.public_key ?? "");
  if (!publicKey) {
    throw new Error("trust store entry is missing public_key");
  }
  if (!/^[0-9a-f]+$/.test(publicKey) || publicKey.length % 2 !== 0) {
    throw new Error("invalid trusted public_key");
  }
  const keyBytes = fromHex(publicKey);
  if (keyBytes.length !== 32) {
    throw new Error("invalid trusted public_key");
  }

  const derived = deriveKeyId(publicKey);
  const keyIdRaw = (entry.key_id ?? "").trim();
  const keyId = keyIdRaw ? normalizeHex(keyIdRaw) : derived;
  if (!keyId) {
    throw new Error("trust store entry is missing key_id");
  }

  const statusRaw = (entry.status ?? "").trim().toLowerCase();
  let status: SpiderSenseTrustedKeyStatus;
  if (statusRaw === "" || statusRaw === "active") {
    status = "active";
  } else if (statusRaw === "deprecated") {
    status = "deprecated";
  } else if (statusRaw === "revoked") {
    status = "revoked";
  } else {
    throw new Error(`unsupported trusted key status "${entry.status}"`);
  }

  const trusted: SpiderSenseTrustedKey = { keyId, publicKey, status };
  if (entry.not_before) {
    trusted.notBefore = parseDateStrict(entry.not_before, `invalid not_before for key_id "${keyId}"`);
  }
  if (entry.not_after) {
    trusted.notAfter = parseDateStrict(entry.not_after, `invalid not_after for key_id "${keyId}"`);
  }
  if (trusted.notBefore && trusted.notAfter && trusted.notAfter.getTime() < trusted.notBefore.getTime()) {
    throw new Error(`invalid trusted key window for key_id "${keyId}"`);
  }
  return trusted;
}

async function parseTrustStoreFile(path: string): Promise<SpiderSenseTrustedKeyConfig[]> {
  const raw = await readFile(path, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`read trust store "${path}": ${err instanceof Error ? err.message : String(err)}`);
  }
  if (Array.isArray(parsed)) {
    return parsed as SpiderSenseTrustedKeyConfig[];
  }
  if (isRecord(parsed) && Array.isArray(parsed.keys)) {
    return parsed.keys as SpiderSenseTrustedKeyConfig[];
  }
  throw new Error("trust store must be a JSON array or object with keys[]");
}

function extractJSONObject(raw: string): string | null {
  const start = raw.indexOf("{");
  if (start < 0) {
    return null;
  }
  let depth = 0;
  for (let i = start; i < raw.length; i += 1) {
    const char = raw[i];
    if (char === "{") {
      depth += 1;
    } else if (char === "}") {
      depth -= 1;
      if (depth === 0) {
        return raw.slice(start, i + 1);
      }
    }
  }
  return null;
}

function deepPathPromptTemplateKey(id: string, version: string): string {
  return `${id.trim().toLowerCase()}@${version.trim()}`;
}

function defaultPromptTemplate(actionText: string): string {
  return [
    "You are a security classifier. Classify the AI-agent action below and return JSON only.",
    "Allowed verdicts: allow, warn, deny.",
    'JSON schema: {"verdict":"allow|warn|deny","reason":"..."}',
    "",
    "Action:",
    actionText,
  ].join("\n").trim();
}

const DEEP_PATH_PROMPT_TEMPLATES = new Map<string, (actionText: string) => string>([
  [deepPathPromptTemplateKey(DEFAULT_PROMPT_TEMPLATE_ID, DEFAULT_PROMPT_TEMPLATE_VERSION), defaultPromptTemplate],
]);

function parseRetryAfterMs(raw: string, nowMs: number): number | null {
  const value = raw.trim();
  if (!value) {
    return null;
  }
  const seconds = Number.parseFloat(value);
  if (Number.isFinite(seconds)) {
    if (seconds <= 0) {
      return null;
    }
    return Math.floor(seconds * 1_000);
  }
  const absolute = Date.parse(value);
  if (!Number.isFinite(absolute)) {
    return null;
  }
  const delta = absolute - nowMs;
  return delta > 0 ? delta : null;
}

function rateLimitValueToDelayMs(rawValue: number, nowMs: number, graceMs: number): number | null {
  if (!Number.isFinite(rawValue) || rawValue <= 0) {
    return null;
  }
  if (rawValue >= 1e12) {
    const delay = Math.floor(rawValue - nowMs + graceMs);
    return delay > 0 ? delay : null;
  }
  if (rawValue >= 1e9) {
    const delay = Math.floor(rawValue * 1_000 - nowMs + graceMs);
    return delay > 0 ? delay : null;
  }
  return Math.floor(rawValue * 1_000 + graceMs);
}

function parseRateLimitResetMs(raw: string, nowMs: number, graceMs: number): number | null {
  const value = raw.trim();
  if (!value) {
    return null;
  }
  const numeric = Number.parseFloat(value);
  if (Number.isFinite(numeric)) {
    return rateLimitValueToDelayMs(numeric, nowMs, graceMs);
  }
  const absolute = Date.parse(value);
  if (!Number.isFinite(absolute)) {
    return null;
  }
  const delta = Math.floor(absolute - nowMs + graceMs);
  return delta > 0 ? delta : null;
}

function headersRetryDelayMs(
  headers: Headers,
  retry: SpiderSenseRetryRuntimeConfig,
): number | null {
  const nowMs = Date.now();
  let best: number | null = null;
  const consider = (value: number | null) => {
    if (value === null) {
      return;
    }
    if (best === null || value > best) {
      best = value;
    }
  };

  if (retry.honorRetryAfter) {
    consider(parseRetryAfterMs(headers.get("Retry-After") ?? "", nowMs));
  }
  if (retry.honorRateLimitReset) {
    for (const key of ["RateLimit-Reset", "X-RateLimit-Reset", "X-Rate-Limit-Reset", "x-ratelimit-reset-requests"]) {
      consider(
        parseRateLimitResetMs(
          headers.get(key) ?? "",
          nowMs,
          retry.rateLimitResetGraceMs,
        ),
      );
    }
  }
  if (best !== null && retry.retryAfterCapMs > 0) {
    return Math.min(best, retry.retryAfterCapMs);
  }
  return best;
}

function resolveProviderRetryDelayMs(
  fallbackMs: number,
  err: SpiderSenseProviderError | null,
  retry: SpiderSenseRetryRuntimeConfig,
): number {
  let delay = fallbackMs;
  if (err?.retryAfterMs !== undefined && err.retryAfterMs > 0) {
    const hint = retry.retryAfterCapMs > 0
      ? Math.min(err.retryAfterMs, retry.retryAfterCapMs)
      : err.retryAfterMs;
    if (hint > delay) {
      delay = hint;
    }
  }
  return delay > 0 ? delay : fallbackMs;
}

function resolvePathRelative(baseFile: string, rawPath: string): string {
  const trimmed = rawPath.trim();
  if (!trimmed || trimmed.startsWith("builtin:")) {
    return trimmed;
  }
  if (isAbsolute(trimmed)) {
    return trimmed;
  }
  return resolvePath(dirname(baseFile), trimmed);
}

function trustedKeysDigest(keys: SpiderSenseTrustedKeyConfig[]): string {
  if (keys.length === 0) {
    return toHex(sha256(new Uint8Array()));
  }
  const parts = keys.map((entry) => {
    const keyId = normalizeHex(entry.key_id ?? "");
    const publicKey = normalizeHex(entry.public_key ?? "");
    const status = (entry.status ?? "").trim().toLowerCase();
    const notBefore = (entry.not_before ?? "").trim();
    const notAfter = (entry.not_after ?? "").trim();
    return `${keyId}|${publicKey}|${status}|${notBefore}|${notAfter}`;
  });
  parts.sort();
  return toHex(sha256(parts.join(";")));
}

function manifestSigningMessage(manifest: SpiderSensePatternManifest): Uint8Array {
  const payload = [
    "spider_sense_manifest:v1",
    String(manifest.pattern_db_path ?? "").trim(),
    String(manifest.pattern_db_version ?? "").trim(),
    normalizeHex(String(manifest.pattern_db_checksum ?? "")),
    normalizeHex(String(manifest.pattern_db_signature ?? "")),
    normalizeHex(String(manifest.pattern_db_signature_key_id ?? "")),
    normalizeHex(String(manifest.pattern_db_public_key ?? "")),
    String(manifest.pattern_db_trust_store_path ?? "").trim(),
    trustedKeysDigest(Array.isArray(manifest.pattern_db_trusted_keys) ? manifest.pattern_db_trusted_keys : []),
    String(manifest.not_before ?? "").trim(),
    String(manifest.not_after ?? "").trim(),
  ].join(":");
  return new TextEncoder().encode(payload);
}

function isRetryableHttpStatus(status: number): boolean {
  return status === 408 || status === 429 || (status >= 500 && status <= 599);
}

function isRetryableFetchError(err: unknown): boolean {
  if (err instanceof SpiderSenseProviderError) {
    return err.retryable;
  }
  if (!(err instanceof Error)) {
    return false;
  }
  if (err.name === "AbortError") {
    return true;
  }
  const message = err.message.toLowerCase();
  return message.includes("network") || message.includes("timeout") || message.includes("fetch");
}

function normalizeProviderUrl(rawUrl: string): string {
  const trimmed = rawUrl.trim();
  try {
    const parsed = new URL(trimmed);
    parsed.protocol = parsed.protocol.toLowerCase();
    parsed.hostname = parsed.hostname.toLowerCase();
    parsed.search = "";
    parsed.hash = "";
    const pathValue = parsed.pathname.trim();
    parsed.pathname = pathValue ? `/${pathValue.replace(/^\/+|\/+$/g, "")}` : "/";
    return parsed.toString();
  } catch {
    return trimmed.toLowerCase();
  }
}

function embeddingCacheKey(providerUrl: string, model: string, text: string): string {
  const payload = `v1|${normalizeProviderUrl(providerUrl)}|${model.trim()}|${text.trim()}`;
  return toHex(sha256(payload));
}

function verdictFromResult(result: GuardResult): SpiderSenseVerdict {
  if (!result.allowed) {
    return "deny";
  }
  if (result.severity === Severity.WARNING) {
    return "ambiguous";
  }
  return "allow";
}

function nextBackoffMs(current: number, retry: SpiderSenseRetryRuntimeConfig): number {
  return Math.min(Math.floor(current * retry.multiplier), retry.maxBackoffMs);
}

async function sleep(ms: number): Promise<void> {
  if (ms <= 0) {
    return;
  }
  await new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
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
  private readonly deepPathFetchFn: typeof fetch;

  private readonly runtimeConfig: SpiderSenseRuntimeConfig;
  private readonly embeddingCache: SpiderSenseEmbeddingCache;
  private readonly embeddingBreaker: SpiderSenseCircuitBreaker | null;
  private readonly llmBreaker: SpiderSenseCircuitBreaker | null;

  private readonly deepPath: SpiderSenseDeepPathConfig;

  private readonly metricsHook?: SpiderSenseMetricsHook;
  private allowCount = 0;
  private ambiguousCount = 0;
  private denyCount = 0;
  private totalCount = 0;

  private patternDb: PatternDb | null = null;
  private dbSource = "";
  private dbVersion = "";
  private trustKeyId = "";
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

    this.runtimeConfig = parseRuntimeConfig(config.async);
    this.deepPath = parseDeepPathConfig(config, this.runtimeConfig);

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

    const explicitEmbeddingTimeout = toPositiveInt(config.embeddingTimeoutMs);
    this.embeddingTimeoutMs = explicitEmbeddingTimeout
      ?? (this.runtimeConfig.hasTimeout ? this.runtimeConfig.timeoutMs : DEFAULT_EMBEDDING_TIMEOUT_MS);
    this.fetchFn = config.fetchFn ?? fetch;
    this.deepPathFetchFn = config.deepPathFetchFn ?? this.fetchFn;
    this.metricsHook = config.metricsHook;

    this.embeddingCache = new SpiderSenseEmbeddingCache(
      this.runtimeConfig.cacheEnabled,
      this.runtimeConfig.cacheTtlMs,
      this.runtimeConfig.cacheMaxSizeBytes,
    );
    this.embeddingBreaker = this.runtimeConfig.circuitBreaker
      ? new SpiderSenseCircuitBreaker(this.runtimeConfig.circuitBreaker)
      : null;
    this.llmBreaker = this.runtimeConfig.circuitBreaker
      ? new SpiderSenseCircuitBreaker(this.runtimeConfig.circuitBreaker)
      : null;

    if (config.patterns) {
      if (config.patterns.length === 0) {
        throw new Error("spider_sense: patterns must contain at least one entry when set");
      }
      this.patternDb = parsePatternDbJson(JSON.stringify(config.patterns));
      this.dbSource = "inline";
      this.dbVersion = "inline";
    } else if (config.patternDbManifestPath?.trim() || config.patternDbPath?.trim()) {
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
    this.trustKeyId = "";
    this.pendingPatternConfig = null;
    this.loadPromise = null;
  }

  handles(_action: GuardAction): boolean {
    return true;
  }

  async check(action: GuardAction, context: GuardContext): Promise<GuardResult> {
    const runtime: SpiderSenseMetricRuntime = {
      trustKeyId: this.trustKeyId,
    };

    if (!this.enabled) {
      const result = GuardResult.allow(this.name);
      this.emitMetrics("allow", 0, result.severity, false, "disabled", undefined, runtime);
      return result;
    }

    await this.ensurePatternDbLoaded();
    runtime.trustKeyId = this.trustKeyId;
    if (!this.patternDb) {
      const details = {
        analysis: "configuration",
        error: "pattern DB missing while spider_sense is enabled",
        db_source: this.dbSource,
        db_version: this.dbVersion,
      };
      const result = GuardResult.block(
        this.name,
        Severity.ERROR,
        "Spider-Sense pattern DB missing (fail-closed)",
      ).withDetails(details);
      this.emitMetrics("deny", 0, result.severity, false, "pattern_db_missing", undefined, runtime);
      return result;
    }

    let embedding = this.extractEmbedding(action.customData);
    let embeddingSource: "action" | "provider" = "action";

    if (!embedding) {
      if (!this.embeddingEnabled) {
        const result = GuardResult.allow(this.name);
        this.emitMetrics("allow", 0, result.severity, false, "embedding_missing", undefined, runtime);
        return result;
      }

      const text = this.actionToText(action);
      const cacheKey = embeddingCacheKey(this.embeddingApiUrl, this.embeddingModel, text);
      const cached = this.embeddingCache.get(cacheKey);
      if (cached) {
        embedding = cached;
        embeddingSource = "provider";
        runtime.cacheHit = true;
        runtime.circuitState = this.embeddingBreaker?.currentState() ?? "closed";
      } else {
        const providerResult = await this.fetchEmbeddingWithRetry(text, context);
        runtime.providerAttempts = providerResult.stats.attempts;
        runtime.retryCount = providerResult.stats.retries;
        runtime.circuitState = providerResult.stats.circuitState;
        runtime.embeddingLatencyMs = providerResult.stats.latencyMs;
        if (providerResult.error || !providerResult.embedding) {
          const err = providerResult.error ?? new Error("embedding request failed");
          if (providerResult.stats.circuitOpened) {
            const result = this.circuitOpenProviderResult(err);
            this.emitMetrics(
              verdictFromResult(result),
              0,
              result.severity,
              false,
              "provider_circuit_open",
              "provider",
              runtime,
            );
            return result;
          }
          const details = {
            analysis: "provider",
            error: err.message,
            db_source: this.dbSource,
            db_version: this.dbVersion,
            embedding_from: "provider",
          };
          const result = GuardResult.block(
            this.name,
            Severity.ERROR,
            "Spider-Sense embedding provider error (fail-closed)",
          ).withDetails(details);
          this.emitMetrics("deny", 0, result.severity, true, "provider_error", "provider", runtime);
          return result;
        }
        embedding = providerResult.embedding;
        embeddingSource = "provider";
        this.embeddingCache.set(cacheKey, embedding);
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
      this.emitMetrics("deny", 0, result.severity, true, "dimension_mismatch", embeddingSource, runtime);
      return result;
    }

    const screening = this.screen(embedding);
    const details = this.resultDetails(screening, embeddingSource);

    if (screening.verdict === "ambiguous" && this.deepPath.enabled) {
      const deepPathResult = await this.runDeepPath(this.actionToText(action), screening, embeddingSource, context);
      runtime.deepPathUsed = deepPathResult.stats.used;
      runtime.deepPathVerdict = deepPathResult.stats.verdict;
      runtime.deepPathLatencyMs = deepPathResult.stats.latencyMs;
      runtime.retryCount = (runtime.retryCount ?? 0) + deepPathResult.stats.retries;
      if (!runtime.circuitState) {
        runtime.circuitState = deepPathResult.stats.circuitState;
      }

      if (deepPathResult.error || !deepPathResult.result) {
        const fallback = this.deepPathFailureResult(
          deepPathResult.error ?? new Error("deep path failed"),
          screening,
          embeddingSource,
          details,
        );
        this.emitMetrics(
          verdictFromResult(fallback),
          screening.topScore,
          fallback.severity,
          true,
          "deep_path_error",
          embeddingSource,
          runtime,
        );
        return fallback;
      }

      this.emitMetrics(
        verdictFromResult(deepPathResult.result),
        screening.topScore,
        deepPathResult.result.severity,
        true,
        undefined,
        embeddingSource,
        runtime,
      );
      return deepPathResult.result;
    }

    if (screening.verdict === "deny") {
      const topLabel = screening.topMatches[0]?.entry.label ?? "";
      const result = GuardResult.block(
        this.name,
        Severity.ERROR,
        `Spider-Sense threat detected (score=${screening.topScore.toFixed(3)}, label="${topLabel}")`,
      ).withDetails(details);
      this.emitMetrics("deny", screening.topScore, result.severity, true, undefined, embeddingSource, runtime);
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
        runtime,
      );
      return result;
    }

    const result = GuardResult.allow(this.name).withDetails(details);
    this.emitMetrics("allow", screening.topScore, result.severity, true, undefined, embeddingSource, runtime);
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
      const configForLoad = { ...this.pendingPatternConfig };
      this.pendingPatternConfig = null;
      this.loadPromise = (async () => {
        try {
          await this.loadPatternDbFromPath(configForLoad);
        } catch (err) {
          // Preserve retryability after transient load failures.
          this.pendingPatternConfig = { ...configForLoad };
          throw err;
        } finally {
          this.loadPromise = null;
        }
      })();
    }
    if (!this.loadPromise) {
      return;
    }
    await this.loadPromise;
  }

  private async loadPatternDbFromPath(config: SpiderSenseGuardConfig): Promise<void> {
    let path = (config.patternDbPath ?? "").trim();
    let version = (config.patternDbVersion ?? "").trim();
    let checksum = (config.patternDbChecksum ?? "").trim();
    let signature = (config.patternDbSignature ?? "").trim();
    let publicKey = (config.patternDbPublicKey ?? "").trim();
    let signatureKeyId = normalizeHex(config.patternDbSignatureKeyId ?? "");
    let trustStorePath = (config.patternDbTrustStorePath ?? "").trim();
    let trustedKeys = Array.isArray(config.patternDbTrustedKeys) ? config.patternDbTrustedKeys : [];

    const manifestPath = (config.patternDbManifestPath ?? "").trim();
    if (manifestPath) {
      const resolved = await this.resolvePatternDbFromManifest(config, manifestPath);
      path = resolved.path;
      version = resolved.version;
      checksum = resolved.checksum;
      signature = resolved.signature;
      publicKey = resolved.publicKey;
      signatureKeyId = resolved.signatureKeyId;
      trustStorePath = resolved.trustStorePath;
      trustedKeys = resolved.trustedKeys;
    }

    if (!path) {
      throw new Error("spider_sense: pattern_db_path cannot be empty");
    }

    if (!version || !checksum) {
      throw new Error(
        "spider_sense: pattern_db_version and pattern_db_checksum are required when pattern_db_path is set",
      );
    }

    const useTrustStore = signatureKeyId.length > 0 || trustStorePath.length > 0 || trustedKeys.length > 0;
    const useLegacyPair = signature.length > 0 && publicKey.length > 0;

    if (useTrustStore && publicKey.length > 0) {
      throw new Error("spider_sense: pattern_db_public_key cannot be combined with trust-store based verification");
    }
    if (useTrustStore) {
      if (!signature) {
        throw new Error("spider_sense: pattern_db_signature is required when trust-store fields are set");
      }
      if (!signatureKeyId) {
        throw new Error("spider_sense: pattern_db_signature_key_id is required when trust-store fields are set");
      }
    } else if ((signature.length > 0) !== (publicKey.length > 0)) {
      throw new Error(
        "spider_sense: pattern_db_signature and pattern_db_public_key must either both be set or both be omitted",
      );
    }

    let bytes: Uint8Array;
    let source = path;
    if (path === "builtin:s2bench-v1") {
      const builtinUrl = new URL("./patterns/s2bench-v1.json", import.meta.url);
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

    const message = new TextEncoder().encode(`spider_sense_db:v1:${version}:${normalizedExpected}`);
    let trustKeyId = "";
    if (useLegacyPair) {
      const signatureBytes = this.parseHexBytes(signature, "spider_sense: invalid pattern DB signature");
      const publicKeyBytes = this.parseHexBytes(publicKey, "spider_sense: invalid pattern DB public key");
      const valid = await verifySignature(message, signatureBytes, publicKeyBytes);
      if (!valid) {
        throw new Error("spider_sense: pattern DB signature verification failed");
      }
    } else if (useTrustStore) {
      const trustStore = await this.loadTrustStore(trustStorePath, trustedKeys);
      const key = this.selectTrustedKey(trustStore, signatureKeyId);
      const signatureBytes = this.parseHexBytes(signature, "spider_sense: invalid pattern DB signature");
      const valid = await verifySignature(message, signatureBytes, fromHex(key.publicKey));
      if (!valid) {
        throw new Error(`spider_sense: pattern DB signature verification failed for key_id "${key.keyId}"`);
      }
      trustKeyId = key.keyId;
    }

    const db = parsePatternDbJson(new TextDecoder().decode(bytes));
    this.patternDb = db;
    this.dbSource = source;
    this.dbVersion = version;
    this.trustKeyId = trustKeyId;
  }

  private async resolvePatternDbFromManifest(
    config: SpiderSenseGuardConfig,
    manifestPath: string,
  ): Promise<{
      path: string;
      version: string;
      checksum: string;
      signature: string;
      publicKey: string;
      signatureKeyId: string;
      trustStorePath: string;
      trustedKeys: SpiderSenseTrustedKeyConfig[];
    }> {
    const raw = await readFile(manifestPath, "utf8");
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new Error(
        `spider_sense: parse pattern DB manifest "${manifestPath}": ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (!isRecord(parsed)) {
      throw new Error("spider_sense: pattern DB manifest must be a JSON object");
    }
    const manifest = parsed as SpiderSensePatternManifest;

    const manifestRootsPathRaw = (config.patternDbManifestTrustStorePath ?? "").trim();
    const manifestRootsPath = manifestRootsPathRaw
      ? resolvePathRelative(manifestPath, manifestRootsPathRaw)
      : "";
    const manifestRootsInline = Array.isArray(config.patternDbManifestTrustedKeys)
      ? config.patternDbManifestTrustedKeys
      : [];
    if (!manifestRootsPath && manifestRootsInline.length === 0) {
      throw new Error(
        "spider_sense: pattern_db_manifest_path requires pattern_db_manifest_trust_store_path or pattern_db_manifest_trusted_keys",
      );
    }

    const notBeforeRaw = typeof manifest.not_before === "string" ? manifest.not_before.trim() : "";
    if (notBeforeRaw) {
      const notBefore = Date.parse(notBeforeRaw);
      if (!Number.isFinite(notBefore)) {
        throw new Error("spider_sense: invalid pattern DB manifest not_before");
      }
      if (Date.now() < notBefore) {
        throw new Error("spider_sense: pattern DB manifest not yet valid");
      }
    }
    const notAfterRaw = typeof manifest.not_after === "string" ? manifest.not_after.trim() : "";
    if (notAfterRaw) {
      const notAfter = Date.parse(notAfterRaw);
      if (!Number.isFinite(notAfter)) {
        throw new Error("spider_sense: invalid pattern DB manifest not_after");
      }
      if (Date.now() > notAfter) {
        throw new Error("spider_sense: pattern DB manifest expired");
      }
    }

    const manifestSignature = normalizeHex(typeof manifest.manifest_signature === "string" ? manifest.manifest_signature : "");
    const manifestSignatureKeyId = normalizeHex(
      typeof manifest.manifest_signature_key_id === "string" ? manifest.manifest_signature_key_id : "",
    );
    if (!manifestSignature) {
      throw new Error("spider_sense: pattern DB manifest missing manifest_signature");
    }
    if (!manifestSignatureKeyId) {
      throw new Error("spider_sense: pattern DB manifest missing manifest_signature_key_id");
    }
    const manifestRootStore = await this.loadTrustStore(manifestRootsPath, manifestRootsInline);
    const manifestRootKey = this.selectTrustedKey(manifestRootStore, manifestSignatureKeyId);
    const manifestSignatureBytes = this.parseHexBytes(
      manifestSignature,
      "spider_sense: invalid pattern DB manifest signature",
    );
    const manifestValid = await verifySignature(
      manifestSigningMessage(manifest),
      manifestSignatureBytes,
      fromHex(manifestRootKey.publicKey),
    );
    if (!manifestValid) {
      throw new Error(
        `spider_sense: pattern DB manifest signature verification failed for key_id "${manifestRootKey.keyId}"`,
      );
    }

    const pathRaw = typeof manifest.pattern_db_path === "string" ? manifest.pattern_db_path.trim() : "";
    if (!pathRaw) {
      throw new Error("spider_sense: pattern DB manifest missing pattern_db_path");
    }
    const version = typeof manifest.pattern_db_version === "string" ? manifest.pattern_db_version.trim() : "";
    const checksum = typeof manifest.pattern_db_checksum === "string" ? manifest.pattern_db_checksum.trim() : "";
    const signature = typeof manifest.pattern_db_signature === "string" ? manifest.pattern_db_signature.trim() : "";
    const publicKey = typeof manifest.pattern_db_public_key === "string" ? manifest.pattern_db_public_key.trim() : "";
    const signatureKeyId = normalizeHex(
      typeof manifest.pattern_db_signature_key_id === "string" ? manifest.pattern_db_signature_key_id : "",
    );
    const trustStorePathRaw = typeof manifest.pattern_db_trust_store_path === "string"
      ? manifest.pattern_db_trust_store_path.trim()
      : "";
    const trustStorePath = trustStorePathRaw ? resolvePathRelative(manifestPath, trustStorePathRaw) : "";

    const trustedKeyEntries = Array.isArray(manifest.pattern_db_trusted_keys)
      ? manifest.pattern_db_trusted_keys as unknown[]
      : [];
    const trustedKeys = trustedKeyEntries
      .filter((entry): entry is Record<string, unknown> => isRecord(entry))
      .map((entry) => ({
        key_id: typeof entry.key_id === "string" ? entry.key_id : undefined,
        public_key: typeof entry.public_key === "string" ? entry.public_key : "",
        not_before: typeof entry.not_before === "string" ? entry.not_before : undefined,
        not_after: typeof entry.not_after === "string" ? entry.not_after : undefined,
        status: typeof entry.status === "string" ? entry.status : undefined,
      }));

    return {
      path: resolvePathRelative(manifestPath, pathRaw),
      version,
      checksum,
      signature,
      publicKey,
      signatureKeyId,
      trustStorePath,
      trustedKeys,
    };
  }

  private parseHexBytes(value: string, label: string): Uint8Array {
    const normalized = normalizeHex(value);
    if (!/^[0-9a-f]+$/.test(normalized) || normalized.length % 2 !== 0) {
      throw new Error(label);
    }
    try {
      return fromHex(normalized);
    } catch {
      throw new Error(label);
    }
  }

  private async loadTrustStore(
    path: string,
    inline: SpiderSenseTrustedKeyConfig[],
  ): Promise<Map<string, SpiderSenseTrustedKey>> {
    const store = new Map<string, SpiderSenseTrustedKey>();
    const addEntries = (entries: SpiderSenseTrustedKeyConfig[]) => {
      for (const entry of entries) {
        const normalized = normalizeTrustedKey(entry);
        store.set(normalized.keyId, normalized);
      }
    };

    if (path) {
      const fileEntries = await parseTrustStoreFile(path);
      addEntries(fileEntries);
    }
    addEntries(inline);
    if (store.size === 0) {
      throw new Error("spider_sense: load trust store: trust store is empty");
    }
    return store;
  }

  private selectTrustedKey(
    trustStore: Map<string, SpiderSenseTrustedKey>,
    keyId: string,
  ): SpiderSenseTrustedKey {
    const normalizedKeyId = normalizeHex(keyId);
    const key = trustStore.get(normalizedKeyId);
    if (!key) {
      throw new Error(`spider_sense: pattern DB signature key_id "${normalizedKeyId}" not found in trust store`);
    }
    if (key.status === "revoked") {
      throw new Error(`spider_sense: pattern DB signature key_id "${normalizedKeyId}" is revoked`);
    }
    const now = Date.now();
    if (key.notBefore && now < key.notBefore.getTime()) {
      throw new Error(`spider_sense: pattern DB signature key_id "${normalizedKeyId}" is not yet valid`);
    }
    if (key.notAfter && now > key.notAfter.getTime()) {
      throw new Error(`spider_sense: pattern DB signature key_id "${normalizedKeyId}" is expired`);
    }
    return key;
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

  private async fetchEmbeddingWithRetry(
    text: string,
    _context: GuardContext,
  ): Promise<{ embedding: number[] | null; stats: SpiderSenseProviderStats; error?: Error }> {
    const stats: SpiderSenseProviderStats = {
      attempts: 0,
      retries: 0,
      circuitState: this.embeddingBreaker?.currentState() ?? "closed",
      latencyMs: 0,
      circuitOpened: false,
    };
    const circuit = this.embeddingBreaker;
    if (circuit) {
      const allowed = circuit.allow();
      stats.circuitState = allowed.state;
      if (!allowed.allowed) {
        stats.circuitOpened = true;
        return {
          embedding: null,
          stats,
          error: new Error("embedding provider circuit breaker open"),
        };
      }
    }

    const maxRetries = this.runtimeConfig.retry.enabled ? this.runtimeConfig.retry.maxRetries : 0;
    let backoffMs = this.runtimeConfig.retry.initialBackoffMs;
    const startedAt = Date.now();
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
      stats.attempts = attempt + 1;
      try {
        const embedding = await this.fetchEmbeddingOnce(text);
        circuit?.recordSuccess();
        stats.retries = attempt;
        stats.latencyMs = Date.now() - startedAt;
        stats.circuitState = this.embeddingBreaker?.currentState() ?? "closed";
        return { embedding, stats };
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        lastError = error;
        const retryable = isRetryableFetchError(error);
        if (attempt >= maxRetries || !retryable) {
          circuit?.recordFailure();
          stats.retries = attempt;
          stats.latencyMs = Date.now() - startedAt;
          stats.circuitState = this.embeddingBreaker?.currentState() ?? "closed";
          return { embedding: null, stats, error };
        }
        const providerError = error instanceof SpiderSenseProviderError ? error : null;
        const waitMs = resolveProviderRetryDelayMs(backoffMs, providerError, this.runtimeConfig.retry);
        await sleep(waitMs);
        backoffMs = nextBackoffMs(waitMs, this.runtimeConfig.retry);
      }
    }

    circuit?.recordFailure();
    stats.retries = maxRetries;
    stats.latencyMs = Date.now() - startedAt;
    stats.circuitState = this.embeddingBreaker?.currentState() ?? "closed";
    return { embedding: null, stats, error: lastError ?? new Error("embedding request failed") };
  }

  private async fetchEmbeddingOnce(text: string): Promise<number[]> {
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
    } catch (err) {
      throw new SpiderSenseProviderError(
        `embedding request failed: ${err instanceof Error ? err.message : String(err)}`,
        isRetryableFetchError(err),
      );
    } finally {
      clearTimeout(timeout);
    }

    const rawBody = await response.text();
    if (Buffer.byteLength(rawBody, "utf8") > MAX_EMBEDDING_RESPONSE_BYTES) {
      throw new SpiderSenseProviderError("embedding API response exceeds size limit", false);
    }
    if (!response.ok) {
      const retryAfterMs = headersRetryDelayMs(response.headers, this.runtimeConfig.retry);
      throw new SpiderSenseProviderError(
        `embedding API returned HTTP ${response.status}: ${rawBody.trim() || "empty response body"}`,
        isRetryableHttpStatus(response.status),
        response.status,
        retryAfterMs ?? undefined,
      );
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(rawBody);
    } catch (err) {
      throw new SpiderSenseProviderError(
        `parse embedding response: ${err instanceof Error ? err.message : String(err)}`,
        false,
      );
    }

    let embedding: number[] | null = null;
    if (this.embeddingProvider === "cohere") {
      if (isRecord(parsed)) {
        const embeddings = parsed.embeddings;
        if (Array.isArray(embeddings) && embeddings.length > 0) {
          embedding = coerceEmbedding(embeddings[0]);
        } else if (isRecord(embeddings)) {
          const floatEmbeddings = embeddings.float;
          if (Array.isArray(floatEmbeddings) && floatEmbeddings.length > 0) {
            embedding = coerceEmbedding(floatEmbeddings[0]);
          }
        }
      }
    } else if (isRecord(parsed) && Array.isArray(parsed.data) && parsed.data.length > 0) {
      const first = parsed.data[0];
      if (isRecord(first)) {
        embedding = coerceEmbedding(first.embedding);
      }
    }

    if (!embedding || embedding.length === 0) {
      throw new SpiderSenseProviderError("embedding API returned an empty or invalid embedding", false);
    }
    return embedding;
  }

  private async runDeepPath(
    text: string,
    fast: ScreeningResult,
    embeddingSource: "action" | "provider",
    _context: GuardContext,
  ): Promise<{ result: GuardResult | null; stats: SpiderSenseDeepPathStats; error?: Error }> {
    const stats: SpiderSenseDeepPathStats = {
      used: true,
      attempts: 0,
      retries: 0,
      circuitState: this.llmBreaker?.currentState() ?? "closed",
      latencyMs: 0,
      verdict: "",
    };
    const circuit = this.llmBreaker;
    if (circuit) {
      const allowed = circuit.allow();
      stats.circuitState = allowed.state;
      if (!allowed.allowed) {
        return {
          result: null,
          stats,
          error: new Error("deep path circuit breaker open"),
        };
      }
    }

    const maxRetries = this.runtimeConfig.retry.enabled ? this.runtimeConfig.retry.maxRetries : 0;
    let backoffMs = this.runtimeConfig.retry.initialBackoffMs;
    const startedAt = Date.now();
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
      stats.attempts = attempt + 1;
      try {
        const verdict = await this.deepPathVerdictOnce(text);
        circuit?.recordSuccess();
        stats.retries = attempt;
        stats.latencyMs = Date.now() - startedAt;
        stats.circuitState = this.llmBreaker?.currentState() ?? "closed";
        stats.verdict = verdict.verdict;
        return {
          result: this.deepPathDecision(verdict, fast, embeddingSource),
          stats,
        };
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        lastError = error;
        const retryable = isRetryableFetchError(error);
        if (attempt >= maxRetries || !retryable) {
          circuit?.recordFailure();
          stats.retries = attempt;
          stats.latencyMs = Date.now() - startedAt;
          stats.circuitState = this.llmBreaker?.currentState() ?? "closed";
          return { result: null, stats, error };
        }
        const providerError = error instanceof SpiderSenseProviderError ? error : null;
        const waitMs = resolveProviderRetryDelayMs(backoffMs, providerError, this.runtimeConfig.retry);
        await sleep(waitMs);
        backoffMs = nextBackoffMs(waitMs, this.runtimeConfig.retry);
      }
    }

    circuit?.recordFailure();
    stats.retries = maxRetries;
    stats.latencyMs = Date.now() - startedAt;
    stats.circuitState = this.llmBreaker?.currentState() ?? "closed";
    return { result: null, stats, error: lastError ?? new Error("deep-path request failed") };
  }

  private async deepPathVerdictOnce(text: string): Promise<SpiderSenseLLMVerdict> {
    const prompt = this.deepPathPrompt(text);
    const request = this.deepPathRequestMaterial(prompt);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.deepPath.timeoutMs);
    let response: Response;
    try {
      response = await this.deepPathFetchFn(this.deepPath.apiUrl, {
        method: "POST",
        headers: request.headers,
        body: JSON.stringify(request.body),
        signal: controller.signal,
      });
    } catch (err) {
      throw new SpiderSenseProviderError(
        `deep-path request failed: ${err instanceof Error ? err.message : String(err)}`,
        isRetryableFetchError(err),
      );
    } finally {
      clearTimeout(timeout);
    }

    const rawBody = await response.text();
    if (Buffer.byteLength(rawBody, "utf8") > MAX_EMBEDDING_RESPONSE_BYTES) {
      throw new SpiderSenseProviderError("deep-path response exceeds size limit", false);
    }
    if (!response.ok) {
      const retryAfterMs = headersRetryDelayMs(response.headers, this.runtimeConfig.retry);
      throw new SpiderSenseProviderError(
        `deep-path API returned HTTP ${response.status}: ${rawBody.trim() || "empty response body"}`,
        isRetryableHttpStatus(response.status),
        response.status,
        retryAfterMs ?? undefined,
      );
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(rawBody);
    } catch (err) {
      throw new SpiderSenseProviderError(
        `parse deep-path response: ${err instanceof Error ? err.message : String(err)}`,
        false,
      );
    }

    const content = this.deepPathContent(parsed);
    return this.parseDeepPathVerdict(content);
  }

  private deepPathPrompt(text: string): string {
    return this.deepPath.templateRenderer(text);
  }

  private deepPathRequestMaterial(prompt: string): { body: Record<string, unknown>; headers: Record<string, string> } {
    if (this.deepPath.provider === "anthropic") {
      return {
        body: {
          model: this.deepPath.model,
          max_tokens: 256,
          messages: [{ role: "user", content: prompt }],
        },
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          "x-api-key": this.deepPath.apiKey,
          "anthropic-version": "2023-06-01",
        },
      };
    }
    return {
      body: {
        model: this.deepPath.model,
        max_tokens: 256,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: "Return JSON only." },
          { role: "user", content: prompt },
        ],
      },
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        authorization: `Bearer ${this.deepPath.apiKey}`,
      },
    };
  }

  private deepPathContent(payload: unknown): string {
    if (!isRecord(payload)) {
      throw new SpiderSenseProviderError("parse deep-path response: invalid JSON payload", false);
    }
    if (this.deepPath.provider === "anthropic") {
      if (!Array.isArray(payload.content) || payload.content.length === 0) {
        throw new SpiderSenseProviderError("parse deep-path response: missing content[0].text", false);
      }
      const first = payload.content[0];
      if (!isRecord(first) || typeof first.text !== "string") {
        throw new SpiderSenseProviderError("parse deep-path response: missing content[0].text", false);
      }
      return first.text;
    }
    if (!Array.isArray(payload.choices) || payload.choices.length === 0) {
      throw new SpiderSenseProviderError("parse deep-path response: missing choices[0].message.content", false);
    }
    const choice = payload.choices[0];
    if (!isRecord(choice) || !isRecord(choice.message) || typeof choice.message.content !== "string") {
      throw new SpiderSenseProviderError("parse deep-path response: missing choices[0].message.content", false);
    }
    return choice.message.content;
  }

  private parseDeepPathVerdict(content: string): SpiderSenseLLMVerdict {
    const raw = content.trim();
    if (!raw) {
      throw new SpiderSenseProviderError("parse deep-path verdict: empty response", false);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      const extracted = extractJSONObject(raw);
      if (!extracted) {
        throw new SpiderSenseProviderError(
          `parse deep-path verdict: ${err instanceof Error ? err.message : String(err)}`,
          false,
        );
      }
      parsed = JSON.parse(extracted);
    }

    const verdictRaw = isRecord(parsed) && typeof parsed.verdict === "string" ? parsed.verdict : "";
    const reasonRaw = isRecord(parsed) && typeof parsed.reason === "string" ? parsed.reason : "";
    let verdict = verdictRaw.trim().toLowerCase();
    let reason = reasonRaw.trim();
    if (verdict !== "allow" && verdict !== "warn" && verdict !== "deny") {
      if (!verdict) {
        verdict = "warn";
      } else {
        reason = `${reason}; unknown verdict ${verdict}`.trim();
        verdict = "warn";
      }
    }
    return { verdict, reason };
  }

  private deepPathDecision(
    verdict: SpiderSenseLLMVerdict,
    fast: ScreeningResult,
    embeddingSource: "action" | "provider",
  ): GuardResult {
    const matches = fast.topMatches.map((match) => ({
      id: match.entry.id,
      category: match.entry.category,
      stage: match.entry.stage,
      label: match.entry.label,
      score: match.score,
    }));
    const reason = verdict.reason || "no reason provided";
    const details: Record<string, unknown> = {
      analysis: "deep_path",
      verdict: verdict.verdict,
      reason,
      template_id: this.deepPath.templateId,
      template_version: this.deepPath.templateVersion,
      top_score: fast.topScore,
      threshold: fast.threshold,
      ambiguity_band: fast.ambiguityBand,
      top_matches: matches,
      db_source: this.dbSource,
      db_version: this.dbVersion,
      embedding_from: embeddingSource,
    };
    if (matches[0]) {
      details.top_match = matches[0];
    }

    if (verdict.verdict === "deny") {
      return GuardResult.block(
        this.name,
        Severity.ERROR,
        `Spider-Sense deep analysis: threat confirmed - ${reason}`,
      ).withDetails(details);
    }
    if (verdict.verdict === "allow") {
      return GuardResult.allow(this.name).withDetails(details);
    }
    details.verdict = "warn";
    return GuardResult.warn(
      this.name,
      `Spider-Sense deep analysis: suspicious/ambiguous - ${reason}`,
    ).withDetails(details);
  }

  private deepPathFailureResult(
    err: Error,
    fast: ScreeningResult,
    embeddingSource: "action" | "provider",
    baseDetails: Record<string, unknown>,
  ): GuardResult {
    const details: Record<string, unknown> = {
      analysis: "deep_path_error",
      error: err.message,
      fail_mode: this.deepPath.failMode,
      template_id: this.deepPath.templateId,
      template_version: this.deepPath.templateVersion,
      top_score: fast.topScore,
      threshold: fast.threshold,
      ambiguity_band: fast.ambiguityBand,
      top_matches: baseDetails.top_matches,
      db_source: this.dbSource,
      db_version: this.dbVersion,
      embedding_from: embeddingSource,
    };
    if (baseDetails.top_match) {
      details.top_match = baseDetails.top_match;
    }

    if (this.deepPath.failMode === "allow") {
      return GuardResult.allow(this.name).withDetails(details);
    }
    if (this.deepPath.failMode === "deny") {
      return GuardResult.block(
        this.name,
        Severity.ERROR,
        "Spider-Sense deep-path error (fail-closed)",
      ).withDetails(details);
    }
    return GuardResult.warn(
      this.name,
      "Spider-Sense deep-path error; treating as ambiguous",
    ).withDetails(details);
  }

  private circuitOpenProviderResult(err: Error): GuardResult {
    const details = {
      analysis: "provider",
      error: err.message,
      on_open: this.runtimeConfig.onCircuitOpen,
      db_source: this.dbSource,
      db_version: this.dbVersion,
      embedding_from: "provider",
    };
    if (this.runtimeConfig.onCircuitOpen === "allow") {
      return GuardResult.allow(this.name).withDetails(details);
    }
    if (this.runtimeConfig.onCircuitOpen === "warn") {
      return GuardResult.warn(this.name, "Spider-Sense provider circuit breaker open").withDetails(details);
    }
    return GuardResult.block(
      this.name,
      Severity.ERROR,
      "Spider-Sense embedding provider circuit breaker open",
    ).withDetails(details);
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
    const details: Record<string, unknown> = {
      analysis: "fast_path",
      verdict: result.verdict,
      top_score: result.topScore,
      threshold: result.threshold,
      ambiguity_band: result.ambiguityBand,
      top_matches: matches,
      db_source: this.dbSource,
      db_version: this.dbVersion,
      embedding_from: embeddingSource,
    };
    if (matches[0]) {
      details.top_match = matches[0];
    }
    return details;
  }

  private emitMetrics(
    verdict: SpiderSenseVerdict,
    topScore: number,
    severity: Severity,
    screened: boolean,
    skipReason?: string,
    embeddingSource?: "action" | "provider",
    runtime: SpiderSenseMetricRuntime = {},
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
      cache_hit: runtime.cacheHit,
      provider_attempts: runtime.providerAttempts,
      retry_count: runtime.retryCount,
      circuit_state: runtime.circuitState,
      deep_path_used: runtime.deepPathUsed,
      deep_path_verdict: runtime.deepPathVerdict,
      trust_key_id: runtime.trustKeyId,
      embedding_latency_ms: runtime.embeddingLatencyMs,
      deep_path_latency_ms: runtime.deepPathLatencyMs,
    };
    try {
      this.metricsHook(event);
    } catch {
      // Hooks are best-effort only.
    }
  }
}
