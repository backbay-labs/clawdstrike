import { sha256, toHex } from "./crypto/hash";

export type SensitiveCategory = "secret" | "pii" | "internal" | "custom";

export type RedactionStrategy = "full" | "partial" | "type_label" | "hash" | "none";

export type DetectorType = "pattern" | "entropy" | "denylist" | "entity";

export interface Span {
  start: number;
  end: number;
}

export interface SensitiveDataFinding {
  id: string;
  category: SensitiveCategory;
  dataType: string;
  confidence: number;
  span: Span;
  preview: string;
  detector: DetectorType;
  recommendedAction: RedactionStrategy;
}

export interface Redaction {
  findingId: string;
  strategy: RedactionStrategy;
  originalSpan: Span;
  replacement: string;
}

export interface ProcessingStats {
  inputLength: number;
  outputLength: number;
  findingsCount: number;
  redactionsCount: number;
  processingTimeMs: number;
}

export interface SanitizationResult {
  sanitized: string;
  redacted: boolean;
  findings: SensitiveDataFinding[];
  redactions: Redaction[];
  stats: ProcessingStats;
}

export interface AllowlistConfig {
  exact?: string[];
  patterns?: Array<string | RegExp>;
  allowTestCredentials?: boolean;
}

export interface DenylistConfig {
  patterns?: Array<string | RegExp>;
}

export interface EntropyConfig {
  enabled?: boolean;
  threshold?: number; // bits/char
  minTokenLen?: number;
}

export interface StreamingConfig {
  enabled?: boolean;
  bufferSize?: number;
  carryBytes?: number;
}

export interface OutputSanitizerConfig {
  categories?: {
    secrets?: boolean;
    pii?: boolean;
    internal?: boolean;
  };
  allowlist?: AllowlistConfig;
  denylist?: DenylistConfig;
  entropy?: EntropyConfig;
  streaming?: StreamingConfig;
  maxInputBytes?: number;
}

export interface EntityFinding {
  entityType: string;
  confidence: number;
  span: Span;
}

export interface EntityRecognizer {
  detect(text: string): EntityFinding[];
}

type CompiledPattern = {
  id: string;
  category: SensitiveCategory;
  dataType: string;
  confidence: number;
  strategy: RedactionStrategy;
  re: RegExp;
};

function compileMaybe(pattern: string | RegExp): RegExp | null {
  try {
    if (pattern instanceof RegExp) return pattern;
    return new RegExp(pattern, "g");
  } catch {
    return null;
  }
}

function normalizeAllowlist(cfg: AllowlistConfig | undefined): Required<AllowlistConfig> & { patterns: RegExp[] } {
  const exact = cfg?.exact ?? [];
  const allowTestCredentials = cfg?.allowTestCredentials ?? false;
  const patternsRaw = cfg?.patterns ?? [];
  const patterns: RegExp[] = [];
  for (const p of patternsRaw) {
    const re = compileMaybe(p);
    if (re) patterns.push(re);
  }
  return { exact, patterns, allowTestCredentials };
}

function normalizeDenylist(cfg: DenylistConfig | undefined): RegExp[] {
  const patternsRaw = cfg?.patterns ?? [];
  const patterns: RegExp[] = [];
  for (const p of patternsRaw) {
    const re = compileMaybe(p);
    if (re) patterns.push(re);
  }
  return patterns;
}

function previewRedacted(s: string): string {
  // Deterministic and safe: never return the raw string.
  const len = s.length;
  if (len <= 4) return "*".repeat(len);
  return `${s.slice(0, 2)}***${s.slice(-2)}`;
}

function isObviouslyTestCredential(value: string): boolean {
  const lower = value.toLowerCase();
  if (lower.includes("example") || lower.includes("dummy")) return true;

  const isRepeated = (s: string) => s.length > 0 && s.split("").every((c) => c === s[0]);
  if (lower.startsWith("sk-")) {
    const rest = lower.slice(3);
    return rest.length >= 16 && isRepeated(rest);
  }
  for (const prefix of ["ghp_", "ghs_", "gho_", "ghu_"]) {
    if (lower.startsWith(prefix)) {
      const rest = lower.slice(prefix.length);
      return rest.length >= 16 && isRepeated(rest);
    }
  }
  if (lower.startsWith("akia")) {
    const rest = lower.slice(4);
    return rest.length >= 8 && isRepeated(rest);
  }
  return false;
}

function shannonEntropyAscii(token: string): number | null {
  for (let i = 0; i < token.length; i++) {
    if (token.charCodeAt(i) > 0x7f) return null;
  }
  if (token.length === 0) return null;
  const counts = new Array<number>(256).fill(0);
  for (let i = 0; i < token.length; i++) {
    counts[token.charCodeAt(i)] += 1;
  }
  const len = token.length;
  let entropy = 0;
  for (const c of counts) {
    if (c === 0) continue;
    const p = c / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isCandidateSecretToken(token: string): boolean {
  return /^[A-Za-z0-9+/=_-]+$/.test(token);
}

function isLuhnValidCardNumber(text: string): boolean {
  const digits = text.replace(/[^0-9]/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  if (/^(\d)\1+$/.test(digits)) return false;

  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    const d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    let v = d;
    if (double) {
      v *= 2;
      if (v > 9) v -= 9;
    }
    sum += v;
    double = !double;
  }
  return sum % 10 === 0;
}

function replacementFor(
  strategy: RedactionStrategy,
  category: SensitiveCategory,
  dataType: string,
  raw: string,
): string {
  switch (strategy) {
    case "none":
      return raw;
    case "full":
      return `[REDACTED:${dataType}]`;
    case "type_label":
      if (category === "secret") return "[REDACTED:secret]";
      if (category === "pii") return "[REDACTED:pii]";
      if (category === "internal") return "[REDACTED:internal]";
      return "[REDACTED:custom]";
    case "partial":
      return previewRedacted(raw);
    case "hash": {
      const h = toHex(sha256(new TextEncoder().encode(raw)));
      return `[HASH:${h}]`;
    }
  }
}

function truncateToBytes(s: string, maxBytes: number): { slice: string; truncated: boolean } {
  const bytes = Buffer.from(s, "utf8");
  if (bytes.length <= maxBytes) return { slice: s, truncated: false };
  const truncatedBytes = bytes.subarray(0, maxBytes);
  return { slice: truncatedBytes.toString("utf8"), truncated: true };
}

const BUILTIN_PATTERNS: CompiledPattern[] = [
  // Secrets
  {
    id: "secret_openai_api_key",
    category: "secret",
    dataType: "openai_api_key",
    confidence: 0.99,
    strategy: "full",
    re: /sk-[A-Za-z0-9]{48}/g,
  },
  {
    id: "secret_anthropic_api_key",
    category: "secret",
    dataType: "anthropic_api_key",
    confidence: 0.99,
    strategy: "full",
    re: /sk-ant-api03-[A-Za-z0-9_-]{93}/g,
  },
  {
    id: "secret_github_token",
    category: "secret",
    dataType: "github_token",
    confidence: 0.99,
    strategy: "full",
    re: /gh[ps]_[A-Za-z0-9]{36}/g,
  },
  {
    id: "secret_aws_access_key_id",
    category: "secret",
    dataType: "aws_access_key_id",
    confidence: 0.99,
    strategy: "full",
    re: /AKIA[0-9A-Z]{16}/g,
  },
  {
    id: "secret_private_key_block",
    category: "secret",
    dataType: "private_key",
    confidence: 0.99,
    strategy: "full",
    re: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
  },
  {
    id: "secret_jwt",
    category: "secret",
    dataType: "jwt",
    confidence: 0.8,
    strategy: "full",
    re: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  },
  {
    id: "secret_password_assignment",
    category: "secret",
    dataType: "password",
    confidence: 0.7,
    strategy: "full",
    re: /\b(password|passwd|pwd)\b\s*[:=]\s*\S{6,}/gi,
  },
  // PII
  {
    id: "pii_email",
    category: "pii",
    dataType: "email",
    confidence: 0.95,
    strategy: "partial",
    re: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  },
  {
    id: "pii_phone",
    category: "pii",
    dataType: "phone",
    confidence: 0.8,
    strategy: "partial",
    re: /\b(?:\+?1[\s.-]?)?\(?(?:[2-9][0-9]{2})\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}\b/g,
  },
  {
    id: "pii_ssn",
    category: "pii",
    dataType: "ssn",
    confidence: 0.9,
    strategy: "partial",
    re: /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/g,
  },
  {
    id: "pii_credit_card",
    category: "pii",
    dataType: "credit_card",
    confidence: 0.7,
    strategy: "partial",
    re: /\b(?:[0-9][ -]*?){13,19}\b/g,
  },
  // Internal
  {
    id: "internal_localhost_url",
    category: "internal",
    dataType: "internal_url",
    confidence: 0.8,
    strategy: "type_label",
    re: /\bhttps?:\/\/(?:localhost|127\.0\.0\.1)(?::[0-9]{2,5})?\b/gi,
  },
  {
    id: "internal_private_ip",
    category: "internal",
    dataType: "internal_ip",
    confidence: 0.8,
    strategy: "type_label",
    re: /\b(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[0-1]))\.[0-9]{1,3}\.[0-9]{1,3}\b/g,
  },
  {
    id: "internal_windows_path",
    category: "internal",
    dataType: "windows_path",
    confidence: 0.7,
    strategy: "type_label",
    re: /\b[A-Z]:\\(?:[^\\\s]+\\)*[^\\\s]+\b/gi,
  },
  {
    id: "internal_file_path_sensitive",
    category: "internal",
    dataType: "sensitive_path",
    confidence: 0.7,
    strategy: "type_label",
    re: /(?:\/etc\/|\/var\/secrets\/|\/home\/[^\s]+\/\.ssh\/)/gi,
  },
];

export class OutputSanitizer {
  private readonly cfg: {
    categories: { secrets: boolean; pii: boolean; internal: boolean };
    entropy: { enabled: boolean; threshold: number; minTokenLen: number };
    streaming: { enabled: boolean; bufferSize: number; carryBytes: number };
    maxInputBytes: number;
  };
  private readonly allowlist: ReturnType<typeof normalizeAllowlist>;
  private readonly denylist: RegExp[];
  private readonly entityRecognizer?: EntityRecognizer;

  constructor(config: OutputSanitizerConfig = {}, options?: { entityRecognizer?: EntityRecognizer }) {
    this.cfg = {
      categories: {
        secrets: config.categories?.secrets ?? true,
        pii: config.categories?.pii ?? true,
        internal: config.categories?.internal ?? true,
      },
      entropy: {
        enabled: config.entropy?.enabled ?? true,
        threshold: config.entropy?.threshold ?? 4.5,
        minTokenLen: config.entropy?.minTokenLen ?? 32,
      },
      streaming: {
        enabled: config.streaming?.enabled ?? true,
        bufferSize: config.streaming?.bufferSize ?? 50_000,
        carryBytes: config.streaming?.carryBytes ?? 512,
      },
      maxInputBytes: config.maxInputBytes ?? 1_000_000,
    };
    this.allowlist = normalizeAllowlist(config.allowlist);
    this.denylist = normalizeDenylist(config.denylist);
    this.entityRecognizer = options?.entityRecognizer;
  }

  createStream(): SanitizationStream {
    return new SanitizationStream(this, {
      enabled: this.cfg.streaming.enabled,
      bufferSize: this.cfg.streaming.bufferSize,
      carryBytes: this.cfg.streaming.carryBytes,
      maxInputBytes: this.cfg.maxInputBytes,
    });
  }

  sanitizeSync(output: string): SanitizationResult {
    const startedAt = Date.now();
    const { slice, truncated } = truncateToBytes(output, this.cfg.maxInputBytes);

    const findings: SensitiveDataFinding[] = [];

    // Denylist (forced redaction)
    for (const re of this.denylist) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(slice)) !== null) {
        const match = m[0] ?? "";
        const id = "denylist_" + toHex(sha256(new TextEncoder().encode(re.source))).slice(0, 16);
        findings.push({
          id,
          category: "secret",
          dataType: "denylist",
          confidence: 0.95,
          span: { start: m.index, end: m.index + match.length },
          preview: previewRedacted(match),
          detector: "denylist",
          recommendedAction: "full",
        });
      }
      re.lastIndex = 0;
    }

    // Built-in patterns
    for (const p of BUILTIN_PATTERNS) {
      if (p.category === "secret" && !this.cfg.categories.secrets) continue;
      if (p.category === "pii" && !this.cfg.categories.pii) continue;
      if (p.category === "internal" && !this.cfg.categories.internal) continue;

      p.re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = p.re.exec(slice)) !== null) {
        const match = m[0] ?? "";
        if (p.id === "pii_credit_card" && !isLuhnValidCardNumber(match)) continue;
        if (this.isAllowlisted(match)) continue;
        findings.push({
          id: p.id,
          category: p.category,
          dataType: p.dataType,
          confidence: p.confidence,
          span: { start: m.index, end: m.index + match.length },
          preview: previewRedacted(match),
          detector: "pattern",
          recommendedAction: p.strategy,
        });
      }
      p.re.lastIndex = 0;
    }

    // Optional entity recognizer hook (NER, etc).
    if (this.cfg.categories.pii && this.entityRecognizer) {
      const entities = this.entityRecognizer.detect(slice);
      for (const e of entities) {
        const span = e.span;
        if (span.start >= span.end) continue;
        const match = slice.slice(span.start, span.end);
        if (this.isAllowlisted(match)) continue;
        findings.push({
          id: `pii_entity_${e.entityType}`.toLowerCase(),
          category: "pii",
          dataType: e.entityType.toLowerCase(),
          confidence: Math.max(0, Math.min(1, e.confidence)),
          span: { start: span.start, end: span.end },
          preview: previewRedacted(match),
          detector: "entity",
          recommendedAction: "partial",
        });
      }
    }

    // High-entropy tokens
    if (this.cfg.categories.secrets && this.cfg.entropy.enabled) {
      const tokenRe = /[A-Za-z0-9+/=_-]{32,}/g;
      let m: RegExpExecArray | null;
      while ((m = tokenRe.exec(slice)) !== null) {
        const token = m[0] ?? "";
        if (token.length < this.cfg.entropy.minTokenLen) continue;
        if (this.isAllowlisted(token)) continue;
        if (!isCandidateSecretToken(token)) continue;
        const ent = shannonEntropyAscii(token);
        if (ent === null) continue;
        if (ent < this.cfg.entropy.threshold) continue;
        findings.push({
          id: "secret_high_entropy_token",
          category: "secret",
          dataType: "high_entropy_token",
          confidence: 0.6,
          span: { start: m.index, end: m.index + token.length },
          preview: previewRedacted(token),
          detector: "entropy",
          recommendedAction: "full",
        });
      }
    }

    findings.sort((a, b) => a.span.start - b.span.start || a.span.end - b.span.end);

    // Apply redactions (descending by start so indices stay valid).
    const spans: Array<{ span: Span; strategy: RedactionStrategy; category: SensitiveCategory; dataType: string; findingId: string }> = [];
    for (const f of findings) {
      spans.push({
        span: f.span,
        strategy: f.recommendedAction,
        category: f.category,
        dataType: f.dataType,
        findingId: f.id,
      });
    }

    spans.sort((a, b) => b.span.start - a.span.start || b.span.end - a.span.end);

    let sanitized = slice;
    const redactions: Redaction[] = [];
    let redacted = false;

    for (const s of spans) {
      if (s.span.start < 0 || s.span.end > sanitized.length || s.span.start >= s.span.end) continue;
      const raw = sanitized.slice(s.span.start, s.span.end);
      const replacement = replacementFor(s.strategy, s.category, s.dataType, raw);
      if (replacement === raw) continue;
      sanitized = sanitized.slice(0, s.span.start) + replacement + sanitized.slice(s.span.end);
      redacted = true;
      redactions.push({
        findingId: s.findingId,
        strategy: s.strategy,
        originalSpan: s.span,
        replacement,
      });
    }

    if (truncated) {
      sanitized += "\n[TRUNCATED_UNSCANNED_OUTPUT]";
      redacted = true;
    }

    const endedAt = Date.now();

    return {
      sanitized,
      redacted,
      findings,
      redactions,
      stats: {
        inputLength: Buffer.from(output, "utf8").length,
        outputLength: Buffer.from(sanitized, "utf8").length,
        findingsCount: findings.length,
        redactionsCount: redactions.length,
        processingTimeMs: endedAt - startedAt,
      },
    };
  }

  private isAllowlisted(match: string): boolean {
    if (this.allowlist.exact.includes(match)) return true;
    for (const re of this.allowlist.patterns) {
      try {
        re.lastIndex = 0;
        if (re.test(match)) return true;
      } finally {
        re.lastIndex = 0;
      }
    }
    return this.allowlist.allowTestCredentials ? isObviouslyTestCredential(match) : false;
  }
}

export class SanitizationStream {
  private readonly sanitizer: OutputSanitizer;
  private readonly streamCfg: { enabled: boolean; bufferSize: number; carryBytes: number; maxInputBytes: number };
  private rawBuffer = "";
  private readonly findings: SensitiveDataFinding[] = [];
  private readonly redactions: Redaction[] = [];
  private rawOffset = 0;
  private inputBytes = 0;
  private outputBytes = 0;
  private redacted = false;
  private readonly startedAt = Date.now();

  constructor(
    sanitizer: OutputSanitizer,
    streamCfg: { enabled: boolean; bufferSize: number; carryBytes: number; maxInputBytes: number },
  ) {
    this.sanitizer = sanitizer;
    this.streamCfg = streamCfg;
  }

  write(chunk: string): string {
    this.inputBytes += Buffer.from(chunk, "utf8").length;
    if (!this.streamCfg.enabled) {
      const r = this.sanitizer.sanitizeSync(chunk);
      const out = this.absorb(r, this.rawOffset);
      this.rawOffset += chunk.length;
      return out;
    }

    this.rawBuffer += chunk;

    const maxBuffer = Math.max(1, Math.min(this.streamCfg.bufferSize, this.streamCfg.maxInputBytes));
    let out = "";

    while (this.rawBuffer.length > maxBuffer) {
      out += this.drainReady(true);
      if (this.rawBuffer.length <= maxBuffer) break;
    }
    out += this.drainReady(false);
    return out;
  }

  flush(): string {
    if (!this.rawBuffer) return "";
    const prefix = this.rawBuffer;
    this.rawBuffer = "";
    const r = this.sanitizer.sanitizeSync(prefix);
    const out = this.absorb(r, this.rawOffset);
    this.rawOffset += prefix.length;
    return out;
  }

  getFindings(): SensitiveDataFinding[] {
    return [...this.findings];
  }

  end(): SanitizationResult {
    const finalChunk = this.flush();
    const endedAt = Date.now();
    return {
      sanitized: finalChunk,
      redacted: this.redacted,
      findings: [...this.findings],
      redactions: [...this.redactions],
      stats: {
        inputLength: this.inputBytes,
        outputLength: this.outputBytes,
        findingsCount: this.findings.length,
        redactionsCount: this.redactions.length,
        processingTimeMs: endedAt - this.startedAt,
      },
    };
  }

  private drainReady(force: boolean): string {
    const carry = Math.max(1, this.streamCfg.carryBytes);
    if (this.rawBuffer.length <= carry) return "";

    let cutoff = force ? this.rawBuffer.length : Math.max(0, this.rawBuffer.length - carry);
    if (cutoff <= 0) return "";

    // Find redaction spans so we don't cut inside a sensitive match.
    const scan = this.sanitizer.sanitizeSync(this.rawBuffer);
    const spans = scan.redactions
      .map((r) => r.originalSpan)
      .sort((a, b) => a.start - b.start || a.end - b.end);

    const merged: Span[] = [];
    for (const s of spans) {
      const last = merged[merged.length - 1];
      if (last && s.start <= last.end) {
        last.end = Math.max(last.end, s.end);
      } else {
        merged.push({ start: s.start, end: s.end });
      }
    }

    for (const span of merged) {
      if (span.start < cutoff && cutoff < span.end) {
        cutoff = span.start;
        break;
      }
    }

    if (cutoff <= 0) {
      return force ? this.flush() : "";
    }

    const prefix = this.rawBuffer.slice(0, cutoff);
    this.rawBuffer = this.rawBuffer.slice(cutoff);
    const r = this.sanitizer.sanitizeSync(prefix);
    const out = this.absorb(r, this.rawOffset);
    this.rawOffset += prefix.length;
    return out;
  }

  private absorb(result: SanitizationResult, offset: number): string {
    this.redacted = this.redacted || result.redacted;

    for (const f of result.findings) {
      this.findings.push({
        ...f,
        span: { start: f.span.start + offset, end: f.span.end + offset },
      });
    }
    for (const r of result.redactions) {
      this.redactions.push({
        ...r,
        originalSpan: { start: r.originalSpan.start + offset, end: r.originalSpan.end + offset },
      });
    }

    this.outputBytes += Buffer.from(result.sanitized, "utf8").length;
    return result.sanitized;
  }
}
