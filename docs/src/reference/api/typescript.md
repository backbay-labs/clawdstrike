# TypeScript API Reference

The `@clawdstrike/sdk` package provides a TypeScript SDK for Clawdstrike with full feature parity.

## Installation

```bash
npm install @clawdstrike/sdk
```

## Core Classes

### HushEngine

The main entry point for policy enforcement.

```typescript
import { HushEngine, GuardContext } from "@clawdstrike/sdk";

class HushEngine {
  constructor(options?: HushEngineOptions);

  static fromPolicyFile(path: string): Promise<HushEngine>;

  checkFileAccess(path: string, context: GuardContext): Promise<GuardResult>;
  checkFileWrite(path: string, content: string, context: GuardContext): Promise<GuardResult>;
  checkPatch(path: string, patch: string, context: GuardContext): Promise<GuardResult>;
  checkEgress(host: string, port: number, context: GuardContext): Promise<GuardResult>;
  checkMcpTool(toolName: string, args: Record<string, unknown>, context: GuardContext): Promise<GuardResult>;
  checkActionReport(action: GuardAction, context: GuardContext): Promise<GuardReport>;

  createSignedReceipt(contentHash: Uint8Array): Promise<SignedReceipt>;
  getPublicKey(): string;

  withExtraGuard(guard: Guard): HushEngine;
}

interface HushEngineOptions {
  ruleset?: "default" | "strict" | "ai-agent" | "cicd" | "permissive";
  policyFile?: string;
  policy?: PolicyConfig;
  signing?: { enabled: boolean; keyPair?: KeyPair };
}
```

### GuardContext

Execution context passed to guards.

```typescript
class GuardContext {
  constructor(options?: GuardContextOptions);

  cwd?: string;
  sessionId?: string;
  agentId?: string;
  metadata: Record<string, string>;
}

interface GuardContextOptions {
  cwd?: string;
  sessionId?: string;
  agentId?: string;
  metadata?: Record<string, string>;
}
```

### GuardResult

Result of a guard evaluation.

```typescript
interface GuardResult {
  allowed: boolean;
  verdict: Verdict;
  violations: Violation[];
  evidence: GuardEvidence[];
}

type Verdict = "allow" | "warn" | "block";

interface Violation {
  guardName: string;
  pattern?: string;
  reason: string;
  severity: string;
  span?: { start: number; end: number };
}

interface GuardEvidence {
  guardName: string;
  result: GuardResult;
  durationMs: number;
}
```

## Jailbreak Detection

### JailbreakDetector

Multi-layer jailbreak detection with session aggregation.

```typescript
import { JailbreakDetector, JailbreakDetectionResult } from "@clawdstrike/sdk";

class JailbreakDetector {
  constructor(config?: JailbreakDetectorConfig);

  detect(input: string, sessionId?: string): Promise<JailbreakDetectionResult>;
  detectSync(input: string, sessionId?: string): JailbreakDetectionResult;
}

interface JailbreakDetectorConfig {
  layers?: {
    heuristic?: boolean;
    statistical?: boolean;
    ml?: boolean;
    llmJudge?: boolean;
  };
  blockThreshold?: number;    // 0-100, default 70
  warnThreshold?: number;     // 0-100, default 30
  maxInputBytes?: number;     // default 100000
  sessionAggregation?: boolean;
  sessionTtlMs?: number;
  sessionHalfLifeMs?: number;
  llmJudge?: (input: string) => Promise<number>;
}

interface JailbreakDetectionResult {
  severity: "safe" | "suspicious" | "likely" | "confirmed";
  confidence: number;
  riskScore: number;
  blocked: boolean;
  fingerprint: string;
  signals: JailbreakSignal[];
  layers: {
    heuristic: LayerResult;
    statistical: LayerResult;
    ml?: LayerResult;
    llmJudge?: LayerResult;
  };
  session?: JailbreakSession;
}

type JailbreakCategory =
  | "role_play"
  | "authority_confusion"
  | "encoding_attack"
  | "hypothetical_framing"
  | "adversarial_suffix"
  | "system_impersonation"
  | "instruction_extraction"
  | "multi_turn_grooming"
  | "payload_splitting";
```

## Output Sanitization

### OutputSanitizer

Sensitive data detection and redaction.

```typescript
import { OutputSanitizer, SanitizationResult } from "@clawdstrike/sdk";

class OutputSanitizer {
  constructor(config?: OutputSanitizerConfig);

  sanitize(output: string, context?: SanitizationContext): Promise<SanitizationResult>;
  sanitizeSync(output: string): SanitizationResult;
  detect(output: string): Promise<SensitiveDataFinding[]>;
  createStream(options?: StreamOptions): SanitizationStream;
  addPattern(pattern: SecretPatternDef): void;
}

interface OutputSanitizerConfig {
  categories?: {
    secrets?: boolean;
    pii?: boolean;
    phi?: boolean;
    pci?: boolean;
    internal?: boolean;
  };
  redactionStrategies?: Record<SensitiveCategory, RedactionStrategy>;
  secrets?: SecretsConfig;
  pii?: PIIConfig;
  internal?: InternalConfig;
  allowlist?: AllowlistConfig;
  performance?: PerformanceConfig;
}

type RedactionStrategy = "full" | "partial" | "type_label" | "hash" | "none";
type SensitiveCategory = "secret" | "pii" | "phi" | "pci" | "internal" | "custom";

interface SanitizationResult {
  sanitized: string;
  wasRedacted: boolean;
  findings: SensitiveDataFinding[];
  redactions: Redaction[];
  stats: ProcessingStats;
}

interface SensitiveDataFinding {
  id: string;
  category: SensitiveCategory;
  type: string;
  confidence: number;
  span: { start: number; end: number };
  matchPreview: string;
  detector: "pattern" | "ner" | "entropy" | "custom";
  recommendedAction: RedactionStrategy;
}
```

### Streaming Sanitization

```typescript
interface SanitizationStream {
  write(chunk: string): string | null;
  flush(): string;
  getFindings(): SensitiveDataFinding[];
  end(): SanitizationResult;
}

// Usage
const stream = sanitizer.createStream();

for await (const chunk of llmStream) {
  const safe = stream.write(chunk);
  if (safe) yield safe;
}

yield stream.flush();
const findings = stream.getFindings();
```

## Watermarking

### PromptWatermarker

Embed provenance markers in prompts.

```typescript
import { PromptWatermarker, WatermarkExtractor } from "@clawdstrike/sdk";

class PromptWatermarker {
  constructor(config: WatermarkConfig);

  watermark(prompt: string, payload?: Partial<WatermarkPayload>): WatermarkedPrompt;
  generatePayload(overrides?: Partial<WatermarkPayload>): WatermarkPayload;
  getPublicKey(): string;
}

interface WatermarkConfig {
  encoding: WatermarkEncoding;
  generateKeyPair?: boolean;
  keyPair?: { privateKey: string; publicKey: string };
  includeTimestamp?: boolean;
  includeSequence?: boolean;
}

type WatermarkEncoding = "zero_width" | "homoglyph" | "whitespace" | "metadata" | "hybrid";

interface WatermarkedPrompt {
  original: string;
  watermarked: string;
  watermark: EncodedWatermark;
  stats: { bitsEncoded: number; encodingTimeMs: number };
}

class WatermarkExtractor {
  constructor(config: WatermarkVerifierConfig);

  extract(text: string): WatermarkExtractionResult;
  extractAndVerify(text: string): WatermarkExtractionResult;
  addTrustedKey(publicKey: string): void;
}
```

## Cryptographic Primitives

### Hashing

```typescript
import { sha256, keccak256, toHex } from "@clawdstrike/sdk";

const hash: Uint8Array = sha256(data);
const hex: string = toHex(hash);

const ethHash = keccak256(data);
```

### Signing

```typescript
import { generateKeypair, sign, verify } from "@clawdstrike/sdk";

const { privateKey, publicKey } = generateKeypair();
const signature = sign(message, privateKey);
const isValid = verify(message, signature, publicKey);
```

### Receipts

```typescript
import { SignedReceipt, verifyReceipt } from "@clawdstrike/sdk";

interface SignedReceipt {
  receipt: Receipt;
  signature: Uint8Array;
  publicKey: string;

  toJson(): string;
  static fromJson(json: string): SignedReceipt;
}

const isValid = verifyReceipt(receipt, publicKey);
```

## Policy Types

```typescript
interface Policy {
  version: string;
  name: string;
  extends?: string;
  settings?: PolicySettings;
  guards?: Record<string, GuardConfig>;
}

interface PolicySettings {
  failFast?: boolean;
  verboseLogging?: boolean;
  sessionTimeoutSecs?: number;
}

type GuardConfig =
  | ForbiddenPathConfig
  | EgressAllowlistConfig
  | SecretLeakConfig
  | PatchIntegrityConfig
  | McpToolConfig
  | PromptInjectionConfig
  | JailbreakConfig
  | OutputSanitizerConfig
  | WatermarkConfig;
```

## Error Types

```typescript
class PolicyValidationError extends Error {
  validationErrors: string[];
}

class GuardError extends Error {
  guardName: string;
}

class SignatureError extends Error {}

class SanitizationError extends Error {}

class SecurityViolationError extends Error {
  violations: Violation[];
}

class JailbreakDetectedError extends Error {
  result: JailbreakDetectionResult;
}
```

## Guard Interface

For custom guards:

```typescript
interface Guard {
  name: string;
  handles(action: GuardAction): boolean;
  check(action: GuardAction, context: GuardContext): Promise<GuardResult>;
}

type GuardAction =
  | { type: "file_access"; path: string }
  | { type: "file_write"; path: string; content: string }
  | { type: "patch"; path: string; patch: string }
  | { type: "network_egress"; host: string; port: number }
  | { type: "mcp_tool"; name: string; args: Record<string, unknown> }
  | { type: "custom"; kind: string; payload: unknown };
```

## See Also

- [Quick Start (TypeScript)](../../getting-started/quick-start-typescript.md)
- [Vercel AI Integration](../../guides/vercel-ai-integration.md)
- [LangChain Integration](../../guides/langchain-integration.md)
