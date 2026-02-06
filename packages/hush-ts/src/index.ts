/**
 * @clawdstrike/sdk - TypeScript SDK for clawdstrike security verification
 * @packageDocumentation
 */

// eslint-disable-next-line @typescript-eslint/no-require-imports
export const VERSION: string = require("../package.json").version;

// Main entry point
export {
  Clawdstrike,
  ClawdstrikeSession,
  type ClawdstrikeConfig,
  type Decision,
  type DecisionStatus,
  type PolicySpec,
  type Ruleset,
  type SessionOptions,
  type SessionSummary,
  type ToolSet,
} from "./clawdstrike";

// Crypto
export {
  sha256,
  keccak256,
  toHex,
  fromHex,
} from "./crypto/hash";
export {
  generateKeypair,
  signMessage,
  verifySignature,
  type Keypair,
} from "./crypto/sign";

// Canonical JSON
export { canonicalize, canonicalHash } from "./canonical";

// Merkle tree
export {
  hashLeaf,
  hashNode,
  computeRoot,
  generateProof,
  MerkleTree,
  MerkleProof,
} from "./merkle";

// Receipt
export {
  RECEIPT_SCHEMA_VERSION,
  validateReceiptVersion,
  Receipt,
  SignedReceipt,
  type Hash,
  type PublicKey,
  type PublicKeySet,
  type ReceiptData,
  type Signature,
  type Signatures,
  type VerificationResult,
  type Verdict,
  type Provenance,
  type ViolationRef,
} from "./receipt";

// Guards
export {
  Severity,
  GuardResult,
  GuardContext,
  GuardAction,
  type Guard,
  type CanonicalSeverity,
  toCanonicalSeverity,
  fromCanonicalSeverity,
  ForbiddenPathGuard,
  type ForbiddenPathConfig,
  EgressAllowlistGuard,
  type EgressAllowlistConfig,
  SecretLeakGuard,
  type SecretLeakConfig,
  PatchIntegrityGuard,
  type PatchIntegrityConfig,
  type PatchAnalysis,
  type ForbiddenMatch,
  McpToolGuard,
  type McpToolConfig,
  ToolDecision,
} from "./guards";

// Prompt watermarking
export {
  PromptWatermarker,
  WatermarkExtractor,
  type EncodedWatermark,
  type WatermarkConfig,
  type WatermarkEncoding,
  type WatermarkExtractionResult,
  type WatermarkPayload,
  type WatermarkVerifierConfig,
  type WatermarkedPrompt,
} from "./watermarking";

// Instruction hierarchy
export {
  InstructionHierarchyEnforcer,
  InstructionLevel,
  type ConflictAction,
  type ConflictSeverity,
  type EnforcementAction,
  type HierarchyConflict,
  type HierarchyEnforcementResult,
  type HierarchyEnforcerConfig,
  type HierarchyMessage,
  type MessageRole,
} from "./instruction-hierarchy";

// Jailbreak detection
export {
  JailbreakDetector,
  type JailbreakCategory,
  type JailbreakDetectionResult,
  type JailbreakDetectorConfig,
  type JailbreakLinearModelConfig,
  type JailbreakSeverity,
  type JailbreakSignal,
  type LayerResult,
} from "./jailbreak";

// Output sanitization
export {
  OutputSanitizer,
  SanitizationStream,
  type AllowlistConfig,
  type DenylistConfig,
  type DetectorType,
  type EntityFinding,
  type EntityRecognizer,
  type EntropyConfig,
  type OutputSanitizerConfig,
  type ProcessingStats,
  type Redaction,
  type RedactionStrategy,
  type SanitizationResult,
  type SensitiveCategory,
  type SensitiveDataFinding,
  type Span,
  type StreamingConfig,
} from "./output-sanitizer";

// Certification + Compliance
export {
  verifyCertificationBadge,
  type CertificationBadge,
  type CertificationBadgeIssuer,
  type CertificationBadgeSubject,
  type CertificationBadgePolicyBinding,
  type CertificationBadgeEvidenceBinding,
  type CertificationBadgeCertificationBinding,
  type CertificationTier,
} from "./certification-badge";

export {
  ClawdstrikeClient,
  ClawdstrikeError,
  type ClawdstrikeClientOptions,
  type V1Links,
  type V1Meta,
  type V1Response,
  type V1ErrorBody,
  type V1ErrorEnvelope,
} from "./client";

// SIEM/SOAR
export * as siem from "./siem";

// Adapters (merged from @clawdstrike/adapter-core)
// For advanced use cases, these provide direct access to interceptors and adapters
export * as adapters from "./adapters";

// Re-export key adapter types at the top level for convenience
export type {
  AdapterConfig,
  AuditConfig,
  AuditEvent,
  AuditEventType,
  AuditLogger,
  ContextSummary,
  EventHandlers,
  FrameworkAdapter,
  FrameworkHooks,
  GenericToolCall,
  InterceptResult,
  PolicyEngineLike,
  PolicyEvent,
  ProcessedOutput,
  SecurityContext,
  SessionSummary as AdapterSessionSummary,
  ToolInterceptor,
} from "@clawdstrike/adapter-core";

export {
  allowDecision,
  BaseToolInterceptor,
  createDecision,
  createSecurityContext,
  DefaultOutputSanitizer,
  DefaultSecurityContext,
  denyDecision,
  InMemoryAuditLogger,
  PolicyEventFactory,
  warnDecision,
} from "@clawdstrike/adapter-core";
