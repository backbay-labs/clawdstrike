/**
 * @clawdstrike/sdk - TypeScript SDK for clawdstrike security verification
 * @packageDocumentation
 */

declare const __SDK_VERSION__: string;
export const VERSION: string = __SDK_VERSION__;

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
// Adapters (merged from @clawdstrike/adapter-core)
// For advanced use cases, these provide direct access to interceptors and adapters
export * as adapters from "./adapters";
// Canonical JSON
export { canonicalHash, canonicalize } from "./canonical";
// Certification + Compliance
export {
  type CertificationBadge,
  type CertificationBadgeCertificationBinding,
  type CertificationBadgeEvidenceBinding,
  type CertificationBadgeIssuer,
  type CertificationBadgePolicyBinding,
  type CertificationBadgeSubject,
  type CertificationTier,
  verifyCertificationBadge,
} from "./certification-badge";
// Main entry point
export {
  Clawdstrike,
  type ClawdstrikeConfig,
  ClawdstrikeSession,
  type Decision,
  type DecisionStatus,
  type PolicySpec,
  type Ruleset,
  type SessionOptions,
  type SessionSummary,
  type ToolSet,
} from "./clawdstrike";
export {
  ClawdstrikeClient,
  type ClawdstrikeClientOptions,
  ClawdstrikeError,
  type V1ErrorBody,
  type V1ErrorEnvelope,
  type V1Links,
  type V1Meta,
  type V1Response,
} from "./client";
export {
  type CryptoBackend,
  getBackend,
  getWasmModule,
  initWasm,
  isWasmBackend,
  setBackend,
} from "./crypto/backend";
// Crypto
export {
  fromHex,
  keccak256,
  sha256,
  toHex,
} from "./crypto/hash";
export {
  generateKeypair,
  type Keypair,
  signMessage,
  verifySignature,
} from "./crypto/sign";
// Guards
export {
  type CanonicalSeverity,
  type EgressAllowlistConfig,
  EgressAllowlistGuard,
  type ForbiddenMatch,
  type ForbiddenPathConfig,
  ForbiddenPathGuard,
  fromCanonicalSeverity,
  type Guard,
  GuardAction,
  type GuardActionOptions,
  GuardContext,
  GuardResult,
  JailbreakGuard,
  type JailbreakGuardConfig,
  type McpToolConfig,
  McpToolGuard,
  type PatchAnalysis,
  type PatchIntegrityConfig,
  PatchIntegrityGuard,
  type PromptInjectionConfig,
  PromptInjectionGuard,
  type SecretLeakConfig,
  SecretLeakGuard,
  Severity,
  SpiderSenseGuard,
  type SpiderSenseGuardConfig,
  type SpiderSenseMetrics,
  type SpiderSenseMetricsHook,
  ToolDecision,
  toCanonicalSeverity,
} from "./guards";
// Instruction hierarchy
export {
  type ConflictAction,
  type ConflictSeverity,
  type EnforcementAction,
  type HierarchyConflict,
  type HierarchyEnforcementResult,
  type HierarchyEnforcerConfig,
  type HierarchyMessage,
  InstructionHierarchyEnforcer,
  InstructionLevel,
  type MessageRole,
} from "./instruction-hierarchy";
// Jailbreak detection
export {
  type JailbreakCategory,
  type JailbreakDetectionResult,
  JailbreakDetector,
  type JailbreakDetectorConfig,
  type JailbreakLinearModelConfig,
  type JailbreakSeverity,
  type JailbreakSignal,
  type LayerResult,
} from "./jailbreak";
// Spider-Sense detection
export {
  type PatternEntry,
  type PatternMatchResult,
  type ScreeningResult,
  type ScreeningVerdict,
  SpiderSenseDetector,
  type SpiderSenseDetectorConfig,
} from "./spider-sense";
// Merkle tree
export {
  computeRoot,
  generateProof,
  hashLeaf,
  hashNode,
  MerkleProof,
  MerkleTree,
} from "./merkle";
// Output sanitization
export {
  type AllowlistConfig,
  type DenylistConfig,
  type DetectorType,
  type EntityFinding,
  type EntityRecognizer,
  type EntropyConfig,
  OutputSanitizer,
  type OutputSanitizerConfig,
  type ProcessingStats,
  type Redaction,
  type RedactionStrategy,
  type SanitizationResult,
  SanitizationStream,
  type SensitiveCategory,
  type SensitiveDataFinding,
  type Span,
  type StreamingConfig,
} from "./output-sanitizer";
// Receipt
export {
  type Hash,
  type Provenance,
  type PublicKey,
  type PublicKeySet,
  RECEIPT_SCHEMA_VERSION,
  Receipt,
  type ReceiptData,
  type Signature,
  type Signatures,
  SignedReceipt,
  type Verdict,
  type VerificationResult,
  type ViolationRef,
  validateReceiptVersion,
} from "./receipt";
// SIEM/SOAR
export * as siem from "./siem";
// PolicyLab
export {
  PolicyLab,
  type SimulateResult,
  type SimulationResultEntry,
  type SimulationSummary,
  type SynthResult,
} from "./policy-lab";
// Prompt watermarking
export {
  type EncodedWatermark,
  PromptWatermarker,
  type WatermarkConfig,
  type WatermarkEncoding,
  type WatermarkExtractionResult,
  WatermarkExtractor,
  type WatermarkedPrompt,
  type WatermarkPayload,
  type WatermarkVerifierConfig,
} from "./watermarking";
