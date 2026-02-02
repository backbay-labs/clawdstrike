/**
 * @hushclaw/sdk - TypeScript SDK for hushclaw security verification
 * @packageDocumentation
 */

// eslint-disable-next-line @typescript-eslint/no-require-imports
export const VERSION: string = require("../package.json").version;

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
