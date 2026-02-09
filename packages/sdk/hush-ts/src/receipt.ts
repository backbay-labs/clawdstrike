import { keccak256, sha256, fromHex, toHex } from "./crypto/hash";
import { signMessage, verifySignature } from "./crypto/sign";
import { canonicalize } from "./canonical";

export const RECEIPT_SCHEMA_VERSION = "1.0.0";

export type Hash = string; // 0x-prefixed 32-byte hex
export type PublicKey = string; // 32-byte hex (no 0x)
export type Signature = string; // 64-byte hex (no 0x)

export interface Verdict {
  passed: boolean;
  gate_id?: string;
  scores?: unknown;
  threshold?: number;
}

export interface ViolationRef {
  guard: string;
  severity: string;
  message: string;
  action?: string;
}

export interface Provenance {
  clawdstrike_version?: string;
  provider?: string;
  policy_hash?: Hash;
  ruleset?: string;
  violations?: ViolationRef[];
}

export interface ReceiptData {
  version?: string;
  receiptId?: string;
  timestamp?: string;
  contentHash: Hash;
  verdict: Verdict;
  provenance?: Provenance;
  metadata?: unknown;
}

export interface Signatures {
  signer: Signature;
  cosigner?: Signature;
}

export interface PublicKeySet {
  signer: PublicKey;
  cosigner?: PublicKey;
}

export interface VerificationResult {
  valid: boolean;
  signer_valid: boolean;
  cosigner_valid?: boolean;
  errors: string[];
}

export function validateReceiptVersion(version: string): void {
  if (parseSemverStrict(version) === null) {
    throw new Error(`Invalid receipt version: ${version}`);
  }
  if (version !== RECEIPT_SCHEMA_VERSION) {
    throw new Error(
      `Unsupported receipt version: ${version} (supported: ${RECEIPT_SCHEMA_VERSION})`
    );
  }
}

function parseSemverStrict(version: string): [number, number, number] | null {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(version);
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function normalizeHexString(
  input: string,
  bytes: number,
  mode: "0x" | "none",
  label: string
): string {
  const raw = input.startsWith("0x") ? input.slice(2) : input;
  if (!/^[0-9a-fA-F]+$/.test(raw)) {
    throw new Error(`${label} must be hex`);
  }
  if (raw.length !== bytes * 2) {
    throw new Error(`${label} must be ${bytes} bytes`);
  }
  const lower = raw.toLowerCase();
  return mode === "0x" ? `0x${lower}` : lower;
}

function normalizeHash(hash: string): Hash {
  return normalizeHexString(hash, 32, "0x", "hash");
}

function normalizePublicKey(pk: string): PublicKey {
  return normalizeHexString(pk, 32, "none", "public key");
}

function normalizeSignature(sig: string): Signature {
  return normalizeHexString(sig, 64, "none", "signature");
}

function assertObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function assertAllowedKeys(obj: Record<string, unknown>, allowed: Set<string>, label: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      throw new Error(`Unknown ${label} field: ${key}`);
    }
  }
}

function requireString(obj: Record<string, unknown>, key: string, label: string): string {
  const value = obj[key];
  if (typeof value !== "string") {
    throw new Error(`${label} must be a string`);
  }
  return value;
}

function optionalString(obj: Record<string, unknown>, key: string, label: string): string | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    throw new Error(`${label} must be a string`);
  }
  return value;
}

function optionalNumber(
  obj: Record<string, unknown>,
  key: string,
  label: string
): number | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`${label} must be a finite number`);
  }
  return value;
}

function requireBoolean(obj: Record<string, unknown>, key: string, label: string): boolean {
  const value = obj[key];
  if (typeof value !== "boolean") {
    throw new Error(`${label} must be a boolean`);
  }
  return value;
}

function normalizeVerdict(input: unknown): Verdict {
  const verdict = assertObject(input, "verdict");
  assertAllowedKeys(
    verdict,
    new Set(["passed", "gate_id", "scores", "threshold"]),
    "verdict"
  );

  const normalized: Verdict = {
    passed: requireBoolean(verdict, "passed", "verdict.passed"),
  };

  const gateId = optionalString(verdict, "gate_id", "verdict.gate_id");
  if (gateId !== undefined) normalized.gate_id = gateId;

  if (Object.prototype.hasOwnProperty.call(verdict, "scores")) {
    if (verdict.scores !== undefined) normalized.scores = verdict.scores;
  }

  const threshold = optionalNumber(verdict, "threshold", "verdict.threshold");
  if (threshold !== undefined) normalized.threshold = threshold;

  return normalized;
}

function normalizeViolationRef(input: ViolationRef): ViolationRef {
  const v = assertObject(input, "violation");
  assertAllowedKeys(v, new Set(["guard", "severity", "message", "action"]), "violation");
  const out: ViolationRef = {
    guard: requireString(v, "guard", "violation.guard"),
    severity: requireString(v, "severity", "violation.severity"),
    message: requireString(v, "message", "violation.message"),
  };
  const action = optionalString(v, "action", "violation.action");
  if (action !== undefined) out.action = action;
  return out;
}

function normalizeProvenance(input: Provenance): Provenance {
  const prov = assertObject(input, "provenance");
  assertAllowedKeys(
    prov,
    new Set(["clawdstrike_version", "provider", "policy_hash", "ruleset", "violations"]),
    "provenance"
  );

  const violationsVal = prov.violations;
  let violations: ViolationRef[] | undefined;
  if (violationsVal !== undefined) {
    if (!Array.isArray(violationsVal)) {
      throw new Error("provenance.violations must be an array");
    }
    violations = violationsVal.map((v) => normalizeViolationRef(v as ViolationRef));
  }

  const out: Provenance = {};

  const clawdstrikeVersion = optionalString(
    prov,
    "clawdstrike_version",
    "provenance.clawdstrike_version"
  );
  if (clawdstrikeVersion !== undefined) out.clawdstrike_version = clawdstrikeVersion;

  const provider = optionalString(prov, "provider", "provenance.provider");
  if (provider !== undefined) out.provider = provider;

  if (prov.policy_hash !== undefined) {
    out.policy_hash = normalizeHash(requireString(prov, "policy_hash", "provenance.policy_hash"));
  }

  const ruleset = optionalString(prov, "ruleset", "provenance.ruleset");
  if (ruleset !== undefined) out.ruleset = ruleset;

  if (violations !== undefined && violations.length > 0) {
    out.violations = violations;
  }

  return out;
}

/**
 * Receipt for an attested execution (unsigned).
 */
export class Receipt {
  readonly version: string;
  readonly receiptId?: string;
  readonly timestamp: string;
  readonly contentHash: Hash;
  readonly verdict: Verdict;
  readonly provenance?: Provenance;
  readonly metadata?: unknown;

  constructor(data: ReceiptData) {
    this.version = data.version ?? RECEIPT_SCHEMA_VERSION;
    validateReceiptVersion(this.version);

    this.receiptId = data.receiptId;
    this.timestamp = data.timestamp ?? new Date().toISOString();
    this.contentHash = normalizeHash(data.contentHash);
    this.verdict = normalizeVerdict(data.verdict);
    this.provenance = data.provenance ? normalizeProvenance(data.provenance) : undefined;
    this.metadata = data.metadata;
  }

  toObject(): Record<string, unknown> {
    const obj: Record<string, unknown> = {
      version: this.version,
      timestamp: this.timestamp,
      content_hash: this.contentHash,
      verdict: this.verdict,
    };
    if (this.receiptId !== undefined) obj.receipt_id = this.receiptId;
    if (this.provenance !== undefined) obj.provenance = this.provenance;
    if (this.metadata !== undefined) obj.metadata = this.metadata;
    return obj;
  }

  toCanonicalJSON(): string {
    return canonicalize(this.toObject() as Parameters<typeof canonicalize>[0]);
  }

  hashSha256Bytes(): Uint8Array {
    return sha256(this.toCanonicalJSON());
  }

  hashSha256(): Hash {
    return `0x${toHex(this.hashSha256Bytes())}`;
  }

  hashKeccak256Bytes(): Uint8Array {
    return keccak256(this.toCanonicalJSON());
  }

  hashKeccak256(): Hash {
    return `0x${toHex(this.hashKeccak256Bytes())}`;
  }

  static fromObject(obj: unknown): Receipt {
    const r = assertObject(obj, "receipt");
    assertAllowedKeys(
      r,
      new Set([
        "version",
        "receipt_id",
        "timestamp",
        "content_hash",
        "verdict",
        "provenance",
        "metadata",
      ]),
      "receipt"
    );

    const version = requireString(r, "version", "receipt.version");
    validateReceiptVersion(version);

    const contentHash = normalizeHash(requireString(r, "content_hash", "receipt.content_hash"));

    const verdict = normalizeVerdict(r.verdict);

    const provenance =
      r.provenance === undefined
        ? undefined
        : normalizeProvenance(assertObject(r.provenance, "receipt.provenance") as Provenance);

    return new Receipt({
      version,
      receiptId: optionalString(r, "receipt_id", "receipt.receipt_id"),
      timestamp: requireString(r, "timestamp", "receipt.timestamp"),
      contentHash,
      verdict,
      provenance,
      metadata: r.metadata,
    });
  }

  static fromJSON(json: string): Receipt {
    return Receipt.fromObject(JSON.parse(json));
  }
}

/**
 * Receipt with signatures.
 */
export class SignedReceipt {
  constructor(readonly receipt: Receipt, readonly signatures: Signatures) {}

  static async sign(receipt: Receipt, privateKey: Uint8Array): Promise<SignedReceipt> {
    const message = new TextEncoder().encode(receipt.toCanonicalJSON());
    const sig = await signMessage(message, privateKey);
    return new SignedReceipt(receipt, { signer: toHex(sig) });
  }

  async addCosigner(privateKey: Uint8Array): Promise<void> {
    const message = new TextEncoder().encode(this.receipt.toCanonicalJSON());
    const sig = await signMessage(message, privateKey);
    this.signatures.cosigner = toHex(sig);
  }

  async verify(publicKeys: PublicKeySet): Promise<VerificationResult> {
    try {
      validateReceiptVersion(this.receipt.version);
    } catch (e) {
      return {
        valid: false,
        signer_valid: false,
        cosigner_valid: undefined,
        errors: [String(e)],
      };
    }

    const message = new TextEncoder().encode(this.receipt.toCanonicalJSON());

    const signerSig = fromHex(normalizeSignature(this.signatures.signer));
    const signerPk = fromHex(normalizePublicKey(publicKeys.signer));
    const signerValid = await verifySignature(message, signerSig, signerPk);

    const result: VerificationResult = {
      valid: signerValid,
      signer_valid: signerValid,
      cosigner_valid: undefined,
      errors: signerValid ? [] : ["Invalid signer signature"],
    };

    if (this.signatures.cosigner !== undefined && publicKeys.cosigner !== undefined) {
      const cosignerSig = fromHex(normalizeSignature(this.signatures.cosigner));
      const cosignerPk = fromHex(normalizePublicKey(publicKeys.cosigner));
      const cosignerValid = await verifySignature(message, cosignerSig, cosignerPk);
      result.cosigner_valid = cosignerValid;
      if (!cosignerValid) {
        result.valid = false;
        result.errors.push("Invalid cosigner signature");
      }
    }

    return result;
  }

  toObject(): Record<string, unknown> {
    const sigs: Record<string, unknown> = { signer: normalizeSignature(this.signatures.signer) };
    if (this.signatures.cosigner !== undefined) {
      sigs.cosigner = normalizeSignature(this.signatures.cosigner);
    }
    return {
      receipt: this.receipt.toObject(),
      signatures: sigs,
    };
  }

  toCanonicalJSON(): string {
    return canonicalize(this.toObject() as Parameters<typeof canonicalize>[0]);
  }

  toJSON(): string {
    return this.toCanonicalJSON();
  }

  static fromObject(obj: unknown): SignedReceipt {
    const sr = assertObject(obj, "signed receipt");
    assertAllowedKeys(sr, new Set(["receipt", "signatures"]), "signed receipt");

    const receipt = Receipt.fromObject(sr.receipt);

    const sigObj = assertObject(sr.signatures, "signatures");
    assertAllowedKeys(sigObj, new Set(["signer", "cosigner"]), "signatures");
    const signer = normalizeSignature(requireString(sigObj, "signer", "signatures.signer"));
    const cosigner =
      sigObj.cosigner === undefined
        ? undefined
        : normalizeSignature(requireString(sigObj, "cosigner", "signatures.cosigner"));

    return new SignedReceipt(receipt, { signer, cosigner });
  }

  static fromJSON(json: string): SignedReceipt {
    return SignedReceipt.fromObject(JSON.parse(json));
  }
}
