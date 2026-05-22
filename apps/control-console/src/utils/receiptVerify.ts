export interface ReceiptVerification {
  valid: boolean;
  error?: string;
  signer_valid?: boolean;
  cosigner_valid?: boolean | null;
  receipt?: {
    signer_public_key: string;
    decision: string;
    action_type: string;
    target?: string;
    guard?: string;
    policy_hash: string;
    timestamp: string;
    signature: string;
  };
}

export async function verifyReceipt(receiptJson: string): Promise<ReceiptVerification> {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(receiptJson);
  } catch {
    return { valid: false, error: "Invalid JSON" };
  }

  if (isSignedReceipt(parsed)) {
    return verifySignedReceipt(parsed);
  }

  return verifyLegacyFlatReceipt(parsed);
}

async function verifyLegacyFlatReceipt(
  parsed: Record<string, unknown>,
): Promise<ReceiptVerification> {
  const signature = parsed.signature as string | undefined;
  const publicKey = parsed.public_key as string | undefined;

  if (!signature || !publicKey) {
    return { valid: false, error: "Missing signature or public_key field" };
  }

  const receipt = {
    signer_public_key: publicKey,
    decision: String(parsed.decision ?? ""),
    action_type: String(parsed.action_type ?? ""),
    target: parsed.target as string | undefined,
    guard: parsed.guard as string | undefined,
    policy_hash: String(parsed.policy_hash ?? ""),
    timestamp: String(parsed.timestamp ?? ""),
    signature,
  };

  try {
    const signedFields = { ...parsed };
    delete signedFields.signature;
    const canonical = canonicalizeJson(signedFields);
    const encoder = new TextEncoder();
    const data = encoder.encode(canonical);

    const keyBytes = Uint8Array.from(atob(publicKey), (c) => c.charCodeAt(0));
    const sigBytes = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));

    const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "Ed25519" }, false, [
      "verify",
    ]);

    const valid = await crypto.subtle.verify(
      "Ed25519",
      cryptoKey,
      sigBytes.buffer as ArrayBuffer,
      data.buffer as ArrayBuffer,
    );
    return { valid, receipt };
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Verification failed";
    if (msg.includes("Ed25519") || msg.includes("not supported") || msg.includes("Unrecognized")) {
      return { valid: false, error: "Ed25519 not supported in this browser", receipt };
    }
    return { valid: false, error: msg, receipt };
  }
}

async function verifySignedReceipt(parsed: Record<string, unknown>): Promise<ReceiptVerification> {
  const receiptValue = asRecord(parsed.receipt);
  const signatures = asRecord(parsed.signatures);
  const signature = stringValue(signatures?.signer);
  const endpointDecision = asRecord(asRecord(receiptValue?.metadata)?.endpointDecision);
  const signer = asRecord(endpointDecision?.signer);
  const publicKey =
    stringValue(signer?.signerPublicKey) ??
    stringValue(signer?.signer_public_key) ??
    stringValue(parsed.public_key);

  if (!receiptValue || !signature || !publicKey) {
    return {
      valid: false,
      error: "Missing SignedReceipt receipt, signatures.signer, or signer public key field",
    };
  }

  const decision = asRecord(endpointDecision?.decision);
  const policy = asRecord(endpointDecision?.policy);
  const receipt = {
    signer_public_key: publicKey,
    decision: stringValue(endpointDecision?.receiptFamily) ?? String(receiptValue.verdict ?? ""),
    action_type: stringValue(decision?.actionType) ?? stringValue(decision?.action_type) ?? "",
    policy_hash:
      stringValue(policy?.policyHash) ??
      stringValue(policy?.policy_hash) ??
      stringValue(asRecord(receiptValue.provenance)?.policy_hash) ??
      "",
    timestamp: String(receiptValue.timestamp ?? ""),
    signature,
  };

  try {
    const keyBytes = hexToBytes(publicKey);
    const sigBytes = hexToBytes(signature);
    const canonical = canonicalizeJson(receiptValue);
    const data = new TextEncoder().encode(canonical);

    const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "Ed25519" }, false, [
      "verify",
    ]);

    const valid = await crypto.subtle.verify(
      "Ed25519",
      cryptoKey,
      sigBytes.buffer as ArrayBuffer,
      data.buffer as ArrayBuffer,
    );
    return { valid, signer_valid: valid, cosigner_valid: null, receipt };
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Verification failed";
    if (msg.includes("Ed25519") || msg.includes("not supported") || msg.includes("Unrecognized")) {
      return { valid: false, error: "Ed25519 not supported in this browser", receipt };
    }
    return { valid: false, error: msg, receipt };
  }
}

function isSignedReceipt(value: Record<string, unknown>): boolean {
  return asRecord(value.receipt) != null && asRecord(value.signatures) != null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function hexToBytes(value: string): Uint8Array<ArrayBuffer> {
  const hex = value.trim().replace(/^0x/i, "");
  if (hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("Invalid hex value");
  }

  const bytes = new Uint8Array(new ArrayBuffer(hex.length / 2));
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function canonicalizeJson(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;

  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalizeJson(record[key])}`)
      .join(",")}}`;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Non-finite numbers are not valid JSON");
  }

  return JSON.stringify(value);
}
