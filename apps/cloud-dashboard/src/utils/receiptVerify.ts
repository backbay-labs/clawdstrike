export interface ReceiptVerification {
  valid: boolean;
  error?: string;
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
    const canonical = JSON.stringify(signedFields, Object.keys(signedFields).sort());
    const encoder = new TextEncoder();
    const data = encoder.encode(canonical);

    const keyBytes = Uint8Array.from(atob(publicKey), (c) => c.charCodeAt(0));
    const sigBytes = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "Ed25519" },
      false,
      ["verify"],
    );

    const valid = await crypto.subtle.verify("Ed25519", cryptoKey, sigBytes.buffer as ArrayBuffer, data.buffer as ArrayBuffer);
    return { valid, receipt };
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Verification failed";
    if (msg.includes("Ed25519") || msg.includes("not supported") || msg.includes("Unrecognized")) {
      return { valid: false, error: "Ed25519 not supported in this browser", receipt };
    }
    return { valid: false, error: msg, receipt };
  }
}
