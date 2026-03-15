import type { PublicationManifest, PublicationProvenance } from "./shared-types";
import {
  signReceiptPersistentNative,
  verifyReceiptChainNative,
  type TauriSignedReceiptResponse,
} from "@/lib/tauri-commands";

type BrowserKeyPair = {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
};

interface BrowserReceiptPayload {
  id: string;
  timestamp: string;
  verdict: "published";
  guard: "publication";
  policy_name: string;
  output_hash: string;
  document_id: string;
  target: PublicationManifest["target"];
}

interface ProvenanceEnvelope {
  signer: NonNullable<PublicationManifest["signer"]>;
  provenance: PublicationProvenance;
  receiptId: string;
}

let browserKeyPairPromise: Promise<BrowserKeyPair> | null = null;

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a.localeCompare(b),
    );
    return `{${entries
      .map(([key, inner]) => `${JSON.stringify(key)}:${stableJson(inner)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(value, "base64"));
  }
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function extractSignerSignature(
  signedReceipt: Record<string, unknown>,
): string | null {
  const signatures = signedReceipt.signatures;
  if (!signatures || typeof signatures !== "object" || Array.isArray(signatures)) {
    return null;
  }
  const signer = (signatures as Record<string, unknown>).signer;
  return typeof signer === "string" && signer.length > 0 ? signer : null;
}

function extractSignedReceiptTimestamp(
  signedReceipt: Record<string, unknown>,
): string | null {
  const receipt = signedReceipt.receipt;
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
    return null;
  }
  const timestamp = (receipt as Record<string, unknown>).timestamp;
  return typeof timestamp === "string" && timestamp.length > 0 ? timestamp : null;
}

function extractSignedReceiptOutputHash(
  signedReceipt: Record<string, unknown>,
): string | null {
  const receipt = signedReceipt.receipt;
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
    return null;
  }
  const objectReceipt = receipt as Record<string, unknown>;
  const contentHash = objectReceipt.content_hash;
  if (typeof contentHash === "string" && contentHash.length > 0) {
    return contentHash;
  }
  const outputHash = objectReceipt.output_hash;
  return typeof outputHash === "string" && outputHash.length > 0 ? outputHash : null;
}

async function getBrowserKeyPair(): Promise<BrowserKeyPair> {
  if (!browserKeyPairPromise) {
    browserKeyPairPromise = crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"],
    ) as Promise<BrowserKeyPair>;
  }
  return browserKeyPairPromise;
}

async function buildBrowserEnvelope(
  outputHash: string,
  documentId: string,
  target: PublicationManifest["target"],
): Promise<ProvenanceEnvelope> {
  const keyPair = await getBrowserKeyPair();
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

  const receiptId = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const receiptPayload: BrowserReceiptPayload = {
    id: receiptId,
    timestamp,
    verdict: "published",
    guard: "publication",
    policy_name: target,
    output_hash: outputHash,
    document_id: documentId,
    target,
  };

  const payloadBytes = new TextEncoder().encode(stableJson(receiptPayload));
  const signatureBuffer = await crypto.subtle.sign(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    keyPair.privateKey,
    payloadBytes,
  );
  const signature = bytesToBase64(new Uint8Array(signatureBuffer));

  return {
    signer: {
      publicKey: JSON.stringify(publicJwk),
      keyType: "ephemeral",
    },
    provenance: {
      algorithm: "browser_ecdsa_p256",
      signature,
      signedAt: timestamp,
      receiptHash: outputHash,
      signedReceipt: {
        receipt: receiptPayload,
        signatures: {
          signer: signature,
        },
      },
    },
    receiptId,
  };
}

function buildTauriEnvelope(
  outputHash: string,
  signed: TauriSignedReceiptResponse,
): ProvenanceEnvelope {
  const signature = extractSignerSignature(signed.signed_receipt);
  if (!signature) {
    throw new Error("Signed publication receipt is missing signer signature");
  }

  const receiptId = signed.receipt_hash;
  return {
    signer: {
      publicKey: signed.public_key,
      keyType: signed.key_type === "persistent" ? "persistent" : "ephemeral",
    },
    provenance: {
      algorithm: "tauri_signed_receipt",
      signature,
      signedAt:
        extractSignedReceiptTimestamp(signed.signed_receipt) ?? new Date().toISOString(),
      receiptHash: signed.receipt_hash,
      signedReceipt: signed.signed_receipt,
    },
    receiptId,
  };
}

export async function signPublicationOutput(
  outputHash: string,
  documentId: string,
  target: PublicationManifest["target"],
): Promise<ProvenanceEnvelope> {
  const nativeSigned = await signReceiptPersistentNative(outputHash, true);
  if (nativeSigned) {
    return buildTauriEnvelope(outputHash, nativeSigned);
  }
  return buildBrowserEnvelope(outputHash, documentId, target);
}

export async function verifyPublicationProvenance(
  manifest: PublicationManifest,
): Promise<{ valid: boolean; reason?: string }> {
  if (!manifest.signer || !manifest.provenance) {
    return { valid: false, reason: "Publication manifest is missing signer or provenance metadata" };
  }

  const { provenance } = manifest;
  const signedReceipt = provenance.signedReceipt;
  if (!signedReceipt) {
    return { valid: false, reason: "Publication manifest is missing signed receipt content" };
  }

  const signedOutputHash = extractSignedReceiptOutputHash(signedReceipt);
  if (signedOutputHash !== manifest.outputHash) {
    return {
      valid: false,
      reason: "Signed receipt output hash does not match manifest output hash",
    };
  }

  if (provenance.algorithm === "tauri_signed_receipt") {
    const verification = await verifyReceiptChainNative([
      {
        id: manifest.receiptId ?? manifest.id,
        timestamp: provenance.signedAt,
        verdict: "allow",
        guard: "publication",
        policyName: manifest.target,
        signature: provenance.signature,
        publicKey: manifest.signer.publicKey,
        valid: true,
        signedReceipt,
      },
    ]);

    if (!verification) {
      return {
        valid: false,
        reason: "Tauri receipt verification unavailable for publication provenance",
      };
    }

    if (!verification.all_signatures_valid) {
      return {
        valid: false,
        reason: verification.receipts[0]?.signature_reason ?? "Receipt signature verification failed",
      };
    }

    return { valid: true };
  }

  if (provenance.algorithm === "browser_ecdsa_p256") {
    try {
      const publicJwk = JSON.parse(manifest.signer.publicKey) as JsonWebKey;
      const publicKey = await crypto.subtle.importKey(
        "jwk",
        publicJwk,
        {
          name: "ECDSA",
          namedCurve: "P-256",
        },
        true,
        ["verify"],
      );

      const receipt = signedReceipt.receipt;
      const payloadBytes = new TextEncoder().encode(stableJson(receipt));
      const verified = await crypto.subtle.verify(
        {
          name: "ECDSA",
          hash: { name: "SHA-256" },
        },
        publicKey,
        base64ToBytes(provenance.signature).buffer as ArrayBuffer,
        payloadBytes,
      );

      return verified
        ? { valid: true }
        : { valid: false, reason: "Browser publication signature verification failed" };
    } catch (error) {
      return {
        valid: false,
        reason: error instanceof Error ? error.message : "Failed to verify browser publication signature",
      };
    }
  }

  return {
    valid: false,
    reason: `Unsupported publication provenance algorithm "${provenance.algorithm}"`,
  };
}
