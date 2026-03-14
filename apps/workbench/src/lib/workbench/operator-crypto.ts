import type { OperatorIdentity } from "./operator-types";

function buf(data: Uint8Array): ArrayBuffer {
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("hexToBytes: input must have even length");
  }
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("hexToBytes: input contains invalid hex characters");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

export type SigilType = "diamond" | "eye" | "wave" | "crown" | "spiral" | "key" | "star" | "moon";

export const SIGILS: readonly SigilType[] = [
  "diamond",
  "eye",
  "wave",
  "crown",
  "spiral",
  "key",
  "star",
  "moon",
] as const;

export function deriveSigil(fingerprint: string): SigilType {
  const firstByte = parseInt(fingerprint.slice(0, 2), 16);
  return SIGILS[firstByte % SIGILS.length];
}

function buildPkcs8Ed25519(seed: Uint8Array): ArrayBuffer {
  const prefix = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ]);
  const pkcs8 = new Uint8Array(prefix.length + seed.length);
  pkcs8.set(prefix);
  pkcs8.set(seed, prefix.length);
  return pkcs8.buffer;
}

export async function generateOperatorKeypair(): Promise<{
  publicKeyHex: string;
  secretKeyHex: string;
}> {
  try {
    const keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const publicKeyRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    const privateKeyRaw = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const seed = new Uint8Array(privateKeyRaw).slice(-32);
    return {
      publicKeyHex: toHex(new Uint8Array(publicKeyRaw)),
      secretKeyHex: toHex(seed),
    };
  } catch {
    throw new Error(
      "Ed25519 not supported in this environment. Web Crypto Ed25519 (Chrome 113+/Node 20+) is required.",
    );
  }
}

export async function deriveFingerprint(publicKeyHex: string): Promise<string> {
  const bytes = hexToBytes(publicKeyHex);
  const hash = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return toHex(new Uint8Array(hash)).slice(0, 16);
}

export async function createOperatorIdentity(
  displayName: string,
): Promise<{ identity: OperatorIdentity; secretKeyHex: string }> {
  const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();
  const fingerprint = await deriveFingerprint(publicKeyHex);
  const sigil = deriveSigil(fingerprint);
  const nickname = displayName
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .slice(0, 24);
  const deviceId = toHex(crypto.getRandomValues(new Uint8Array(8)));
  const now = Date.now();

  return {
    identity: {
      publicKey: publicKeyHex,
      fingerprint,
      sigil,
      nickname,
      displayName,
      idpClaims: null,
      createdAt: now,
      originDeviceId: deviceId,
      devices: [{ deviceId, deviceName: "primary", addedAt: now, lastSeenAt: now }],
    },
    secretKeyHex,
  };
}

export async function signData(data: Uint8Array, secretKeyHex: string): Promise<string> {
  try {
    const seed = hexToBytes(secretKeyHex);
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      buildPkcs8Ed25519(seed),
      "Ed25519",
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign("Ed25519", privateKey, buf(data));
    return toHex(new Uint8Array(sig));
  } catch {
    throw new Error(
      "Ed25519 not supported in this environment. Web Crypto Ed25519 (Chrome 113+/Node 20+) is required.",
    );
  }
}

export async function verifySignature(
  data: Uint8Array,
  signatureHex: string,
  publicKeyHex: string,
): Promise<boolean> {
  try {
    const publicKeyBytes = hexToBytes(publicKeyHex);
    const publicKey = await crypto.subtle.importKey("raw", buf(publicKeyBytes), "Ed25519", false, [
      "verify",
    ]);
    const signature = hexToBytes(signatureHex);
    return crypto.subtle.verify("Ed25519", publicKey, buf(signature), buf(data));
  } catch {
    return false;
  }
}

export function canonicalizeJson(obj: unknown): string {
  return JSON.stringify(obj, (_, value) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return Object.keys(value)
        .sort()
        .reduce<Record<string, unknown>>((sorted, key) => {
          sorted[key] = value[key];
          return sorted;
        }, {});
    }
    return value;
  });
}

export async function signCanonical(obj: unknown, secretKeyHex: string): Promise<string> {
  const data = new TextEncoder().encode(canonicalizeJson(obj));
  return signData(data, secretKeyHex);
}

export async function verifyCanonical(
  obj: unknown,
  signatureHex: string,
  publicKeyHex: string,
): Promise<boolean> {
  const data = new TextEncoder().encode(canonicalizeJson(obj));
  return verifySignature(data, signatureHex, publicKeyHex);
}

export const OWNERSHIP_PROOF_MAX_AGE_MS = 24 * 60 * 60 * 1000;

export interface OwnershipProof {
  signature: string;
  timestamp: number;
}

export async function signOwnershipProof(
  sentinelPublicKey: string,
  operatorSecretKey: string,
  timestamp: number = Date.now(),
): Promise<OwnershipProof> {
  const data = new TextEncoder().encode(
    `clawdstrike:ownership:${sentinelPublicKey}:${timestamp}`,
  );
  const signature = await signData(data, operatorSecretKey);
  return { signature, timestamp };
}

export async function verifyOwnershipProof(
  sentinelPublicKey: string,
  proof: OwnershipProof,
  operatorPublicKey: string,
  maxAgeMs: number = OWNERSHIP_PROOF_MAX_AGE_MS,
): Promise<boolean> {
  if (!Number.isFinite(proof.timestamp) || proof.timestamp < 0) {
    return false;
  }

  if (Number.isFinite(maxAgeMs)) {
    const age = Date.now() - proof.timestamp;
    if (age > maxAgeMs || age < -60_000) {
      return false;
    }
  }

  const data = new TextEncoder().encode(
    `clawdstrike:ownership:${sentinelPublicKey}:${proof.timestamp}`,
  );
  return verifySignature(data, proof.signature, operatorPublicKey);
}

export async function exportKey(secretKeyHex: string, publicKeyHex: string, passphrase: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const passphraseKey = await crypto.subtle.importKey(
    "raw",
    buf(new TextEncoder().encode(passphrase)),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: buf(salt), iterations: 600_000, hash: "SHA-256" },
    passphraseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const plaintext = new TextEncoder().encode(publicKeyHex + ":" + secretKeyHex);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: buf(iv) }, aesKey, buf(plaintext));

  const packed = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  packed.set(salt, 0);
  packed.set(iv, salt.length);
  packed.set(new Uint8Array(encrypted), salt.length + iv.length);

  return btoa(String.fromCharCode(...packed))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export async function importKey(
  encoded: string,
  passphrase: string,
): Promise<{ publicKeyHex: string; secretKeyHex: string }> {
  const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const packed = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));

  const salt = packed.slice(0, 16);
  const iv = packed.slice(16, 28);
  const ciphertext = packed.slice(28);

  const passphraseKey = await crypto.subtle.importKey(
    "raw",
    buf(new TextEncoder().encode(passphrase)),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: buf(salt), iterations: 600_000, hash: "SHA-256" },
    passphraseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf(iv) }, aesKey, buf(ciphertext));
  const combined = new TextDecoder().decode(decrypted);
  const separatorIndex = combined.indexOf(":");
  if (separatorIndex === -1) {
    throw new Error("importKey: invalid encrypted payload format");
  }
  const publicKeyHex = combined.slice(0, separatorIndex);
  const secretKeyHex = combined.slice(separatorIndex + 1);

  return { publicKeyHex, secretKeyHex };
}
