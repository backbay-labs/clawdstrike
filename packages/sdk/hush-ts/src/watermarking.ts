import { canonicalize } from "./canonical";
import { sha256, toHex, fromHex } from "./crypto/hash";
import { generateKeypair, signMessage, verifySignature } from "./crypto/sign";
import * as ed25519 from "@noble/ed25519";

export type WatermarkEncoding = "metadata";

export interface WatermarkPayload {
  applicationId: string;
  sessionId: string;
  createdAt: number; // unix ms
  expiresAt?: number;
  sequenceNumber: number;
  totalMessages?: number;
  metadata?: Record<string, string>;
}

export interface EncodedWatermark {
  payload: WatermarkPayload;
  encoding: WatermarkEncoding;
  encodedData: Uint8Array; // canonical JSON bytes
  signature: string; // hex (no 0x)
  publicKey: string; // hex (no 0x)
}

export interface WatermarkedPrompt {
  original: string;
  watermarked: string;
  watermark: EncodedWatermark;
}

export interface WatermarkConfig {
  encoding?: WatermarkEncoding;
  privateKeyHex?: string; // 32-byte hex (no 0x)
  generateKeypair?: boolean;
  includeTimestamp?: boolean;
  includeSequence?: boolean;
  customMetadata?: Record<string, string>;
}

export interface WatermarkVerifierConfig {
  trustedPublicKeys?: string[]; // 32-byte hex
  allowUnverified?: boolean;
}

export interface WatermarkExtractionResult {
  found: boolean;
  watermark?: EncodedWatermark;
  verified: boolean;
  errors: string[];
}

const META_PREFIX = "<!--hushclaw.watermark:v1:";
const META_SUFFIX = "-->";

function nowMs(): number {
  return Date.now();
}

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function fromBase64Url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

function normalizeHex32(hex: string, label: string): string {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]+$/.test(raw)) throw new Error(`${label} must be hex`);
  if (raw.length !== 64) throw new Error(`${label} must be 32 bytes`);
  return raw.toLowerCase();
}

function normalizeHex64(hex: string, label: string): string {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]+$/.test(raw)) throw new Error(`${label} must be hex`);
  if (raw.length !== 128) throw new Error(`${label} must be 64 bytes`);
  return raw.toLowerCase();
}

function encodePayload(payload: WatermarkPayload): Uint8Array {
  const obj: any = {
    applicationId: payload.applicationId,
    sessionId: payload.sessionId,
    createdAt: payload.createdAt,
    sequenceNumber: payload.sequenceNumber,
  };
  if (payload.expiresAt !== undefined) obj.expiresAt = payload.expiresAt;
  if (payload.totalMessages !== undefined) obj.totalMessages = payload.totalMessages;
  if (payload.metadata !== undefined) obj.metadata = payload.metadata;

  const canonical = canonicalize(obj);
  return new TextEncoder().encode(canonical);
}

function embedMetadata(prompt: string, watermark: EncodedWatermark): string {
  const payloadB64 = toBase64Url(watermark.encodedData);
  const blob = {
    encoding: watermark.encoding,
    payload: payloadB64,
    signature: watermark.signature,
    publicKey: watermark.publicKey,
  };
  const blobBytes = new TextEncoder().encode(JSON.stringify(blob));
  const blobB64 = toBase64Url(blobBytes);
  return `${META_PREFIX}${blobB64}${META_SUFFIX}\n${prompt}`;
}

function extractMetadata(text: string): EncodedWatermark | undefined {
  const start = text.indexOf(META_PREFIX);
  if (start < 0) return undefined;
  const payloadStart = start + META_PREFIX.length;
  const end = text.indexOf(META_SUFFIX, payloadStart);
  if (end < 0) throw new Error("watermark metadata missing suffix");
  const blobB64 = text.slice(payloadStart, end);
  const blobBytes = fromBase64Url(blobB64);
  const blob = JSON.parse(new TextDecoder().decode(blobBytes));

  const encoding = blob.encoding as WatermarkEncoding;
  if (encoding !== "metadata") throw new Error("unsupported watermark encoding");

  const signature = normalizeHex64(String(blob.signature ?? ""), "signature");
  const publicKey = normalizeHex32(String(blob.publicKey ?? ""), "public key");

  const encodedData = fromBase64Url(String(blob.payload ?? ""));
  const payload = JSON.parse(new TextDecoder().decode(encodedData)) as WatermarkPayload;

  return {
    payload,
    encoding,
    encodedData,
    signature,
    publicKey,
  };
}

export class PromptWatermarker {
  private readonly config: Required<Pick<WatermarkConfig, "encoding" | "generateKeypair" | "includeTimestamp" | "includeSequence">> &
    Omit<WatermarkConfig, "encoding" | "generateKeypair" | "includeTimestamp" | "includeSequence">;
  private readonly privateKey: Uint8Array;
  private readonly publicKey: Uint8Array;
  private seq: number = 0;

  private constructor(cfg: WatermarkConfig, privateKey: Uint8Array, publicKey: Uint8Array) {
    this.config = {
      encoding: cfg.encoding ?? "metadata",
      generateKeypair: cfg.generateKeypair ?? true,
      includeTimestamp: cfg.includeTimestamp ?? true,
      includeSequence: cfg.includeSequence ?? true,
      privateKeyHex: cfg.privateKeyHex,
      customMetadata: cfg.customMetadata,
    };
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  static async create(config: WatermarkConfig = {}): Promise<PromptWatermarker> {
    if (config.privateKeyHex) {
      const pkHex = normalizeHex32(config.privateKeyHex, "privateKeyHex");
      const privateKey = fromHex(pkHex);
      const publicKey = await ed25519.getPublicKeyAsync(privateKey);
      return new PromptWatermarker(config, privateKey, publicKey);
    }

    if (config.generateKeypair === false) {
      throw new Error("privateKeyHex missing and generateKeypair is false");
    }

    const kp = await generateKeypair();
    return new PromptWatermarker(config, kp.privateKey, kp.publicKey);
  }

  publicKeyHex(): string {
    return toHex(this.publicKey);
  }

  generatePayload(applicationId: string, sessionId: string): WatermarkPayload {
    const createdAt = this.config.includeTimestamp ? nowMs() : 0;
    const sequenceNumber = this.config.includeSequence ? this.seq++ : 0;
    return {
      applicationId,
      sessionId,
      createdAt,
      sequenceNumber,
      metadata: this.config.customMetadata,
    };
  }

  async watermark(prompt: string, payload?: WatermarkPayload): Promise<WatermarkedPrompt> {
    const p = payload ?? this.generatePayload("unknown", "unknown");
    const encodedData = encodePayload(p);
    const sigBytes = await signMessage(encodedData, this.privateKey);

    const watermark: EncodedWatermark = {
      payload: p,
      encoding: this.config.encoding,
      encodedData,
      signature: toHex(sigBytes),
      publicKey: toHex(this.publicKey),
    };

    const watermarked = embedMetadata(prompt, watermark);
    return { original: prompt, watermarked, watermark };
  }
}

export class WatermarkExtractor {
  private readonly cfg: Required<Pick<WatermarkVerifierConfig, "trustedPublicKeys" | "allowUnverified">> &
    Omit<WatermarkVerifierConfig, "trustedPublicKeys" | "allowUnverified">;

  constructor(config: WatermarkVerifierConfig = {}) {
    this.cfg = {
      trustedPublicKeys: (config.trustedPublicKeys ?? []).map((k) => normalizeHex32(k, "public key")),
      allowUnverified: config.allowUnverified ?? false,
    };
  }

  async extract(text: string): Promise<WatermarkExtractionResult> {
    try {
      const wm = extractMetadata(text);
      if (!wm) {
        return { found: false, verified: false, errors: [] };
      }

      const message = wm.encodedData;
      const signature = fromHex(normalizeHex64(wm.signature, "signature"));
      const publicKey = fromHex(normalizeHex32(wm.publicKey, "public key"));
      const ok = await verifySignature(message, signature, publicKey);

      const trusted =
        this.cfg.trustedPublicKeys.length === 0 ||
        this.cfg.trustedPublicKeys.some((k) => k === wm.publicKey.toLowerCase());

      const verified = ok && trusted;
      if (!verified && !this.cfg.allowUnverified) {
        return {
          found: true,
          watermark: wm,
          verified: false,
          errors: ["watermark signature invalid or untrusted"],
        };
      }

      return { found: true, watermark: wm, verified, errors: [] };
    } catch (err) {
      return { found: false, verified: false, errors: [String(err)] };
    }
  }

  fingerprint(wm: EncodedWatermark): string {
    return toHex(sha256(wm.encodedData)).toLowerCase();
  }
}
