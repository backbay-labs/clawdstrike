import { sha256, toHex } from "./crypto/hash";
import { signMessage, verifySignature } from "./crypto/sign";
import { canonicalize } from "./canonical";

export interface ReceiptData {
  id: string;
  artifactRoot: string;
  eventCount: number;
  metadata?: Record<string, unknown>;
}

/**
 * Verification receipt for a run or task.
 */
export class Receipt {
  readonly id: string;
  readonly artifactRoot: string;
  readonly eventCount: number;
  readonly metadata: Record<string, unknown>;

  constructor(data: ReceiptData) {
    this.id = data.id;
    this.artifactRoot = data.artifactRoot;
    this.eventCount = data.eventCount;
    this.metadata = data.metadata ?? {};
  }

  /**
   * Convert to plain object (snake_case keys for compatibility).
   */
  toObject(): Record<string, unknown> {
    return {
      id: this.id,
      artifact_root: this.artifactRoot,
      event_count: this.eventCount,
      metadata: this.metadata,
    };
  }

  /**
   * Convert to canonical JSON string.
   */
  toJSON(): string {
    return canonicalize(this.toObject() as Parameters<typeof canonicalize>[0]);
  }

  /**
   * Create from plain object.
   */
  static fromObject(obj: Record<string, unknown>): Receipt {
    return new Receipt({
      id: obj.id as string,
      artifactRoot: obj.artifact_root as string,
      eventCount: obj.event_count as number,
      metadata: (obj.metadata as Record<string, unknown>) ?? {},
    });
  }

  /**
   * Create from JSON string.
   */
  static fromJSON(json: string): Receipt {
    return Receipt.fromObject(JSON.parse(json));
  }

  /**
   * Compute SHA-256 hash of canonical JSON.
   */
  hash(): Uint8Array {
    return sha256(this.toJSON());
  }

  /**
   * Compute SHA-256 hash as hex string with 0x prefix.
   */
  hashHex(): string {
    return "0x" + toHex(this.hash());
  }
}

/**
 * Receipt with Ed25519 signature.
 */
export class SignedReceipt {
  constructor(
    readonly receipt: Receipt,
    readonly signature: Uint8Array,
    readonly publicKey: Uint8Array
  ) {}

  /**
   * Sign a receipt.
   */
  static async sign(
    receipt: Receipt,
    privateKey: Uint8Array,
    publicKey: Uint8Array
  ): Promise<SignedReceipt> {
    const message = new TextEncoder().encode(receipt.toJSON());
    const signature = await signMessage(message, privateKey);
    return new SignedReceipt(receipt, signature, publicKey);
  }

  /**
   * Verify the signature.
   */
  async verify(): Promise<boolean> {
    const message = new TextEncoder().encode(this.receipt.toJSON());
    return verifySignature(message, this.signature, this.publicKey);
  }

  /**
   * Convert to plain object.
   */
  toObject(): Record<string, unknown> {
    return {
      receipt: this.receipt.toObject(),
      signature: base64Encode(this.signature),
      public_key: base64Encode(this.publicKey),
    };
  }

  /**
   * Convert to JSON string.
   */
  toJSON(): string {
    return canonicalize(this.toObject() as Parameters<typeof canonicalize>[0]);
  }

  /**
   * Create from plain object.
   */
  static fromObject(obj: Record<string, unknown>): SignedReceipt {
    const receiptObj = obj.receipt as Record<string, unknown>;
    return new SignedReceipt(
      Receipt.fromObject(receiptObj),
      base64Decode(obj.signature as string),
      base64Decode(obj.public_key as string)
    );
  }

  /**
   * Create from JSON string.
   */
  static fromJSON(json: string): SignedReceipt {
    return SignedReceipt.fromObject(JSON.parse(json));
  }
}

// Base64 helpers
function base64Encode(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  // Browser fallback
  return btoa(String.fromCharCode(...bytes));
}

function base64Decode(str: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(str, "base64"));
  }
  // Browser fallback
  return new Uint8Array(
    atob(str)
      .split("")
      .map((c) => c.charCodeAt(0))
  );
}
