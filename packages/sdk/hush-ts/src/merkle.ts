import { getWasmModule } from "./crypto/backend";
import { sha256, toHex, fromHex } from "./crypto/hash";

function requireWasm() {
  const wasm = getWasmModule();
  if (!wasm) throw new Error("WASM not initialized. Call initWasm() before using Merkle operations.");
  return wasm;
}

function bytesToHexPrefixed(bytes: Uint8Array): string {
  return "0x" + toHex(bytes);
}

function hexPrefixedToBytes(hex: string): Uint8Array {
  return fromHex(hex.startsWith("0x") ? hex.slice(2) : hex);
}

/**
 * Compute leaf hash per RFC 6962: SHA256(0x00 || data)
 */
export function hashLeaf(data: Uint8Array): Uint8Array {
  const prefixed = new Uint8Array(1 + data.length);
  prefixed[0] = 0x00;
  prefixed.set(data, 1);
  return sha256(prefixed);
}

/**
 * Compute node hash per RFC 6962: SHA256(0x01 || left || right)
 */
export function hashNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  const prefixed = new Uint8Array(1 + left.length + right.length);
  prefixed[0] = 0x01;
  prefixed.set(left, 1);
  prefixed.set(right, 1 + left.length);
  return sha256(prefixed);
}

/**
 * Compute Merkle root from leaf hashes.
 * Delegates to WASM `compute_merkle_root`.
 */
export function computeRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) {
    throw new Error("Cannot compute root of empty tree");
  }
  const wasm = requireWasm();
  const hexLeaves = leaves.map(bytesToHexPrefixed);
  const rootHex = wasm.compute_merkle_root(JSON.stringify(hexLeaves));
  return hexPrefixedToBytes(rootHex);
}

/**
 * Merkle inclusion proof.
 */
export class MerkleProof {
  constructor(
    public readonly treeSize: number,
    public readonly leafIndex: number,
    public readonly auditPath: Uint8Array[],
  ) {}

  /**
   * Compute root from leaf hash and proof.
   * Uses local traversal with hashNode since the WASM module does not
   * expose a dedicated "compute root from proof" function.
   */
  computeRoot(leafHash: Uint8Array): Uint8Array {
    if (this.treeSize === 0 || this.leafIndex >= this.treeSize) {
      throw new Error("Invalid proof: index out of range");
    }

    let h = leafHash;
    let idx = this.leafIndex;
    let size = this.treeSize;
    let pathIdx = 0;

    while (size > 1) {
      if (idx % 2 === 0) {
        if (idx + 1 < size) {
          if (pathIdx >= this.auditPath.length) {
            throw new Error("Invalid proof: missing sibling");
          }
          h = hashNode(h, this.auditPath[pathIdx++]);
        }
      } else {
        if (pathIdx >= this.auditPath.length) {
          throw new Error("Invalid proof: missing sibling");
        }
        h = hashNode(this.auditPath[pathIdx++], h);
      }

      idx = Math.floor(idx / 2);
      size = Math.ceil(size / 2);
    }

    if (pathIdx !== this.auditPath.length) {
      throw new Error("Invalid proof: extra siblings");
    }

    return h;
  }

  /**
   * Verify proof against expected root.
   */
  verify(leafHash: Uint8Array, expectedRoot: Uint8Array): boolean {
    const wasm = requireWasm();
    const leafHex = bytesToHexPrefixed(leafHash);
    const rootHex = bytesToHexPrefixed(expectedRoot);
    const proofJson = JSON.stringify({
      tree_size: this.treeSize,
      leaf_index: this.leafIndex,
      audit_path: this.auditPath.map(bytesToHexPrefixed),
    });
    return wasm.verify_merkle_proof(leafHex, proofJson, rootHex);
  }

  /**
   * Serialize to JSON-compatible object.
   */
  toJSON(): { treeSize: number; leafIndex: number; auditPath: string[] } {
    return {
      treeSize: this.treeSize,
      leafIndex: this.leafIndex,
      auditPath: this.auditPath.map((h) => toHex(h)),
    };
  }

  /**
   * Deserialize from JSON.
   */
  static fromJSON(json: { treeSize: number; leafIndex: number; auditPath: string[] }): MerkleProof {
    const auditPath = json.auditPath.map((hex) => fromHex(hex));
    return new MerkleProof(json.treeSize, json.leafIndex, auditPath);
  }
}

/**
 * Generate inclusion proof for a leaf at given index.
 * Delegates to WASM `generate_merkle_proof`.
 */
export function generateProof(leaves: Uint8Array[], index: number): MerkleProof {
  if (leaves.length === 0) {
    throw new Error("Cannot generate proof for empty tree");
  }
  if (index < 0 || index >= leaves.length) {
    throw new Error(`Index ${index} out of range for ${leaves.length} leaves`);
  }

  const wasm = requireWasm();
  const hexLeaves = leaves.map(bytesToHexPrefixed);
  const resultJson = wasm.generate_merkle_proof(JSON.stringify(hexLeaves), index);
  const result = JSON.parse(resultJson);

  const auditPath = (result.auditPath ?? result.audit_path ?? []).map(
    (hex: string) => hexPrefixedToBytes(hex),
  );
  const treeSize = result.treeSize ?? result.tree_size ?? leaves.length;
  const leafIndex = result.leafIndex ?? result.leaf_index ?? index;

  return new MerkleProof(treeSize, leafIndex, auditPath);
}

/**
 * RFC 6962-compatible Merkle tree.
 */
export class MerkleTree {
  private leafHashes: Uint8Array[];
  private cachedRoot: Uint8Array | null = null;

  private constructor(leafHashes: Uint8Array[]) {
    this.leafHashes = leafHashes;
  }

  /**
   * Build tree from raw leaf data (will be hashed).
   */
  static fromData(data: Uint8Array[]): MerkleTree {
    if (data.length === 0) {
      throw new Error("Cannot build tree from empty data");
    }
    const leaves = data.map((d) => hashLeaf(d));
    return MerkleTree.fromHashes(leaves);
  }

  /**
   * Build tree from pre-hashed leaves.
   */
  static fromHashes(leafHashes: Uint8Array[]): MerkleTree {
    if (leafHashes.length === 0) {
      throw new Error("Cannot build tree from empty leaves");
    }
    return new MerkleTree([...leafHashes]);
  }

  get leafCount(): number {
    return this.leafHashes.length;
  }

  get root(): Uint8Array {
    if (!this.cachedRoot) {
      this.cachedRoot = computeRoot(this.leafHashes);
    }
    return this.cachedRoot;
  }

  /**
   * Generate inclusion proof for leaf at given index.
   */
  inclusionProof(leafIndex: number): MerkleProof {
    if (leafIndex < 0 || leafIndex >= this.leafCount) {
      throw new Error(`Index ${leafIndex} out of range for ${this.leafCount} leaves`);
    }
    return generateProof(this.leafHashes, leafIndex);
  }
}
