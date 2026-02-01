import { sha256 } from "./crypto/hash";

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
  const combined = new Uint8Array(1 + 32 + 32);
  combined[0] = 0x01;
  combined.set(left, 1);
  combined.set(right, 33);
  return sha256(combined);
}

/**
 * Compute Merkle root from leaf hashes.
 * Uses left-balanced semantics: odd node carried upward (not duplicated).
 */
export function computeRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) {
    throw new Error("Cannot compute root of empty tree");
  }

  if (leaves.length === 1) {
    return leaves[0];
  }

  let current = [...leaves];
  while (current.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 < current.length) {
        next.push(hashNode(current[i], current[i + 1]));
      } else {
        // Odd node: carry upward unchanged
        next.push(current[i]);
      }
    }
    current = next;
  }

  return current[0];
}

/**
 * Merkle inclusion proof.
 */
export class MerkleProof {
  constructor(
    public readonly treeSize: number,
    public readonly leafIndex: number,
    public readonly auditPath: Uint8Array[]
  ) {}

  /**
   * Compute root from leaf hash and proof.
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
        // Current is left child
        if (idx + 1 < size) {
          // Has sibling on right
          if (pathIdx >= this.auditPath.length) {
            throw new Error("Invalid proof: missing sibling");
          }
          h = hashNode(h, this.auditPath[pathIdx++]);
        }
        // else: no sibling, carry upward
      } else {
        // Current is right child
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
    try {
      const computed = this.computeRoot(leafHash);
      return arrayEquals(computed, expectedRoot);
    } catch {
      return false;
    }
  }

  /**
   * Serialize to JSON-compatible object.
   */
  toJSON(): { treeSize: number; leafIndex: number; auditPath: string[] } {
    return {
      treeSize: this.treeSize,
      leafIndex: this.leafIndex,
      auditPath: this.auditPath.map((h) =>
        Array.from(h)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("")
      ),
    };
  }

  /**
   * Deserialize from JSON.
   */
  static fromJSON(json: {
    treeSize: number;
    leafIndex: number;
    auditPath: string[];
  }): MerkleProof {
    const auditPath = json.auditPath.map((hex) => {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      }
      return bytes;
    });
    return new MerkleProof(json.treeSize, json.leafIndex, auditPath);
  }
}

/**
 * Generate inclusion proof for a leaf at given index.
 */
export function generateProof(leaves: Uint8Array[], index: number): MerkleProof {
  if (leaves.length === 0) {
    throw new Error("Cannot generate proof for empty tree");
  }
  if (index < 0 || index >= leaves.length) {
    throw new Error(`Index ${index} out of range for ${leaves.length} leaves`);
  }

  // Build tree levels
  const levels: Uint8Array[][] = [[...leaves]];
  let current = [...leaves];

  while (current.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 < current.length) {
        next.push(hashNode(current[i], current[i + 1]));
      } else {
        next.push(current[i]);
      }
    }
    levels.push(next);
    current = next;
  }

  // Collect audit path
  const auditPath: Uint8Array[] = [];
  let idx = index;

  for (const level of levels.slice(0, -1)) {
    if (level.length <= 1) break;

    if (idx % 2 === 0) {
      // Current is left, sibling is right
      const siblingIdx = idx + 1;
      if (siblingIdx < level.length) {
        auditPath.push(level[siblingIdx]);
      }
    } else {
      // Current is right, sibling is left
      auditPath.push(level[idx - 1]);
    }

    idx = Math.floor(idx / 2);
  }

  return new MerkleProof(leaves.length, index, auditPath);
}

/**
 * RFC 6962-compatible Merkle tree.
 */
export class MerkleTree {
  private levels: Uint8Array[][];

  private constructor(levels: Uint8Array[][]) {
    this.levels = levels;
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

    const levels: Uint8Array[][] = [[...leafHashes]];
    let current = [...leafHashes];

    while (current.length > 1) {
      const next: Uint8Array[] = [];
      for (let i = 0; i < current.length; i += 2) {
        if (i + 1 < current.length) {
          next.push(hashNode(current[i], current[i + 1]));
        } else {
          next.push(current[i]);
        }
      }
      levels.push(next);
      current = next;
    }

    return new MerkleTree(levels);
  }

  get leafCount(): number {
    return this.levels[0]?.length ?? 0;
  }

  get root(): Uint8Array {
    const lastLevel = this.levels[this.levels.length - 1];
    return lastLevel?.[0] ?? new Uint8Array(32);
  }

  /**
   * Generate inclusion proof for leaf at given index.
   */
  inclusionProof(leafIndex: number): MerkleProof {
    if (leafIndex < 0 || leafIndex >= this.leafCount) {
      throw new Error(`Index ${leafIndex} out of range for ${this.leafCount} leaves`);
    }

    const auditPath: Uint8Array[] = [];
    let idx = leafIndex;

    for (const level of this.levels.slice(0, -1)) {
      if (level.length <= 1) break;

      if (idx % 2 === 0) {
        const siblingIdx = idx + 1;
        if (siblingIdx < level.length) {
          auditPath.push(level[siblingIdx]);
        }
      } else {
        auditPath.push(level[idx - 1]);
      }

      idx = Math.floor(idx / 2);
    }

    return new MerkleProof(this.leafCount, leafIndex, auditPath);
  }
}

function arrayEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
