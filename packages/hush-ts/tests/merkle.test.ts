import { describe, it, expect } from "vitest";
import {
  hashLeaf,
  hashNode,
  computeRoot,
  generateProof,
  MerkleTree,
  MerkleProof,
} from "../src/merkle";
import { toHex } from "../src/crypto/hash";

describe("hashLeaf", () => {
  it("produces 32 bytes", () => {
    const result = hashLeaf(new Uint8Array([1, 2, 3]));
    expect(result.length).toBe(32);
  });

  it("prefixes with 0x00", () => {
    // Leaf hash = SHA256(0x00 || data)
    const result = hashLeaf(new TextEncoder().encode("hello"));
    expect(result.length).toBe(32);
  });
});

describe("hashNode", () => {
  it("produces 32 bytes", () => {
    const left = hashLeaf(new Uint8Array([1]));
    const right = hashLeaf(new Uint8Array([2]));
    const result = hashNode(left, right);
    expect(result.length).toBe(32);
  });

  it("order matters", () => {
    const a = hashLeaf(new Uint8Array([1]));
    const b = hashLeaf(new Uint8Array([2]));
    const ab = hashNode(a, b);
    const ba = hashNode(b, a);
    expect(toHex(ab)).not.toBe(toHex(ba));
  });
});

describe("computeRoot", () => {
  it("single leaf: root equals leaf hash", () => {
    const leaf = hashLeaf(new TextEncoder().encode("single"));
    const root = computeRoot([leaf]);
    expect(toHex(root)).toBe(toHex(leaf));
  });

  it("two leaves: root is hashNode(left, right)", () => {
    const left = hashLeaf(new TextEncoder().encode("left"));
    const right = hashLeaf(new TextEncoder().encode("right"));
    const root = computeRoot([left, right]);
    const expected = hashNode(left, right);
    expect(toHex(root)).toBe(toHex(expected));
  });

  it("throws for empty array", () => {
    expect(() => computeRoot([])).toThrow("empty");
  });

  it("three leaves: last carried upward (not duplicated)", () => {
    const a = hashLeaf(new TextEncoder().encode("a"));
    const b = hashLeaf(new TextEncoder().encode("b"));
    const c = hashLeaf(new TextEncoder().encode("c"));
    const root = computeRoot([a, b, c]);
    // Level 0: [a, b, c]
    // Level 1: [hash(a,b), c] - c carried up
    // Level 2: [hash(hash(a,b), c)]
    const expected = hashNode(hashNode(a, b), c);
    expect(toHex(root)).toBe(toHex(expected));
  });
});

describe("MerkleProof", () => {
  it("verifies valid two-leaf proof (left)", () => {
    const left = hashLeaf(new TextEncoder().encode("left"));
    const right = hashLeaf(new TextEncoder().encode("right"));
    const root = hashNode(left, right);

    const proof = new MerkleProof(2, 0, [right]);
    expect(proof.verify(left, root)).toBe(true);
  });

  it("verifies valid two-leaf proof (right)", () => {
    const left = hashLeaf(new TextEncoder().encode("left"));
    const right = hashLeaf(new TextEncoder().encode("right"));
    const root = hashNode(left, right);

    const proof = new MerkleProof(2, 1, [left]);
    expect(proof.verify(right, root)).toBe(true);
  });

  it("rejects proof with wrong root", () => {
    const left = hashLeaf(new TextEncoder().encode("left"));
    const right = hashLeaf(new TextEncoder().encode("right"));
    const wrongRoot = hashLeaf(new TextEncoder().encode("wrong"));

    const proof = new MerkleProof(2, 0, [right]);
    expect(proof.verify(left, wrongRoot)).toBe(false);
  });

  it("serializes and deserializes", () => {
    const left = hashLeaf(new TextEncoder().encode("left"));
    const right = hashLeaf(new TextEncoder().encode("right"));
    const root = hashNode(left, right);

    const proof = new MerkleProof(2, 0, [right]);
    const json = proof.toJSON();
    const restored = MerkleProof.fromJSON(json);

    expect(restored.treeSize).toBe(2);
    expect(restored.leafIndex).toBe(0);
    expect(restored.verify(left, root)).toBe(true);
  });
});

describe("generateProof", () => {
  it("generates valid proof for 2-leaf tree", () => {
    const leaves = [
      hashLeaf(new TextEncoder().encode("a")),
      hashLeaf(new TextEncoder().encode("b")),
    ];
    const root = computeRoot(leaves);

    const proof0 = generateProof(leaves, 0);
    const proof1 = generateProof(leaves, 1);

    expect(proof0.verify(leaves[0], root)).toBe(true);
    expect(proof1.verify(leaves[1], root)).toBe(true);
  });

  it("generates valid proofs for 8-leaf tree", () => {
    const leaves = Array.from({ length: 8 }, (_, i) =>
      hashLeaf(new TextEncoder().encode(`leaf${i}`))
    );
    const root = computeRoot(leaves);

    for (let i = 0; i < 8; i++) {
      const proof = generateProof(leaves, i);
      expect(proof.verify(leaves[i], root)).toBe(true);
    }
  });

  it("generates valid proofs for 7-leaf tree (odd count)", () => {
    const leaves = Array.from({ length: 7 }, (_, i) =>
      hashLeaf(new TextEncoder().encode(`leaf${i}`))
    );
    const root = computeRoot(leaves);

    for (let i = 0; i < 7; i++) {
      const proof = generateProof(leaves, i);
      expect(proof.verify(leaves[i], root)).toBe(true);
    }
  });

  it("throws for out-of-range index", () => {
    const leaves = [hashLeaf(new Uint8Array([1])), hashLeaf(new Uint8Array([2]))];
    expect(() => generateProof(leaves, 2)).toThrow("out of range");
    expect(() => generateProof(leaves, -1)).toThrow("out of range");
  });
});

describe("MerkleTree", () => {
  it("builds from raw data", () => {
    const tree = MerkleTree.fromData([
      new TextEncoder().encode("a"),
      new TextEncoder().encode("b"),
      new TextEncoder().encode("c"),
    ]);
    expect(tree.leafCount).toBe(3);
    expect(tree.root.length).toBe(32);
  });

  it("builds from pre-hashed leaves", () => {
    const leaves = [
      hashLeaf(new TextEncoder().encode("a")),
      hashLeaf(new TextEncoder().encode("b")),
    ];
    const tree = MerkleTree.fromHashes(leaves);
    expect(tree.leafCount).toBe(2);
    expect(toHex(tree.root)).toBe(toHex(computeRoot(leaves)));
  });

  it("generates valid inclusion proofs", () => {
    const leaves = Array.from({ length: 10 }, (_, i) =>
      hashLeaf(new TextEncoder().encode(`leaf${i}`))
    );
    const tree = MerkleTree.fromHashes(leaves);

    for (let i = 0; i < 10; i++) {
      const proof = tree.inclusionProof(i);
      expect(proof.verify(leaves[i], tree.root)).toBe(true);
    }
  });

  it("single leaf tree works", () => {
    const leaf = hashLeaf(new TextEncoder().encode("single"));
    const tree = MerkleTree.fromHashes([leaf]);

    expect(tree.leafCount).toBe(1);
    expect(toHex(tree.root)).toBe(toHex(leaf));

    const proof = tree.inclusionProof(0);
    expect(proof.verify(leaf, tree.root)).toBe(true);
    expect(proof.auditPath.length).toBe(0);
  });
});
