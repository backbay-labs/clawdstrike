package merkle

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/backbay-labs/clawdstrike-go/crypto"
)

// Reference implementation: recursive tree hash for verification
func treeHashRecursive(hashes []crypto.Hash) crypto.Hash {
	switch len(hashes) {
	case 0:
		return crypto.Hash{}
	case 1:
		return hashes[0]
	default:
		k := largestPowerOfTwoLessThan(len(hashes))
		left := treeHashRecursive(hashes[:k])
		right := treeHashRecursive(hashes[k:])
		return NodeHash(left, right)
	}
}

func largestPowerOfTwoLessThan(n int) int {
	p := 1
	for p<<1 < n {
		p <<= 1
	}
	return p
}

func TestRootMatchesRecursiveReference(t *testing.T) {
	for n := 1; n <= 31; n++ {
		leaves := make([][]byte, n)
		for i := range leaves {
			leaves[i] = []byte(fmt.Sprintf("leaf-%d", i))
		}
		tree, err := FromLeaves(leaves)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}

		leafHashes := make([]crypto.Hash, n)
		for i, l := range leaves {
			leafHashes[i] = LeafHash(l)
		}
		expected := treeHashRecursive(leafHashes)
		if tree.Root() != expected {
			t.Errorf("n=%d: root mismatch", n)
		}
	}
}

func TestInclusionProofsRoundtrip(t *testing.T) {
	leaves := make([][]byte, 25)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("leaf-%d", i))
	}
	tree, err := FromLeaves(leaves)
	if err != nil {
		t.Fatal(err)
	}
	root := tree.Root()

	for idx, leaf := range leaves {
		proof, err := tree.InclusionProof(idx)
		if err != nil {
			t.Fatalf("idx=%d: %v", idx, err)
		}
		if !proof.Verify(leaf, root) {
			t.Errorf("idx=%d: proof failed", idx)
		}
	}
}

func TestInclusionProofRejectsWrongLeaf(t *testing.T) {
	leaves := make([][]byte, 10)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("leaf-%d", i))
	}
	tree, err := FromLeaves(leaves)
	if err != nil {
		t.Fatal(err)
	}
	root := tree.Root()

	proof, err := tree.InclusionProof(3)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Verify([]byte("wrong"), root) {
		t.Error("proof should reject wrong leaf")
	}
}

func TestSingleLeafTree(t *testing.T) {
	tree, err := FromLeaves([][]byte{[]byte("single")})
	if err != nil {
		t.Fatal(err)
	}
	if tree.LeafCount() != 1 {
		t.Errorf("leaf count = %d, want 1", tree.LeafCount())
	}
	if tree.Root() != LeafHash([]byte("single")) {
		t.Error("single leaf root should equal leaf hash")
	}

	proof, err := tree.InclusionProof(0)
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Verify([]byte("single"), tree.Root()) {
		t.Error("single leaf proof failed")
	}
	if len(proof.AuditPath) != 0 {
		t.Error("single leaf proof should have empty audit path")
	}
}

func TestTwoLeafTree(t *testing.T) {
	tree, err := FromLeaves([][]byte{[]byte("left"), []byte("right")})
	if err != nil {
		t.Fatal(err)
	}
	if tree.LeafCount() != 2 {
		t.Errorf("leaf count = %d, want 2", tree.LeafCount())
	}
	expected := NodeHash(LeafHash([]byte("left")), LeafHash([]byte("right")))
	if tree.Root() != expected {
		t.Error("two leaf root mismatch")
	}
}

func TestEmptyTreeFails(t *testing.T) {
	_, err := FromLeaves(nil)
	if err == nil {
		t.Error("expected error for empty tree")
	}
}

func TestFromHashes(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	tree1, err := FromLeaves(leaves)
	if err != nil {
		t.Fatal(err)
	}

	hashes := make([]crypto.Hash, len(leaves))
	for i, l := range leaves {
		hashes[i] = LeafHash(l)
	}
	tree2, err := FromHashes(hashes)
	if err != nil {
		t.Fatal(err)
	}

	if tree1.Root() != tree2.Root() {
		t.Error("FromLeaves and FromHashes should produce same root")
	}
}

func TestProofSerializationRoundtrip(t *testing.T) {
	leaves := make([][]byte, 5)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("leaf-%d", i))
	}
	tree, err := FromLeaves(leaves)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tree.InclusionProof(2)
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var restored MerkleProof
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}

	if restored.TreeSize != proof.TreeSize {
		t.Error("tree size mismatch")
	}
	if restored.LeafIndex != proof.LeafIndex {
		t.Error("leaf index mismatch")
	}
	if len(restored.AuditPath) != len(proof.AuditPath) {
		t.Error("audit path length mismatch")
	}
	if !restored.Verify(leaves[2], tree.Root()) {
		t.Error("deserialized proof failed")
	}
}
