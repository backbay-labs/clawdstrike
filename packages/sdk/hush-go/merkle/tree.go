// Package merkle implements RFC 6962-compatible Merkle trees.
//
// Leaf hash: SHA256(0x00 || data)
// Node hash: SHA256(0x01 || left || right)
//
// Odd nodes are carried upward unchanged (no duplication).
package merkle

import (
	"crypto/sha256"
	"errors"

	"github.com/backbay/clawdstrike-go/crypto"
)

// LeafHash computes the RFC 6962 leaf hash: SHA256(0x00 || data).
func LeafHash(data []byte) crypto.Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out crypto.Hash
	copy(out[:], h.Sum(nil))
	return out
}

// NodeHash computes the RFC 6962 node hash: SHA256(0x01 || left || right).
func NodeHash(left, right crypto.Hash) crypto.Hash {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out crypto.Hash
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleTree is an RFC 6962-compatible Merkle tree.
type MerkleTree struct {
	levels [][]crypto.Hash
}

// FromLeaves builds a Merkle tree from raw leaf data.
func FromLeaves(leaves [][]byte) (*MerkleTree, error) {
	if len(leaves) == 0 {
		return nil, errors.New("merkle: empty tree")
	}

	current := make([]crypto.Hash, len(leaves))
	for i, leaf := range leaves {
		current[i] = LeafHash(leaf)
	}

	levels := [][]crypto.Hash{copyHashes(current)}

	for len(current) > 1 {
		next := make([]crypto.Hash, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, NodeHash(current[i], current[i+1]))
			} else {
				// Carry last node upward unchanged
				next = append(next, current[i])
			}
		}
		levels = append(levels, copyHashes(next))
		current = next
	}

	return &MerkleTree{levels: levels}, nil
}

// FromHashes builds a Merkle tree from pre-computed leaf hashes.
func FromHashes(leafHashes []crypto.Hash) (*MerkleTree, error) {
	if len(leafHashes) == 0 {
		return nil, errors.New("merkle: empty tree")
	}

	current := copyHashes(leafHashes)
	levels := [][]crypto.Hash{copyHashes(current)}

	for len(current) > 1 {
		next := make([]crypto.Hash, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, NodeHash(current[i], current[i+1]))
			} else {
				next = append(next, current[i])
			}
		}
		levels = append(levels, copyHashes(next))
		current = next
	}

	return &MerkleTree{levels: levels}, nil
}

// Root returns the root hash of the tree.
func (t *MerkleTree) Root() crypto.Hash {
	if len(t.levels) == 0 {
		return crypto.Hash{}
	}
	last := t.levels[len(t.levels)-1]
	if len(last) == 0 {
		return crypto.Hash{}
	}
	return last[0]
}

// LeafCount returns the number of leaves.
func (t *MerkleTree) LeafCount() int {
	if len(t.levels) == 0 {
		return 0
	}
	return len(t.levels[0])
}

// InclusionProof generates a Merkle inclusion proof for the leaf at index.
func (t *MerkleTree) InclusionProof(leafIndex int) (*MerkleProof, error) {
	treeSize := t.LeafCount()
	if leafIndex < 0 || leafIndex >= treeSize {
		return nil, errors.New("merkle: index out of range")
	}

	var auditPath []crypto.Hash
	idx := leafIndex

	for _, level := range t.levels {
		if len(level) <= 1 {
			break
		}
		if idx%2 == 0 {
			sib := idx + 1
			if sib < len(level) {
				auditPath = append(auditPath, level[sib])
			}
		} else {
			auditPath = append(auditPath, level[idx-1])
		}
		idx /= 2
	}

	return &MerkleProof{
		TreeSize:  treeSize,
		LeafIndex: leafIndex,
		AuditPath: auditPath,
	}, nil
}

// MerkleProof is an inclusion proof for a leaf in a Merkle tree.
type MerkleProof struct {
	TreeSize  int           `json:"tree_size"`
	LeafIndex int           `json:"leaf_index"`
	AuditPath []crypto.Hash `json:"audit_path"`
}

// ComputeRoot computes the root from raw leaf data and this proof.
func (p *MerkleProof) ComputeRoot(leafBytes []byte) (crypto.Hash, error) {
	return p.ComputeRootFromHash(LeafHash(leafBytes))
}

// ComputeRootFromHash computes the root from a pre-hashed leaf.
func (p *MerkleProof) ComputeRootFromHash(leafHash crypto.Hash) (crypto.Hash, error) {
	if p.TreeSize == 0 || p.LeafIndex >= p.TreeSize {
		return crypto.Hash{}, errors.New("merkle: invalid proof")
	}

	h := leafHash
	idx := p.LeafIndex
	size := p.TreeSize
	pathIdx := 0

	for size > 1 {
		if idx%2 == 0 {
			if idx+1 < size {
				if pathIdx >= len(p.AuditPath) {
					return crypto.Hash{}, errors.New("merkle: proof path exhausted")
				}
				h = NodeHash(h, p.AuditPath[pathIdx])
				pathIdx++
			}
			// else: carried upward, no sibling
		} else {
			if pathIdx >= len(p.AuditPath) {
				return crypto.Hash{}, errors.New("merkle: proof path exhausted")
			}
			h = NodeHash(p.AuditPath[pathIdx], h)
			pathIdx++
		}
		idx /= 2
		size = (size + 1) / 2
	}

	if pathIdx != len(p.AuditPath) {
		return crypto.Hash{}, errors.New("merkle: unused proof elements")
	}

	return h, nil
}

// Verify checks the proof against an expected root using raw leaf data.
func (p *MerkleProof) Verify(leafBytes []byte, expectedRoot crypto.Hash) bool {
	root, err := p.ComputeRoot(leafBytes)
	if err != nil {
		return false
	}
	return root == expectedRoot
}

// VerifyHash checks the proof against an expected root using a pre-hashed leaf.
func (p *MerkleProof) VerifyHash(leafHash crypto.Hash, expectedRoot crypto.Hash) bool {
	root, err := p.ComputeRootFromHash(leafHash)
	if err != nil {
		return false
	}
	return root == expectedRoot
}

func copyHashes(src []crypto.Hash) []crypto.Hash {
	dst := make([]crypto.Hash, len(src))
	copy(dst, src)
	return dst
}
