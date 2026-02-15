package hush

import (
	"errors"
	"runtime"
)

// MerkleRoot computes the Merkle root from a JSON array of hex-encoded leaf hashes.
// Returns the root hash as a hex string.
func MerkleRoot(leafHashesJSON string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cl, err := allocCString(leafHashesJSON)
	if err != nil {
		return "", err
	}
	defer freeCString(cl)

	p := ffiMerkleRoot(cl)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// MerkleProof generates a Merkle inclusion proof for the leaf at the given index.
// Returns the proof as a JSON string.
func MerkleProof(leafHashesJSON string, index int) (string, error) {
	if index < 0 {
		return "", errors.New("hush: index must be non-negative")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cl, err := allocCString(leafHashesJSON)
	if err != nil {
		return "", err
	}
	defer freeCString(cl)

	p := ffiMerkleProof(cl, index)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// VerifyMerkleProof verifies a Merkle inclusion proof.
// Returns true if the proof is valid.
func VerifyMerkleProof(leafHex, proofJSON, rootHex string) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	clh, err := allocCString(leafHex)
	if err != nil {
		return false, err
	}
	defer freeCString(clh)
	cpj, err := allocCString(proofJSON)
	if err != nil {
		return false, err
	}
	defer freeCString(cpj)
	crh, err := allocCString(rootHex)
	if err != nil {
		return false, err
	}
	defer freeCString(crh)

	rc := ffiVerifyMerkleProof(clh, cpj, crh)
	switch rc {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, lastError()
	}
}
