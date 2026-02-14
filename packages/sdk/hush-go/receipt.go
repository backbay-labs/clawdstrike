package hush

// VerifyReceipt verifies a signed receipt JSON against a signer public key.
// cosignerHex is optional (pass nil to skip cosigner verification).
// Returns the verification result as a JSON string.
func VerifyReceipt(receiptJSON, signerHex string, cosignerHex *string) (string, error) {
	cr := allocCString(receiptJSON)
	defer freeCString(cr)
	cs := allocCString(signerHex)
	defer freeCString(cs)
	cc := allocCStringOpt(cosignerHex)
	defer freeCString(cc)

	p := ffiVerifyReceipt(cr, cs, cc)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// SignReceipt signs an unsigned receipt JSON with a keypair.
// Returns the signed receipt as a JSON string.
func SignReceipt(receiptJSON string, kp *Keypair) (string, error) {
	cr := allocCString(receiptJSON)
	defer freeCString(cr)

	p := ffiSignReceipt(cr, kp.ptr)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// HashReceipt hashes a receipt with the given algorithm ("sha256" or "keccak256").
// Returns the hash as a hex string.
func HashReceipt(receiptJSON, algorithm string) (string, error) {
	cr := allocCString(receiptJSON)
	defer freeCString(cr)
	ca := allocCString(algorithm)
	defer freeCString(ca)

	p := ffiHashReceipt(cr, ca)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// ReceiptCanonicalJSON returns the canonical JSON (RFC 8785) representation of a receipt.
func ReceiptCanonicalJSON(receiptJSON string) (string, error) {
	cr := allocCString(receiptJSON)
	defer freeCString(cr)

	p := ffiReceiptCanonicalJSON(cr)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}
