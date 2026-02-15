package hush

import "runtime"

// VerifyReceipt verifies a signed receipt JSON against a signer public key.
// cosignerHex is optional (pass nil to skip cosigner verification).
// Returns the verification result as a JSON string.
func VerifyReceipt(receiptJSON, signerHex string, cosignerHex *string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cr, err := allocCString(receiptJSON)
	if err != nil {
		return "", err
	}
	defer freeCString(cr)
	cs, err := allocCString(signerHex)
	if err != nil {
		return "", err
	}
	defer freeCString(cs)
	cc, err := allocCStringOpt(cosignerHex)
	if err != nil {
		return "", err
	}
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
	ptr, unlock, err := kp.rlockPtrOrErr()
	if err != nil {
		return "", err
	}
	defer unlock()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cr, err := allocCString(receiptJSON)
	if err != nil {
		return "", err
	}
	defer freeCString(cr)

	p := ffiSignReceipt(cr, ptr)
	runtime.KeepAlive(kp)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// HashReceipt hashes a receipt with the given algorithm ("sha256" or "keccak256").
// Returns the hash as a hex string.
func HashReceipt(receiptJSON, algorithm string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cr, err := allocCString(receiptJSON)
	if err != nil {
		return "", err
	}
	defer freeCString(cr)
	ca, err := allocCString(algorithm)
	if err != nil {
		return "", err
	}
	defer freeCString(ca)

	p := ffiHashReceipt(cr, ca)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// ReceiptCanonicalJSON returns the canonical JSON (RFC 8785) representation of a receipt.
func ReceiptCanonicalJSON(receiptJSON string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cr, err := allocCString(receiptJSON)
	if err != nil {
		return "", err
	}
	defer freeCString(cr)

	p := ffiReceiptCanonicalJSON(cr)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}
