//! Receipt signing, verification, hashing, and canonical JSON FFI functions.

use std::ffi::{c_char, CStr};

use hush_core::receipt::PublicKeySet;
use hush_core::signing::PublicKey;
use hush_core::{Receipt, SignedReceipt};

use crate::error::{ffi_try, set_last_error};
use crate::signing::HushKeypair;

/// Verify a signed receipt.
///
/// Returns a JSON string with the verification result.
/// `cosigner_hex` may be `NULL` if there is no co-signer.
/// Caller must free the returned string with `hush_free_string`.
/// Returns `NULL` on error.
///
/// # Safety
///
/// - `receipt_json` must be a valid NUL-terminated C string (JSON-serialized `SignedReceipt`).
/// - `signer_hex` must be a valid NUL-terminated C string (hex-encoded public key).
/// - `cosigner_hex` may be `NULL` or a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_verify_receipt(
    receipt_json: *const c_char,
    signer_hex: *const c_char,
    cosigner_hex: *const c_char,
) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            if receipt_json.is_null() || signer_hex.is_null() {
                set_last_error("null pointer");
                return std::ptr::null_mut();
            }

            let receipt_str = ffi_try!(
                unsafe { CStr::from_ptr(receipt_json) }.to_str(),
                std::ptr::null_mut()
            );
            let signer_str = ffi_try!(
                unsafe { CStr::from_ptr(signer_hex) }.to_str(),
                std::ptr::null_mut()
            );

            let signed: SignedReceipt =
                ffi_try!(serde_json::from_str(receipt_str), std::ptr::null_mut());
            let signer_pk = ffi_try!(PublicKey::from_hex(signer_str), std::ptr::null_mut());

            let keys = if !cosigner_hex.is_null() {
                let cosigner_str = ffi_try!(
                    unsafe { CStr::from_ptr(cosigner_hex) }.to_str(),
                    std::ptr::null_mut()
                );
                let cosigner_pk = ffi_try!(PublicKey::from_hex(cosigner_str), std::ptr::null_mut());
                PublicKeySet::new(signer_pk).with_cosigner(cosigner_pk)
            } else {
                PublicKeySet::new(signer_pk)
            };

            let result = signed.verify(&keys);
            let json = ffi_try!(serde_json::to_string(&result), std::ptr::null_mut());
            crate::string_to_c(json)
        },
        std::ptr::null_mut(),
    )
}

/// Sign an unsigned receipt with a keypair.
///
/// Takes a JSON-serialized `Receipt` and returns a JSON-serialized `SignedReceipt`.
/// Caller must free the returned string with `hush_free_string`.
/// Returns `NULL` on error.
///
/// # Safety
///
/// - `receipt_json` must be a valid NUL-terminated C string (JSON-serialized `Receipt`).
/// - `kp` must be a valid `HushKeypair` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_sign_receipt(
    receipt_json: *const c_char,
    kp: *const HushKeypair,
) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            if receipt_json.is_null() || kp.is_null() {
                set_last_error("null pointer");
                return std::ptr::null_mut();
            }

            let receipt_str = ffi_try!(
                unsafe { CStr::from_ptr(receipt_json) }.to_str(),
                std::ptr::null_mut()
            );
            let receipt: Receipt =
                ffi_try!(serde_json::from_str(receipt_str), std::ptr::null_mut());
            let kp = unsafe { &*kp };

            let signed = ffi_try!(
                SignedReceipt::sign(receipt, &kp.inner),
                std::ptr::null_mut()
            );
            let json = ffi_try!(serde_json::to_string(&signed), std::ptr::null_mut());
            crate::string_to_c(json)
        },
        std::ptr::null_mut(),
    )
}

/// Hash a receipt using the specified algorithm.
///
/// `algorithm` must be `"sha256"` or `"keccak256"`.
/// Returns a hex-encoded hash string with `0x` prefix.
/// Caller must free the returned string with `hush_free_string`.
/// Returns `NULL` on error.
///
/// # Safety
///
/// - `receipt_json` must be a valid NUL-terminated C string (JSON-serialized `Receipt`).
/// - `algorithm` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_hash_receipt(
    receipt_json: *const c_char,
    algorithm: *const c_char,
) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            if receipt_json.is_null() || algorithm.is_null() {
                set_last_error("null pointer");
                return std::ptr::null_mut();
            }

            let receipt_str = ffi_try!(
                unsafe { CStr::from_ptr(receipt_json) }.to_str(),
                std::ptr::null_mut()
            );
            let algo_str = ffi_try!(
                unsafe { CStr::from_ptr(algorithm) }.to_str(),
                std::ptr::null_mut()
            );

            let receipt: Receipt =
                ffi_try!(serde_json::from_str(receipt_str), std::ptr::null_mut());

            let hash = match algo_str {
                "sha256" => ffi_try!(receipt.hash_sha256(), std::ptr::null_mut()),
                "keccak256" => ffi_try!(receipt.hash_keccak256(), std::ptr::null_mut()),
                other => {
                    set_last_error(&format!(
                        "invalid algorithm '{}': use 'sha256' or 'keccak256'",
                        other
                    ));
                    return std::ptr::null_mut();
                }
            };

            crate::string_to_c(hash.to_hex_prefixed())
        },
        std::ptr::null_mut(),
    )
}

/// Get the canonical JSON representation of a receipt (the bytes that are signed).
///
/// Caller must free the returned string with `hush_free_string`.
/// Returns `NULL` on error.
///
/// # Safety
///
/// `receipt_json` must be a valid NUL-terminated C string (JSON-serialized `Receipt`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_receipt_canonical_json(receipt_json: *const c_char) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            if receipt_json.is_null() {
                set_last_error("null pointer");
                return std::ptr::null_mut();
            }

            let receipt_str = ffi_try!(
                unsafe { CStr::from_ptr(receipt_json) }.to_str(),
                std::ptr::null_mut()
            );
            let receipt: Receipt =
                ffi_try!(serde_json::from_str(receipt_str), std::ptr::null_mut());
            let canonical = ffi_try!(receipt.to_canonical_json(), std::ptr::null_mut());
            crate::string_to_c(canonical)
        },
        std::ptr::null_mut(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hush_core::{sha256, Verdict};

    fn make_test_receipt() -> Receipt {
        let content_hash = sha256(b"test content");
        Receipt::new(content_hash, Verdict::pass())
    }

    #[test]
    fn test_sign_and_verify_receipt() {
        let receipt = make_test_receipt();
        let receipt_json = serde_json::to_string(&receipt).unwrap();
        let c_receipt = std::ffi::CString::new(receipt_json).unwrap();

        let kp = unsafe { crate::signing::hush_keypair_generate() };

        // Sign
        let signed_ptr = unsafe { hush_sign_receipt(c_receipt.as_ptr(), kp) };
        assert!(!signed_ptr.is_null());
        let signed_str = unsafe { CStr::from_ptr(signed_ptr) }.to_str().unwrap();

        // Get public key
        let pk_ptr = unsafe { crate::signing::hush_keypair_public_key_hex(kp) };
        let pk_hex = unsafe { CStr::from_ptr(pk_ptr) }.to_str().unwrap();
        let c_pk = std::ffi::CString::new(pk_hex).unwrap();

        // Verify
        let c_signed = std::ffi::CString::new(signed_str).unwrap();
        let result_ptr =
            unsafe { hush_verify_receipt(c_signed.as_ptr(), c_pk.as_ptr(), std::ptr::null()) };
        assert!(!result_ptr.is_null());
        let result_str = unsafe { CStr::from_ptr(result_ptr) }.to_str().unwrap();
        let result: serde_json::Value = serde_json::from_str(result_str).unwrap();
        assert_eq!(result["valid"], true);
        assert_eq!(result["signer_valid"], true);

        unsafe { crate::hush_free_string(signed_ptr) };
        unsafe { crate::hush_free_string(pk_ptr) };
        unsafe { crate::hush_free_string(result_ptr) };
        unsafe { crate::signing::hush_keypair_destroy(kp) };
    }

    #[test]
    fn test_hash_receipt_sha256() {
        let receipt = make_test_receipt();
        let receipt_json = serde_json::to_string(&receipt).unwrap();
        let c_receipt = std::ffi::CString::new(receipt_json).unwrap();
        let c_algo = std::ffi::CString::new("sha256").unwrap();

        let hash_ptr = unsafe { hush_hash_receipt(c_receipt.as_ptr(), c_algo.as_ptr()) };
        assert!(!hash_ptr.is_null());
        let hash_str = unsafe { CStr::from_ptr(hash_ptr) }.to_str().unwrap();
        assert!(hash_str.starts_with("0x"));
        assert_eq!(hash_str.len(), 66);

        unsafe { crate::hush_free_string(hash_ptr) };
    }

    #[test]
    fn test_hash_receipt_keccak256() {
        let receipt = make_test_receipt();
        let receipt_json = serde_json::to_string(&receipt).unwrap();
        let c_receipt = std::ffi::CString::new(receipt_json).unwrap();
        let c_algo = std::ffi::CString::new("keccak256").unwrap();

        let hash_ptr = unsafe { hush_hash_receipt(c_receipt.as_ptr(), c_algo.as_ptr()) };
        assert!(!hash_ptr.is_null());
        let hash_str = unsafe { CStr::from_ptr(hash_ptr) }.to_str().unwrap();
        assert!(hash_str.starts_with("0x"));
        assert_eq!(hash_str.len(), 66);

        unsafe { crate::hush_free_string(hash_ptr) };
    }

    #[test]
    fn test_hash_receipt_invalid_algorithm() {
        let receipt = make_test_receipt();
        let receipt_json = serde_json::to_string(&receipt).unwrap();
        let c_receipt = std::ffi::CString::new(receipt_json).unwrap();
        let c_algo = std::ffi::CString::new("md5").unwrap();

        let hash_ptr = unsafe { hush_hash_receipt(c_receipt.as_ptr(), c_algo.as_ptr()) };
        assert!(hash_ptr.is_null());
    }

    #[test]
    fn test_receipt_canonical_json() {
        let receipt = make_test_receipt();
        let receipt_json = serde_json::to_string(&receipt).unwrap();
        let c_receipt = std::ffi::CString::new(receipt_json).unwrap();

        let canon_ptr = unsafe { hush_receipt_canonical_json(c_receipt.as_ptr()) };
        assert!(!canon_ptr.is_null());
        let canon_str = unsafe { CStr::from_ptr(canon_ptr) }.to_str().unwrap();
        assert!(!canon_str.is_empty());

        // Calling again should produce identical output
        let canon_ptr2 = unsafe { hush_receipt_canonical_json(c_receipt.as_ptr()) };
        let canon_str2 = unsafe { CStr::from_ptr(canon_ptr2) }.to_str().unwrap();
        assert_eq!(canon_str, canon_str2);

        unsafe { crate::hush_free_string(canon_ptr) };
        unsafe { crate::hush_free_string(canon_ptr2) };
    }

    #[test]
    fn test_null_pointers() {
        assert!(unsafe {
            hush_verify_receipt(std::ptr::null(), std::ptr::null(), std::ptr::null())
        }
        .is_null());
        assert!(unsafe { hush_sign_receipt(std::ptr::null(), std::ptr::null()) }.is_null());
        assert!(unsafe { hush_hash_receipt(std::ptr::null(), std::ptr::null()) }.is_null());
        assert!(unsafe { hush_receipt_canonical_json(std::ptr::null()) }.is_null());
    }
}
