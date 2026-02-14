//! Ed25519 signature verification FFI functions.

use std::ffi::{c_char, CStr};

use hush_core::signing::{PublicKey, Signature};

use crate::error::{ffi_try, set_last_error};

/// Verify an Ed25519 signature using hex-encoded public key and signature.
///
/// Returns 1 if valid, 0 if invalid, -1 on error.
///
/// # Safety
///
/// - `pubkey_hex` must be a valid NUL-terminated C string (64 hex chars, optional 0x prefix).
/// - `msg` must point to at least `msg_len` readable bytes (may be NULL if `msg_len == 0`).
/// - `sig_hex` must be a valid NUL-terminated C string (128 hex chars, optional 0x prefix).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_verify_ed25519(
    pubkey_hex: *const c_char,
    msg: *const u8,
    msg_len: usize,
    sig_hex: *const c_char,
) -> i32 {
    crate::error::with_ffi_guard(
        || {
            if pubkey_hex.is_null() || sig_hex.is_null() {
                set_last_error("null pointer");
                return -1;
            }

            let pk_str = ffi_try!(unsafe { CStr::from_ptr(pubkey_hex) }.to_str(), -1);
            let sig_str = ffi_try!(unsafe { CStr::from_ptr(sig_hex) }.to_str(), -1);

            let pk = ffi_try!(PublicKey::from_hex(pk_str), -1);
            let sig = ffi_try!(Signature::from_hex(sig_str), -1);

            let message = if msg_len == 0 {
                &[]
            } else {
                if msg.is_null() {
                    set_last_error("null data pointer with non-zero length");
                    return -1;
                }
                unsafe { std::slice::from_raw_parts(msg, msg_len) }
            };

            i32::from(pk.verify(message, &sig))
        },
        -1,
    )
}

/// Verify an Ed25519 signature using raw byte pointers.
///
/// Returns 1 if valid, 0 if invalid, -1 on error.
///
/// # Safety
///
/// - `pubkey_32` must point to 32 readable bytes.
/// - `msg` must point to at least `msg_len` readable bytes (may be NULL if `msg_len == 0`).
/// - `sig_64` must point to 64 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_verify_ed25519_bytes(
    pubkey_32: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig_64: *const u8,
) -> i32 {
    crate::error::with_ffi_guard(
        || {
            if pubkey_32.is_null() || sig_64.is_null() {
                set_last_error("null pointer");
                return -1;
            }

            let pk_slice = unsafe { std::slice::from_raw_parts(pubkey_32, 32) };
            let sig_slice = unsafe { std::slice::from_raw_parts(sig_64, 64) };

            let mut pk_bytes = [0u8; 32];
            pk_bytes.copy_from_slice(pk_slice);

            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(sig_slice);

            let pk = ffi_try!(PublicKey::from_bytes(&pk_bytes), -1);
            let sig = Signature::from_bytes(&sig_bytes);

            let message = if msg_len == 0 {
                &[]
            } else {
                if msg.is_null() {
                    set_last_error("null data pointer with non-zero length");
                    return -1;
                }
                unsafe { std::slice::from_raw_parts(msg, msg_len) }
            };

            i32::from(pk.verify(message, &sig))
        },
        -1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_hex_roundtrip() {
        let kp = hush_core::Keypair::generate();
        let msg = b"hello ed25519";
        let sig = kp.sign(msg);

        let pk_hex = std::ffi::CString::new(kp.public_key().to_hex()).unwrap();
        let sig_hex = std::ffi::CString::new(sig.to_hex()).unwrap();

        let result = unsafe {
            hush_verify_ed25519(pk_hex.as_ptr(), msg.as_ptr(), msg.len(), sig_hex.as_ptr())
        };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_verify_hex_wrong_message() {
        let kp = hush_core::Keypair::generate();
        let sig = kp.sign(b"original");

        let pk_hex = std::ffi::CString::new(kp.public_key().to_hex()).unwrap();
        let sig_hex = std::ffi::CString::new(sig.to_hex()).unwrap();

        let wrong = b"wrong";
        let result = unsafe {
            hush_verify_ed25519(
                pk_hex.as_ptr(),
                wrong.as_ptr(),
                wrong.len(),
                sig_hex.as_ptr(),
            )
        };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_verify_hex_null_ptrs() {
        let dummy = std::ffi::CString::new("aa".repeat(32)).unwrap();
        assert_eq!(
            unsafe { hush_verify_ed25519(std::ptr::null(), b"x".as_ptr(), 1, dummy.as_ptr()) },
            -1
        );
        assert_eq!(
            unsafe { hush_verify_ed25519(dummy.as_ptr(), b"x".as_ptr(), 1, std::ptr::null()) },
            -1
        );
    }

    #[test]
    fn test_verify_bytes_roundtrip() {
        let kp = hush_core::Keypair::generate();
        let msg = b"hello bytes";
        let sig = kp.sign(msg);

        let pk = kp.public_key();
        let pk_bytes = pk.as_bytes();
        let sig_bytes = sig.to_bytes();

        let result = unsafe {
            hush_verify_ed25519_bytes(
                pk_bytes.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                sig_bytes.as_ptr(),
            )
        };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_verify_bytes_wrong_sig() {
        let kp = hush_core::Keypair::generate();
        let msg = b"hello";
        let _sig = kp.sign(msg);

        let pk = kp.public_key();
        let pk_bytes = pk.as_bytes();
        let bad_sig = [0u8; 64];

        let result = unsafe {
            hush_verify_ed25519_bytes(pk_bytes.as_ptr(), msg.as_ptr(), msg.len(), bad_sig.as_ptr())
        };
        // 0 (invalid) or -1 (error if bad sig bytes are rejected by dalek)
        assert!(result == 0 || result == -1);
    }

    #[test]
    fn test_verify_bytes_null_ptrs() {
        let dummy = [0u8; 32];
        let sig = [0u8; 64];
        assert_eq!(
            unsafe { hush_verify_ed25519_bytes(std::ptr::null(), b"x".as_ptr(), 1, sig.as_ptr()) },
            -1
        );
        assert_eq!(
            unsafe {
                hush_verify_ed25519_bytes(dummy.as_ptr(), b"x".as_ptr(), 1, std::ptr::null())
            },
            -1
        );
    }

    #[test]
    fn test_verify_empty_message() {
        let kp = hush_core::Keypair::generate();
        let msg: &[u8] = b"";
        let sig = kp.sign(msg);

        let pk_hex = std::ffi::CString::new(kp.public_key().to_hex()).unwrap();
        let sig_hex = std::ffi::CString::new(sig.to_hex()).unwrap();

        let result =
            unsafe { hush_verify_ed25519(pk_hex.as_ptr(), std::ptr::null(), 0, sig_hex.as_ptr()) };
        assert_eq!(result, 1);
    }
}
