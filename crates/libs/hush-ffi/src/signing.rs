//! Ed25519 keypair lifecycle (opaque `HushKeypair`) FFI functions.

use std::ffi::{c_char, CStr};

use crate::error::{ffi_try, set_last_error};

/// Opaque Ed25519 keypair handle.
pub struct HushKeypair {
    pub(crate) inner: hush_core::Keypair,
}

/// Generate a new random Ed25519 keypair.
///
/// Caller must free with `hush_keypair_destroy`.
///
/// # Safety
///
/// The returned pointer is exclusively owned by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_keypair_generate() -> *mut HushKeypair {
    crate::error::with_ffi_guard(
        || {
            Box::into_raw(Box::new(HushKeypair {
                inner: hush_core::Keypair::generate(),
            }))
        },
        std::ptr::null_mut(),
    )
}

/// Create a keypair from a 32-byte seed.
///
/// Caller must free with `hush_keypair_destroy`.
/// Returns `NULL` on error.
///
/// # Safety
///
/// `seed_32` must point to at least 32 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_keypair_from_seed(seed_32: *const u8) -> *mut HushKeypair {
    crate::error::with_ffi_guard(
        || {
            if seed_32.is_null() {
                set_last_error("null pointer");
                return std::ptr::null_mut();
            }
            let slice = unsafe { std::slice::from_raw_parts(seed_32, 32) };
            let mut seed = [0u8; 32];
            seed.copy_from_slice(slice);
            Box::into_raw(Box::new(HushKeypair {
                inner: hush_core::Keypair::from_seed(&seed),
            }))
        },
        std::ptr::null_mut(),
    )
}

/// Create a keypair from a hex-encoded seed.
///
/// Caller must free with `hush_keypair_destroy`.
/// Returns `NULL` on error.
///
/// # Safety
///
/// `hex` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_keypair_from_hex(hex: *const c_char) -> *mut HushKeypair {
    crate::error::with_ffi_guard(
        || {
            if hex.is_null() {
                set_last_error("null pointer");
                return std::ptr::null_mut();
            }
            let c_str = unsafe { CStr::from_ptr(hex) };
            let s = ffi_try!(c_str.to_str(), std::ptr::null_mut());
            let kp = ffi_try!(hush_core::Keypair::from_hex(s), std::ptr::null_mut());
            Box::into_raw(Box::new(HushKeypair { inner: kp }))
        },
        std::ptr::null_mut(),
    )
}

/// Get the public key as a hex-encoded string (64 hex chars, no 0x prefix).
///
/// Caller must free with `hush_free_string`.
/// Returns `NULL` on error.
///
/// # Safety
///
/// `kp` must be a valid pointer returned by a `hush_keypair_*` constructor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_keypair_public_key_hex(kp: *const HushKeypair) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            if kp.is_null() {
                set_last_error("null pointer");
                return std::ptr::null_mut();
            }
            let kp = unsafe { &*kp };
            crate::string_to_c(kp.inner.public_key().to_hex())
        },
        std::ptr::null_mut(),
    )
}

/// Write the 32-byte public key into `out_32`.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `kp` must be a valid `HushKeypair` pointer.
/// - `out_32` must point to a writable buffer of at least 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_keypair_public_key_bytes(
    kp: *const HushKeypair,
    out_32: *mut u8,
) -> i32 {
    crate::error::with_ffi_guard(
        || {
            if kp.is_null() || out_32.is_null() {
                set_last_error("null pointer");
                return -1;
            }
            let kp = unsafe { &*kp };
            let pk = kp.inner.public_key();
            let bytes = pk.as_bytes();
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_32, 32);
            }
            0
        },
        -1,
    )
}

/// Sign a message, returning the signature as a hex-encoded string (128 hex chars).
///
/// Caller must free with `hush_free_string`.
/// Returns `NULL` on error.
///
/// # Safety
///
/// - `kp` must be a valid `HushKeypair` pointer.
/// - `msg` must point to at least `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_keypair_sign_hex(
    kp: *const HushKeypair,
    msg: *const u8,
    len: usize,
) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            if kp.is_null() {
                set_last_error("null pointer");
                return std::ptr::null_mut();
            }
            let kp = unsafe { &*kp };
            let slice = if len == 0 {
                &[]
            } else {
                if msg.is_null() {
                    set_last_error("null data pointer with non-zero length");
                    return std::ptr::null_mut();
                }
                unsafe { std::slice::from_raw_parts(msg, len) }
            };
            let sig = kp.inner.sign(slice);
            crate::string_to_c(sig.to_hex())
        },
        std::ptr::null_mut(),
    )
}

/// Sign a message, writing the 64-byte signature into `out_64`.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `kp` must be a valid `HushKeypair` pointer.
/// - `msg` must point to at least `len` readable bytes.
/// - `out_64` must point to a writable buffer of at least 64 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_keypair_sign(
    kp: *const HushKeypair,
    msg: *const u8,
    len: usize,
    out_64: *mut u8,
) -> i32 {
    crate::error::with_ffi_guard(
        || {
            if kp.is_null() || out_64.is_null() {
                set_last_error("null pointer");
                return -1;
            }
            let kp = unsafe { &*kp };
            let slice = if len == 0 {
                &[]
            } else {
                if msg.is_null() {
                    set_last_error("null data pointer with non-zero length");
                    return -1;
                }
                unsafe { std::slice::from_raw_parts(msg, len) }
            };
            let sig = kp.inner.sign(slice);
            let bytes = sig.to_bytes();
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_64, 64);
            }
            0
        },
        -1,
    )
}

/// Export the keypair seed as a hex-encoded string (64 hex chars).
///
/// Caller must free with `hush_free_string`.
/// Returns `NULL` on error.
///
/// # Safety
///
/// `kp` must be a valid `HushKeypair` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_keypair_to_hex(kp: *const HushKeypair) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            if kp.is_null() {
                set_last_error("null pointer");
                return std::ptr::null_mut();
            }
            let kp = unsafe { &*kp };
            crate::string_to_c(kp.inner.to_hex())
        },
        std::ptr::null_mut(),
    )
}

/// Destroy a keypair, freeing its memory.
///
/// Passing `NULL` is a no-op.
///
/// # Safety
///
/// `kp` must have been returned by a `hush_keypair_*` constructor, and must
/// not be used after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_keypair_destroy(kp: *mut HushKeypair) {
    crate::error::with_ffi_guard(
        || {
            if !kp.is_null() {
                unsafe {
                    drop(Box::from_raw(kp));
                }
            }
        },
        (),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn test_generate_and_destroy() {
        let kp = unsafe { hush_keypair_generate() };
        assert!(!kp.is_null());
        unsafe { hush_keypair_destroy(kp) };
    }

    #[test]
    fn test_destroy_null_is_noop() {
        unsafe { hush_keypair_destroy(std::ptr::null_mut()) };
    }

    #[test]
    fn test_from_seed_roundtrip() {
        let seed = [42u8; 32];
        let kp = unsafe { hush_keypair_from_seed(seed.as_ptr()) };
        assert!(!kp.is_null());

        let hex_ptr = unsafe { hush_keypair_public_key_hex(kp) };
        assert!(!hex_ptr.is_null());
        let pk_hex = unsafe { CStr::from_ptr(hex_ptr) }.to_str().unwrap();
        assert_eq!(pk_hex.len(), 64);

        unsafe { crate::hush_free_string(hex_ptr) };
        unsafe { hush_keypair_destroy(kp) };
    }

    #[test]
    fn test_from_hex_roundtrip() {
        let seed_hex = "2a".repeat(32);
        let c_hex = std::ffi::CString::new(seed_hex.clone()).unwrap();
        let kp = unsafe { hush_keypair_from_hex(c_hex.as_ptr()) };
        assert!(!kp.is_null());

        let export_ptr = unsafe { hush_keypair_to_hex(kp) };
        assert!(!export_ptr.is_null());
        let exported = unsafe { CStr::from_ptr(export_ptr) }.to_str().unwrap();
        assert_eq!(exported, seed_hex);

        unsafe { crate::hush_free_string(export_ptr) };
        unsafe { hush_keypair_destroy(kp) };
    }

    #[test]
    fn test_public_key_bytes() {
        let kp = unsafe { hush_keypair_generate() };
        let mut out = [0u8; 32];
        let ret = unsafe { hush_keypair_public_key_bytes(kp, out.as_mut_ptr()) };
        assert_eq!(ret, 0);
        assert!(out.iter().any(|&b| b != 0));
        unsafe { hush_keypair_destroy(kp) };
    }

    #[test]
    fn test_sign_hex_produces_128_chars() {
        let kp = unsafe { hush_keypair_generate() };
        let msg = b"test message";
        let sig_ptr = unsafe { hush_keypair_sign_hex(kp, msg.as_ptr(), msg.len()) };
        assert!(!sig_ptr.is_null());
        let sig_hex = unsafe { CStr::from_ptr(sig_ptr) }.to_str().unwrap();
        assert_eq!(sig_hex.len(), 128);

        unsafe { crate::hush_free_string(sig_ptr) };
        unsafe { hush_keypair_destroy(kp) };
    }

    #[test]
    fn test_sign_bytes() {
        let kp = unsafe { hush_keypair_generate() };
        let msg = b"test";
        let mut sig = [0u8; 64];
        let ret = unsafe { hush_keypair_sign(kp, msg.as_ptr(), msg.len(), sig.as_mut_ptr()) };
        assert_eq!(ret, 0);
        assert!(sig.iter().any(|&b| b != 0));
        unsafe { hush_keypair_destroy(kp) };
    }

    #[test]
    fn test_null_pointer_checks() {
        assert!(unsafe { hush_keypair_from_seed(std::ptr::null()) }.is_null());
        assert!(unsafe { hush_keypair_from_hex(std::ptr::null()) }.is_null());
        assert!(unsafe { hush_keypair_public_key_hex(std::ptr::null()) }.is_null());
        assert_eq!(
            unsafe { hush_keypair_public_key_bytes(std::ptr::null(), [0u8; 32].as_mut_ptr()) },
            -1
        );
        assert!(unsafe { hush_keypair_sign_hex(std::ptr::null(), b"x".as_ptr(), 1) }.is_null());
        assert_eq!(
            unsafe {
                hush_keypair_sign(std::ptr::null(), b"x".as_ptr(), 1, [0u8; 64].as_mut_ptr())
            },
            -1
        );
        assert!(unsafe { hush_keypair_to_hex(std::ptr::null()) }.is_null());
    }

    #[test]
    fn test_deterministic_seed() {
        let seed = [1u8; 32];
        let kp1 = unsafe { hush_keypair_from_seed(seed.as_ptr()) };
        let kp2 = unsafe { hush_keypair_from_seed(seed.as_ptr()) };

        let pk1_ptr = unsafe { hush_keypair_public_key_hex(kp1) };
        let pk2_ptr = unsafe { hush_keypair_public_key_hex(kp2) };
        let pk1 = unsafe { CStr::from_ptr(pk1_ptr) }.to_str().unwrap();
        let pk2 = unsafe { CStr::from_ptr(pk2_ptr) }.to_str().unwrap();
        assert_eq!(pk1, pk2);

        unsafe { crate::hush_free_string(pk1_ptr) };
        unsafe { crate::hush_free_string(pk2_ptr) };
        unsafe { hush_keypair_destroy(kp1) };
        unsafe { hush_keypair_destroy(kp2) };
    }
}
