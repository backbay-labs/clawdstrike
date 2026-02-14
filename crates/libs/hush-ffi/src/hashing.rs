//! SHA-256, Keccak-256, and canonical JSON FFI functions.

use std::ffi::{c_char, CStr};

use crate::error::{ffi_try, set_last_error};

/// Compute SHA-256 hash, writing 32 bytes into `out_32`.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `data` must point to at least `len` readable bytes (may be NULL if `len == 0`).
/// - `out_32` must point to a writable buffer of at least 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_sha256(data: *const u8, len: usize, out_32: *mut u8) -> i32 {
    crate::error::with_ffi_guard(
        || {
            if out_32.is_null() {
                set_last_error("null output pointer");
                return -1;
            }
            let slice = if len == 0 {
                &[]
            } else {
                if data.is_null() {
                    set_last_error("null data pointer with non-zero length");
                    return -1;
                }
                unsafe { std::slice::from_raw_parts(data, len) }
            };
            let hash = hush_core::hashing::sha256(slice);
            unsafe {
                std::ptr::copy_nonoverlapping(hash.as_bytes().as_ptr(), out_32, 32);
            }
            0
        },
        -1,
    )
}

/// Compute SHA-256 hash, returning a lowercase, unprefixed hex string.
///
/// Caller must free the returned string with `hush_free_string`.
/// Returns `NULL` on error.
///
/// # Safety
///
/// `data` must point to at least `len` readable bytes (may be NULL if `len == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_sha256_hex(data: *const u8, len: usize) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            let slice = if len == 0 {
                &[]
            } else {
                if data.is_null() {
                    set_last_error("null data pointer with non-zero length");
                    return std::ptr::null_mut();
                }
                unsafe { std::slice::from_raw_parts(data, len) }
            };
            let hash = hush_core::hashing::sha256(slice);
            crate::string_to_c(hash.to_hex())
        },
        std::ptr::null_mut(),
    )
}

/// Compute Keccak-256 hash, writing 32 bytes into `out_32`.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// - `data` must point to at least `len` readable bytes (may be NULL if `len == 0`).
/// - `out_32` must point to a writable buffer of at least 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_keccak256(data: *const u8, len: usize, out_32: *mut u8) -> i32 {
    crate::error::with_ffi_guard(
        || {
            if out_32.is_null() {
                set_last_error("null output pointer");
                return -1;
            }
            let slice = if len == 0 {
                &[]
            } else {
                if data.is_null() {
                    set_last_error("null data pointer with non-zero length");
                    return -1;
                }
                unsafe { std::slice::from_raw_parts(data, len) }
            };
            let hash = hush_core::hashing::keccak256(slice);
            unsafe {
                std::ptr::copy_nonoverlapping(hash.as_bytes().as_ptr(), out_32, 32);
            }
            0
        },
        -1,
    )
}

/// Compute Keccak-256 hash, returning a lowercase, unprefixed hex string.
///
/// Caller must free the returned string with `hush_free_string`.
/// Returns `NULL` on error.
///
/// # Safety
///
/// `data` must point to at least `len` readable bytes (may be NULL if `len == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_keccak256_hex(data: *const u8, len: usize) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            let slice = if len == 0 {
                &[]
            } else {
                if data.is_null() {
                    set_last_error("null data pointer with non-zero length");
                    return std::ptr::null_mut();
                }
                unsafe { std::slice::from_raw_parts(data, len) }
            };
            let hash = hush_core::hashing::keccak256(slice);
            crate::string_to_c(hash.to_hex())
        },
        std::ptr::null_mut(),
    )
}

/// Canonicalize a JSON string according to RFC 8785.
///
/// Caller must free the returned string with `hush_free_string`.
/// Returns `NULL` on error (invalid JSON, canonicalization failure).
///
/// # Safety
///
/// `json` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_canonicalize_json(json: *const c_char) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            if json.is_null() {
                set_last_error("null pointer");
                return std::ptr::null_mut();
            }
            let c_str = unsafe { CStr::from_ptr(json) };
            let s = ffi_try!(c_str.to_str(), std::ptr::null_mut());
            let value: serde_json::Value = ffi_try!(serde_json::from_str(s), std::ptr::null_mut());
            let canonical = ffi_try!(hush_core::canonicalize_json(&value), std::ptr::null_mut());
            crate::string_to_c(canonical)
        },
        std::ptr::null_mut(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn test_sha256_known_vector() {
        let data = b"hello";
        let mut out = [0u8; 32];
        let ret = unsafe { hush_sha256(data.as_ptr(), data.len(), out.as_mut_ptr()) };
        assert_eq!(ret, 0);
        let hex = hex::encode(out);
        assert_eq!(
            hex,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_empty() {
        let mut out = [0u8; 32];
        let ret = unsafe { hush_sha256(std::ptr::null(), 0, out.as_mut_ptr()) };
        assert_eq!(ret, 0);
        let hex = hex::encode(out);
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_null_output() {
        let data = b"hello";
        let ret = unsafe { hush_sha256(data.as_ptr(), data.len(), std::ptr::null_mut()) };
        assert_eq!(ret, -1);
    }

    #[test]
    fn test_sha256_hex_roundtrip() {
        let data = b"hello";
        let ptr = unsafe { hush_sha256_hex(data.as_ptr(), data.len()) };
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(
            s,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        unsafe { crate::hush_free_string(ptr) };
    }

    #[test]
    fn test_keccak256_known_vector() {
        let mut out = [0u8; 32];
        let ret = unsafe { hush_keccak256(b"".as_ptr(), 0, out.as_mut_ptr()) };
        assert_eq!(ret, 0);
        let hex = hex::encode(out);
        assert_eq!(
            hex,
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn test_keccak256_hex_nonempty() {
        let data = b"hello";
        let ptr = unsafe { hush_keccak256_hex(data.as_ptr(), data.len()) };
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(s.len(), 64);
        unsafe { crate::hush_free_string(ptr) };
    }

    #[test]
    fn test_canonicalize_json_sorts_keys() {
        let input = b"{\"b\":2,\"a\":1}\0";
        let ptr = unsafe { hush_canonicalize_json(input.as_ptr().cast()) };
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(s, r#"{"a":1,"b":2}"#);
        unsafe { crate::hush_free_string(ptr) };
    }

    #[test]
    fn test_canonicalize_json_null_ptr() {
        let ptr = unsafe { hush_canonicalize_json(std::ptr::null()) };
        assert!(ptr.is_null());
    }

    #[test]
    fn test_canonicalize_json_invalid() {
        let input = b"not json\0";
        let ptr = unsafe { hush_canonicalize_json(input.as_ptr().cast()) };
        assert!(ptr.is_null());
    }
}
