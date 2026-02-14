#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
//! C ABI for hush-core and clawdstrike.
//!
//! This crate exposes a flat C API surface that can be consumed from any
//! language with FFI support (C#, Go, Swift, Kotlin, Ruby, …).
//!
//! # Error handling
//!
//! Functions that can fail return a sentinel value (`NULL` for pointers,
//! `-1` for integers). Call [`hush_last_error`] to retrieve a human-readable
//! error message (valid until the next FFI call on the same thread).
//!
//! # Memory
//!
//! Callee-allocated strings must be freed with [`hush_free_string`].
//! Fixed-size outputs (hashes, signatures) write into caller-provided buffers.

mod error;
mod hashing;
mod jailbreak;
mod merkle;
mod receipt;
mod sanitizer;
mod signing;
mod verify;
mod watermark;

use std::ffi::CString;
use std::os::raw::c_char;

/// Return the library version (static string, do **not** free).
///
/// # Safety
///
/// The returned pointer is valid for the lifetime of the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_version() -> *const c_char {
    // Computed once; leaked intentionally so the pointer is 'static.
    static VERSION: std::sync::OnceLock<CString> = std::sync::OnceLock::new();
    VERSION
        .get_or_init(|| {
            CString::new(env!("CARGO_PKG_VERSION"))
                .unwrap_or_else(|_| CString::new("unknown").unwrap_or_default())
        })
        .as_ptr()
}

/// Free a string previously returned by this library.
///
/// Passing `NULL` is a no-op.
///
/// # Safety
///
/// `ptr` must have been returned by a `hush_*` function that documents
/// "caller must free with `hush_free_string`".
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

/// Free a byte buffer previously returned by this library.
///
/// Passing `NULL` is a no-op.
///
/// # Safety
///
/// `ptr` and `len` must correspond to a `Vec<u8>` returned by a `hush_*`
/// function that documents "caller must free with `hush_free_bytes`".
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        unsafe {
            drop(Vec::from_raw_parts(ptr, len, len));
        }
    }
}

/// Helper: convert a Rust `String` into a caller-owned `*mut c_char`.
///
/// On allocation failure returns `NULL` and sets the last error.
pub(crate) fn string_to_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(e) => {
            error::set_last_error(&format!("string contains NUL byte: {e}"));
            std::ptr::null_mut()
        }
    }
}
