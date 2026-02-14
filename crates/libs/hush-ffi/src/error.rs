//! Thread-local error handling for FFI (OpenSSL/SQLite pattern).
//!
//! Functions that fail set a thread-local error string retrievable via
//! `hush_last_error()`. The string is valid until the next FFI call on
//! the same thread.

use std::any::Any;
use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::c_char;
use std::panic;

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

/// Store an error message in thread-local storage.
pub(crate) fn set_last_error(msg: &str) {
    LAST_ERROR.with(|cell| {
        // Replace NUL bytes so CString::new never fails.
        let sanitised = msg.replace('\0', "\\0");
        if let Ok(cs) = CString::new(sanitised) {
            *cell.borrow_mut() = cs;
        }
    });
}

pub(crate) fn panic_to_string(panic: &(dyn Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic payload was not a string".to_string()
    }
}

pub(crate) fn with_ffi_guard<T, F>(f: F, fallback: T) -> T
where
    F: FnOnce() -> T,
    F: panic::UnwindSafe,
{
    match panic::catch_unwind(f) {
        Ok(value) => value,
        Err(payload) => {
            let message = panic_to_string(payload.as_ref());
            set_last_error(&format!("FFI panic: {message}"));
            fallback
        }
    }
}

/// Return a pointer to the last error message (static, do **not** free).
///
/// Returns an empty string if no error has been recorded on this thread.
///
/// # Safety
///
/// The returned pointer is valid until the next FFI call on the same thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_last_error() -> *const c_char {
    crate::error::with_ffi_guard(
        || {
            // Reading thread-local state is safe but still wrapped to avoid
            // panics unwinding across the FFI boundary.
            LAST_ERROR.with(|cell| cell.borrow().as_ptr())
        },
        std::ptr::null(),
    )
}

/// Evaluate an expression that returns `Result<T, E>`.
///
/// On `Ok(v)` the macro evaluates to `v`.
/// On `Err(e)` it calls `set_last_error`, then evaluates to `$fail`.
///
/// # Examples
///
/// ```ignore
/// let ptr = ffi_try!(some_fallible_call(), std::ptr::null_mut());
/// let code = ffi_try!(another_call(), -1);
/// ```
macro_rules! ffi_try {
    ($expr:expr, $fail:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                $crate::error::set_last_error(&e.to_string());
                return $fail;
            }
        }
    };
}

pub(crate) use ffi_try;
