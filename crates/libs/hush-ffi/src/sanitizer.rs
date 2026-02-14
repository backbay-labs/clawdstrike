//! Output sanitization FFI function.

use std::ffi::{c_char, CStr};

use crate::error::{ffi_try, set_last_error};
use crate::string_to_c;

/// Sanitize model output for secret/PII leakage.
///
/// Returns a JSON string describing the sanitization result, or `NULL` on error.
/// The caller must free the returned string with `hush_free_string`.
///
/// # Safety
///
/// - `text` must be a valid, NUL-terminated UTF-8 C string.
/// - `config_json` may be `NULL` (uses default `OutputSanitizerConfig`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_sanitize_output(
    text: *const c_char,
    config_json: *const c_char,
) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            if text.is_null() {
                set_last_error("text pointer is null");
                return std::ptr::null_mut();
            }

            let text_str = ffi_try!(
                unsafe { CStr::from_ptr(text) }
                    .to_str()
                    .map_err(|e| format!("text is not valid UTF-8: {e}")),
                std::ptr::null_mut()
            );

            let cfg: clawdstrike::OutputSanitizerConfig = if config_json.is_null() {
                clawdstrike::OutputSanitizerConfig::default()
            } else {
                let cfg_str = ffi_try!(
                    unsafe { CStr::from_ptr(config_json) }
                        .to_str()
                        .map_err(|e| format!("config_json is not valid UTF-8: {e}")),
                    std::ptr::null_mut()
                );
                ffi_try!(
                    serde_json::from_str(cfg_str)
                        .map_err(|e| format!("Invalid OutputSanitizerConfig JSON: {e}")),
                    std::ptr::null_mut()
                )
            };

            let sanitizer = clawdstrike::OutputSanitizer::with_config(cfg);
            let result = sanitizer.sanitize_sync(text_str);

            let json = ffi_try!(
                serde_json::to_string(&result)
                    .map_err(|e| format!("Failed to serialize result: {e}")),
                std::ptr::null_mut()
            );
            string_to_c(json)
        },
        std::ptr::null_mut(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_sanitize_output_clean() {
        let text = CString::new("The weather today is sunny.").unwrap();
        let result = unsafe { hush_sanitize_output(text.as_ptr(), std::ptr::null()) };
        assert!(!result.is_null());
        let json_str = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        let v: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert!(v.get("sanitized").is_some());
        unsafe { crate::hush_free_string(result) };
    }

    #[test]
    fn test_sanitize_output_null_text() {
        let result = unsafe { hush_sanitize_output(std::ptr::null(), std::ptr::null()) };
        assert!(result.is_null());
    }

    #[test]
    fn test_sanitize_output_with_config() {
        let text = CString::new("Some text to sanitize").unwrap();
        let config = CString::new("{}").unwrap();
        let result = unsafe { hush_sanitize_output(text.as_ptr(), config.as_ptr()) };
        assert!(!result.is_null());
        let json_str = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        let _v: serde_json::Value = serde_json::from_str(json_str).unwrap();
        unsafe { crate::hush_free_string(result) };
    }
}
