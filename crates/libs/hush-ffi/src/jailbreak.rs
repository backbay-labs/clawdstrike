//! Jailbreak detection FFI function.

use std::ffi::{c_char, CStr};
use std::sync::OnceLock;

use crate::error::{ffi_try, set_last_error};
use crate::string_to_c;

static DEFAULT_DETECTOR: OnceLock<clawdstrike::JailbreakDetector> = OnceLock::new();

/// Detect jailbreak attempts in the given text.
///
/// Returns a JSON string describing the detection result, or `NULL` on error.
/// The caller must free the returned string with `hush_free_string`.
///
/// # Safety
///
/// - `text` must be a valid, NUL-terminated UTF-8 C string.
/// - `session_id` may be `NULL` (treated as no session).
/// - `config_json` may be `NULL` (uses a default detector singleton).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_detect_jailbreak(
    text: *const c_char,
    session_id: *const c_char,
    config_json: *const c_char,
) -> *mut c_char {
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

    let session_id_str = if session_id.is_null() {
        None
    } else {
        Some(ffi_try!(
            unsafe { CStr::from_ptr(session_id) }
                .to_str()
                .map_err(|e| format!("session_id is not valid UTF-8: {e}")),
            std::ptr::null_mut()
        ))
    };

    let result = if config_json.is_null() {
        let detector = DEFAULT_DETECTOR.get_or_init(clawdstrike::JailbreakDetector::new);
        futures::executor::block_on(detector.detect(text_str, session_id_str))
    } else {
        let cfg_str = ffi_try!(
            unsafe { CStr::from_ptr(config_json) }
                .to_str()
                .map_err(|e| format!("config_json is not valid UTF-8: {e}")),
            std::ptr::null_mut()
        );
        let cfg: clawdstrike::JailbreakGuardConfig = ffi_try!(
            serde_json::from_str(cfg_str)
                .map_err(|e| format!("Invalid JailbreakGuardConfig JSON: {e}")),
            std::ptr::null_mut()
        );
        let detector = clawdstrike::JailbreakDetector::with_config(cfg);
        futures::executor::block_on(detector.detect(text_str, session_id_str))
    };

    let json = ffi_try!(
        serde_json::to_string(&result).map_err(|e| format!("Failed to serialize result: {e}")),
        std::ptr::null_mut()
    );
    string_to_c(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_detect_jailbreak_benign() {
        let text = CString::new("What is the weather today?").unwrap();
        let result =
            unsafe { hush_detect_jailbreak(text.as_ptr(), std::ptr::null(), std::ptr::null()) };
        assert!(!result.is_null());
        let json_str = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        let v: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert!(v.get("blocked").is_some());
        unsafe { crate::hush_free_string(result) };
    }

    #[test]
    fn test_detect_jailbreak_null_text() {
        let result =
            unsafe { hush_detect_jailbreak(std::ptr::null(), std::ptr::null(), std::ptr::null()) };
        assert!(result.is_null());
    }

    #[test]
    fn test_detect_jailbreak_with_session_id() {
        let text = CString::new("Hello world").unwrap();
        let session = CString::new("session-123").unwrap();
        let result = unsafe {
            hush_detect_jailbreak(text.as_ptr(), session.as_ptr(), std::ptr::null())
        };
        assert!(!result.is_null());
        let json_str = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        let v: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert!(v.get("blocked").is_some());
        unsafe { crate::hush_free_string(result) };
    }
}
