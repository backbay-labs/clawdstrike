//! Prompt watermarking FFI functions.

use std::collections::{HashMap, VecDeque};
use std::ffi::{c_char, CStr};
use std::sync::{Arc, Mutex, OnceLock};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::error::{ffi_try, set_last_error};
use crate::string_to_c;

const MAX_WATERMARKER_CACHE_ENTRIES: usize = 128;

#[derive(Default)]
struct WatermarkerCache {
    map: HashMap<String, CachedWatermarker>,
    // Tracks only non-pinned entries (pinned entries must not be evicted).
    // Most-recently-used (back) -> least-recently-used (front).
    lru_non_pinned: VecDeque<String>,
}

impl WatermarkerCache {
    fn touch_non_pinned(&mut self, key: &str) {
        if let Some(pos) = self.lru_non_pinned.iter().position(|k| k == key) {
            self.lru_non_pinned.remove(pos);
        }
        self.lru_non_pinned.push_back(key.to_string());
    }

    fn evict_one_non_pinned(&mut self) -> bool {
        while let Some(old_key) = self.lru_non_pinned.pop_front() {
            match self.map.get(&old_key) {
                Some(entry) if entry.pinned => continue, // shouldn't happen, but avoid evicting
                Some(_) => {
                    self.map.remove(&old_key);
                    return true;
                }
                None => continue,
            }
        }
        false
    }
}

struct CachedWatermarker {
    /// If true, re-creating this watermarker would generate a new random keypair, so eviction
    /// would silently rotate keys and break verification for callers that previously trusted the
    /// public key.
    pinned: bool,
    wm: Arc<clawdstrike::PromptWatermarker>,
}

static WATERMARKERS: OnceLock<Mutex<WatermarkerCache>> = OnceLock::new();

fn parse_config_and_key(
    config_json: &str,
) -> Result<(clawdstrike::WatermarkConfig, String, bool), String> {
    let cfg: clawdstrike::WatermarkConfig =
        serde_json::from_str(config_json).map_err(|e| format!("invalid WatermarkConfig: {e}"))?;
    let pinned = cfg.private_key.is_none() && cfg.generate_keypair;

    let value = serde_json::to_value(&cfg).map_err(|e| format!("Invalid WatermarkConfig: {e}"))?;
    let key = hush_core::canonicalize_json(&value).map_err(|e| e.to_string())?;
    Ok((cfg, key, pinned))
}

fn get_or_create_watermarker(
    config_json: &str,
) -> Result<Arc<clawdstrike::PromptWatermarker>, String> {
    let (cfg, key, pinned) = parse_config_and_key(config_json)?;

    let cache = WATERMARKERS.get_or_init(|| Mutex::new(WatermarkerCache::default()));
    let mut guard = cache
        .lock()
        .map_err(|_| "watermarker lock poisoned".to_string())?;
    if let Some(entry) = guard.map.get(&key) {
        let wm = entry.wm.clone();
        let pinned_entry = entry.pinned;
        if !pinned_entry {
            guard.touch_non_pinned(&key);
        }
        return Ok(wm);
    }

    let mut should_cache = true;
    if guard.map.len() >= MAX_WATERMARKER_CACHE_ENTRIES {
        if guard.evict_one_non_pinned() {
            // ok
        } else if pinned {
            return Err(format!(
                "watermarker cache full ({MAX_WATERMARKER_CACHE_ENTRIES} entries) and cannot evict \
                 generate_keypair entries; provide private_key or increase cache size"
            ));
        } else {
            // Deterministic key (private_key provided): safe to skip caching rather than evicting
            // a pinned entry and silently rotating its key.
            should_cache = false;
        }
    }

    let wm = clawdstrike::PromptWatermarker::new(cfg).map_err(|e| format!("{e:?}"))?;
    let wm = Arc::new(wm);
    if should_cache {
        guard.map.insert(
            key.clone(),
            CachedWatermarker {
                pinned,
                wm: wm.clone(),
            },
        );
        if !pinned {
            guard.touch_non_pinned(&key);
        }
    }
    Ok(wm)
}

/// Return the hex-encoded public key for a watermark configuration.
///
/// Returns a C string, or `NULL` on error.
/// The caller must free the returned string with `hush_free_string`.
///
/// # Safety
///
/// `config_json` must be a valid, NUL-terminated UTF-8 C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_watermark_public_key(config_json: *const c_char) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            if config_json.is_null() {
                set_last_error("config_json pointer is null");
                return std::ptr::null_mut();
            }

            let cfg_str = ffi_try!(
                unsafe { CStr::from_ptr(config_json) }
                    .to_str()
                    .map_err(|e| format!("config_json is not valid UTF-8: {e}")),
                std::ptr::null_mut()
            );

            let wm = ffi_try!(get_or_create_watermarker(cfg_str), std::ptr::null_mut());

            string_to_c(wm.public_key())
        },
        std::ptr::null_mut(),
    )
}

/// Watermark a prompt and return a JSON result.
///
/// Returns a JSON string with `original`, `watermarked`, and `watermark` fields,
/// or `NULL` on error.
/// The caller must free the returned string with `hush_free_string`.
///
/// # Safety
///
/// - `prompt` must be a valid, NUL-terminated UTF-8 C string.
/// - `config_json` must be a valid, NUL-terminated UTF-8 C string.
/// - `app_id` may be `NULL` (defaults to `"unknown"`).
/// - `session_id` may be `NULL` (defaults to `"unknown"`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_watermark_prompt(
    prompt: *const c_char,
    config_json: *const c_char,
    app_id: *const c_char,
    session_id: *const c_char,
) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            if prompt.is_null() {
                set_last_error("prompt pointer is null");
                return std::ptr::null_mut();
            }
            if config_json.is_null() {
                set_last_error("config_json pointer is null");
                return std::ptr::null_mut();
            }

            let prompt_str = ffi_try!(
                unsafe { CStr::from_ptr(prompt) }
                    .to_str()
                    .map_err(|e| format!("prompt is not valid UTF-8: {e}")),
                std::ptr::null_mut()
            );

            let cfg_str = ffi_try!(
                unsafe { CStr::from_ptr(config_json) }
                    .to_str()
                    .map_err(|e| format!("config_json is not valid UTF-8: {e}")),
                std::ptr::null_mut()
            );

            let app_id_str = if app_id.is_null() {
                "unknown"
            } else {
                ffi_try!(
                    unsafe { CStr::from_ptr(app_id) }
                        .to_str()
                        .map_err(|e| format!("app_id is not valid UTF-8: {e}")),
                    std::ptr::null_mut()
                )
            };

            let session_id_str = if session_id.is_null() {
                "unknown"
            } else {
                ffi_try!(
                    unsafe { CStr::from_ptr(session_id) }
                        .to_str()
                        .map_err(|e| format!("session_id is not valid UTF-8: {e}")),
                    std::ptr::null_mut()
                )
            };

            let wm = ffi_try!(get_or_create_watermarker(cfg_str), std::ptr::null_mut());

            let payload = wm.generate_payload(app_id_str, session_id_str);
            let out = ffi_try!(
                wm.watermark(prompt_str, Some(payload))
                    .map_err(|e| format!("Watermarking failed: {e:?}")),
                std::ptr::null_mut()
            );

            let encoded_data_b64 = URL_SAFE_NO_PAD.encode(&out.watermark.encoded_data);
            let v = serde_json::json!({
                "original": out.original,
                "watermarked": out.watermarked,
                "watermark": {
                    "payload": out.watermark.payload,
                    "encoding": out.watermark.encoding,
                    "encodedDataBase64Url": encoded_data_b64,
                    "signature": out.watermark.signature,
                    "publicKey": out.watermark.public_key,
                    "fingerprint": out.watermark.fingerprint(),
                }
            });

            let json = ffi_try!(
                serde_json::to_string(&v).map_err(|e| format!("Failed to serialize result: {e}")),
                std::ptr::null_mut()
            );
            string_to_c(json)
        },
        std::ptr::null_mut(),
    )
}

/// Extract (and verify) a watermark from text.
///
/// Returns a JSON string with `found`, `verified`, `errors`, and `watermark` fields,
/// or `NULL` on error.
/// The caller must free the returned string with `hush_free_string`.
///
/// # Safety
///
/// - `text` must be a valid, NUL-terminated UTF-8 C string.
/// - `config_json` must be a valid, NUL-terminated UTF-8 C string
///   (serialized `WatermarkVerifierConfig`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_extract_watermark(
    text: *const c_char,
    config_json: *const c_char,
) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            if text.is_null() {
                set_last_error("text pointer is null");
                return std::ptr::null_mut();
            }
            if config_json.is_null() {
                set_last_error("config_json pointer is null");
                return std::ptr::null_mut();
            }

            let text_str = ffi_try!(
                unsafe { CStr::from_ptr(text) }
                    .to_str()
                    .map_err(|e| format!("text is not valid UTF-8: {e}")),
                std::ptr::null_mut()
            );

            let cfg_str = ffi_try!(
                unsafe { CStr::from_ptr(config_json) }
                    .to_str()
                    .map_err(|e| format!("config_json is not valid UTF-8: {e}")),
                std::ptr::null_mut()
            );

            let cfg: clawdstrike::WatermarkVerifierConfig = ffi_try!(
                serde_json::from_str(cfg_str)
                    .map_err(|e| format!("Invalid WatermarkVerifierConfig JSON: {e}")),
                std::ptr::null_mut()
            );

            let extractor = clawdstrike::WatermarkExtractor::new(cfg);
            let r = extractor.extract(text_str);

            let watermark = match r.watermark {
                Some(wm) => serde_json::json!({
                    "payload": wm.payload,
                    "encoding": wm.encoding,
                    "encodedDataBase64Url": URL_SAFE_NO_PAD.encode(&wm.encoded_data),
                    "signature": wm.signature,
                    "publicKey": wm.public_key,
                    "fingerprint": wm.fingerprint(),
                }),
                None => serde_json::Value::Null,
            };

            let v = serde_json::json!({
                "found": r.found,
                "verified": r.verified,
                "errors": r.errors,
                "watermark": watermark,
            });

            let json = ffi_try!(
                serde_json::to_string(&v).map_err(|e| format!("Failed to serialize result: {e}")),
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

    fn test_config_json() -> CString {
        CString::new(r#"{"generate_keypair": true}"#).unwrap()
    }

    #[test]
    fn test_watermark_public_key() {
        let config = test_config_json();
        let result = unsafe { hush_watermark_public_key(config.as_ptr()) };
        assert!(!result.is_null());
        let key_str = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        // Ed25519 public key hex is 64 chars
        assert_eq!(key_str.len(), 64);
        unsafe { crate::hush_free_string(result) };
    }

    #[test]
    fn test_watermark_public_key_null_config() {
        let result = unsafe { hush_watermark_public_key(std::ptr::null()) };
        assert!(result.is_null());
    }

    #[test]
    fn test_watermark_prompt_roundtrip() {
        let config = test_config_json();
        let prompt = CString::new("Hello, world!").unwrap();

        let result = unsafe {
            hush_watermark_prompt(
                prompt.as_ptr(),
                config.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert!(!result.is_null());

        let json_str = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        let v: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert!(v.get("original").is_some());
        assert!(v.get("watermarked").is_some());
        assert!(v.get("watermark").is_some());
        unsafe { crate::hush_free_string(result) };
    }

    #[test]
    fn test_watermark_prompt_null_prompt() {
        let config = test_config_json();
        let result = unsafe {
            hush_watermark_prompt(
                std::ptr::null(),
                config.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert!(result.is_null());
    }

    #[test]
    fn test_extract_watermark_no_watermark() {
        let text = CString::new("Just plain text with no watermark").unwrap();
        let config = CString::new(r#"{"trusted_public_keys": []}"#).unwrap();
        let result = unsafe { hush_extract_watermark(text.as_ptr(), config.as_ptr()) };
        assert!(!result.is_null());
        let json_str = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        let v: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(v["found"], false);
        unsafe { crate::hush_free_string(result) };
    }

    #[test]
    fn test_extract_watermark_null_text() {
        let config = CString::new(r#"{"trusted_public_keys": []}"#).unwrap();
        let result = unsafe { hush_extract_watermark(std::ptr::null(), config.as_ptr()) };
        assert!(result.is_null());
    }

    #[test]
    fn test_extract_watermark_null_config() {
        let text = CString::new("Some text").unwrap();
        let result = unsafe { hush_extract_watermark(text.as_ptr(), std::ptr::null()) };
        assert!(result.is_null());
    }
}
