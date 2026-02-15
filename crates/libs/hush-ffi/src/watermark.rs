//! Prompt watermarking FFI functions.

use std::collections::{HashMap, VecDeque};
use std::ffi::{c_char, CStr};
use std::sync::{Arc, Mutex, OnceLock};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::error::{ffi_try, set_last_error};
use crate::string_to_c;

const MAX_WATERMARKER_CACHE_ENTRIES: usize = 128;

fn watermark_json(wm: &clawdstrike::EncodedWatermark) -> serde_json::Value {
    serde_json::json!({
        "payload": &wm.payload,
        "encoding": &wm.encoding,
        "encodedDataBase64Url": URL_SAFE_NO_PAD.encode(&wm.encoded_data),
        "signature": &wm.signature,
        "publicKey": &wm.public_key,
        "fingerprint": wm.fingerprint(),
    })
}

#[derive(Default)]
struct WatermarkerCache {
    map: HashMap<String, CachedWatermarker>,
    // Tracks only non-pinned entries (pinned entries must not be evicted).
    // Most-recently-used (back) -> least-recently-used (front).
    lru_non_pinned: VecDeque<String>,
    // Reservations for pinned entries that are being constructed outside the mutex.
    // This prevents a race where we generate an expensive random keypair, then fail to
    // insert because other threads filled the cache while we were constructing.
    in_flight_pinned: usize,
}

impl WatermarkerCache {
    fn effective_len(&self) -> usize {
        self.map.len() + self.in_flight_pinned
    }

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

struct PinnedReservation<'a> {
    cache: &'a Mutex<WatermarkerCache>,
    active: bool,
}

impl<'a> PinnedReservation<'a> {
    fn new(cache: &'a Mutex<WatermarkerCache>) -> Self {
        Self {
            cache,
            active: false,
        }
    }

    fn reserve(&mut self, guard: &mut WatermarkerCache) {
        guard.in_flight_pinned = guard.in_flight_pinned.saturating_add(1);
        self.active = true;
    }

    fn release_with_guard(&mut self, guard: &mut WatermarkerCache) {
        if self.active {
            guard.in_flight_pinned = guard.in_flight_pinned.saturating_sub(1);
            self.active = false;
        }
    }
}

impl Drop for PinnedReservation<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // Best-effort rollback. Never panic from drop.
        let mut guard = match self.cache.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        guard.in_flight_pinned = guard.in_flight_pinned.saturating_sub(1);
    }
}

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
    let mut reservation = PinnedReservation::new(cache);
    let mut should_cache = true;
    {
        // Fast path: cache hit.
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

        if guard.effective_len() >= MAX_WATERMARKER_CACHE_ENTRIES {
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

        if pinned && should_cache {
            reservation.reserve(&mut guard);
        }
    }

    // Construct outside the global lock to avoid blocking other cache keys.
    let wm = clawdstrike::PromptWatermarker::new(cfg).map_err(|e| format!("{e:?}"))?;
    let wm = Arc::new(wm);

    if !should_cache {
        return Ok(wm);
    }

    // Re-acquire and insert (double-check in case another thread won the race).
    let mut guard = cache
        .lock()
        .map_err(|_| "watermarker lock poisoned".to_string())?;
    reservation.release_with_guard(&mut guard);
    if let Some(entry) = guard.map.get(&key) {
        let existing = entry.wm.clone();
        let pinned_entry = entry.pinned;
        if !pinned_entry {
            guard.touch_non_pinned(&key);
        }
        return Ok(existing);
    }

    if guard.effective_len() >= MAX_WATERMARKER_CACHE_ENTRIES {
        if guard.evict_one_non_pinned() {
            // ok
        } else if pinned {
            return Err(format!(
                "watermarker cache full ({MAX_WATERMARKER_CACHE_ENTRIES} entries) and cannot evict \
                 generate_keypair entries; provide private_key or increase cache size"
            ));
        } else {
            // Still safe to skip caching rather than evicting pinned entries.
            return Ok(wm);
        }
    }

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

            let v = serde_json::json!({
                "original": out.original,
                "watermarked": out.watermarked,
                "watermark": watermark_json(&out.watermark),
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

            let watermark = match r.watermark.as_ref() {
                Some(wm) => watermark_json(wm),
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

    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        // These tests share a process-wide cache, and `cargo test` runs tests in parallel by
        // default. Serialize and reset to avoid inter-test flakiness due to eviction/pinning.
        let guard = TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let cache = WATERMARKERS.get_or_init(|| Mutex::new(WatermarkerCache::default()));
        let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.map.clear();
        cache.lru_non_pinned.clear();
        cache.in_flight_pinned = 0;

        guard
    }

    fn test_config_json() -> CString {
        CString::new(r#"{"generate_keypair": true}"#).unwrap()
    }

    fn seed_hex(byte: u8) -> String {
        let seed = [byte; 32];
        format!("0x{}", hex::encode(seed))
    }

    #[test]
    fn watermarker_cache_is_bounded() {
        let _guard = test_guard();
        for i in 0..(MAX_WATERMARKER_CACHE_ENTRIES + 10) {
            let cfg = format!("{{\"private_key\":\"{}\"}}", seed_hex(i as u8));
            let _ = get_or_create_watermarker(&cfg).unwrap();
        }

        let cache = WATERMARKERS.get().unwrap().lock().unwrap();
        assert!(cache.map.len() <= MAX_WATERMARKER_CACHE_ENTRIES);
        assert!(cache.lru_non_pinned.len() <= MAX_WATERMARKER_CACHE_ENTRIES);
    }

    #[test]
    fn test_watermark_public_key() {
        let _guard = test_guard();
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
        let _guard = test_guard();
        let result = unsafe { hush_watermark_public_key(std::ptr::null()) };
        assert!(result.is_null());
    }

    #[test]
    fn test_watermark_prompt_roundtrip() {
        let _guard = test_guard();
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
        let _guard = test_guard();
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
        let _guard = test_guard();
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
        let _guard = test_guard();
        let config = CString::new(r#"{"trusted_public_keys": []}"#).unwrap();
        let result = unsafe { hush_extract_watermark(std::ptr::null(), config.as_ptr()) };
        assert!(result.is_null());
    }

    #[test]
    fn test_extract_watermark_null_config() {
        let _guard = test_guard();
        let text = CString::new("Some text").unwrap();
        let result = unsafe { hush_extract_watermark(text.as_ptr(), std::ptr::null()) };
        assert!(result.is_null());
    }
}
