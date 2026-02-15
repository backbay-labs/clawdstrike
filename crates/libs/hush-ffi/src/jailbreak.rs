//! Jailbreak detection FFI function.

use std::collections::{HashMap, VecDeque};
use std::ffi::{c_char, CStr};
use std::sync::{Arc, Mutex, OnceLock};

use crate::error::{ffi_try, set_last_error};
use crate::string_to_c;

const MAX_DETECTOR_CACHE_ENTRIES: usize = 128;

#[derive(Default)]
struct DetectorCache {
    map: HashMap<String, Arc<clawdstrike::JailbreakDetector>>,
    // Most-recently-used (back) -> least-recently-used (front).
    lru: VecDeque<String>,
}

impl DetectorCache {
    fn touch(&mut self, key: &str) {
        if let Some(pos) = self.lru.iter().position(|k| k == key) {
            self.lru.remove(pos);
        }
        self.lru.push_back(key.to_string());
    }

    // Evict until inserting one new entry will not exceed the configured maximum.
    fn evict_to_make_room(&mut self) {
        while self.map.len() >= MAX_DETECTOR_CACHE_ENTRIES {
            let Some(old_key) = self.lru.pop_front() else {
                break;
            };
            self.map.remove(&old_key);
        }
    }
}

static DETECTORS: OnceLock<Mutex<DetectorCache>> = OnceLock::new();

fn detector_key(cfg: &clawdstrike::JailbreakGuardConfig) -> Result<String, String> {
    let value =
        serde_json::to_value(cfg).map_err(|e| format!("Invalid JailbreakGuardConfig: {e}"))?;
    hush_core::canonicalize_json(&value).map_err(|e| e.to_string())
}

fn get_or_create_detector(
    cfg: clawdstrike::JailbreakGuardConfig,
) -> Result<Arc<clawdstrike::JailbreakDetector>, String> {
    let key = detector_key(&cfg)?;

    let cache = DETECTORS.get_or_init(|| Mutex::new(DetectorCache::default()));
    {
        // Fast path: cache hit.
        let mut guard = cache
            .lock()
            .map_err(|_| "jailbreak detector lock poisoned".to_string())?;
        if let Some(detector) = guard.map.get(&key).cloned() {
            guard.touch(&key);
            return Ok(detector);
        }

        // Ensure we have room before releasing the lock to construct.
        //
        // Note: we also evict again under the lock right before insertion below, so the cache size
        // remains bounded even when multiple threads construct detectors concurrently.
        guard.evict_to_make_room();
    }

    // Construct outside the global lock to avoid blocking other cache keys.
    let detector = Arc::new(clawdstrike::JailbreakDetector::with_config(cfg));

    // Re-acquire and insert (double-check in case another thread won the race).
    let mut guard = cache
        .lock()
        .map_err(|_| "jailbreak detector lock poisoned".to_string())?;
    if let Some(existing) = guard.map.get(&key).cloned() {
        guard.touch(&key);
        return Ok(existing);
    }

    guard.evict_to_make_room();
    guard.map.insert(key.clone(), detector.clone());
    guard.touch(&key);
    debug_assert!(guard.map.len() <= MAX_DETECTOR_CACHE_ENTRIES);
    debug_assert!(guard.lru.len() <= MAX_DETECTOR_CACHE_ENTRIES);
    Ok(detector)
}

/// Detect jailbreak attempts in the given text.
///
/// Returns a JSON string describing the detection result, or `NULL` on error.
/// The caller must free the returned string with `hush_free_string`.
///
/// # Safety
///
/// - `text` must be a valid, NUL-terminated UTF-8 C string.
/// - `session_id` may be `NULL` (treated as no session).
/// - `config_json` may be `NULL` (uses a cached default detector singleton).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_detect_jailbreak(
    text: *const c_char,
    session_id: *const c_char,
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

            let cfg = if config_json.is_null() {
                clawdstrike::JailbreakGuardConfig::default()
            } else {
                let cfg_str = ffi_try!(
                    unsafe { CStr::from_ptr(config_json) }
                        .to_str()
                        .map_err(|e| format!("config_json is not valid UTF-8: {e}")),
                    std::ptr::null_mut()
                );
                ffi_try!(
                    serde_json::from_str(cfg_str)
                        .map_err(|e| format!("Invalid JailbreakGuardConfig JSON: {e}")),
                    std::ptr::null_mut()
                )
            };

            let detector = ffi_try!(get_or_create_detector(cfg), std::ptr::null_mut());
            let result = detector.detect_sync(text_str, session_id_str);

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
    use std::sync::Arc;

    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        // These tests share a process-wide cache, and `cargo test` runs tests in parallel by
        // default. Serialize and reset to avoid inter-test flakiness due to eviction.
        let guard = TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let cache = DETECTORS.get_or_init(|| Mutex::new(DetectorCache::default()));
        let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.map.clear();
        cache.lru.clear();

        guard
    }

    #[test]
    fn test_detect_jailbreak_benign() {
        let _guard = test_guard();
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
        let _guard = test_guard();
        let result =
            unsafe { hush_detect_jailbreak(std::ptr::null(), std::ptr::null(), std::ptr::null()) };
        assert!(result.is_null());
    }

    #[test]
    fn test_detect_jailbreak_with_session_id() {
        let _guard = test_guard();
        let text = CString::new("Hello world").unwrap();
        let session = CString::new("session-123").unwrap();
        let result =
            unsafe { hush_detect_jailbreak(text.as_ptr(), session.as_ptr(), std::ptr::null()) };
        assert!(!result.is_null());
        let json_str = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        let v: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert!(v.get("blocked").is_some());
        unsafe { crate::hush_free_string(result) };
    }

    #[test]
    fn test_cached_detectors_reused_for_equivalent_configs() {
        let _guard = test_guard();
        let d1 = get_or_create_detector(clawdstrike::JailbreakGuardConfig::default()).unwrap();
        let cfg_from_json: clawdstrike::JailbreakGuardConfig = serde_json::from_str("{}").unwrap();
        let d2 = get_or_create_detector(cfg_from_json).unwrap();
        assert!(Arc::ptr_eq(&d1, &d2));
    }

    #[test]
    fn test_detector_cache_is_bounded() {
        let _guard = test_guard();
        // Create more unique configs than the cache limit; we should still remain bounded.
        for i in 0..(MAX_DETECTOR_CACHE_ENTRIES + 10) {
            let cfg = clawdstrike::JailbreakGuardConfig {
                block_threshold: i as u8,
                ..Default::default()
            };
            let _ = get_or_create_detector(cfg).unwrap();
        }

        let cache = DETECTORS.get().unwrap().lock().unwrap();
        assert!(cache.map.len() <= MAX_DETECTOR_CACHE_ENTRIES);
        assert!(cache.lru.len() <= MAX_DETECTOR_CACHE_ENTRIES);
    }
}
