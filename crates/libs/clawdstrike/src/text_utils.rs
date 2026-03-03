//! Shared text-processing utilities for detection modules.
//!
//! This module deduplicates common functions used across jailbreak detection, prompt-injection
//! hygiene, output sanitization, and instruction hierarchy enforcement.

use regex::Regex;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

// `std::time::Instant` panics on `wasm32-unknown-unknown`.  On WASM we fall
// back to `js_sys::Date::now()`.  On native targets we use `Instant` for
// monotonic elapsed-time and `SystemTime` only for epoch timestamps.

#[derive(Clone, Copy)]
pub struct Timestamp {
    #[cfg(not(target_arch = "wasm32"))]
    instant: std::time::Instant,
    #[cfg(target_arch = "wasm32")]
    epoch_ms: f64,
}

pub fn now() -> Timestamp {
    #[cfg(not(target_arch = "wasm32"))]
    {
        Timestamp {
            instant: std::time::Instant::now(),
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        Timestamp {
            epoch_ms: js_sys::Date::now(),
        }
    }
}

pub fn elapsed_ms(ts: &Timestamp) -> f64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        ts.instant.elapsed().as_secs_f64() * 1000.0
    }
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() - ts.epoch_ms).max(0.0)
    }
}

pub fn now_epoch_ms() -> u64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u64
    }
}

/// Returns `true` if `c` is a zero-width or Unicode formatting character that is commonly used
/// for text obfuscation attacks.
pub fn is_zero_width_or_formatting(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}' // soft hyphen
            | '\u{180E}' // mongolian vowel separator (deprecated)
            | '\u{200B}' // zero width space
            | '\u{200C}' // zero width non-joiner
            | '\u{200D}' // zero width joiner
            | '\u{200E}' // left-to-right mark
            | '\u{200F}' // right-to-left mark
            | '\u{202A}' // left-to-right embedding
            | '\u{202B}' // right-to-left embedding
            | '\u{202C}' // pop directional formatting
            | '\u{202D}' // left-to-right override
            | '\u{202E}' // right-to-left override
            | '\u{2060}' // word joiner
            | '\u{2066}' // left-to-right isolate
            | '\u{2067}' // right-to-left isolate
            | '\u{2068}' // first strong isolate
            | '\u{2069}' // pop directional isolate
            | '\u{FEFF}' // zero width no-break space
    )
}

/// Truncate `text` to the largest valid char boundary at or before `max_bytes`.
///
/// Returns `(slice, was_truncated)`.
pub fn truncate_to_char_boundary(text: &str, max_bytes: usize) -> (&str, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }
    let mut end = max_bytes.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    (&text[..end], end < text.len())
}

/// Compile a hardcoded regex pattern, logging an error and returning a never-matching regex on
/// failure.
pub fn compile_hardcoded_regex(pattern: &'static str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|err| {
        tracing::error!(error = %err, %pattern, "failed to compile hardcoded regex");
        // "a^" is always valid; it matches nothing (anchor after literal).
        Regex::new("a^").unwrap_or_else(|_| unreachable!())
    })
}

/// Canonicalization statistics produced by [`canonicalize_for_detection`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalizationStats {
    pub scanned_bytes: usize,
    pub truncated: bool,
    pub nfkc_changed: bool,
    pub casefold_changed: bool,
    pub zero_width_stripped: usize,
    pub whitespace_collapsed: bool,
    pub canonical_bytes: usize,
}

/// Canonicalize text for detection: NFKC normalize, casefold, strip zero-width chars, collapse
/// whitespace.
///
/// Returns the canonical string and statistics about what changed.
pub fn canonicalize_for_detection(text: &str) -> (String, CanonicalizationStats) {
    let mut stats = CanonicalizationStats {
        scanned_bytes: text.len(),
        ..Default::default()
    };

    let nfkc: String = text.nfkc().collect();
    stats.nfkc_changed = nfkc != text;

    let folded: String = nfkc.chars().flat_map(|c| c.to_lowercase()).collect();
    stats.casefold_changed = folded != nfkc;

    let mut stripped = String::with_capacity(folded.len());
    for c in folded.chars() {
        if is_zero_width_or_formatting(c) {
            stats.zero_width_stripped = stats.zero_width_stripped.saturating_add(1);
            continue;
        }
        stripped.push(c);
    }

    let collapsed = stripped.split_whitespace().collect::<Vec<_>>().join(" ");
    stats.whitespace_collapsed = collapsed != stripped;
    stats.canonical_bytes = collapsed.len();
    (collapsed, stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_width_detection() {
        assert!(is_zero_width_or_formatting('\u{200B}'));
        assert!(is_zero_width_or_formatting('\u{FEFF}'));
        assert!(!is_zero_width_or_formatting('a'));
        assert!(!is_zero_width_or_formatting(' '));
    }

    #[test]
    fn truncate_within_bounds() {
        let (s, trunc) = truncate_to_char_boundary("hello", 10);
        assert_eq!(s, "hello");
        assert!(!trunc);
    }

    #[test]
    fn truncate_respects_char_boundary() {
        // Multi-byte: "é" is 2 bytes in UTF-8.
        let text = "héllo";
        let (s, trunc) = truncate_to_char_boundary(text, 2);
        assert!(trunc);
        assert!(s.is_char_boundary(s.len()));
    }

    #[test]
    fn canonicalize_strips_zero_width() {
        let input = "he\u{200B}llo";
        let (canon, stats) = canonicalize_for_detection(input);
        assert_eq!(canon, "hello");
        assert_eq!(stats.zero_width_stripped, 1);
    }

    #[test]
    fn canonicalize_collapses_whitespace() {
        let input = "hello   world";
        let (canon, stats) = canonicalize_for_detection(input);
        assert_eq!(canon, "hello world");
        assert!(stats.whitespace_collapsed);
    }

    #[test]
    fn compile_hardcoded_regex_works() {
        let re = compile_hardcoded_regex(r"\bhello\b");
        assert!(re.is_match("hello world"));
    }

    #[test]
    fn compile_hardcoded_regex_invalid_returns_never_match() {
        let re = compile_hardcoded_regex(r"(invalid[");
        assert!(!re.is_match("anything"));
    }
}
