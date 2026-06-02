//! Small shared formatting/encoding helpers for the `hush pkg` subcommands.

use std::path::PathBuf;

const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

/// Minimal percent-encoding for query parameters (avoids pulling in another dep).
pub(super) fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX_UPPER[(b >> 4) as usize]));
                out.push(char::from(HEX_UPPER[(b & 0x0f) as usize]));
            }
        }
    }
    out
}

pub(super) fn truncate_with_ellipsis(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let truncated: String = input.chars().take(max_chars).collect();
    format!("{truncated}...")
}

/// Format a number with comma separators (e.g. 1234 -> "1,234").
pub(super) fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

pub(super) fn tempdir_for_download() -> std::io::Result<PathBuf> {
    let nonce: u64 = rand::Rng::random(&mut rand::rng());
    let dir = std::env::temp_dir().join(format!("clawdstrike_dl_{nonce:x}"));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
