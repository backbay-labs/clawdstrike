#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // SHA-256 should never panic on any input
    let hash = hush_core::sha256(data);

    // Basic sanity checks
    assert_eq!(hash.as_bytes().len(), 32);

    // Hash should be deterministic
    let hash2 = hush_core::sha256(data);
    assert_eq!(hash, hash2);

    // Hex roundtrip should work
    let hex = hash.to_hex();
    let restored = hush_core::Hash::from_hex(&hex).expect("valid hex");
    assert_eq!(hash, restored);
});
