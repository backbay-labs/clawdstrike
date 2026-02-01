#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Policy parsing should never panic on any input
    if let Ok(yaml) = std::str::from_utf8(data) {
        // Attempt to parse - should not panic
        let _ = hushclaw::Policy::from_yaml(yaml);
    }
});
