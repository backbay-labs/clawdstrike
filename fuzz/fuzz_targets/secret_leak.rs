#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // SecretLeakGuard should never panic on any input
    let guard = clawdstrike::SecretLeakGuard::new();
    let _ = guard.scan(data);
});
