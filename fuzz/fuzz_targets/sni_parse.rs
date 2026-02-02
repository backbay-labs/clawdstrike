#![no_main]

use hush_proxy::sni::extract_sni;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = extract_sni(data);
});

