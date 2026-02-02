#![no_main]

use hush_proxy::dns::extract_domain_from_query;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = extract_domain_from_query(data);
});

