//! Property-based tests for packet parsers.

use hush_proxy::{dns::extract_domain_from_query, sni::extract_sni};
use proptest::prelude::*;

proptest! {
    /// DNS parser should never panic on arbitrary bytes.
    #[test]
    fn proptest_dns_extract_domain_no_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = extract_domain_from_query(&data);
    }

    /// TLS SNI parser should never panic on arbitrary bytes.
    #[test]
    fn proptest_sni_extract_no_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = extract_sni(&data);
    }
}
