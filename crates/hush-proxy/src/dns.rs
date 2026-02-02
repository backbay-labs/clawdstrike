//! DNS packet parsing and domain extraction
//!
//! Provides utilities for extracting domain names from DNS queries
//! for egress filtering.

use crate::error::{Error, Result};
use globset::GlobBuilder;

/// Extract domain name from a DNS query packet
pub fn extract_domain_from_query(packet: &[u8]) -> Result<Option<String>> {
    // DNS header is 12 bytes minimum
    if packet.len() < 12 {
        return Err(Error::DnsParseError(
            "Packet too short for DNS header".into(),
        ));
    }

    // Check if it's a query (QR bit = 0)
    let qr = (packet[2] >> 7) & 1;
    if qr != 0 {
        // This is a response, not a query
        return Ok(None);
    }

    // Get question count
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if qdcount == 0 {
        return Ok(None);
    }

    // Parse the first question
    let mut offset = 12;
    let mut labels = Vec::new();

    loop {
        if offset >= packet.len() {
            return Err(Error::DnsParseError("Unexpected end of packet".into()));
        }

        let len = packet[offset] as usize;
        if len == 0 {
            break;
        }

        // Check for compression pointer (starts with 0b11)
        if len & 0xC0 == 0xC0 {
            return Err(Error::DnsParseError(
                "Compression pointers not supported in queries".into(),
            ));
        }

        if len > 63 {
            return Err(Error::DnsParseError("Label too long".into()));
        }

        offset += 1;
        if offset + len > packet.len() {
            return Err(Error::DnsParseError("Label extends beyond packet".into()));
        }

        let label = std::str::from_utf8(&packet[offset..offset + len])
            .map_err(|_| Error::DnsParseError("Invalid UTF-8 in label".into()))?;
        labels.push(label.to_string());
        offset += len;
    }

    if labels.is_empty() {
        return Ok(None);
    }

    Ok(Some(labels.join(".")))
}

/// Check if a domain matches a pattern (supports wildcards)
pub fn domain_matches(domain: &str, pattern: &str) -> bool {
    let Ok(glob) = GlobBuilder::new(pattern)
        .case_insensitive(true)
        .literal_separator(true)
        .build()
    else {
        return false;
    };

    glob.compile_matcher().is_match(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matches_exact() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(domain_matches("Example.COM", "example.com"));
        assert!(!domain_matches("other.com", "example.com"));
    }

    #[test]
    fn test_domain_matches_wildcard() {
        assert!(domain_matches("sub.example.com", "*.example.com"));
        assert!(domain_matches("deep.sub.example.com", "*.example.com"));
        assert!(!domain_matches("example.com", "*.example.com"));
        assert!(!domain_matches("example.org", "*.example.com"));
    }

    #[test]
    fn test_domain_matches_glob_features() {
        assert!(domain_matches("api-1.example.com", "api-?.example.com"));
        assert!(domain_matches("api-a.example.com", "api-[a-z].example.com"));
        assert!(!domain_matches("api-aa.example.com", "api-?.example.com"));
    }

    #[test]
    fn test_extract_domain_short_packet() {
        let result = extract_domain_from_query(&[0; 5]);
        assert!(result.is_err());
    }
}
