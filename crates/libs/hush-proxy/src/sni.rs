//! TLS SNI (Server Name Indication) extraction
//!
//! Provides utilities for extracting the server name from TLS ClientHello
//! messages for HTTPS egress filtering.

use crate::error::{Error, Result};

/// Extract SNI hostname from TLS ClientHello
pub fn extract_sni(data: &[u8]) -> Result<Option<String>> {
    // Minimum TLS record: 5 byte header + 1 byte content
    if data.len() < 6 {
        return Ok(None);
    }

    // Check for TLS Handshake (content type 0x16)
    if data[0] != 0x16 {
        return Ok(None);
    }

    // Check version (TLS 1.0 = 0x0301, TLS 1.1 = 0x0302, TLS 1.2 = 0x0303)
    let version = u16::from_be_bytes([data[1], data[2]]);
    if !(0x0300..=0x0304).contains(&version) {
        return Ok(None);
    }

    // Get record length
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return Err(Error::SniParseError("Incomplete TLS record".into()));
    }

    let handshake = &data[5..5 + record_len];

    // Check for ClientHello (handshake type 0x01)
    if handshake.is_empty() || handshake[0] != 0x01 {
        return Ok(None);
    }

    // Parse ClientHello
    parse_client_hello(handshake)
}

fn parse_client_hello(data: &[u8]) -> Result<Option<String>> {
    // Handshake header: type (1) + length (3)
    if data.len() < 4 {
        return Ok(None);
    }

    let handshake_len = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + handshake_len {
        return Err(Error::SniParseError("Incomplete ClientHello".into()));
    }

    let hello = &data[4..4 + handshake_len];

    // ClientHello structure:
    // - client_version (2)
    // - random (32)
    // - session_id length (1) + session_id
    // - cipher_suites length (2) + cipher_suites
    // - compression_methods length (1) + compression_methods
    // - extensions length (2) + extensions (optional)

    if hello.len() < 35 {
        return Ok(None);
    }

    let mut offset = 34; // Skip version (2) + random (32)

    // Skip session ID
    if offset >= hello.len() {
        return Ok(None);
    }
    let session_id_len = hello[offset] as usize;
    offset += 1 + session_id_len;

    // Skip cipher suites
    if offset + 2 > hello.len() {
        return Ok(None);
    }
    let cipher_suites_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    // Skip compression methods
    if offset >= hello.len() {
        return Ok(None);
    }
    let compression_len = hello[offset] as usize;
    offset += 1 + compression_len;

    // Parse extensions
    if offset + 2 > hello.len() {
        return Ok(None); // No extensions
    }
    let extensions_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
    offset += 2;

    if offset + extensions_len > hello.len() {
        return Err(Error::SniParseError("Invalid extensions length".into()));
    }

    let extensions = &hello[offset..offset + extensions_len];
    parse_extensions(extensions)
}

fn parse_extensions(data: &[u8]) -> Result<Option<String>> {
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + ext_len > data.len() {
            return Err(Error::SniParseError("Extension extends beyond data".into()));
        }

        // SNI extension type is 0x0000
        if ext_type == 0x0000 {
            return parse_sni_extension(&data[offset..offset + ext_len]);
        }

        offset += ext_len;
    }

    Ok(None)
}

fn parse_sni_extension(data: &[u8]) -> Result<Option<String>> {
    if data.len() < 2 {
        return Ok(None);
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return Err(Error::SniParseError("Invalid SNI list length".into()));
    }

    let mut offset = 2;
    while offset + 3 <= 2 + list_len {
        let name_type = data[offset];
        let name_len = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;
        offset += 3;

        if offset + name_len > data.len() {
            return Err(Error::SniParseError("SNI name extends beyond data".into()));
        }

        // Host name type is 0x00
        if name_type == 0x00 {
            let name = std::str::from_utf8(&data[offset..offset + name_len])
                .map_err(|_| Error::SniParseError("Invalid UTF-8 in SNI".into()))?;
            return Ok(Some(name.to_string()));
        }

        offset += name_len;
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sni_short_packet() {
        assert_eq!(extract_sni(&[0; 5]).unwrap(), None);
    }

    #[test]
    fn test_extract_sni_non_tls() {
        let data = [0x17, 0x03, 0x03, 0x00, 0x01, 0x00]; // Not handshake type
        assert_eq!(extract_sni(&data).unwrap(), None);
    }

    #[test]
    fn test_extract_sni_with_hostname() {
        // Real TLS ClientHello with SNI = "example.com"
        let client_hello = include_bytes!("../testdata/client_hello_example.bin");
        let result = extract_sni(client_hello).unwrap();
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_sni_no_sni_extension() {
        // ClientHello without SNI extension
        let client_hello = include_bytes!("../testdata/client_hello_no_sni.bin");
        let result = extract_sni(client_hello).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_sni_http_request() {
        // HTTP request (not TLS)
        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_sni(http).unwrap(), None);
    }

    #[test]
    fn test_extract_sni_invalid_version() {
        // Invalid TLS version
        let data = [0x16, 0x02, 0x00, 0x00, 0x01, 0x00]; // SSL 2.0
        assert_eq!(extract_sni(&data).unwrap(), None);
    }

    #[test]
    fn test_extract_sni_empty() {
        assert_eq!(extract_sni(&[]).unwrap(), None);
    }

    #[test]
    fn test_extract_sni_truncated_record() {
        // Handshake header says 100 bytes but data is shorter
        let data = [0x16, 0x03, 0x03, 0x00, 0x64, 0x01, 0x00, 0x00, 0x05];
        let result = extract_sni(&data);
        assert!(result.is_err()); // Should error on incomplete record
    }
}
