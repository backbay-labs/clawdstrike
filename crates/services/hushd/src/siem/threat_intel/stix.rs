use std::net::IpAddr;

use serde::Deserialize;

#[derive(Clone, Debug)]
pub enum IndicatorValue {
    Domain(String),
    Ip(IpAddr),
    FileName(String),
    FileSha256(String),
}

#[derive(Clone, Debug)]
pub struct ParsedIndicator {
    pub stix_id: String,
    pub confidence: Option<u8>,
    pub value: IndicatorValue,
}

#[derive(Debug, Deserialize)]
struct StixIndicator {
    #[serde(rename = "type")]
    obj_type: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    pattern: String,
    #[serde(default)]
    confidence: Option<u8>,
}

pub fn parse_indicators(
    objects: &[serde_json::Value],
    min_confidence: Option<u8>,
) -> Vec<ParsedIndicator> {
    let mut out = Vec::new();
    for obj in objects {
        let Ok(ind) = serde_json::from_value::<StixIndicator>(obj.clone()) else {
            continue;
        };
        if ind.obj_type != "indicator" {
            continue;
        }
        if let Some(min) = min_confidence {
            if ind.confidence.unwrap_or(0) < min {
                continue;
            }
        }

        for value in parse_pattern_values(&ind.pattern) {
            out.push(ParsedIndicator {
                stix_id: ind.id.clone(),
                confidence: ind.confidence,
                value,
            });
        }
    }
    out
}

fn parse_pattern_values(pattern: &str) -> Vec<IndicatorValue> {
    // Very small STIX 2.1 pattern subset:
    //   [domain-name:value = 'evil.com']
    //   [ipv4-addr:value = '192.0.2.1']
    //   [ipv6-addr:value = '2001:db8::1']
    //   [url:value = 'http://evil.com/malware']
    let pat = pattern.trim();
    let mut out = Vec::new();

    if pat.contains("domain-name:value") {
        if let Some(v) = extract_single_quoted_value(pat) {
            out.push(IndicatorValue::Domain(v));
        }
        return out;
    }

    if pat.contains("ipv4-addr:value") || pat.contains("ipv6-addr:value") {
        if let Some(v) = extract_single_quoted_value(pat) {
            if let Ok(ip) = v.parse::<IpAddr>() {
                out.push(IndicatorValue::Ip(ip));
            }
        }
        return out;
    }

    if pat.contains("url:value") {
        if let Some(v) = extract_single_quoted_value(pat) {
            if let Some(host) = extract_host_from_url(&v) {
                out.push(IndicatorValue::Domain(host));
            }
        }
        return out;
    }

    if pat.contains("file:name") {
        if let Some(v) = extract_single_quoted_value(pat) {
            out.push(IndicatorValue::FileName(v));
        }
        return out;
    }

    if pat.contains("file:hashes.SHA-256") || pat.contains("file:hashes.'SHA-256'") {
        if let Some(v) = extract_single_quoted_value(pat) {
            out.push(IndicatorValue::FileSha256(v.to_lowercase()));
        }
        return out;
    }

    out
}

fn extract_single_quoted_value(s: &str) -> Option<String> {
    let start = s.find('\'')?;
    let rest = &s[start + 1..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

fn extract_host_from_url(url: &str) -> Option<String> {
    // Minimal parser that avoids extra deps.
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host_port = host_port.split('@').next_back().unwrap_or(host_port);
    let host = host_port.split(':').next().unwrap_or(host_port).trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}
