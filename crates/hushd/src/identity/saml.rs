//! SAML assertion parsing and normalization.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use clawdstrike::{AuthMethod, IdentityPrincipal, IdentityProvider};
use roxmltree::Document;

use crate::config::SamlConfig;

#[derive(Debug, thiserror::Error)]
pub enum SamlError {
    #[error("signature validation is enabled but not implemented")]
    SignatureValidationNotImplemented,
    #[error("invalid assertion xml: {0}")]
    InvalidXml(String),
    #[error("missing field: {0}")]
    MissingField(String),
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),
    #[error("assertion conditions failed: {0}")]
    ConditionsFailed(String),
}

pub type Result<T> = std::result::Result<T, SamlError>;

pub fn parse_assertion(cfg: &SamlConfig, assertion_or_b64: &str) -> Result<IdentityPrincipal> {
    if cfg.validate_signature {
        return Err(SamlError::SignatureValidationNotImplemented);
    }

    let xml = decode_assertion(assertion_or_b64)?;
    let doc = Document::parse(&xml).map_err(|e| SamlError::InvalidXml(e.to_string()))?;

    let issuer = find_first_text_by_local_name(&doc, "Issuer").unwrap_or_else(|| "saml".to_string());
    let name_id = find_first_text_by_local_name(&doc, "NameID")
        .ok_or_else(|| SamlError::MissingField("NameID".to_string()))?;

    let issue_instant = find_attribute_by_local_name(&doc, "Assertion", "IssueInstant")
        .as_deref()
        .and_then(parse_rfc3339)
        .unwrap_or_else(|| Utc::now());

    if cfg.validate_conditions {
        validate_conditions(cfg, &doc)?;
    }

    let attributes = extract_attributes(&doc);
    let mapping = &cfg.attribute_mapping;

    let id = map_single(mapping.user_id.as_deref(), &attributes).unwrap_or(name_id);
    let email = map_single(mapping.email.as_deref(), &attributes);
    let display_name = map_single(mapping.display_name.as_deref(), &attributes);
    let organization_id = map_single(mapping.organization_id.as_deref(), &attributes);

    let roles = map_list(mapping.roles.as_deref(), &attributes);
    let teams = map_list(mapping.teams.as_deref(), &attributes);

    let mut extra = HashMap::new();
    for key in &mapping.additional_attributes {
        if let Some(values) = attributes.get(key) {
            if values.len() == 1 {
                extra.insert(key.clone(), serde_json::Value::String(values[0].clone()));
            } else {
                extra.insert(
                    key.clone(),
                    serde_json::Value::Array(values.iter().cloned().map(serde_json::Value::String).collect()),
                );
            }
        }
    }

    let expires_at = extract_not_on_or_after(&doc).map(|dt| dt.to_rfc3339());

    Ok(IdentityPrincipal {
        id,
        provider: IdentityProvider::Saml,
        issuer,
        display_name,
        email,
        email_verified: None,
        organization_id,
        teams,
        roles,
        attributes: extra,
        authenticated_at: issue_instant.to_rfc3339(),
        auth_method: Some(AuthMethod::Sso),
        expires_at,
    })
}

fn decode_assertion(assertion_or_b64: &str) -> Result<String> {
    let s = assertion_or_b64.trim();
    if s.starts_with('<') {
        return Ok(s.to_string());
    }
    let decoded = B64
        .decode(s.as_bytes())
        .map_err(|e| SamlError::InvalidXml(format!("base64 decode failed: {e}")))?;
    String::from_utf8(decoded).map_err(|e| SamlError::InvalidXml(format!("invalid utf-8: {e}")))
}

fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn validate_conditions(cfg: &SamlConfig, doc: &Document<'_>) -> Result<()> {
    let now = Utc::now();

    if let Some(not_before) = find_attribute_by_local_name(doc, "Conditions", "NotBefore") {
        let not_before = parse_rfc3339(&not_before).ok_or_else(|| SamlError::InvalidTimestamp(not_before))?;
        if now < not_before {
            return Err(SamlError::ConditionsFailed("not_before".to_string()));
        }
    }

    if let Some(not_on_or_after) = find_attribute_by_local_name(doc, "Conditions", "NotOnOrAfter") {
        let not_on_or_after =
            parse_rfc3339(&not_on_or_after).ok_or_else(|| SamlError::InvalidTimestamp(not_on_or_after))?;
        if now >= not_on_or_after {
            return Err(SamlError::ConditionsFailed("expired".to_string()));
        }
    }

    // Audience restriction (best-effort).
    let mut audiences = Vec::new();
    for n in doc.descendants().filter(|n| n.has_tag_name(("urn:oasis:names:tc:SAML:2.0:assertion", "Audience"))) {
        if let Some(t) = n.text() {
            audiences.push(t.trim().to_string());
        }
    }
    if audiences.is_empty() {
        for n in doc.descendants().filter(|n| n.tag_name().name() == "Audience") {
            if let Some(t) = n.text() {
                audiences.push(t.trim().to_string());
            }
        }
    }
    if !audiences.is_empty() && !audiences.iter().any(|a| a == &cfg.entity_id) {
        return Err(SamlError::ConditionsFailed("audience".to_string()));
    }

    if let Some(max_age) = cfg.max_assertion_age_secs {
        if let Some(issue_instant) = find_attribute_by_local_name(doc, "Assertion", "IssueInstant")
            .and_then(|v| parse_rfc3339(&v))
        {
            if now - Duration::seconds(max_age as i64) > issue_instant {
                return Err(SamlError::ConditionsFailed("max_age".to_string()));
            }
        }
    }

    Ok(())
}

fn extract_not_on_or_after(doc: &Document<'_>) -> Option<DateTime<Utc>> {
    find_attribute_by_local_name(doc, "Conditions", "NotOnOrAfter").and_then(|v| parse_rfc3339(&v))
}

fn find_attribute_by_local_name(doc: &Document<'_>, element_local: &str, attr: &str) -> Option<String> {
    for n in doc.descendants() {
        if n.is_element() && n.tag_name().name() == element_local {
            if let Some(v) = n.attribute(attr) {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn find_first_text_by_local_name(doc: &Document<'_>, local: &str) -> Option<String> {
    for n in doc.descendants() {
        if n.is_element() && n.tag_name().name() == local {
            if let Some(t) = n.text() {
                let t = t.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
        }
    }
    None
}

fn extract_attributes(doc: &Document<'_>) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for attr in doc.descendants().filter(|n| n.is_element() && n.tag_name().name() == "Attribute") {
        let Some(name) = attr.attribute("Name").or_else(|| attr.attribute("FriendlyName")) else {
            continue;
        };
        let mut values = Vec::new();
        for v in attr
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "AttributeValue")
        {
            if let Some(t) = v.text() {
                let t = t.trim();
                if !t.is_empty() {
                    values.push(t.to_string());
                }
            }
        }
        if !values.is_empty() {
            out.entry(name.to_string()).or_default().extend(values);
        }
    }
    out
}

fn map_single(key: Option<&str>, attrs: &HashMap<String, Vec<String>>) -> Option<String> {
    let key = key?;
    attrs.get(key).and_then(|v| v.first()).cloned()
}

fn map_list(key: Option<&str>, attrs: &HashMap<String, Vec<String>>) -> Vec<String> {
    let Some(key) = key else {
        return Vec::new();
    };
    attrs.get(key).cloned().unwrap_or_default()
}
