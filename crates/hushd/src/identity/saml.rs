//! SAML assertion parsing and normalization.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use clawdstrike::{AuthMethod, IdentityPrincipal, IdentityProvider};
use roxmltree::Document;
use rust_xmlsec::Output as XmlSecOutput;

use crate::config::SamlConfig;

#[derive(Debug, thiserror::Error)]
pub enum SamlError {
    #[error("invalid saml configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid assertion xml: {0}")]
    InvalidXml(String),
    #[error("missing field: {0}")]
    MissingField(String),
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),
    #[error("assertion conditions failed: {0}")]
    ConditionsFailed(String),
    #[error("signature validation failed: {0}")]
    SignatureValidationFailed(String),
}

pub type Result<T> = std::result::Result<T, SamlError>;

pub fn parse_assertion(cfg: &SamlConfig, assertion_or_b64: &str) -> Result<IdentityPrincipal> {
    let xml = decode_assertion(assertion_or_b64)?;
    if cfg.validate_signature {
        validate_signature(cfg, &xml)?;
    }
    let doc = Document::parse(&xml).map_err(|e| SamlError::InvalidXml(e.to_string()))?;

    let assertion = if cfg.validate_signature {
        find_signed_assertion(&doc).ok_or_else(|| {
            SamlError::SignatureValidationFailed("signed_assertion_not_found".to_string())
        })?
    } else {
        find_first_assertion(&doc)
            .ok_or_else(|| SamlError::MissingField("Assertion".to_string()))?
    };

    let issuer =
        find_first_text_by_local_name(assertion, "Issuer").unwrap_or_else(|| "saml".to_string());
    let name_id = find_first_text_by_local_name(assertion, "NameID")
        .ok_or_else(|| SamlError::MissingField("NameID".to_string()))?;

    let issue_instant = find_attribute_by_local_name(assertion, "Assertion", "IssueInstant")
        .as_deref()
        .and_then(parse_rfc3339)
        .unwrap_or_else(Utc::now);

    if cfg.validate_conditions {
        validate_conditions(cfg, assertion)?;
    }

    let attributes = extract_attributes(assertion);
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
                    serde_json::Value::Array(
                        values
                            .iter()
                            .cloned()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            }
        }
    }

    let expires_at = extract_not_on_or_after(assertion).map(|dt| dt.to_rfc3339());

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

fn validate_signature(cfg: &SamlConfig, xml: &str) -> Result<()> {
    let expected_pem = cfg.idp_signing_cert_pem.as_ref().ok_or_else(|| {
        SamlError::InvalidConfig(
            "idp_signing_cert_pem is required when validate_signature is true".to_string(),
        )
    })?;

    let output = rust_xmlsec::decode_and_verify_signed_document(xml)
        .map_err(SamlError::SignatureValidationFailed)?;

    let XmlSecOutput::Verified { pkey, .. } = output else {
        return Err(SamlError::SignatureValidationFailed(
            "unsigned_assertion".to_string(),
        ));
    };

    let cert = openssl::x509::X509::from_pem(expected_pem.as_bytes())
        .map_err(|e| SamlError::InvalidConfig(e.to_string()))?;
    let expected_pkey = cert
        .public_key()
        .map_err(|e| SamlError::InvalidConfig(e.to_string()))?;

    if !pkey.public_eq(&expected_pkey) {
        return Err(SamlError::SignatureValidationFailed(
            "untrusted_signing_certificate".to_string(),
        ));
    }

    Ok(())
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

fn validate_conditions(cfg: &SamlConfig, assertion: roxmltree::Node<'_, '_>) -> Result<()> {
    let now = Utc::now();

    if let Some(not_before) = find_attribute_by_local_name(assertion, "Conditions", "NotBefore") {
        let not_before =
            parse_rfc3339(&not_before).ok_or(SamlError::InvalidTimestamp(not_before))?;
        if now < not_before {
            return Err(SamlError::ConditionsFailed("not_before".to_string()));
        }
    }

    if let Some(not_on_or_after) =
        find_attribute_by_local_name(assertion, "Conditions", "NotOnOrAfter")
    {
        let not_on_or_after =
            parse_rfc3339(&not_on_or_after).ok_or(SamlError::InvalidTimestamp(not_on_or_after))?;
        if now >= not_on_or_after {
            return Err(SamlError::ConditionsFailed("expired".to_string()));
        }
    }

    // Audience restriction (best-effort).
    let mut audiences = Vec::new();
    for n in assertion
        .descendants()
        .filter(|n| n.has_tag_name(("urn:oasis:names:tc:SAML:2.0:assertion", "Audience")))
    {
        if let Some(t) = n.text() {
            audiences.push(t.trim().to_string());
        }
    }
    if audiences.is_empty() {
        for n in assertion
            .descendants()
            .filter(|n| n.tag_name().name() == "Audience")
        {
            if let Some(t) = n.text() {
                audiences.push(t.trim().to_string());
            }
        }
    }
    if !audiences.is_empty() && !audiences.iter().any(|a| a == &cfg.entity_id) {
        return Err(SamlError::ConditionsFailed("audience".to_string()));
    }

    if let Some(max_age) = cfg.max_assertion_age_secs {
        if let Some(issue_instant) =
            find_attribute_by_local_name(assertion, "Assertion", "IssueInstant")
                .and_then(|v| parse_rfc3339(&v))
        {
            if now - Duration::seconds(max_age as i64) > issue_instant {
                return Err(SamlError::ConditionsFailed("max_age".to_string()));
            }
        }
    }

    Ok(())
}

fn extract_not_on_or_after(assertion: roxmltree::Node<'_, '_>) -> Option<DateTime<Utc>> {
    find_attribute_by_local_name(assertion, "Conditions", "NotOnOrAfter")
        .and_then(|v| parse_rfc3339(&v))
}

fn find_attribute_by_local_name(
    root: roxmltree::Node<'_, '_>,
    element_local: &str,
    attr: &str,
) -> Option<String> {
    for n in root.descendants() {
        if n.is_element() && n.tag_name().name() == element_local {
            if let Some(v) = n.attribute(attr) {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn find_first_text_by_local_name(root: roxmltree::Node<'_, '_>, local: &str) -> Option<String> {
    for n in root.descendants() {
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

fn extract_attributes(root: roxmltree::Node<'_, '_>) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for attr in root
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "Attribute")
    {
        let Some(name) = attr
            .attribute("Name")
            .or_else(|| attr.attribute("FriendlyName"))
        else {
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

fn find_signed_assertion<'a, 'input>(
    doc: &'a Document<'input>,
) -> Option<roxmltree::Node<'a, 'input>> {
    let root = doc.root_element();

    let mut uris = Vec::new();
    for n in root.descendants() {
        if n.is_element()
            && n.tag_name().namespace() == Some("http://www.w3.org/2000/09/xmldsig#")
            && n.tag_name().name() == "Reference"
        {
            if let Some(uri) = n.attribute("URI") {
                uris.push(uri.trim().to_string());
            }
        }
    }

    for uri in uris {
        let signed_root = if uri.is_empty() {
            Some(root)
        } else if let Some(id) = uri.strip_prefix('#') {
            find_element_by_id(doc, id)
        } else {
            None
        }?;

        if let Some(assertion) = find_saml_assertion_in(signed_root) {
            return Some(assertion);
        }
    }

    None
}

fn find_first_assertion<'a, 'input>(
    doc: &'a Document<'input>,
) -> Option<roxmltree::Node<'a, 'input>> {
    find_saml_assertion_in(doc.root_element())
}

fn find_saml_assertion_in<'a, 'input>(
    root: roxmltree::Node<'a, 'input>,
) -> Option<roxmltree::Node<'a, 'input>> {
    if root.is_element() && root.tag_name().name() == "Assertion" {
        return Some(root);
    }
    root.descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Assertion")
}

fn find_element_by_id<'a, 'input>(
    doc: &'a Document<'input>,
    id: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    let id = id.trim();
    if id.is_empty() {
        return None;
    }

    for n in doc.descendants() {
        if !n.is_element() {
            continue;
        }

        for attr in n.attributes() {
            if attr.name().eq_ignore_ascii_case("id") && attr.value() == id {
                return Some(n);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNED_SAML_RESPONSE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/saml/signed_response.xml"
    ));

    fn extract_embedded_signing_cert_pem(xml: &str) -> String {
        let doc = Document::parse(xml).expect("fixture xml");
        let cert_b64 = find_first_text_by_local_name(doc.root_element(), "X509Certificate")
            .expect("x509 certificate");
        let cert_b64: String = cert_b64.chars().filter(|c| !c.is_whitespace()).collect();
        let der = B64.decode(cert_b64.as_bytes()).expect("base64");
        let cert = openssl::x509::X509::from_der(&der).expect("x509");
        String::from_utf8(cert.to_pem().expect("pem")).expect("pem utf8")
    }

    fn generate_test_cert() -> (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ) {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509NameBuilder, X509};

        let rsa = Rsa::generate(2048).expect("rsa");
        let pkey = PKey::from_rsa(rsa).expect("pkey");

        let mut name = X509NameBuilder::new().expect("name");
        name.append_entry_by_text("CN", "hushd-test").expect("cn");
        let name = name.build();

        let mut builder = X509::builder().expect("builder");
        builder.set_version(2).expect("version");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&pkey).expect("pubkey");
        builder
            .set_not_before(Asn1Time::days_from_now(0).expect("nb").as_ref())
            .expect("not_before");
        builder
            .set_not_after(Asn1Time::days_from_now(365).expect("na").as_ref())
            .expect("not_after");
        builder.sign(&pkey, MessageDigest::sha256()).expect("sign");
        (builder.build(), pkey)
    }

    #[test]
    fn validates_signature_against_configured_cert() {
        let pem = extract_embedded_signing_cert_pem(SIGNED_SAML_RESPONSE);

        let cfg = SamlConfig {
            entity_id: "sp-entity".to_string(),
            idp_signing_cert_pem: Some(pem),
            validate_signature: true,
            validate_conditions: false,
            attribute_mapping: Default::default(),
            max_assertion_age_secs: None,
        };

        let principal = parse_assertion(&cfg, SIGNED_SAML_RESPONSE).expect("principal");
        assert_eq!(principal.provider, IdentityProvider::Saml);
        assert_eq!(principal.email, None);
        assert_eq!(principal.id, "q@as207960.net");
    }

    #[test]
    fn rejects_untrusted_signing_cert() {
        let (other_cert, _other_key) = generate_test_cert();

        let cfg = SamlConfig {
            entity_id: "sp-entity".to_string(),
            idp_signing_cert_pem: Some(
                String::from_utf8(other_cert.to_pem().expect("pem")).expect("pem utf8"),
            ),
            validate_signature: true,
            validate_conditions: false,
            attribute_mapping: Default::default(),
            max_assertion_age_secs: None,
        };

        let err = parse_assertion(&cfg, SIGNED_SAML_RESPONSE).expect_err("should fail");
        assert!(matches!(err, SamlError::SignatureValidationFailed(_)));
    }

    #[test]
    fn signature_validation_ignores_wrapped_unsigned_assertion() {
        let pem = extract_embedded_signing_cert_pem(SIGNED_SAML_RESPONSE);

        let signed_without_decl = SIGNED_SAML_RESPONSE
            .trim()
            .strip_prefix(r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?>"#)
            .unwrap_or(SIGNED_SAML_RESPONSE)
            .trim();

        let wrapped = format!(
            r#"<Root xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><saml2:Assertion ID="evil" IssueInstant="{}"><saml2:Issuer>https://evil.example</saml2:Issuer><saml2:Subject><saml2:NameID>evil@example.com</saml2:NameID></saml2:Subject></saml2:Assertion>{}</Root>"#,
            Utc::now().to_rfc3339(),
            signed_without_decl
        );

        let cfg = SamlConfig {
            entity_id: "sp-entity".to_string(),
            idp_signing_cert_pem: Some(pem),
            validate_signature: true,
            validate_conditions: false,
            attribute_mapping: Default::default(),
            max_assertion_age_secs: None,
        };

        let principal = parse_assertion(&cfg, &wrapped).expect("principal");
        assert_eq!(principal.id, "q@as207960.net");
    }
}
