use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificationTier {
    Certified,
    Silver,
    Gold,
    Platinum,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BadgeVariant {
    Full,
    Compact,
    Icon,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BadgeTheme {
    Light,
    Dark,
    Auto,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BadgeSubject {
    #[serde(rename = "type")]
    pub subject_type: String,
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BadgePolicyBinding {
    pub hash: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ruleset: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BadgeEvidenceBinding {
    pub receipt_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_log_ref: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BadgeCertificationBinding {
    pub tier: CertificationTier,
    pub issue_date: String,
    pub expiry_date: String,
    #[serde(default)]
    pub frameworks: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BadgeIssuer {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub signature: String,
    pub signed_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationBadge {
    pub certification_id: String,
    pub version: String,
    pub subject: BadgeSubject,
    pub certification: BadgeCertificationBinding,
    pub policy: BadgePolicyBinding,
    pub evidence: BadgeEvidenceBinding,
    pub issuer: BadgeIssuer,
}

pub fn now_rfc3339_nanos() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true)
}

pub fn keypair_public_key_base64url(keypair: &hush_core::Keypair) -> String {
    URL_SAFE_NO_PAD.encode(keypair.public_key().as_bytes())
}

fn signature_base64url(signature: &hush_core::Signature) -> String {
    URL_SAFE_NO_PAD.encode(signature.to_bytes())
}

pub fn sign_badge(
    mut badge: CertificationBadge,
    keypair: &hush_core::Keypair,
) -> Result<CertificationBadge> {
    // Build canonical JSON excluding issuer.signature.
    let signed_at = badge.issuer.signed_at.clone();
    let issuer_without_sig = serde_json::json!({
        "id": badge.issuer.id,
        "name": badge.issuer.name,
        "publicKey": badge.issuer.public_key,
        "signedAt": signed_at,
    });

    let unsigned = serde_json::json!({
        "certificationId": badge.certification_id,
        "version": badge.version,
        "subject": serde_json::to_value(&badge.subject)?,
        "certification": serde_json::to_value(&badge.certification)?,
        "policy": serde_json::to_value(&badge.policy)?,
        "evidence": serde_json::to_value(&badge.evidence)?,
        "issuer": issuer_without_sig,
    });

    let canonical = hush_core::canonicalize_json(&unsigned)?;
    let sig = keypair.sign(canonical.as_bytes());
    let sig_b64 = signature_base64url(&sig);

    badge.issuer.signature = sig_b64;
    Ok(badge)
}

pub fn verify_badge(badge: &CertificationBadge) -> Result<bool> {
    let pubkey_bytes = URL_SAFE_NO_PAD
        .decode(&badge.issuer.public_key)
        .map_err(|e| Error::InvalidInput(format!("invalid issuer public key: {e}")))?;
    let pubkey_bytes: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| Error::InvalidInput("issuer public key must be 32 bytes".to_string()))?;
    let pubkey = hush_core::PublicKey::from_bytes(&pubkey_bytes)?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&badge.issuer.signature)
        .map_err(|e| Error::InvalidInput(format!("invalid issuer signature: {e}")))?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Error::InvalidInput("issuer signature must be 64 bytes".to_string()))?;
    let sig = hush_core::Signature::from_bytes(&sig_bytes);

    let issuer_without_sig = serde_json::json!({
        "id": badge.issuer.id,
        "name": badge.issuer.name,
        "publicKey": badge.issuer.public_key,
        "signedAt": badge.issuer.signed_at,
    });

    let unsigned = serde_json::json!({
        "certificationId": badge.certification_id,
        "version": badge.version,
        "subject": serde_json::to_value(&badge.subject)?,
        "certification": serde_json::to_value(&badge.certification)?,
        "policy": serde_json::to_value(&badge.policy)?,
        "evidence": serde_json::to_value(&badge.evidence)?,
        "issuer": issuer_without_sig,
    });

    let canonical = hush_core::canonicalize_json(&unsigned)?;
    Ok(pubkey.verify(canonical.as_bytes(), &sig))
}

fn tier_colors(tier: CertificationTier, theme: BadgeTheme) -> (&'static str, &'static str) {
    // (bg, fg)
    match (tier, theme) {
        (CertificationTier::Certified, BadgeTheme::Dark) => ("#111827", "#E5E7EB"),
        (CertificationTier::Certified, _) => ("#6B7280", "#111827"),
        (CertificationTier::Silver, BadgeTheme::Dark) => ("#374151", "#F3F4F6"),
        (CertificationTier::Silver, _) => ("#9CA3AF", "#111827"),
        (CertificationTier::Gold, BadgeTheme::Dark) => ("#92400E", "#FEF3C7"),
        (CertificationTier::Gold, _) => ("#F59E0B", "#111827"),
        (CertificationTier::Platinum, BadgeTheme::Dark) => ("#4C1D95", "#F5F3FF"),
        (CertificationTier::Platinum, _) => ("#8B5CF6", "#111827"),
    }
}

pub struct BadgeSvgInput<'a> {
    pub certification_id: &'a str,
    pub tier: CertificationTier,
    pub subject_name: &'a str,
    pub issue_date: Option<&'a str>,
    pub expiry_date: Option<&'a str>,
    pub verification_url: &'a str,
}

pub fn render_badge_svg(input: BadgeSvgInput<'_>, variant: BadgeVariant, theme: BadgeTheme) -> String {
    let (bg, fg) = tier_colors(input.tier, theme);
    let tier_text = match input.tier {
        CertificationTier::Certified => "CERTIFIED",
        CertificationTier::Silver => "SILVER",
        CertificationTier::Gold => "GOLD",
        CertificationTier::Platinum => "PLATINUM",
    };

    match variant {
        BadgeVariant::Icon => format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48" role="img" aria-label="OpenClaw {tier_text}">
  <rect x="2" y="2" width="44" height="44" rx="10" fill="{bg}"/>
  <path d="M24 10l8 4v8c0 7-5 13-8 14-3-1-8-7-8-14v-8l8-4z" fill="{fg}" opacity="0.95"/>
</svg>"#
        ),
        BadgeVariant::Compact => format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="210" height="48" viewBox="0 0 210 48" role="img" aria-label="OpenClaw {tier_text}">
  <rect x="2" y="2" width="206" height="44" rx="10" fill="{bg}"/>
  <path d="M24 10l8 4v8c0 7-5 13-8 14-3-1-8-7-8-14v-8l8-4z" fill="{fg}" opacity="0.95"/>
  <text x="50" y="30" font-family="ui-sans-serif, system-ui, -apple-system" font-size="16" fill="{fg}" font-weight="700">OPENCLAW {tier_text}</text>
</svg>"#
        ),
        BadgeVariant::Full => {
            let validity = match (input.issue_date, input.expiry_date) {
                (Some(i), Some(e)) => format!("Valid: {i} to {e}"),
                _ => "Valid: see verification".to_string(),
            };
            let fp = input
                .certification_id
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(8)
                .collect::<String>();
            format!(
                r#"<svg xmlns="http://www.w3.org/2000/svg" width="520" height="120" viewBox="0 0 520 120" role="img" aria-label="OpenClaw Certified {tier_text}">
  <rect x="2" y="2" width="516" height="116" rx="14" fill="{bg}"/>
  <path d="M46 22l18 8v18c0 16-11 29-18 32-7-3-18-16-18-32V30l18-8z" fill="{fg}" opacity="0.95"/>
  <text x="86" y="42" font-family="ui-sans-serif, system-ui, -apple-system" font-size="18" fill="{fg}" font-weight="800">OPENCLAW CERTIFIED</text>
  <text x="86" y="66" font-family="ui-sans-serif, system-ui, -apple-system" font-size="16" fill="{fg}" font-weight="700">{tier_text}</text>
  <text x="86" y="88" font-family="ui-sans-serif, system-ui, -apple-system" font-size="14" fill="{fg}" opacity="0.95">{subject}</text>
  <text x="86" y="108" font-family="ui-sans-serif, system-ui, -apple-system" font-size="12" fill="{fg}" opacity="0.9">{validity} • Verify: {url} • {fp}</text>
</svg>"#,
                subject = xml_escape(input.subject_name),
                validity = xml_escape(&validity),
                url = xml_escape(input.verification_url),
                fp = xml_escape(&fp)
            )
        }
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn parse_rfc3339_date(date: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(date)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn badge_sign_verify_roundtrip() {
        let keypair = hush_core::Keypair::generate();
        let pubkey = keypair_public_key_base64url(&keypair);

        let badge = CertificationBadge {
            certification_id: "cert_test".to_string(),
            version: "1.0.0".to_string(),
            subject: BadgeSubject {
                subject_type: "agent".to_string(),
                id: "agent_1".to_string(),
                name: "test-agent".to_string(),
                metadata: None,
            },
            certification: BadgeCertificationBinding {
                tier: CertificationTier::Gold,
                issue_date: now_rfc3339_nanos(),
                expiry_date: now_rfc3339_nanos(),
                frameworks: vec!["soc2".to_string()],
            },
            policy: BadgePolicyBinding {
                hash: "sha256:deadbeef".to_string(),
                version: "1.0.0".to_string(),
                ruleset: Some("clawdstrike:strict".to_string()),
            },
            evidence: BadgeEvidenceBinding {
                receipt_count: 10,
                merkle_root: Some("sha256:cafe".to_string()),
                audit_log_ref: Some("file://audit".to_string()),
            },
            issuer: BadgeIssuer {
                id: "iss_test".to_string(),
                name: "Test Issuer".to_string(),
                public_key: pubkey,
                signature: "".to_string(),
                signed_at: now_rfc3339_nanos(),
            },
        };

        let signed = sign_badge(badge, &keypair).unwrap();
        assert!(!signed.issuer.signature.is_empty());
        assert!(verify_badge(&signed).unwrap());
    }
}

