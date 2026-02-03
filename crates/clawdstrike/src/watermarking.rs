//! Prompt watermarking utilities.
//!
//! This is a lightweight implementation intended for provenance/audit use-cases.
//! It supports embedding a signed watermark payload into text using a metadata comment.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use hush_core::{canonical, sha256, Keypair, PublicKey, Signature};

/// Watermark encoding strategies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatermarkEncoding {
    Metadata,
}

impl Default for WatermarkEncoding {
    fn default() -> Self {
        Self::Metadata
    }
}

/// Watermark payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatermarkPayload {
    #[serde(alias = "application_id")]
    pub application_id: String,
    #[serde(alias = "session_id")]
    pub session_id: String,
    #[serde(alias = "created_at")]
    pub created_at: u64, // Unix timestamp ms
    #[serde(alias = "sequence_number")]
    pub sequence_number: u32,
    #[serde(alias = "expires_at")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(alias = "total_messages")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_messages: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

impl WatermarkPayload {
    pub fn new(application_id: String, session_id: String) -> Self {
        Self {
            application_id,
            session_id,
            created_at: now_ms(),
            expires_at: None,
            sequence_number: 0,
            total_messages: None,
            metadata: None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Canonical JSON (RFC 8785 JCS) to make signatures and fingerprints portable across languages.
        let value = serde_json::to_value(self).expect("payload json serialization");
        let canonical =
            canonical::canonicalize(&value).expect("payload canonical json serialization");
        canonical.into_bytes()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Encoded watermark.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedWatermark {
    pub payload: WatermarkPayload,
    pub encoding: WatermarkEncoding,
    /// Serialized payload bytes (canonical JSON).
    pub encoded_data: Vec<u8>,
    /// Ed25519 signature over `encoded_data`.
    pub signature: String,
    /// Verifying key as hex (no prefix).
    pub public_key: String,
}

impl EncodedWatermark {
    pub fn verify(&self) -> bool {
        let pk = match PublicKey::from_hex(&self.public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let sig = match Signature::from_hex(&self.signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        pk.verify(&self.encoded_data, &sig)
    }

    /// Stable fingerprint for correlation (SHA-256 of encoded payload).
    pub fn fingerprint(&self) -> String {
        sha256(&self.encoded_data).to_hex()
    }
}

/// Extraction result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatermarkExtractionResult {
    pub found: bool,
    pub watermark: Option<EncodedWatermark>,
    pub verified: bool,
    pub errors: Vec<String>,
}

/// Watermarker configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatermarkConfig {
    #[serde(default)]
    pub encoding: WatermarkEncoding,
    /// Optional ed25519 seed hex (32 bytes). If omitted and `generate_keypair` is true, a new key is generated.
    pub private_key: Option<String>,
    /// If set, requires `private_key` or generates one.
    #[serde(default = "default_true")]
    pub generate_keypair: bool,
    #[serde(default = "default_true")]
    pub include_timestamp: bool,
    #[serde(default = "default_true")]
    pub include_sequence: bool,
    pub custom_metadata: Option<HashMap<String, String>>,
}

fn default_true() -> bool {
    true
}

impl Default for WatermarkConfig {
    fn default() -> Self {
        Self {
            encoding: WatermarkEncoding::Metadata,
            private_key: None,
            generate_keypair: true,
            include_timestamp: true,
            include_sequence: true,
            custom_metadata: None,
        }
    }
}

/// Watermarked prompt result.
#[derive(Clone, Debug)]
pub struct WatermarkedPrompt {
    pub original: String,
    pub watermarked: String,
    pub watermark: EncodedWatermark,
}

/// Verifier configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WatermarkVerifierConfig {
    pub trusted_public_keys: Vec<String>,
    #[serde(default)]
    pub allow_unverified: bool,
}

/// Prompt watermarker.
pub struct PromptWatermarker {
    config: WatermarkConfig,
    keypair: Keypair,
    sequence: AtomicU32,
}

impl PromptWatermarker {
    pub fn new(config: WatermarkConfig) -> Result<Self, WatermarkError> {
        let keypair = if let Some(seed_hex) = &config.private_key {
            let seed_hex = seed_hex.strip_prefix("0x").unwrap_or(seed_hex);
            let bytes =
                hex::decode(seed_hex).map_err(|e| WatermarkError::ConfigError(e.to_string()))?;
            if bytes.len() != 32 {
                return Err(WatermarkError::ConfigError(
                    "private_key must be 32-byte seed hex".to_string(),
                ));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            Keypair::from_seed(&seed)
        } else if config.generate_keypair {
            Keypair::generate()
        } else {
            return Err(WatermarkError::ConfigError(
                "private_key missing and generate_keypair is false".to_string(),
            ));
        };

        Ok(Self {
            config,
            keypair,
            sequence: AtomicU32::new(0),
        })
    }

    pub fn public_key(&self) -> String {
        self.keypair.public_key().to_hex()
    }

    pub fn generate_payload(&self, application_id: &str, session_id: &str) -> WatermarkPayload {
        let mut payload = WatermarkPayload::new(application_id.to_string(), session_id.to_string());
        if !self.config.include_timestamp {
            payload.created_at = 0;
        }
        if self.config.include_sequence {
            payload.sequence_number = self.sequence.fetch_add(1, Ordering::Relaxed);
        }
        payload.metadata = self.config.custom_metadata.clone();
        payload
    }

    pub fn watermark(
        &self,
        prompt: &str,
        payload: Option<WatermarkPayload>,
    ) -> Result<WatermarkedPrompt, WatermarkError> {
        let payload = payload.unwrap_or_else(|| self.generate_payload("unknown", "unknown"));
        let encoded_data = payload.to_bytes();
        let signature = self.keypair.sign(&encoded_data).to_hex();
        let public_key = self.keypair.public_key().to_hex();

        let watermark = EncodedWatermark {
            payload,
            encoding: self.config.encoding.clone(),
            encoded_data: encoded_data.clone(),
            signature,
            public_key,
        };

        let watermarked = match self.config.encoding {
            WatermarkEncoding::Metadata => embed_metadata_comment(prompt, &watermark)?,
        };

        Ok(WatermarkedPrompt {
            original: prompt.to_string(),
            watermarked,
            watermark,
        })
    }
}

/// Extract watermark from text.
pub struct WatermarkExtractor {
    config: WatermarkVerifierConfig,
}

impl WatermarkExtractor {
    pub fn new(config: WatermarkVerifierConfig) -> Self {
        Self { config }
    }

    pub fn extract(&self, text: &str) -> WatermarkExtractionResult {
        match extract_metadata_comment(text) {
            Ok(Some(wm)) => {
                let verified = wm.verify()
                    && (self.config.trusted_public_keys.is_empty()
                        || self
                            .config
                            .trusted_public_keys
                            .iter()
                            .any(|k| k.eq_ignore_ascii_case(&wm.public_key)));
                WatermarkExtractionResult {
                    found: true,
                    watermark: Some(wm),
                    verified,
                    errors: Vec::new(),
                }
            }
            Ok(None) => WatermarkExtractionResult {
                found: false,
                watermark: None,
                verified: false,
                errors: Vec::new(),
            },
            Err(e) => WatermarkExtractionResult {
                found: false,
                watermark: None,
                verified: false,
                errors: vec![e],
            },
        }
    }
}

#[derive(Debug)]
pub enum WatermarkError {
    ConfigError(String),
    EncodingError(String),
}

const META_PREFIX: &str = "<!--hushclaw.watermark:v1:";
const META_SUFFIX: &str = "-->";

fn embed_metadata_comment(
    prompt: &str,
    watermark: &EncodedWatermark,
) -> Result<String, WatermarkError> {
    // Embed base64url(JSON) where JSON includes payload bytes (b64), signature (hex), public_key (hex).
    let payload_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&watermark.encoded_data);
    let json = serde_json::json!({
        "encoding": watermark.encoding,
        "payload": payload_b64,
        "signature": watermark.signature,
        "publicKey": watermark.public_key,
    });
    let blob =
        serde_json::to_vec(&json).map_err(|e| WatermarkError::EncodingError(e.to_string()))?;
    let blob_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob);
    Ok(format!("{META_PREFIX}{blob_b64}{META_SUFFIX}\n{prompt}"))
}

fn extract_metadata_comment(text: &str) -> Result<Option<EncodedWatermark>, String> {
    let start = match text.find(META_PREFIX) {
        Some(i) => i + META_PREFIX.len(),
        None => return Ok(None),
    };
    let end = match text[start..].find(META_SUFFIX) {
        Some(i) => start + i,
        None => return Err("watermark metadata missing suffix".to_string()),
    };
    let blob_b64 = &text[start..end];
    let blob = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(blob_b64)
        .map_err(|e| format!("watermark base64 decode failed: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&blob).map_err(|e| format!("watermark json decode failed: {e}"))?;

    let encoding = v.get("encoding").ok_or("watermark missing encoding")?;
    let encoding: WatermarkEncoding = serde_json::from_value(encoding.clone())
        .map_err(|e| format!("watermark encoding parse failed: {e}"))?;

    let payload_b64 = v
        .get("payload")
        .and_then(|x| x.as_str())
        .ok_or("watermark missing payload")?;
    let encoded_data = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("watermark payload base64 decode failed: {e}"))?;
    let payload: WatermarkPayload = serde_json::from_slice(&encoded_data)
        .map_err(|e| format!("watermark payload json decode failed: {e}"))?;

    let signature = v
        .get("signature")
        .and_then(|x| x.as_str())
        .ok_or("watermark missing signature")?
        .to_string();
    let public_key = v
        .get("publicKey")
        .and_then(|x| x.as_str())
        .ok_or("watermark missing publicKey")?
        .to_string();

    Ok(Some(EncodedWatermark {
        payload,
        encoding,
        encoded_data,
        signature,
        public_key,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_bytes_are_jcs_canonical_and_omit_nulls() {
        let mut p = WatermarkPayload::new("app".to_string(), "session".to_string());
        p.created_at = 1;
        p.sequence_number = 2;
        p.expires_at = None;
        p.total_messages = None;
        p.metadata = None;

        let bytes = p.to_bytes();
        let s = String::from_utf8(bytes).expect("utf8");

        // Keys are sorted lexicographically (RFC 8785), no whitespace, and optional fields omitted.
        assert_eq!(
            s,
            r#"{"applicationId":"app","createdAt":1,"sequenceNumber":2,"sessionId":"session"}"#
        );
    }

    #[test]
    fn roundtrips_metadata_watermark_and_verifies() {
        let w = PromptWatermarker::new(WatermarkConfig::default()).expect("watermarker");
        let payload = w.generate_payload("app", "session");
        let out = w.watermark("hello", Some(payload)).expect("watermark");

        let extractor = WatermarkExtractor::new(WatermarkVerifierConfig {
            trusted_public_keys: vec![w.public_key()],
            allow_unverified: false,
        });
        let r = extractor.extract(&out.watermarked);
        assert!(r.found);
        assert!(r.verified);
        let wm = r.watermark.expect("watermark");
        assert_eq!(wm.payload.application_id, "app");
        assert_eq!(wm.payload.session_id, "session");
        assert!(wm.verify());
    }
}
