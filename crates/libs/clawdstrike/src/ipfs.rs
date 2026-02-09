//! IPFS pinning client with gateway fetch and SHA-256 verification.
//!
//! Supports Pinata (remote managed pinning), self-hosted IPFS HTTP API, and
//! an ordered gateway fallback chain for content retrieval.
//!
//! Gated behind the `ipfs` feature flag.

use hush_core::{sha256, Hash};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::error::{Error, Result};

/// Default IPFS gateways used when none are configured.
pub const DEFAULT_GATEWAYS: &[&str] = &[
    "https://gateway.pinata.cloud/ipfs/",
    "https://dweb.link/ipfs/",
    "https://ipfs.io/ipfs/",
];

const GATEWAY_TIMEOUT: Duration = Duration::from_secs(10);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for IPFS pinning and retrieval.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpfsPinningConfig {
    /// Pinata JWT token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinata_jwt: Option<String>,
    /// Self-hosted IPFS API URL (e.g., `http://localhost:5001`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipfs_api_url: Option<String>,
    /// Ordered list of IPFS gateway base URLs for fetching.
    #[serde(default)]
    pub gateways: Vec<String>,
}

impl IpfsPinningConfig {
    /// Returns the effective gateway list: configured gateways falling back to defaults.
    pub fn effective_gateways(&self) -> Vec<String> {
        if self.gateways.is_empty() {
            DEFAULT_GATEWAYS.iter().map(|s| (*s).to_string()).collect()
        } else {
            self.gateways.clone()
        }
    }
}

/// Pinata API response for `pinJSONToIPFS`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinataPinResponse {
    #[serde(rename = "IpfsHash")]
    ipfs_hash: String,
    #[serde(rename = "PinSize")]
    _pin_size: u64,
    #[serde(rename = "Timestamp")]
    _timestamp: String,
}

/// Self-hosted IPFS API response for `/api/v0/add`.
#[derive(Debug, Deserialize)]
struct IpfsAddResponse {
    #[serde(rename = "Hash")]
    hash: String,
}

/// Information about a pinned item.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinInfo {
    pub cid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_pinned: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

/// IPFS client for pinning and fetching content-addressed data.
pub struct IpfsClient {
    config: IpfsPinningConfig,
    http: reqwest::Client,
}

impl IpfsClient {
    /// Create a new IPFS client from configuration.
    pub fn new(config: IpfsPinningConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(GATEWAY_TIMEOUT)
            .build()
            .map_err(|e| Error::ConfigError(format!("Failed to build IPFS HTTP client: {e}")))?;
        Ok(Self { config, http })
    }

    /// Pin JSON content to IPFS via Pinata or self-hosted node and return the CID.
    pub async fn pin_json(&self, json: &serde_json::Value, name: &str) -> Result<String> {
        if let Some(ref jwt) = self.config.pinata_jwt {
            return self.pin_json_pinata(json, name, jwt).await;
        }
        if let Some(ref api_url) = self.config.ipfs_api_url {
            return self.pin_json_self_hosted(json, api_url).await;
        }
        Err(Error::ConfigError(
            "No IPFS pinning backend configured (set pinata_jwt or ipfs_api_url)".to_string(),
        ))
    }

    /// Fetch content by CID, trying each gateway in order.
    ///
    /// If `expected_sha256` is provided, the fetched content is verified against it.
    /// Returns the raw bytes on success.
    pub async fn fetch_verified(
        &self,
        cid: &str,
        expected_sha256: Option<&Hash>,
        extra_gateway_hints: &[String],
    ) -> Result<Vec<u8>> {
        let cid = cid.trim().trim_start_matches('/');
        if cid.is_empty() {
            return Err(Error::ConfigError("IPFS CID is empty".to_string()));
        }

        // Build gateway list: hints first, then configured, then defaults.
        let mut gateways: Vec<String> = Vec::new();
        for g in extra_gateway_hints {
            let normalized = ensure_trailing_slash(g);
            if !gateways.contains(&normalized) {
                gateways.push(normalized);
            }
        }
        for g in self.config.effective_gateways() {
            let normalized = ensure_trailing_slash(&g);
            if !gateways.contains(&normalized) {
                gateways.push(normalized);
            }
        }

        if gateways.is_empty() {
            return Err(Error::ConfigError(
                "No IPFS gateways configured".to_string(),
            ));
        }

        let deadline = tokio::time::Instant::now() + TOTAL_TIMEOUT;
        let mut errors = Vec::new();

        for gateway in &gateways {
            if tokio::time::Instant::now() >= deadline {
                break;
            }

            let url = format!("{gateway}{cid}");
            match self.fetch_single_gateway(&url).await {
                Ok(bytes) => {
                    if let Some(expected) = expected_sha256 {
                        let actual = sha256(&bytes);
                        if &actual != expected {
                            errors.push(format!(
                                "{url}: SHA-256 mismatch (expected {}, got {})",
                                expected.to_hex(),
                                actual.to_hex()
                            ));
                            continue;
                        }
                    }
                    return Ok(bytes);
                }
                Err(e) => {
                    errors.push(format!("{url}: {e}"));
                }
            }
        }

        Err(Error::ConfigError(format!(
            "Failed to fetch CID {cid} from all gateways:\n- {}",
            errors.join("\n- ")
        )))
    }

    /// List currently pinned items.
    pub async fn list_pins(&self) -> Result<Vec<PinInfo>> {
        if let Some(ref jwt) = self.config.pinata_jwt {
            return self.list_pins_pinata(jwt).await;
        }
        if let Some(ref api_url) = self.config.ipfs_api_url {
            return self.list_pins_self_hosted(api_url).await;
        }
        Err(Error::ConfigError(
            "No IPFS pinning backend configured".to_string(),
        ))
    }

    /// Unpin a CID.
    pub async fn unpin(&self, cid: &str) -> Result<()> {
        if let Some(ref jwt) = self.config.pinata_jwt {
            return self.unpin_pinata(cid, jwt).await;
        }
        if let Some(ref api_url) = self.config.ipfs_api_url {
            return self.unpin_self_hosted(cid, api_url).await;
        }
        Err(Error::ConfigError(
            "No IPFS pinning backend configured".to_string(),
        ))
    }

    // -----------------------------------------------------------------------
    // Pinata API
    // -----------------------------------------------------------------------

    async fn pin_json_pinata(
        &self,
        json: &serde_json::Value,
        name: &str,
        jwt: &str,
    ) -> Result<String> {
        let body = serde_json::json!({
            "pinataContent": json,
            "pinataMetadata": { "name": name },
        });

        let resp = self
            .http
            .post("https://api.pinata.cloud/pinning/pinJSONToIPFS")
            .bearer_auth(jwt)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::ConfigError(format!("Pinata pin request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::ConfigError(format!(
                "Pinata pin failed (HTTP {status}): {text}"
            )));
        }

        let pin_resp: PinataPinResponse = resp
            .json()
            .await
            .map_err(|e| Error::ConfigError(format!("Invalid Pinata response: {e}")))?;

        Ok(pin_resp.ipfs_hash)
    }

    async fn list_pins_pinata(&self, jwt: &str) -> Result<Vec<PinInfo>> {
        let resp = self
            .http
            .get("https://api.pinata.cloud/data/pinList?status=pinned&pageLimit=100")
            .bearer_auth(jwt)
            .send()
            .await
            .map_err(|e| Error::ConfigError(format!("Pinata list request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::ConfigError(format!(
                "Pinata list failed (HTTP {status}): {text}"
            )));
        }

        let value: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::ConfigError(format!("Invalid Pinata list response: {e}")))?;

        let rows = value
            .get("rows")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut pins = Vec::new();
        for row in rows {
            let cid = row
                .get("ipfs_pin_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let name = row
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let date_pinned = row
                .get("date_pinned")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let size_bytes = row.get("size").and_then(|v| v.as_u64());

            if !cid.is_empty() {
                pins.push(PinInfo {
                    cid,
                    name,
                    date_pinned,
                    size_bytes,
                });
            }
        }

        Ok(pins)
    }

    async fn unpin_pinata(&self, cid: &str, jwt: &str) -> Result<()> {
        let url = format!("https://api.pinata.cloud/pinning/unpin/{cid}");
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(jwt)
            .send()
            .await
            .map_err(|e| Error::ConfigError(format!("Pinata unpin request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::ConfigError(format!(
                "Pinata unpin failed (HTTP {status}): {text}"
            )));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Self-hosted IPFS API
    // -----------------------------------------------------------------------

    async fn pin_json_self_hosted(
        &self,
        json: &serde_json::Value,
        api_url: &str,
    ) -> Result<String> {
        let data = serde_json::to_vec(json)?;
        let api_url = api_url.trim_end_matches('/');
        let url = format!("{api_url}/api/v0/add?pin=true");

        let part = reqwest::multipart::Part::bytes(data).file_name("data.json");
        let form = reqwest::multipart::Form::new().part("file", part);

        let resp = self
            .http
            .post(&url)
            .multipart(form)
            .send()
            .await
            .map_err(|e| Error::ConfigError(format!("IPFS add request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::ConfigError(format!(
                "IPFS add failed (HTTP {status}): {text}"
            )));
        }

        let add_resp: IpfsAddResponse = resp
            .json()
            .await
            .map_err(|e| Error::ConfigError(format!("Invalid IPFS add response: {e}")))?;

        Ok(add_resp.hash)
    }

    async fn list_pins_self_hosted(&self, api_url: &str) -> Result<Vec<PinInfo>> {
        let api_url = api_url.trim_end_matches('/');
        let url = format!("{api_url}/api/v0/pin/ls?type=recursive");

        let resp = self
            .http
            .post(&url)
            .send()
            .await
            .map_err(|e| Error::ConfigError(format!("IPFS pin/ls request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::ConfigError(format!(
                "IPFS pin/ls failed (HTTP {status}): {text}"
            )));
        }

        let value: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::ConfigError(format!("Invalid IPFS pin/ls response: {e}")))?;

        let keys = value
            .get("Keys")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        let pins: Vec<PinInfo> = keys
            .keys()
            .map(|cid| PinInfo {
                cid: cid.clone(),
                name: None,
                date_pinned: None,
                size_bytes: None,
            })
            .collect();

        Ok(pins)
    }

    async fn unpin_self_hosted(&self, cid: &str, api_url: &str) -> Result<()> {
        let api_url = api_url.trim_end_matches('/');
        let url = format!("{api_url}/api/v0/pin/rm?arg={cid}");

        let resp = self
            .http
            .post(&url)
            .send()
            .await
            .map_err(|e| Error::ConfigError(format!("IPFS pin/rm request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::ConfigError(format!(
                "IPFS pin/rm failed (HTTP {status}): {text}"
            )));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Gateway fetch
    // -----------------------------------------------------------------------

    async fn fetch_single_gateway(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| Error::ConfigError(format!("Gateway request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::ConfigError(format!(
                "Gateway returned HTTP {}",
                resp.status()
            )));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::ConfigError(format!("Gateway read failed: {e}")))?;

        Ok(bytes.to_vec())
    }
}

/// Ensure a gateway URL ends with a slash for CID concatenation.
fn ensure_trailing_slash(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.ends_with('/') {
        trimmed.to_string()
    } else {
        format!("{trimmed}/")
    }
}

/// Parse an `ipfs://` URI and return the bare CID (and optional path).
pub fn parse_ipfs_uri(uri: &str) -> Result<&str> {
    let stripped = uri
        .strip_prefix("ipfs://")
        .ok_or_else(|| Error::ConfigError(format!("Not an ipfs:// URI: {uri}")))?;
    let trimmed = stripped.trim_start_matches('/');
    if trimmed.is_empty() {
        return Err(Error::ConfigError(
            "Invalid ipfs:// URI (missing CID)".to_string(),
        ));
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_gateways_are_populated() {
        let config = IpfsPinningConfig::default();
        let gateways = config.effective_gateways();
        assert_eq!(gateways.len(), DEFAULT_GATEWAYS.len());
        for gw in &gateways {
            assert!(gw.starts_with("https://"), "gateway should be HTTPS: {gw}");
        }
    }

    #[test]
    fn custom_gateways_override_defaults() {
        let config = IpfsPinningConfig {
            gateways: vec!["https://custom.gateway/ipfs/".to_string()],
            ..Default::default()
        };
        let gateways = config.effective_gateways();
        assert_eq!(gateways.len(), 1);
        assert_eq!(gateways[0], "https://custom.gateway/ipfs/");
    }

    #[test]
    fn ensure_trailing_slash_works() {
        assert_eq!(
            ensure_trailing_slash("https://gw.example.com/ipfs"),
            "https://gw.example.com/ipfs/"
        );
        assert_eq!(
            ensure_trailing_slash("https://gw.example.com/ipfs/"),
            "https://gw.example.com/ipfs/"
        );
    }

    #[test]
    fn parse_ipfs_uri_valid() {
        assert_eq!(
            parse_ipfs_uri("ipfs://bafyexample123").unwrap(),
            "bafyexample123"
        );
        assert_eq!(
            parse_ipfs_uri("ipfs://bafyexample123/path/to/file").unwrap(),
            "bafyexample123/path/to/file"
        );
    }

    #[test]
    fn parse_ipfs_uri_rejects_empty() {
        assert!(parse_ipfs_uri("ipfs://").is_err());
        assert!(parse_ipfs_uri("https://example.com").is_err());
    }

    #[test]
    fn pin_info_round_trips() {
        let pin = PinInfo {
            cid: "bafytest123".to_string(),
            name: Some("test-bundle".to_string()),
            date_pinned: Some("2026-02-07T00:00:00Z".to_string()),
            size_bytes: Some(1024),
        };
        let json = serde_json::to_string(&pin).unwrap();
        let parsed: PinInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cid, "bafytest123");
        assert_eq!(parsed.name.unwrap(), "test-bundle");
    }

    #[test]
    fn ipfs_pinning_config_serde_round_trip() {
        let config = IpfsPinningConfig {
            pinata_jwt: Some("test-jwt".to_string()),
            ipfs_api_url: Some("http://localhost:5001".to_string()),
            gateways: vec!["https://gw.example.com/ipfs/".to_string()],
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: IpfsPinningConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pinata_jwt.unwrap(), "test-jwt");
        assert_eq!(parsed.ipfs_api_url.unwrap(), "http://localhost:5001");
        assert_eq!(parsed.gateways.len(), 1);
    }

    #[tokio::test]
    async fn fetch_verified_rejects_empty_cid() {
        let client = IpfsClient::new(IpfsPinningConfig::default()).unwrap();
        let result = client.fetch_verified("", None, &[]).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"), "unexpected error: {err}");
    }

    #[test]
    fn no_pinning_backend_returns_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = IpfsClient::new(IpfsPinningConfig::default()).unwrap();
        let result = rt.block_on(client.pin_json(&serde_json::json!({}), "test"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("No IPFS pinning backend"),
            "unexpected error: {err}"
        );
    }
}
