//! Marketplace feed commands (signed feed + signed policy bundles).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Component, Path};
use std::sync::{LazyLock, Mutex};

use clawdstrike::{
    ContentIds, CuratorConfig, CuratorConfigFile, CuratorTrustSet, SignedMarketplaceFeed,
    SignedPolicyBundle, TrustLevel, ValidatedCurator,
};
use hush_core::{sha256, Hash, MerkleProof, PublicKey};
use reqwest::header::LOCATION;
use serde::{Deserialize, Serialize};
use tauri::path::BaseDirectory;
use tauri::{AppHandle, Manager, State};

use crate::state::AppState;

const MAX_FEED_BYTES: usize = 1024 * 1024; // 1 MiB
const MAX_BUNDLE_BYTES: usize = 2 * 1024 * 1024; // 2 MiB
const MAX_NOTARY_BYTES: usize = 1024 * 1024; // 1 MiB
const MAX_FETCH_REDIRECTS: usize = 5;

const BUILTIN_FEED_PATH: &str = "resources/marketplace/feed.signed.json";
const BUILTIN_BUNDLE_PREFIX: &str = "builtin://bundles/";
const IPFS_PREFIX: &str = "ipfs://";
const CURATOR_CONFIG_FILENAME: &str = "trusted_curators.toml";
const PROVENANCE_CONFIG_FILENAME: &str = "marketplace_provenance.json";

const DEFAULT_IPFS_GATEWAYS: &[&str] = &[
    "https://w3s.link",
    "https://cloudflare-ipfs.com",
    "https://ipfs.io",
];

#[derive(Clone)]
struct TrustedInstallEntry {
    signed_bundle: SignedPolicyBundle,
    install_allowed: bool,
}

type TrustedInstallCache = HashMap<String, HashMap<String, TrustedInstallEntry>>;

static TRUSTED_INSTALL_CACHE: LazyLock<Mutex<TrustedInstallCache>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketplacePolicyDto {
    pub entry_id: String,
    pub bundle_uri: String,
    pub title: String,
    pub description: String,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub author: Option<String>,
    pub author_url: Option<String>,
    pub icon: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notary_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spine_envelope_hash: Option<String>,
    pub bundle_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curator_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curator_trust_level: Option<String>,
    #[serde(default)]
    pub install_allowed: bool,
    pub signed_bundle: SignedPolicyBundle,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketplaceListResponse {
    pub feed_id: String,
    pub published_at: String,
    pub seq: u64,
    pub signer_public_key: String,
    pub policies: Vec<MarketplacePolicyDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarketplaceProvenanceConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notary_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proofs_api_url: Option<String>,
    #[serde(default)]
    pub trusted_attesters: Vec<String>,
    #[serde(default)]
    pub require_verified: bool,
    #[serde(default = "default_prefer_spine")]
    pub prefer_spine: bool,
    #[serde(default)]
    pub trusted_witness_keys: Vec<String>,
}

impl Default for MarketplaceProvenanceConfig {
    fn default() -> Self {
        Self {
            notary_url: None,
            proofs_api_url: None,
            trusted_attesters: Vec::new(),
            require_verified: false,
            prefer_spine: true,
            trusted_witness_keys: Vec::new(),
        }
    }
}

impl MarketplaceProvenanceConfig {
    fn normalized(self) -> Self {
        Self {
            notary_url: normalize_optional_setting_url(self.notary_url),
            proofs_api_url: normalize_optional_setting_url(self.proofs_api_url),
            trusted_attesters: normalize_setting_list(self.trusted_attesters, 64),
            require_verified: self.require_verified,
            prefer_spine: self.prefer_spine,
            trusted_witness_keys: normalize_setting_list(self.trusted_witness_keys, 64),
        }
    }
}

fn default_prefer_spine() -> bool {
    true
}

fn normalize_marketplace_identifier(value: &str, label: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("Missing {label}"));
    }
    if trimmed.len() > 256 {
        return Err(format!("{label} too long"));
    }
    Ok(trimmed.to_string())
}

fn cache_trusted_install_entries(
    feed_id: &str,
    entries: HashMap<String, TrustedInstallEntry>,
) -> Result<(), String> {
    let feed_id = normalize_marketplace_identifier(feed_id, "feed ID")?;
    let mut cache = TRUSTED_INSTALL_CACHE
        .lock()
        .map_err(|_| "Trusted marketplace install cache is unavailable".to_string())?;
    cache.clear();
    cache.insert(feed_id, entries);
    Ok(())
}

fn get_trusted_install_bundle(
    feed_id: &str,
    entry_id: &str,
) -> Result<TrustedInstallEntry, String> {
    let feed_id = normalize_marketplace_identifier(feed_id, "feed ID")?;
    let entry_id = normalize_marketplace_identifier(entry_id, "entry ID")?;

    let cache = TRUSTED_INSTALL_CACHE
        .lock()
        .map_err(|_| "Trusted marketplace install cache is unavailable".to_string())?;

    cache
        .get(&feed_id)
        .and_then(|entries| entries.get(&entry_id))
        .cloned()
        .ok_or_else(|| {
            format!(
                "Trusted marketplace entry {entry_id} from feed {feed_id} is unavailable. Refresh the marketplace feed and try again."
            )
        })
}

fn ensure_expected_policy_hash_matches(
    signed_bundle: &SignedPolicyBundle,
    expected_policy_hash: &str,
) -> Result<(), String> {
    let expected_policy_hash =
        normalize_marketplace_identifier(expected_policy_hash, "policy hash")?;
    let actual_policy_hash = signed_bundle.bundle.policy_hash.to_hex();
    if !actual_policy_hash.eq_ignore_ascii_case(&expected_policy_hash) {
        return Err(
            "Trusted marketplace entry changed since it was opened. Refresh and review the policy again before installing."
                .to_string(),
        );
    }
    Ok(())
}

fn ensure_expected_bundle_signature_matches(
    signed_bundle: &SignedPolicyBundle,
    expected_bundle_signature: &str,
) -> Result<(), String> {
    let expected_bundle_signature =
        normalize_marketplace_identifier(expected_bundle_signature, "bundle signature")?;
    let actual_bundle_signature = signed_bundle.signature.to_hex();
    if !actual_bundle_signature.eq_ignore_ascii_case(&expected_bundle_signature) {
        return Err(
            "Trusted marketplace entry changed since it was opened. Refresh and review the policy again before installing."
                .to_string(),
        );
    }
    Ok(())
}

fn build_notary_verify_url(notary_url: &str, uid: &str) -> Result<reqwest::Url, String> {
    let uid = uid.trim();
    if uid.is_empty() {
        return Err("Missing attestation UID".to_string());
    }
    if uid.len() > 256 {
        return Err("Attestation UID too long".to_string());
    }

    let base = notary_url.trim();
    if base.is_empty() {
        return Err("Missing notary URL".to_string());
    }

    let mut url = reqwest::Url::parse(base).map_err(|e| format!("Invalid notary URL: {e}"))?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err("Notary URL must not include query or fragment".to_string());
    }

    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| "Notary URL cannot be a base".to_string())?;
        segments.pop_if_empty();
        segments.push("verify");
        segments.push(uid);
    }

    Ok(url)
}

#[tauri::command]
pub async fn marketplace_list_policies(
    app: AppHandle,
    sources: Option<Vec<String>>,
    state: State<'_, AppState>,
) -> Result<MarketplaceListResponse, String> {
    let curator_config = load_marketplace_curator_config()?;
    let sources = sources.unwrap_or_else(|| vec!["builtin".to_string()]);

    let mut attempts = Vec::new();
    let mut selected: Option<(SignedMarketplaceFeed, ValidatedCurator)> = None;

    for source in sources {
        match load_signed_feed(&app, &state.http_client, &source).await {
            Ok(feed) => {
                let parsed = match serde_json::from_slice::<SignedMarketplaceFeed>(&feed) {
                    Ok(v) => v,
                    Err(e) => {
                        attempts.push(format!("{source}: failed to parse JSON: {e}"));
                        continue;
                    }
                };
                match parsed.verify_with_config(&curator_config) {
                    Ok(curator) => {
                        selected = Some((parsed, curator.clone()));
                        break;
                    }
                    Err(e) => {
                        attempts.push(format!(
                            "{source}: marketplace feed verification failed: {e}"
                        ));
                        continue;
                    }
                }
            }
            Err(e) => attempts.push(format!("{source}: {e}")),
        }
    }

    let (signed, curator) = selected.ok_or_else(|| {
        if attempts.is_empty() {
            "No marketplace feed sources configured".to_string()
        } else {
            format!(
                "Failed to load marketplace feed:\n- {}",
                attempts.join("\n- ")
            )
        }
    })?;

    let mut warnings = Vec::new();
    let mut policies = Vec::new();
    let mut trusted_install_entries = HashMap::new();
    let install_allowed = matches!(curator.trust_level, TrustLevel::Full);
    let curator_trust_level = Some(match curator.trust_level {
        TrustLevel::Full => "full".to_string(),
        TrustLevel::AuditOnly => "audit-only".to_string(),
    });

    for entry in &signed.feed.entries {
        let bundle_bytes = match load_bundle_bytes_with_hints(
            &app,
            &state.http_client,
            &entry.bundle_uri,
            &entry.gateway_hints,
            entry.content_ids.as_ref(),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                warnings.push(format!("{}: failed to load bundle: {e}", entry.entry_id));
                continue;
            }
        };

        let signed_bundle: SignedPolicyBundle = match serde_json::from_slice(&bundle_bytes) {
            Ok(v) => v,
            Err(e) => {
                warnings.push(format!("{}: invalid bundle JSON: {e}", entry.entry_id));
                continue;
            }
        };

        let bundle_valid = match signed_bundle.verify_embedded() {
            Ok(v) => v,
            Err(e) => {
                warnings.push(format!(
                    "{}: bundle verification failed: {e}",
                    entry.entry_id
                ));
                continue;
            }
        };
        if !bundle_valid {
            warnings.push(format!("{}: bundle signature invalid", entry.entry_id));
            continue;
        }
        trusted_install_entries.insert(
            entry.entry_id.clone(),
            TrustedInstallEntry {
                signed_bundle: signed_bundle.clone(),
                install_allowed,
            },
        );

        let policy = &signed_bundle.bundle.policy;
        let title = entry
            .title
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                if policy.name.trim().is_empty() {
                    None
                } else {
                    Some(policy.name.clone())
                }
            })
            .unwrap_or_else(|| entry.entry_id.clone());

        let description = entry
            .description
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                if policy.description.trim().is_empty() {
                    None
                } else {
                    Some(policy.description.clone())
                }
            })
            .unwrap_or_else(|| "Signed policy bundle".to_string());

        policies.push(MarketplacePolicyDto {
            entry_id: entry.entry_id.clone(),
            bundle_uri: entry.bundle_uri.clone(),
            title,
            description,
            category: entry.category.clone(),
            tags: entry.tags.clone(),
            author: entry.author.clone(),
            author_url: entry.author_url.clone(),
            icon: entry.icon.clone(),
            created_at: entry.created_at.clone(),
            updated_at: entry.updated_at.clone(),
            attestation_uid: entry
                .provenance
                .as_ref()
                .and_then(|p| p.attestation_uid.clone()),
            notary_url: entry.provenance.as_ref().and_then(|p| p.notary_url.clone()),
            spine_envelope_hash: entry
                .provenance
                .as_ref()
                .and_then(|p| p.spine_envelope_hash.clone()),
            bundle_public_key: signed_bundle.public_key.as_ref().map(|k| k.to_hex()),
            curator_name: Some(curator.name.clone()),
            curator_trust_level: curator_trust_level.clone(),
            install_allowed,
            signed_bundle,
        });
    }

    cache_trusted_install_entries(&signed.feed.feed_id, trusted_install_entries)?;

    Ok(MarketplaceListResponse {
        feed_id: signed.feed.feed_id,
        published_at: signed.feed.published_at,
        seq: signed.feed.seq,
        signer_public_key: curator.public_key.to_hex(),
        policies,
        warnings,
    })
}

#[tauri::command]
pub async fn marketplace_install_policy(
    daemon_url: String,
    feed_id: String,
    entry_id: String,
    policy_hash: String,
    bundle_signature: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let trusted_entry = get_trusted_install_bundle(&feed_id, &entry_id)?;
    if !trusted_entry.install_allowed {
        return Err(
            "This marketplace entry is trusted for review only (`audit-only`) and cannot be installed."
                .to_string(),
        );
    }
    ensure_expected_policy_hash_matches(&trusted_entry.signed_bundle, &policy_hash)?;
    ensure_expected_bundle_signature_matches(&trusted_entry.signed_bundle, &bundle_signature)?;
    let verified = trusted_entry
        .signed_bundle
        .verify_embedded()
        .map_err(|e| format!("Bundle verification failed: {e}"))?;
    if !verified {
        return Err("Bundle signature invalid".to_string());
    }

    let daemon_url = daemon_url.trim_end_matches('/');
    let url = format!("{daemon_url}/api/v1/policy/bundle");

    let resp = state
        .http_client
        .put(&url)
        .json(&trusted_entry.signed_bundle)
        .send()
        .await
        .map_err(|e| format!("Install request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Install failed (HTTP {status}): {text}"));
    }

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotaryVerifyResult {
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attester: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[tauri::command]
pub async fn marketplace_verify_attestation(
    uid: String,
    state: State<'_, AppState>,
) -> Result<NotaryVerifyResult, String> {
    let provenance = load_marketplace_provenance_config()?;
    let notary_url = provenance
        .notary_url
        .ok_or_else(|| "Marketplace notary URL is not configured".to_string())?;
    let url = build_notary_verify_url(&notary_url, &uid)?;

    let bytes =
        fetch_http_bytes_limited(&state.http_client, url.as_str(), MAX_NOTARY_BYTES).await?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("Invalid notary JSON: {e}"))?;

    let valid = value
        .get("valid")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| "Notary response missing `valid` boolean".to_string())?;

    let attester = value
        .get("attester")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let attested_at = value
        .get("attestedAt")
        .or_else(|| value.get("attested_at"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let error = value
        .get("error")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(NotaryVerifyResult {
        valid,
        attester,
        attested_at,
        error,
    })
}

#[tauri::command]
pub async fn marketplace_save_provenance_settings(
    settings: MarketplaceProvenanceConfig,
) -> Result<(), String> {
    save_marketplace_provenance_config(&settings.normalized())
}

fn desktop_config_dir() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|d| d.join("clawdstrike"))
}

fn curator_config_path() -> Option<std::path::PathBuf> {
    desktop_config_dir().map(|d| d.join(CURATOR_CONFIG_FILENAME))
}

fn load_curator_trust_set() -> Result<CuratorTrustSet, String> {
    let config_path = curator_config_path();
    CuratorTrustSet::load(config_path.as_deref())
        .map_err(|e| format!("Failed to load curator trust set: {e}"))
}

fn load_marketplace_curator_config() -> Result<CuratorConfig, String> {
    if let Some(path) = curator_config_path() {
        if path.exists() {
            if let Ok(config) = CuratorConfig::load(&path) {
                return Ok(config);
            }
        }
    }

    let trust_set = load_curator_trust_set()?;
    curator_config_from_trust_set(&trust_set)
}

fn curator_config_from_trust_set(trust_set: &CuratorTrustSet) -> Result<CuratorConfig, String> {
    let mut toml = String::new();
    for (idx, key) in trust_set.keys().iter().enumerate() {
        let _ = writeln!(
            toml,
            "[[curator]]\nname = \"trusted-{idx}\"\npublic_key = \"{}\"\ntrust_level = \"full\"\n",
            key.to_hex()
        );
    }
    CuratorConfig::parse(&toml)
        .map_err(|e| format!("Failed to build curator config from trusted keys: {e}"))
}

fn provenance_config_path() -> Option<std::path::PathBuf> {
    desktop_config_dir().map(|d| d.join(PROVENANCE_CONFIG_FILENAME))
}

fn load_marketplace_provenance_config() -> Result<MarketplaceProvenanceConfig, String> {
    let Some(path) = provenance_config_path() else {
        return Err("Cannot determine config directory".to_string());
    };

    if !path.exists() {
        return Ok(MarketplaceProvenanceConfig::default());
    }

    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read marketplace provenance config: {e}"))?;
    let parsed: MarketplaceProvenanceConfig = serde_json::from_str(&raw)
        .map_err(|e| format!("Invalid marketplace provenance config: {e}"))?;
    Ok(parsed.normalized())
}

fn save_marketplace_provenance_config(
    settings: &MarketplaceProvenanceConfig,
) -> Result<(), String> {
    let Some(path) = provenance_config_path() else {
        return Err("Cannot determine config directory".to_string());
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {e}"))?;
    }

    let bytes = serde_json::to_vec_pretty(settings)
        .map_err(|e| format!("Failed to serialize marketplace provenance config: {e}"))?;
    std::fs::write(&path, bytes)
        .map_err(|e| format!("Failed to write marketplace provenance config: {e}"))
}

fn normalize_optional_setting_url(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.chars().take(512).collect())
        }
    })
}

fn normalize_setting_list(values: Vec<String>, max_items: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized: String = trimmed.chars().take(512).collect();
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
        if out.len() >= max_items {
            break;
        }
    }
    out
}

async fn load_signed_feed(
    app: &AppHandle,
    client: &reqwest::Client,
    source: &str,
) -> Result<Vec<u8>, String> {
    if source == "builtin" {
        return read_resource_bytes(app, BUILTIN_FEED_PATH, MAX_FEED_BYTES);
    }

    load_uri_bytes(client, source, MAX_FEED_BYTES).await
}

async fn load_bundle_bytes_with_hints(
    app: &AppHandle,
    client: &reqwest::Client,
    uri: &str,
    gateway_hints: &[String],
    content_ids: Option<&ContentIds>,
) -> Result<Vec<u8>, String> {
    if let Some(rel) = uri.strip_prefix(BUILTIN_BUNDLE_PREFIX) {
        validate_resource_relpath(rel)?;
        let rel_path = format!("resources/marketplace/bundles/{rel}");
        return read_resource_bytes(app, &rel_path, MAX_BUNDLE_BYTES);
    }

    let bytes = load_uri_bytes_with_hints(client, uri, MAX_BUNDLE_BYTES, gateway_hints).await?;

    // Defense-in-depth: verify SHA-256 against content_ids if present
    if let Some(ids) = content_ids {
        let actual = sha256(&bytes);
        if actual != ids.sha256 {
            return Err(format!(
                "Bundle SHA-256 mismatch (expected {}, got {})",
                ids.sha256.to_hex(),
                actual.to_hex()
            ));
        }
    }

    Ok(bytes)
}

fn read_resource_bytes(
    app: &AppHandle,
    rel_path: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let path = app
        .path()
        .resolve(rel_path, BaseDirectory::Resource)
        .map_err(|e| format!("Failed to resolve resource path {rel_path}: {e}"))?;
    let bytes = std::fs::read(&path).map_err(|e| format!("Failed to read {rel_path}: {e}"))?;
    if bytes.len() > max_bytes {
        return Err(format!(
            "Resource {rel_path} exceeds max size ({} > {})",
            bytes.len(),
            max_bytes
        ));
    }
    Ok(bytes)
}

async fn load_uri_bytes(
    client: &reqwest::Client,
    uri: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    load_uri_bytes_with_hints(client, uri, max_bytes, &[]).await
}

async fn load_uri_bytes_with_hints(
    client: &reqwest::Client,
    uri: &str,
    max_bytes: usize,
    gateway_hints: &[String],
) -> Result<Vec<u8>, String> {
    if let Some(ipfs) = uri.strip_prefix(IPFS_PREFIX) {
        let urls = ipfs_gateway_urls_with_hints(ipfs, gateway_hints)?;
        let mut errs = Vec::new();
        for url in urls {
            match fetch_http_bytes_limited(client, &url, max_bytes).await {
                Ok(bytes) => return Ok(bytes),
                Err(e) => errs.push(format!("{url}: {e}")),
            }
        }
        return Err(format!(
            "Failed to fetch from IPFS gateways:\n- {}",
            errs.join("\n- ")
        ));
    }

    fetch_http_bytes_limited(client, uri, max_bytes).await
}

fn ipfs_gateway_urls_with_hints(
    ipfs_path: &str,
    gateway_hints: &[String],
) -> Result<Vec<String>, String> {
    // ipfs://<CID>/<path>
    let trimmed = ipfs_path.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return Err("Invalid ipfs:// URI (missing CID)".to_string());
    }

    let (cid, rest) = trimmed
        .split_once('/')
        .map(|(cid, rest)| (cid, format!("/{rest}")))
        .unwrap_or((trimmed, String::new()));

    let mut urls = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Gateway hints first (per-entry overrides)
    for hint in gateway_hints {
        let base = hint.trim().trim_end_matches('/');
        if !base.is_empty() {
            let url = format!("{base}/ipfs/{cid}{rest}");
            if seen.insert(url.clone()) {
                urls.push(url);
            }
        }
    }

    // Default gateways
    for gateway in DEFAULT_IPFS_GATEWAYS {
        let base = gateway.trim_end_matches('/');
        let url = format!("{base}/ipfs/{cid}{rest}");
        if seen.insert(url.clone()) {
            urls.push(url);
        }
    }

    Ok(urls)
}

async fn fetch_http_bytes_limited(
    _client: &reqwest::Client,
    url: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut current = reqwest::Url::parse(url).map_err(|e| format!("Invalid URL: {e}"))?;
    current.set_fragment(None);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    for _ in 0..=MAX_FETCH_REDIRECTS {
        validate_fetch_target(&current)?;

        let mut resp = client
            .get(current.clone())
            .send()
            .await
            .map_err(|e| format!("Request failed: {e}"))?;

        if resp.status().is_redirection() {
            let location = resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| format!("Redirect missing Location header: {current}"))?;
            let mut next = current
                .join(location)
                .map_err(|e| format!("Invalid redirect URL: {e}"))?;
            next.set_fragment(None);
            current = next;
            continue;
        }

        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }

        if let Some(len) = resp.content_length() {
            if len > (max_bytes as u64) {
                return Err(format!(
                    "Response exceeds size limit ({} > {})",
                    len, max_bytes
                ));
            }
        }

        let mut bytes = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| format!("Read failed: {e}"))?
        {
            if bytes.len().saturating_add(chunk.len()) > max_bytes {
                return Err(format!(
                    "Response exceeds size limit (>{} bytes)",
                    max_bytes
                ));
            }
            bytes.extend_from_slice(&chunk);
        }

        return Ok(bytes);
    }

    Err(format!(
        "Too many redirects while fetching marketplace URI (>{MAX_FETCH_REDIRECTS})"
    ))
}

fn validate_fetch_target(url: &reqwest::Url) -> Result<(), String> {
    if url.scheme() == "https" {
        if cfg!(debug_assertions) || !is_localhost(url) {
            return Ok(());
        }
        return Err(format!(
            "Blocked localhost target in release build: {}",
            url
        ));
    }
    if is_allowed_dev_http(url) {
        return Ok(());
    }
    Err(format!("Blocked URL scheme: {}", url.scheme()))
}

fn is_allowed_dev_http(url: &reqwest::Url) -> bool {
    if url.scheme() != "http" {
        return false;
    }
    cfg!(debug_assertions) && is_localhost(url)
}

fn is_localhost(url: &reqwest::Url) -> bool {
    let host = url.host_str().unwrap_or("");
    matches!(
        normalize_host(host).as_str(),
        "localhost" | "127.0.0.1" | "::1"
    )
}

fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Curator management commands
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CuratorKeyInfo {
    pub hex: String,
    pub source: String,
}

#[tauri::command]
pub async fn marketplace_list_curators() -> Result<Vec<CuratorKeyInfo>, String> {
    let trust_set = load_curator_trust_set()?;
    let keys: Vec<CuratorKeyInfo> = trust_set
        .keys()
        .iter()
        .map(|k| CuratorKeyInfo {
            hex: k.to_hex(),
            source: "merged".to_string(),
        })
        .collect();
    Ok(keys)
}

#[tauri::command]
pub async fn marketplace_add_curator(hex_key: String) -> Result<(), String> {
    let hex_key = hex_key.trim().to_string();
    // Validate the key is parseable
    PublicKey::from_hex(&hex_key).map_err(|e| format!("Invalid public key: {e}"))?;

    let config_path =
        curator_config_path().ok_or_else(|| "Cannot determine config directory".to_string())?;

    let mut config = CuratorConfigFile::load(&config_path)
        .map_err(|e| format!("Failed to load config: {e}"))?
        .unwrap_or_default();

    if !config.trusted_keys.contains(&hex_key) {
        config.trusted_keys.push(hex_key);
    }

    config
        .save(&config_path)
        .map_err(|e| format!("Failed to save config: {e}"))?;

    Ok(())
}

#[tauri::command]
pub async fn marketplace_remove_curator(hex_key: String) -> Result<(), String> {
    let hex_key = hex_key.trim().to_string();

    let config_path =
        curator_config_path().ok_or_else(|| "Cannot determine config directory".to_string())?;

    let mut config = CuratorConfigFile::load(&config_path)
        .map_err(|e| format!("Failed to load config: {e}"))?
        .unwrap_or_default();

    config.trusted_keys.retain(|k| k != &hex_key);

    config
        .save(&config_path)
        .map_err(|e| format!("Failed to save config: {e}"))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Spine proofs-api verification
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpineProofResult {
    pub included: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[tauri::command]
pub async fn marketplace_verify_spine_proof(
    proofs_api_url: String,
    envelope_hash: String,
    state: State<'_, AppState>,
) -> Result<SpineProofResult, String> {
    let envelope_hash = envelope_hash.trim();
    if envelope_hash.is_empty() {
        return Err("Missing envelope hash".to_string());
    }

    let base = proofs_api_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err("Missing proofs API URL".to_string());
    }

    let url = format!("{base}/v1/proofs/inclusion?envelope_hash={envelope_hash}");

    let bytes = fetch_http_bytes_limited(&state.http_client, &url, MAX_NOTARY_BYTES).await?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("Invalid proofs API JSON: {e}"))?;

    let has_included_flag = value
        .get("included")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let has_audit_path = value.get("audit_path").and_then(|v| v.as_array()).is_some();
    let included = has_included_flag || has_audit_path;

    let log_id = value
        .get("log_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let checkpoint_seq = value.get("checkpoint_seq").and_then(|v| v.as_u64());

    let tree_size = value.get("tree_size").and_then(|v| v.as_u64());

    let log_index = value.get("log_index").and_then(|v| v.as_u64());

    let error = value
        .get("error")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Local proof verification if audit_path is present
    let proof_verified = (|| -> Option<bool> {
        let audit_path_json = value.get("audit_path")?.as_array()?;
        let ts = value.get("tree_size")?.as_u64()? as usize;
        let li = value.get("log_index")?.as_u64()? as usize;
        let merkle_root_hex = value.get("merkle_root").and_then(|v| v.as_str())?;
        let envelope_hash_hex = value.get("envelope_hash").and_then(|v| v.as_str())?;

        let audit_path: Vec<Hash> = audit_path_json
            .iter()
            .filter_map(|v| v.as_str())
            .filter_map(|s| Hash::from_hex(s).ok())
            .collect();
        if audit_path.len() != audit_path_json.len() {
            return Some(false);
        }

        let expected_root = Hash::from_hex(merkle_root_hex).ok()?;
        let eh = Hash::from_hex(envelope_hash_hex).ok()?;

        let proof = MerkleProof {
            tree_size: ts,
            leaf_index: li,
            audit_path,
        };
        Some(proof.verify(eh.as_bytes(), &expected_root))
    })();

    Ok(SpineProofResult {
        included,
        log_id,
        checkpoint_seq,
        tree_size,
        log_index,
        proof_verified,
        error,
    })
}

fn validate_resource_relpath(rel: &str) -> Result<(), String> {
    if rel.contains('\\') {
        return Err("Invalid resource path".to_string());
    }

    let path = Path::new(rel);
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            _ => return Err("Invalid resource path".to_string()),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clawdstrike::{Policy, PolicyBundle};
    use hush_core::Keypair;

    #[test]
    fn validate_fetch_target_rejects_release_localhost_https() {
        let url = reqwest::Url::parse("https://localhost/bundle.json").expect("parse url");
        if cfg!(debug_assertions) {
            assert!(validate_fetch_target(&url).is_ok());
        } else {
            assert!(validate_fetch_target(&url).is_err());
        }
    }

    #[test]
    fn is_allowed_dev_http_only_allows_localhost() {
        let localhost = reqwest::Url::parse("http://127.0.0.1/feed.json").expect("parse url");
        let remote = reqwest::Url::parse("http://example.com/feed.json").expect("parse url");
        if cfg!(debug_assertions) {
            assert!(is_allowed_dev_http(&localhost));
            assert!(!is_allowed_dev_http(&remote));
        } else {
            assert!(!is_allowed_dev_http(&localhost));
            assert!(!is_allowed_dev_http(&remote));
        }
    }

    #[test]
    fn trusted_install_cache_only_serves_previously_listed_entries() {
        let feed_id = "trusted-feed-cache";
        let entry_id = "policy-1";
        let bundle = sample_signed_bundle();

        let mut entries = HashMap::new();
        entries.insert(
            entry_id.to_string(),
            TrustedInstallEntry {
                signed_bundle: bundle.clone(),
                install_allowed: true,
            },
        );
        cache_trusted_install_entries(feed_id, entries).expect("cache entries");

        let cached = get_trusted_install_bundle(feed_id, entry_id).expect("cached bundle");
        assert_eq!(
            cached.signed_bundle.bundle.bundle_id,
            bundle.bundle.bundle_id
        );
        assert!(cached.install_allowed);
        assert!(get_trusted_install_bundle(feed_id, "missing").is_err());
        assert!(get_trusted_install_bundle("missing-feed", entry_id).is_err());
    }

    #[test]
    fn provenance_config_normalizes_urls_and_lists() {
        let normalized = MarketplaceProvenanceConfig {
            notary_url: Some(" https://notary.example/api ".to_string()),
            proofs_api_url: Some("   ".to_string()),
            trusted_attesters: vec![
                "clawdstrike-official".to_string(),
                " clawdstrike-official ".to_string(),
                "".to_string(),
                "backbay-labs".to_string(),
            ],
            require_verified: true,
            prefer_spine: false,
            trusted_witness_keys: vec![
                " witness-1 ".to_string(),
                "witness-1".to_string(),
                "witness-2".to_string(),
            ],
        }
        .normalized();

        assert_eq!(
            normalized.notary_url.as_deref(),
            Some("https://notary.example/api")
        );
        assert!(normalized.proofs_api_url.is_none());
        assert_eq!(
            normalized.trusted_attesters,
            vec![
                "clawdstrike-official".to_string(),
                "backbay-labs".to_string()
            ]
        );
        assert_eq!(
            normalized.trusted_witness_keys,
            vec!["witness-1".to_string(), "witness-2".to_string()]
        );
        assert!(normalized.require_verified);
        assert!(!normalized.prefer_spine);
    }

    #[test]
    fn trusted_install_requires_matching_policy_hash() {
        let bundle = sample_signed_bundle();
        let policy_hash = bundle.bundle.policy_hash.to_hex();
        assert!(ensure_expected_policy_hash_matches(&bundle, &policy_hash).is_ok());
        assert!(ensure_expected_policy_hash_matches(&bundle, "deadbeef").is_err());
    }

    #[test]
    fn trusted_install_requires_matching_bundle_signature() {
        let bundle = sample_signed_bundle();
        let signature = bundle.signature.to_hex();
        assert!(ensure_expected_bundle_signature_matches(&bundle, &signature).is_ok());
        assert!(ensure_expected_bundle_signature_matches(&bundle, "deadbeef").is_err());
    }

    #[test]
    fn build_notary_verify_url_rejects_query_and_fragment() {
        assert!(
            build_notary_verify_url("https://notary.example/api?source=feed", "uid-123").is_err()
        );
        assert!(build_notary_verify_url("https://notary.example/api#fragment", "uid-123").is_err());

        let url =
            build_notary_verify_url("https://notary.example/api", "uid-123").expect("verify url");
        assert_eq!(url.as_str(), "https://notary.example/api/verify/uid-123");
    }

    fn sample_signed_bundle() -> SignedPolicyBundle {
        let keypair = Keypair::generate();
        let bundle = PolicyBundle::new(Policy::default()).expect("policy bundle");
        SignedPolicyBundle::sign_with_public_key(bundle, &keypair).expect("signed policy bundle")
    }
}
