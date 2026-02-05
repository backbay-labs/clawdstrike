use std::path::{Path, PathBuf};

use clawdstrike::{
    MarketplaceEntry, MarketplaceFeed, SignedMarketplaceFeed, SignedPolicyBundle,
    MARKETPLACE_FEED_SCHEMA_VERSION,
};
use hush_core::Keypair;

fn main() {
    let mut bundles_dir: Option<PathBuf> = None;
    let mut output: PathBuf = PathBuf::from("feed.signed.json");
    let mut feed_id: String = "builtin".to_string();
    let mut seq: u64 = 1;
    let mut published_at: Option<String> = None;
    let mut bundle_uri_prefix: String = "builtin://bundles/".to_string();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bundles-dir" => {
                bundles_dir = args.next().map(PathBuf::from);
            }
            "--output" | "-o" => {
                output = args.next().map(PathBuf::from).unwrap_or(output);
            }
            "--feed-id" => {
                feed_id = args.next().unwrap_or(feed_id);
            }
            "--seq" => {
                if let Some(v) = args.next() {
                    if let Ok(n) = v.parse::<u64>() {
                        seq = n;
                    }
                }
            }
            "--published-at" => {
                published_at = args.next();
            }
            "--bundle-uri-prefix" => {
                bundle_uri_prefix = args.next().unwrap_or(bundle_uri_prefix);
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: marketplace_feed_gen --bundles-dir DIR [--output PATH] [--feed-id ID] [--seq N] [--published-at ISO8601] [--bundle-uri-prefix PREFIX]\n\nEnvironment:\n  MARKETPLACE_FEED_SIGNING_KEY  hex seed (32 bytes) used to sign the feed."
                );
                std::process::exit(0);
            }
            _ => {}
        }
    }

    let Some(bundles_dir) = bundles_dir else {
        eprintln!("Error: --bundles-dir is required");
        std::process::exit(2);
    };

    let signing_key_hex = match std::env::var("MARKETPLACE_FEED_SIGNING_KEY") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("Error: MARKETPLACE_FEED_SIGNING_KEY is not set");
            std::process::exit(2);
        }
    };
    let keypair = match Keypair::from_hex(signing_key_hex.trim()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: invalid signing key: {e}");
            std::process::exit(2);
        }
    };

    let published_at = published_at.unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    let entries = match build_entries(&bundles_dir, &bundle_uri_prefix) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: failed to build entries: {e}");
            std::process::exit(2);
        }
    };

    let feed = MarketplaceFeed {
        version: MARKETPLACE_FEED_SCHEMA_VERSION.to_string(),
        feed_id,
        published_at,
        seq,
        entries,
        metadata: None,
    };

    let signed = match SignedMarketplaceFeed::sign_with_public_key(feed, &keypair) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: failed to sign feed: {e}");
            std::process::exit(2);
        }
    };

    let json = match serde_json::to_string_pretty(&signed) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: failed to encode feed: {e}");
            std::process::exit(2);
        }
    };

    if let Err(e) = std::fs::write(&output, json) {
        eprintln!("Error: failed to write {}: {e}", output.display());
        std::process::exit(2);
    }

    eprintln!("Signed feed written: {}", output.display());
    eprintln!("Feed public key: {}", keypair.public_key().to_hex());
}

fn build_entries(
    bundles_dir: &Path,
    bundle_uri_prefix: &str,
) -> std::io::Result<Vec<MarketplaceEntry>> {
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(bundles_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            if name.ends_with(".signed_bundle.json") {
                files.push(path);
            }
        }
    }
    files.sort();

    let mut entries = Vec::new();
    for path in files {
        let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let entry_id = file_name
            .strip_suffix(".signed_bundle.json")
            .unwrap_or(file_name)
            .to_string();

        let data = std::fs::read(&path)?;
        let signed_bundle: SignedPolicyBundle = match serde_json::from_slice(&data) {
            Ok(v) => v,
            Err(e) => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
            }
        };

        let bundle_valid = signed_bundle.verify_embedded().unwrap_or(false);
        if !bundle_valid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Bundle signature failed verification: {}", file_name),
            ));
        }

        let policy = &signed_bundle.bundle.policy;
        entries.push(MarketplaceEntry {
            entry_id,
            bundle_uri: format!("{bundle_uri_prefix}{file_name}"),
            title: if policy.name.is_empty() {
                None
            } else {
                Some(policy.name.clone())
            },
            description: if policy.description.is_empty() {
                None
            } else {
                Some(policy.description.clone())
            },
            category: None,
            tags: Vec::new(),
            author: Some("Clawdstrike".to_string()),
            author_url: None,
            icon: None,
            created_at: None,
            updated_at: None,
            provenance: None,
        });
    }

    Ok(entries)
}
