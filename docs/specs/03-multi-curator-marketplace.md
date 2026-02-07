# Spec 03: Multi-Curator Trust Configuration and Marketplace Changes

**Status:** Draft
**Author:** spec-writers
**Date:** 2026-02-07
**Effort:** 5 engineer-days
**Dependencies:** None (self-contained, backward-compatible)

---

## Summary / Objective

Evolve ClawdStrike's marketplace trust model from a single hardcoded curator key to a configurable multi-curator system. Users will manage trusted curator keys via a TOML configuration file (`~/.clawdstrike/trusted_curators.toml`), and the `verify_trusted()` function (already accepting `&[PublicKey]`) will load keys from this file instead of requiring them to be compiled in or manually passed.

This implements "Phase 1: Multi-Curator + Config" from Section 2 (Approach A) and Section 13 of `docs/research/marketplace-trust-evolution.md`. It is the simplest evolutionary step that unblocks multi-curator support with zero infrastructure cost.

---

## Current State

### Marketplace feed signing (`marketplace_feed.rs`)

From `crates/clawdstrike/src/marketplace_feed.rs`:

- `MarketplaceFeed` is canonicalized via RFC 8785 and signed with Ed25519 (`SignedMarketplaceFeed::sign()`, line 102)
- `verify_trusted(&self, trusted_public_keys: &[PublicKey])` (line 134) already accepts an array of trusted keys and iterates through them
- If an embedded `public_key` is present, it must be in the trusted set (line 145)
- If no embedded key, all trusted keys are tried until one verifies (line 158-163)
- Schema version is strictly validated: `MARKETPLACE_FEED_SCHEMA_VERSION = "clawdstrike-marketplace-feed-v1"` (line 9)
- `MarketplaceProvenance` has `attestation_uid`, `notary_url`, and `spine_envelope_hash` fields (lines 77-89)
- All types use `#[serde(deny_unknown_fields)]`

### Existing curator config (`curator_config.rs`)

The file `crates/clawdstrike/src/curator_config.rs` **already exists** and provides basic multi-curator types:

- `CuratorConfigFile` -- a TOML-deserializable struct with `trusted_keys: Vec<String>` for loading curator public keys
- `CuratorTrustSet` -- a validated set of trusted curator keys parsed from the config file
- The `CLAWDSTRIKE_TRUSTED_CURATORS` environment variable is already supported as a source for trusted curator keys

However, the existing types are limited:
- No `trust_level` field (no distinction between full trust and audit-only trust)
- No `feed_ids` field (no per-feed curator scoping)
- No `name` field for human-readable curator identification
- No TOML config file loading from `~/.clawdstrike/trusted_curators.toml`
- No integration with `verify_trusted()` to return the matching curator entry

### MarketplaceEntry structure

Each `MarketplaceEntry` (line 47-75) has:
- `entry_id`, `bundle_uri`, `title`, `description`, `category`, `tags`
- `author`, `author_url`, `icon`, `created_at`, `updated_at`
- `provenance: Option<MarketplaceProvenance>`

There is no field identifying which curator added the entry or the curator's trust level.

---

## Target State

### 1. Config file: `~/.clawdstrike/trusted_curators.toml`

```toml
# ClawdStrike Trusted Curators Configuration
# Each [[curator]] entry registers a trusted feed signer.

[[curator]]
name = "clawdstrike-official"
public_key = "0xabc123def456..."
trust_level = "full"          # "full" = auto-install, "audit-only" = show but require user confirmation
feed_ids = ["clawdstrike-official"]  # Optional: restrict to specific feed IDs

[[curator]]
name = "acme-security-team"
public_key = "0xdef456789abc..."
trust_level = "full"
feed_ids = []  # Empty = trust for any feed

[[curator]]
name = "community-experimental"
public_key = "0x789012345def..."
trust_level = "audit-only"
```

### 2. Rust types for curator config

Extend existing file: `crates/clawdstrike/src/curator_config.rs` (refactor `CuratorConfigFile` and `CuratorTrustSet` to support the richer types below)

```rust
pub struct CuratorConfig {
    pub curators: Vec<CuratorEntry>,
}

pub struct CuratorEntry {
    pub name: String,
    pub public_key: PublicKey,
    pub trust_level: TrustLevel,
    pub feed_ids: Vec<String>,
}

pub enum TrustLevel {
    Full,       // Policies auto-installable
    AuditOnly,  // Shown in UI but require explicit user approval
}
```

### 3. Loading function

`CuratorConfig::load()` reads from `~/.clawdstrike/trusted_curators.toml`, falling back to a compiled-in default (the official ClawdStrike key). The function returns `Result<CuratorConfig>`.

### 4. Integration with `verify_trusted()`

A new convenience method `SignedMarketplaceFeed::verify_with_config(config: &CuratorConfig)` that:
1. Extracts `PublicKey` values from the config
2. Calls the existing `verify_trusted(&[PublicKey])`
3. Returns the matching `CuratorEntry` (not just the key) so the caller knows the trust level

### 5. CLI integration

`hush-cli` marketplace commands gain `--curators-config <path>` flag with default `~/.clawdstrike/trusted_curators.toml`.

---

## Implementation Plan

### Step 1: Extend `curator_config.rs`

Refactor existing file: `crates/clawdstrike/src/curator_config.rs`. The existing `CuratorConfigFile` (with `trusted_keys: Vec<String>`) and `CuratorTrustSet` types should be extended or replaced with the richer types below. The existing `CLAWDSTRIKE_TRUSTED_CURATORS` env var support should be preserved as a fallback source.

```rust
//! Multi-curator trust configuration.
//!
//! Loads trusted curator public keys from `~/.clawdstrike/trusted_curators.toml`.

use hush_core::PublicKey;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Default config file location.
pub fn default_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".clawdstrike").join("trusted_curators.toml"))
}

/// Trust level for a curator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustLevel {
    /// Policies from this curator can be auto-installed.
    Full,
    /// Policies shown in UI but require explicit user approval before installation.
    AuditOnly,
}

/// A single trusted curator entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CuratorEntry {
    /// Human-readable curator name.
    pub name: String,
    /// Ed25519 public key (hex-encoded, 0x-prefix optional).
    pub public_key: String,
    /// Trust level.
    #[serde(default = "default_trust_level")]
    pub trust_level: TrustLevel,
    /// Optional: restrict this curator to specific feed IDs.
    /// Empty means trust for any feed.
    #[serde(default)]
    pub feed_ids: Vec<String>,
}

fn default_trust_level() -> TrustLevel {
    TrustLevel::AuditOnlyOnly
}

/// Parsed curator config.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CuratorConfigFile {
    #[serde(default)]
    pub curator: Vec<CuratorEntry>,
}

/// Loaded and validated curator configuration.
#[derive(Clone, Debug)]
pub struct CuratorConfig {
    entries: Vec<ValidatedCurator>,
}

#[derive(Clone, Debug)]
pub struct ValidatedCurator {
    pub name: String,
    pub public_key: PublicKey,
    pub trust_level: TrustLevel,
    pub feed_ids: Vec<String>,
}

impl CuratorConfig {
    /// Load from a TOML file path.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            Error::ConfigError(format!(
                "Failed to read curator config at {}: {}",
                path.display(),
                e
            ))
        })?;
        Self::parse(&content)
    }

    /// Load from the default path, falling back to built-in defaults.
    pub fn load_default() -> Result<Self> {
        if let Some(path) = default_config_path() {
            if path.exists() {
                return Self::load(&path);
            }
        }
        // Fallback: empty config (no curators trusted)
        Ok(Self {
            entries: Vec::new(),
        })
    }

    /// Parse from TOML string.
    pub fn parse(toml_str: &str) -> Result<Self> {
        let file: CuratorConfigFile = toml::from_str(toml_str).map_err(|e| {
            Error::ConfigError(format!("Invalid curator config TOML: {}", e))
        })?;

        let mut entries = Vec::with_capacity(file.curator.len());
        for entry in file.curator {
            let pk = PublicKey::from_hex(&entry.public_key).map_err(|e| {
                Error::ConfigError(format!(
                    "Invalid public key for curator '{}': {}",
                    entry.name, e
                ))
            })?;
            entries.push(ValidatedCurator {
                name: entry.name,
                public_key: pk,
                trust_level: entry.trust_level,
                feed_ids: entry.feed_ids,
            });
        }

        Ok(Self { entries })
    }

    /// Get all trusted public keys (for use with `verify_trusted`).
    pub fn public_keys(&self) -> Vec<PublicKey> {
        self.entries.iter().map(|e| e.public_key.clone()).collect()
    }

    /// Get public keys restricted to a specific feed ID.
    pub fn public_keys_for_feed(&self, feed_id: &str) -> Vec<PublicKey> {
        self.entries
            .iter()
            .filter(|e| e.feed_ids.is_empty() || e.feed_ids.iter().any(|f| f == feed_id))
            .map(|e| e.public_key.clone())
            .collect()
    }

    /// Look up the curator entry for a given public key.
    pub fn find_curator(&self, public_key: &PublicKey) -> Option<&ValidatedCurator> {
        self.entries.iter().find(|e| &e.public_key == public_key)
    }

    /// Returns all curator entries.
    pub fn curators(&self) -> &[ValidatedCurator] {
        &self.entries
    }
}
```

### Step 2: Add `curator_config` module to `lib.rs`

In `crates/clawdstrike/src/lib.rs`, add:

```rust
pub mod curator_config;
```

### Step 3: Add convenience method to `SignedMarketplaceFeed`

In `crates/clawdstrike/src/marketplace_feed.rs`, add:

```rust
use crate::curator_config::{CuratorConfig, TrustLevel, ValidatedCurator};

impl SignedMarketplaceFeed {
    /// Verify against a curator config, returning the matching curator entry.
    pub fn verify_with_config(&self, config: &CuratorConfig) -> Result<&ValidatedCurator> {
        let feed_keys = config.public_keys_for_feed(&self.feed.feed_id);
        let matching_key = self.verify_trusted(&feed_keys)?;
        config.find_curator(&matching_key).ok_or_else(|| {
            Error::ConfigError("Verified key not found in curator config".to_string())
        })
    }
}
```

### Step 4: Add `toml` dependency to `crates/clawdstrike/Cargo.toml`

```toml
[dependencies]
# ... existing deps ...
toml.workspace = true
dirs.workspace = true
```

The `toml` and `dirs` crates are already in the workspace dependencies (Cargo.toml lines 102-103).

### Step 5: Add `MarketplaceEntry` curator attribution field

Extend `MarketplaceEntry` to optionally carry the curator's public key that added it:

```rust
// In marketplace_feed.rs, add to MarketplaceEntry:
#[serde(skip_serializing_if = "Option::is_none")]
pub curator_public_key: Option<String>,
```

This is backward-compatible because it's `Option` with `skip_serializing_if`.

### Step 6: Write unit tests

In `crates/clawdstrike/src/curator_config.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_config() {
        let toml = r#"
[[curator]]
name = "test-curator"
public_key = "0x..."  # Valid hex key
trust_level = "full"
feed_ids = ["test-feed"]
"#;
        // Test with a real key
        let kp = hush_core::Keypair::generate();
        let toml = format!(
            r#"
[[curator]]
name = "test-curator"
public_key = "{}"
trust_level = "full"
feed_ids = ["test-feed"]
"#,
            kp.public_key().to_hex()
        );
        let config = CuratorConfig::parse(&toml).unwrap();
        assert_eq!(config.curators().len(), 1);
        assert_eq!(config.curators()[0].name, "test-curator");
        assert_eq!(config.curators()[0].trust_level, TrustLevel::Full);
    }

    #[test]
    fn empty_config_returns_no_curators() {
        let config = CuratorConfig::parse("").unwrap();
        assert!(config.curators().is_empty());
    }

    #[test]
    fn feed_id_filtering() {
        let kp1 = hush_core::Keypair::generate();
        let kp2 = hush_core::Keypair::generate();
        let toml = format!(
            r#"
[[curator]]
name = "specific"
public_key = "{}"
trust_level = "full"
feed_ids = ["feed-a"]

[[curator]]
name = "wildcard"
public_key = "{}"
trust_level = "full"
feed_ids = []
"#,
            kp1.public_key().to_hex(),
            kp2.public_key().to_hex()
        );
        let config = CuratorConfig::parse(&toml).unwrap();
        // "feed-a" should match both (specific + wildcard)
        assert_eq!(config.public_keys_for_feed("feed-a").len(), 2);
        // "feed-b" should match only wildcard
        assert_eq!(config.public_keys_for_feed("feed-b").len(), 1);
    }

    #[test]
    fn invalid_public_key_errors() {
        let toml = r#"
[[curator]]
name = "bad"
public_key = "not-a-valid-key"
trust_level = "full"
"#;
        let err = CuratorConfig::parse(toml).unwrap_err();
        assert!(err.to_string().contains("Invalid public key"));
    }

    #[test]
    fn default_trust_level_is_audit_only() {
        let kp = hush_core::Keypair::generate();
        let toml = format!(
            r#"
[[curator]]
name = "no-level"
public_key = "{}"
"#,
            kp.public_key().to_hex()
        );
        let config = CuratorConfig::parse(&toml).unwrap();
        assert_eq!(config.curators()[0].trust_level, TrustLevel::AuditOnly);
    }
}
```

### Step 7: Integration test with marketplace feed

Add an integration test that creates a signed feed, loads a curator config, and verifies using `verify_with_config()`:

```rust
#[test]
fn verify_feed_with_curator_config() {
    let kp = hush_core::Keypair::generate();
    let config_toml = format!(
        r#"
[[curator]]
name = "test"
public_key = "{}"
trust_level = "full"
feed_ids = ["test-feed"]
"#,
        kp.public_key().to_hex()
    );
    let config = CuratorConfig::parse(&config_toml).unwrap();

    let feed = MarketplaceFeed {
        version: MARKETPLACE_FEED_SCHEMA_VERSION.to_string(),
        feed_id: "test-feed".to_string(),
        published_at: "2026-01-01T00:00:00Z".to_string(),
        seq: 1,
        entries: Vec::new(),
        metadata: None,
    };
    let signed = SignedMarketplaceFeed::sign(feed, &kp).unwrap();
    let curator = signed.verify_with_config(&config).unwrap();
    assert_eq!(curator.name, "test");
    assert_eq!(curator.trust_level, TrustLevel::Full);
}
```

### Step 8: CLI integration

In `crates/hush-cli/`, add `--curators-config` flag to marketplace-related subcommands:

```rust
#[derive(Parser)]
struct MarketplaceArgs {
    /// Path to trusted curators config file.
    #[arg(long, default_value_t = default_curators_config_display())]
    curators_config: PathBuf,
}
```

### Step 9: Ship a default config

Create `rulesets/trusted_curators.example.toml` as a template users can copy to `~/.clawdstrike/trusted_curators.toml`.

---

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `crates/clawdstrike/src/curator_config.rs` | Modify | Extend existing `CuratorConfigFile`/`CuratorTrustSet` with `CuratorConfig`, `CuratorEntry`, `TrustLevel`, load/parse/query functions. Preserve `CLAWDSTRIKE_TRUSTED_CURATORS` env var support. |
| `crates/clawdstrike/src/lib.rs` | Modify | Add `pub mod curator_config;` |
| `crates/clawdstrike/src/marketplace_feed.rs` | Modify | Add `verify_with_config()` method, add `curator_public_key` to `MarketplaceEntry` |
| `crates/clawdstrike/Cargo.toml` | Modify | Add `toml` and `dirs` workspace dependencies |
| `crates/hush-cli/src/*.rs` | Modify | Add `--curators-config` flag to marketplace subcommands |
| `rulesets/trusted_curators.example.toml` | Create | Example config file for users |

---

## Testing Strategy

### Unit tests

1. **Config parsing**: Valid TOML parses correctly; invalid hex keys are rejected; empty config is valid.
2. **Trust level defaults**: Omitting `trust_level` defaults to `AuditOnly`.
3. **Feed ID filtering**: `public_keys_for_feed()` correctly filters by feed ID; empty `feed_ids` matches all feeds.
4. **`deny_unknown_fields`**: Unknown TOML keys in the config are rejected (serde strict mode).

### Integration tests

5. **Round-trip verification**: Sign a feed, create a config with the signer's key, verify with `verify_with_config()`.
6. **Feed ID mismatch**: Curator configured for `feed-a` should fail to verify a feed with `feed_id = "feed-b"`.
7. **Trust level propagation**: Verify that the returned `ValidatedCurator` carries the correct trust level.
8. **Backward compatibility**: Existing `verify_trusted(&[PublicKey])` tests continue to pass (no breaking change).

### CLI tests

9. **Default config path**: Running `clawdstrike marketplace list` without `--curators-config` uses `~/.clawdstrike/trusted_curators.toml`.
10. **Custom config path**: Running with `--curators-config /tmp/test.toml` loads from the specified path.
11. **Missing config file**: Running without a config file at the default path succeeds (empty curator list, all feeds unverified).

---

## Rollback Plan

This change is fully backward-compatible:

1. The new `curator_config` module is additive -- no existing APIs change.
2. `verify_trusted(&[PublicKey])` continues to work as before.
3. `curator_public_key` on `MarketplaceEntry` is `Option<String>` with `skip_serializing_if = "Option::is_none"`, so existing serialized feeds are unchanged.
4. If the config file does not exist, `load_default()` returns an empty config (no curators trusted), matching the current behavior of having no configured trusted keys.

To rollback: delete the `curator_config.rs` file and remove the `pub mod curator_config;` line. No other files need to change.

---

## Dependencies

| Dependency | Status | Notes |
|------------|--------|-------|
| `toml` crate | Already in workspace | Cargo.toml line 102 |
| `dirs` crate | Already in workspace | Cargo.toml line 103 |
| `hush-core` PublicKey | Already in use | `marketplace_feed.rs` imports it |
| Research doc Section 2 | Reference | `docs/research/marketplace-trust-evolution.md` |

---

## Acceptance Criteria

- [ ] Existing file `crates/clawdstrike/src/curator_config.rs` is extended with `CuratorConfig`, `CuratorEntry`, `TrustLevel` types (refactored from `CuratorConfigFile`/`CuratorTrustSet`)
- [ ] All types use `#[serde(deny_unknown_fields)]` (project convention)
- [ ] `CuratorConfig::load(path)` reads TOML from disk and validates public keys
- [ ] `CuratorConfig::load_default()` uses `~/.clawdstrike/trusted_curators.toml` or returns empty config
- [ ] `CuratorConfig::public_keys_for_feed(feed_id)` filters curators by feed ID
- [ ] `CuratorConfig::find_curator(public_key)` returns the matching `ValidatedCurator`
- [ ] Default `TrustLevel` is `AuditOnly` (defensive default, serializes as `"audit-only"` in TOML)
- [ ] `SignedMarketplaceFeed::verify_with_config(config)` verifies and returns the matching curator entry
- [ ] `MarketplaceEntry` has optional `curator_public_key` field (backward-compatible)
- [ ] At least 6 unit tests covering parsing, filtering, trust levels, and error cases
- [ ] At least 2 integration tests covering round-trip sign+verify with config
- [ ] Example config file at `rulesets/trusted_curators.example.toml`
- [ ] All existing `marketplace_feed.rs` tests continue to pass
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo test -p clawdstrike` passes
