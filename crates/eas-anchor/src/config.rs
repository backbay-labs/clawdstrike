//! TOML configuration for the EAS anchor service.

use serde::Deserialize;
use std::path::Path;

use crate::error::{Error, Result};

/// Top-level configuration for the EAS anchor service.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorConfig {
    pub chain: ChainConfig,
    pub signer: SignerConfig,
    pub batching: BatchingConfig,
    pub schemas: SchemaConfig,
    #[serde(default)]
    pub nats: NatsConfig,
}

/// Ethereum chain configuration (Base L2).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    /// RPC URL for Base L2 (e.g., "https://mainnet.base.org").
    pub rpc_url: String,
    /// Chain ID (8453 for Base mainnet, 84532 for Base Sepolia).
    pub chain_id: u64,
    /// EAS contract address on Base.
    pub eas_contract: String,
    /// SchemaRegistry contract address on Base.
    pub schema_registry: String,
}

/// Signer configuration for submitting EAS transactions.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerConfig {
    /// Environment variable name containing the private key hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_env: Option<String>,
    /// AWS KMS key ARN (future; not yet implemented).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms_key_id: Option<String>,
}

/// Batching parameters for attestation submission.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchingConfig {
    /// Maximum number of attestations per on-chain transaction.
    pub max_batch_size: usize,
    /// Seconds between automatic batch flushes.
    pub batch_interval_secs: u64,
    /// Minimum number of pending attestations before a flush is allowed.
    #[serde(default = "default_min_batch_size")]
    pub min_batch_size: usize,
}

fn default_min_batch_size() -> usize {
    1
}

/// Registered EAS schema UIDs on Base L2.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaConfig {
    /// Schema UID for policy attestations (revocable).
    pub policy_attestation_uid: String,
    /// Schema UID for checkpoint anchors (not revocable).
    pub checkpoint_anchor_uid: String,
    /// Schema UID for key rotation attestations (revocable).
    pub key_rotation_uid: String,
}

/// NATS connection configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatsConfig {
    /// NATS server URL.
    #[serde(default = "default_nats_url")]
    pub url: String,
    /// NATS subject to subscribe to for checkpoint envelopes.
    #[serde(default = "default_nats_subject")]
    pub subject: String,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: default_nats_url(),
            subject: default_nats_subject(),
        }
    }
}

fn default_nats_url() -> String {
    "nats://127.0.0.1:4222".to_string()
}

fn default_nats_subject() -> String {
    "clawdstrike.spine.envelope.log_checkpoint.v1".to_string()
}

impl AnchorConfig {
    /// Parse configuration from a TOML string.
    pub fn parse(toml_str: &str) -> Result<Self> {
        let config: Self =
            toml::from_str(toml_str).map_err(|e| Error::Config(format!("Invalid TOML: {e}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from a file path.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("Cannot read config file: {e}")))?;
        Self::parse(&content)
    }

    /// Validate configuration values.
    fn validate(&self) -> Result<()> {
        if self.chain.rpc_url.is_empty() {
            return Err(Error::Config("chain.rpc_url must not be empty".into()));
        }
        if self.chain.eas_contract.is_empty() {
            return Err(Error::Config("chain.eas_contract must not be empty".into()));
        }
        if self.chain.schema_registry.is_empty() {
            return Err(Error::Config(
                "chain.schema_registry must not be empty".into(),
            ));
        }
        if self.signer.private_key_env.is_none() && self.signer.kms_key_id.is_none() {
            return Err(Error::Config(
                "signer must specify either private_key_env or kms_key_id".into(),
            ));
        }
        if self.batching.max_batch_size == 0 {
            return Err(Error::Config(
                "batching.max_batch_size must be greater than 0".into(),
            ));
        }
        Ok(())
    }

    /// Resolve the signer private key from the environment variable.
    pub fn resolve_private_key(&self) -> Result<String> {
        let env_name = self
            .signer
            .private_key_env
            .as_deref()
            .ok_or_else(|| Error::Config("private_key_env not configured".into()))?;
        std::env::var(env_name).map_err(|e| {
            Error::Config(format!(
                "Cannot read private key from env var {env_name}: {e}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TOML: &str = r#"
[chain]
rpc_url = "https://mainnet.base.org"
chain_id = 8453
eas_contract = "0xA1207F3BBa224E2c9c3c6D5aF63D816e6e1f8e4b"
schema_registry = "0xA7b39296258348C78294F95B872b282326A97BDF"

[signer]
private_key_env = "EAS_SIGNER_PRIVATE_KEY"

[batching]
max_batch_size = 50
batch_interval_secs = 300

[schemas]
policy_attestation_uid = "0xabc123"
checkpoint_anchor_uid = "0xdef456"
key_rotation_uid = "0x789abc"
"#;

    #[test]
    fn parse_valid_config() {
        let config = AnchorConfig::parse(VALID_TOML);
        assert!(config.is_ok(), "parse failed: {config:?}");
        let config = config.unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert_eq!(config.chain.chain_id, 8453);
        assert_eq!(config.batching.max_batch_size, 50);
        assert_eq!(config.batching.min_batch_size, 1); // default
        assert_eq!(config.nats.url, "nats://127.0.0.1:4222"); // default
        assert_eq!(
            config.nats.subject,
            "clawdstrike.spine.envelope.log_checkpoint.v1"
        );
    }

    #[test]
    fn parse_with_nats_override() {
        let toml = format!(
            "{VALID_TOML}\n[nats]\nurl = \"nats://custom:4222\"\nsubject = \"custom.subject\"\n"
        );
        let config = AnchorConfig::parse(&toml).unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert_eq!(config.nats.url, "nats://custom:4222");
        assert_eq!(config.nats.subject, "custom.subject");
    }

    #[test]
    fn reject_empty_rpc_url() {
        let toml = VALID_TOML.replace("https://mainnet.base.org", "");
        let err = AnchorConfig::parse(&toml).expect_err("should reject empty rpc_url");
        assert!(err.to_string().contains("rpc_url"));
    }

    #[test]
    fn reject_zero_batch_size() {
        let toml = VALID_TOML.replace("max_batch_size = 50", "max_batch_size = 0");
        let err = AnchorConfig::parse(&toml).expect_err("should reject zero batch size");
        assert!(err.to_string().contains("max_batch_size"));
    }

    #[test]
    fn reject_no_signer() {
        let toml = VALID_TOML.replace("private_key_env = \"EAS_SIGNER_PRIVATE_KEY\"", "");
        let err = AnchorConfig::parse(&toml).expect_err("should reject missing signer");
        assert!(err.to_string().contains("signer"));
    }

    #[test]
    fn reject_unknown_fields() {
        let toml = format!("{VALID_TOML}\nunknown_field = true\n");
        let err = AnchorConfig::parse(&toml).expect_err("should reject unknown fields");
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn min_batch_size_default() {
        let config =
            AnchorConfig::parse(VALID_TOML).unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert_eq!(config.batching.min_batch_size, 1);
    }

    #[test]
    fn min_batch_size_custom() {
        let toml = VALID_TOML.replace(
            "batch_interval_secs = 300",
            "batch_interval_secs = 300\nmin_batch_size = 5",
        );
        let config = AnchorConfig::parse(&toml).unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert_eq!(config.batching.min_batch_size, 5);
    }
}
