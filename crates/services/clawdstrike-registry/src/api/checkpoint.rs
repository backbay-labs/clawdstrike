//! GET /api/v1/transparency/checkpoint
//!
//! Returns the latest transparency log checkpoint: Merkle root, tree size,
//! and registry signature over the checkpoint data.

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::error::RegistryError;
use crate::state::AppState;

fn checkpoint_signature_message(root: &str, tree_size: u64, timestamp: &str) -> String {
    format!("clawdstrike-checkpoint:v1:{root}:{tree_size}:{timestamp}")
}

/// Transparency log checkpoint.
#[derive(Clone, Debug, Serialize)]
pub struct CheckpointResponse {
    /// Hex-encoded Merkle root hash.
    pub root: String,
    /// Number of leaves in the tree.
    pub tree_size: u64,
    /// ISO-8601 timestamp of the checkpoint.
    pub timestamp: String,
    /// Hex-encoded registry Ed25519 signature over
    /// `clawdstrike-checkpoint:v1:{root}:{tree_size}:{timestamp}`.
    pub registry_sig: String,
    /// Hex-encoded registry public key for verification.
    pub registry_key: String,
}

/// GET /api/v1/transparency/checkpoint
///
/// Returns the latest checkpoint signed by the registry key.
pub async fn get_checkpoint(
    State(state): State<AppState>,
) -> Result<Json<CheckpointResponse>, RegistryError> {
    let timestamp = chrono::Utc::now().to_rfc3339();

    let (root_hex, tree_size) = {
        let tree = state
            .merkle_tree
            .lock()
            .map_err(|e| RegistryError::Internal(format!("merkle_tree lock poisoned: {e}")))?;
        let size = tree.tree_size();
        if size == 0 {
            ("0".repeat(64), 0u64)
        } else {
            let root = tree
                .root()
                .map_err(|e| RegistryError::Internal(format!("merkle root error: {e}")))?;
            (root, size)
        }
    };

    // Build the canonical checkpoint message.
    let checkpoint_msg = checkpoint_signature_message(&root_hex, tree_size, &timestamp);

    let (sig_hex, key_hex) = {
        let key_mgr = state
            .key_manager
            .lock()
            .map_err(|e| RegistryError::Internal(format!("key_manager lock poisoned: {e}")))?;
        let current_keypair = key_mgr.current_keypair();
        let signature = current_keypair.sign(checkpoint_msg.as_bytes());
        (signature.to_hex(), current_keypair.public_key().to_hex())
    };

    Ok(Json(CheckpointResponse {
        root: root_hex,
        tree_size,
        timestamp,
        registry_sig: sig_hex,
        registry_key: key_hex,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use hush_core::{PublicKey, Signature};

    #[test]
    fn checkpoint_response_serializes() {
        let resp = CheckpointResponse {
            root: "a".repeat(64),
            tree_size: 100,
            timestamp: "2026-02-25T10:00:00Z".into(),
            registry_sig: "sig_hex".into(),
            registry_key: "key_hex".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["tree_size"], 100);
        assert!(json["root"].as_str().unwrap().len() == 64);
    }

    fn test_state() -> crate::state::AppState {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config {
            host: "127.0.0.1".to_string(),
            port: 0,
            data_dir: tmp.path().to_path_buf(),
            api_key: String::new(),
            allow_insecure_no_auth: false,
            max_upload_bytes: 1024 * 1024,
        };
        crate::state::AppState::new(cfg).unwrap()
    }

    #[tokio::test]
    async fn checkpoint_empty_tree_is_signed() {
        let state = test_state();
        let resp = get_checkpoint(State(state)).await.unwrap();
        assert_eq!(resp.0.tree_size, 0);
        assert_eq!(resp.0.root, "0".repeat(64));

        let key = PublicKey::from_hex(&resp.0.registry_key).unwrap();
        let sig = Signature::from_hex(&resp.0.registry_sig).unwrap();
        let msg = checkpoint_signature_message(&resp.0.root, resp.0.tree_size, &resp.0.timestamp);
        assert!(key.verify(msg.as_bytes(), &sig));
    }

    #[tokio::test]
    async fn checkpoint_non_empty_tree_is_signed() {
        let state = test_state();
        {
            let mut tree = state.merkle_tree.lock().unwrap();
            tree.append_hash(hush_core::sha256(b"leaf"));
        }
        let resp = get_checkpoint(State(state)).await.unwrap();
        assert_eq!(resp.0.tree_size, 1);
        assert_ne!(resp.0.root, "0".repeat(64));

        let key = PublicKey::from_hex(&resp.0.registry_key).unwrap();
        let sig = Signature::from_hex(&resp.0.registry_sig).unwrap();
        let msg = checkpoint_signature_message(&resp.0.root, resp.0.tree_size, &resp.0.timestamp);
        assert!(key.verify(msg.as_bytes(), &sig));
    }
}
