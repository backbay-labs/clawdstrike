//! GET /api/v1/transparency/consistency
//!
//! Returns a Merkle consistency proof between a previous tree size and the
//! current tree size. Used by audit monitors to verify append-only behavior.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::RegistryError;
use crate::state::AppState;

/// Query parameters for the consistency proof endpoint.
#[derive(Deserialize)]
pub struct ConsistencyQuery {
    /// The previous (old) tree size to prove consistency from.
    pub old_size: u64,
}

/// Consistency proof response.
#[derive(Clone, Debug, Serialize)]
pub struct ConsistencyProofResponse {
    /// The old tree size.
    pub old_size: u64,
    /// The new (current) tree size.
    pub new_size: u64,
    /// Sibling hashes for the consistency proof path (hex-encoded).
    pub proof_path: Vec<String>,
}

/// GET /api/v1/transparency/consistency?old_size=N
///
/// Returns a consistency proof from `old_size` to the current tree size.
pub async fn get_consistency_proof(
    State(state): State<AppState>,
    Query(query): Query<ConsistencyQuery>,
) -> Result<Json<ConsistencyProofResponse>, RegistryError> {
    let tree = state
        .merkle_tree
        .lock()
        .map_err(|e| RegistryError::Internal(format!("merkle_tree lock poisoned: {e}")))?;

    let proof = tree
        .generate_consistency_proof(query.old_size)
        .map_err(|e| {
            RegistryError::BadRequest(format!("failed to generate consistency proof: {e}"))
        })?;

    Ok(Json(ConsistencyProofResponse {
        old_size: proof.old_size,
        new_size: proof.new_size,
        proof_path: proof.proof_path,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consistency_proof_response_serializes() {
        let resp = ConsistencyProofResponse {
            old_size: 5,
            new_size: 10,
            proof_path: vec!["aabb".into(), "ccdd".into()],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["old_size"], 5);
        assert_eq!(json["new_size"], 10);
        assert_eq!(json["proof_path"].as_array().unwrap().len(), 2);
    }
}
