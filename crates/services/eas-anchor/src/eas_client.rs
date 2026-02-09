//! EAS contract interaction via alloy.
//!
//! Provides a client for submitting batched attestations and revocations
//! to the Ethereum Attestation Service on Base L2.

use alloy::primitives::{Address, FixedBytes};
use alloy::signers::local::PrivateKeySigner;

use crate::batcher::PendingAttestation;
use crate::config::AnchorConfig;
use crate::error::{Error, Result};

/// EAS contract address on Base L2.
pub const EAS_CONTRACT_BASE: &str = "0xA1207F3BBa224E2c9c3c6D5aF63D816e6e1f8e4b";

/// SchemaRegistry contract address on Base L2.
pub const SCHEMA_REGISTRY_BASE: &str = "0xA7b39296258348C78294F95B872b282326A97BDF";

/// Client for interacting with the EAS contract on Base L2.
pub struct EasClient {
    _signer: PrivateKeySigner,
    _rpc_url: String,
    eas_address: Address,
    checkpoint_schema_uid: FixedBytes<32>,
}

/// Result of a batch submission.
#[derive(Debug, Clone)]
pub struct BatchSubmitResult {
    /// Number of attestations in the batch.
    pub count: usize,
    /// Hex-encoded transaction hash (0x-prefixed).
    pub tx_hash: String,
}

/// Result of a revocation.
#[derive(Debug, Clone)]
pub struct RevocationResult {
    /// Hex-encoded transaction hash (0x-prefixed).
    pub tx_hash: String,
}

impl EasClient {
    /// Create a new EAS client from the anchor configuration.
    pub fn new(config: &AnchorConfig) -> Result<Self> {
        let private_key = config.resolve_private_key()?;
        let signer: PrivateKeySigner = private_key
            .parse()
            .map_err(|e| Error::Client(format!("Invalid private key: {e}")))?;
        let eas_address: Address = config
            .chain
            .eas_contract
            .parse()
            .map_err(|e| Error::Client(format!("Invalid EAS contract address: {e}")))?;
        let checkpoint_schema_uid: FixedBytes<32> = config
            .schemas
            .checkpoint_anchor_uid
            .parse()
            .map_err(|e| Error::Client(format!("Invalid checkpoint schema UID: {e}")))?;

        Ok(Self {
            _signer: signer,
            _rpc_url: config.chain.rpc_url.clone(),
            eas_address,
            checkpoint_schema_uid,
        })
    }

    /// The EAS contract address this client targets.
    pub fn eas_address(&self) -> Address {
        self.eas_address
    }

    /// The checkpoint anchor schema UID.
    pub fn checkpoint_schema_uid(&self) -> FixedBytes<32> {
        self.checkpoint_schema_uid
    }

    /// Submit a batch of checkpoint attestations via `multiAttest()`.
    ///
    /// Each attestation encodes:
    ///   (checkpointHash, checkpointSeq, treeSize, logOperatorKey, witnessKey)
    ///
    /// Returns the transaction hash on success.
    pub async fn submit_batch(
        &self,
        attestations: &[PendingAttestation],
    ) -> Result<BatchSubmitResult> {
        if attestations.is_empty() {
            return Err(Error::Client("Cannot submit empty batch".into()));
        }

        let count = attestations.len();

        // Encode attestation data for each item in the batch.
        // The EAS multiAttest() call takes:
        //   MultiAttestationRequest[] = [{schema, data: AttestationRequestData[]}]
        // where AttestationRequestData = {recipient, expirationTime, revocable, refUID, data, value}
        let _encoded_items: Vec<Vec<u8>> = attestations
            .iter()
            .map(encode_checkpoint_attestation)
            .collect();

        // TODO: Build and send the actual multiAttest transaction via alloy.
        // The contract ABI encoding for EAS.multiAttest() requires:
        //   1. Build a FillerProvider with the signer and RPC URL
        //   2. ABI-encode the MultiAttestationRequest struct
        //   3. Send the transaction and await confirmation
        //
        // For now, return a placeholder that indicates the encoding succeeded.
        // This will be replaced with the actual contract call once we have
        // a testnet environment to validate against.
        tracing::info!(
            count = count,
            schema_uid = %self.checkpoint_schema_uid,
            eas_address = %self.eas_address,
            "Prepared multiAttest batch (submission pending chain integration)"
        );

        Err(Error::Client(
            "Chain submission not yet implemented — use Base Sepolia testnet for integration testing"
                .into(),
        ))
    }

    /// Revoke an attestation on-chain via `EAS.revoke()`.
    pub async fn revoke_attestation(
        &self,
        schema_uid: FixedBytes<32>,
        attestation_uid: FixedBytes<32>,
    ) -> Result<RevocationResult> {
        // TODO: Build and send the actual revoke transaction via alloy.
        // The EAS.revoke() call takes:
        //   RevocationRequest = {schema, data: RevocationRequestData}
        //   RevocationRequestData = {uid, value}
        tracing::info!(
            schema_uid = %schema_uid,
            attestation_uid = %attestation_uid,
            eas_address = %self.eas_address,
            "Prepared revocation (submission pending chain integration)"
        );

        Err(Error::Client(
            "Chain submission not yet implemented — use Base Sepolia testnet for integration testing"
                .into(),
        ))
    }
}

/// ABI-encode a checkpoint attestation for EAS.
///
/// Encodes the following Solidity tuple:
///   (bytes32 checkpointHash, uint64 checkpointSeq, uint64 treeSize,
///    bytes32 logOperatorKey, bytes32 witnessKey)
fn encode_checkpoint_attestation(att: &PendingAttestation) -> Vec<u8> {
    // Simple ABI encoding: each field is padded to 32 bytes.
    // bytes32 fields are already 32 bytes.
    // uint64 fields are left-padded to 32 bytes.
    let mut data = Vec::with_capacity(5 * 32);

    // bytes32 checkpointHash
    data.extend_from_slice(&att.checkpoint_hash);

    // uint64 checkpointSeq (left-padded to 32 bytes)
    let mut seq_bytes = [0u8; 32];
    seq_bytes[24..32].copy_from_slice(&att.checkpoint_seq.to_be_bytes());
    data.extend_from_slice(&seq_bytes);

    // uint64 treeSize (left-padded to 32 bytes)
    let mut size_bytes = [0u8; 32];
    size_bytes[24..32].copy_from_slice(&att.tree_size.to_be_bytes());
    data.extend_from_slice(&size_bytes);

    // bytes32 logOperatorKey
    data.extend_from_slice(&att.log_operator_key);

    // bytes32 witnessKey
    data.extend_from_slice(&att.witness_key);

    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn encode_checkpoint_attestation_length() {
        let att = PendingAttestation {
            checkpoint_hash: [0x42; 32],
            checkpoint_seq: 100,
            tree_size: 500,
            log_operator_key: [0xAA; 32],
            witness_key: [0xBB; 32],
            received_at: Instant::now(),
        };
        let encoded = encode_checkpoint_attestation(&att);
        // 5 fields * 32 bytes each = 160 bytes
        assert_eq!(encoded.len(), 160);
    }

    #[test]
    fn encode_checkpoint_attestation_hash_at_offset_0() {
        let att = PendingAttestation {
            checkpoint_hash: [0xFF; 32],
            checkpoint_seq: 0,
            tree_size: 0,
            log_operator_key: [0x00; 32],
            witness_key: [0x00; 32],
            received_at: Instant::now(),
        };
        let encoded = encode_checkpoint_attestation(&att);
        assert_eq!(&encoded[0..32], &[0xFF; 32]);
    }

    #[test]
    fn encode_checkpoint_seq_at_correct_offset() {
        let att = PendingAttestation {
            checkpoint_hash: [0x00; 32],
            checkpoint_seq: 42,
            tree_size: 0,
            log_operator_key: [0x00; 32],
            witness_key: [0x00; 32],
            received_at: Instant::now(),
        };
        let encoded = encode_checkpoint_attestation(&att);
        // checkpoint_seq is at offset 32..64, uint64 is at bytes 56..64
        assert_eq!(encoded[63], 42);
        // Leading bytes should be zero
        assert_eq!(&encoded[32..56], &[0u8; 24]);
    }

    #[test]
    fn encode_tree_size_at_correct_offset() {
        let att = PendingAttestation {
            checkpoint_hash: [0x00; 32],
            checkpoint_seq: 0,
            tree_size: 1000,
            log_operator_key: [0x00; 32],
            witness_key: [0x00; 32],
            received_at: Instant::now(),
        };
        let encoded = encode_checkpoint_attestation(&att);
        // tree_size is at offset 64..96, uint64 at bytes 88..96
        let size_bytes = &encoded[88..96];
        let tree_size = u64::from_be_bytes(size_bytes.try_into().unwrap_or_else(|_| {
            panic!("slice should be 8 bytes");
        }));
        assert_eq!(tree_size, 1000);
    }

    #[test]
    fn encode_keys_at_correct_offsets() {
        let att = PendingAttestation {
            checkpoint_hash: [0x00; 32],
            checkpoint_seq: 0,
            tree_size: 0,
            log_operator_key: [0x11; 32],
            witness_key: [0x22; 32],
            received_at: Instant::now(),
        };
        let encoded = encode_checkpoint_attestation(&att);
        // log_operator_key at offset 96..128
        assert_eq!(&encoded[96..128], &[0x11; 32]);
        // witness_key at offset 128..160
        assert_eq!(&encoded[128..160], &[0x22; 32]);
    }

    #[test]
    fn eas_contract_address_constant_is_valid() {
        let addr: std::result::Result<Address, _> = EAS_CONTRACT_BASE.parse();
        assert!(addr.is_ok());
    }

    #[test]
    fn schema_registry_address_constant_is_valid() {
        let addr: std::result::Result<Address, _> = SCHEMA_REGISTRY_BASE.parse();
        assert!(addr.is_ok());
    }
}
