//! Fact schemas for SPIFFE identity binding and runtime proofs.
//!
//! Defines `node_attestation.v1` and `runtime_proof.v1` typed facts that
//! bind Spine issuer identities to SPIFFE workload identities, Kubernetes
//! metadata, and Tetragon kernel-level execution evidence.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema identifier for node attestation facts.
pub const NODE_ATTESTATION_SCHEMA: &str = "clawdstrike.spine.fact.node_attestation.v1";

/// Schema identifier for runtime proof facts.
pub const RUNTIME_PROOF_SCHEMA: &str = "clawdstrike.spine.fact.runtime_proof.v1";

/// Node attestation fact binding a Spine issuer to system identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAttestation {
    pub schema: String,
    pub fact_id: String,
    /// Spine node ID: `"aegis:ed25519:<hex>"`
    pub node_id: String,
    /// System-level attestation data.
    pub system_attestation: SystemAttestation,
    /// Optional transport bindings (Reticulum, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<TransportBindings>,
    /// ISO-8601 timestamp.
    pub issued_at: String,
}

/// System-level attestation data from SPIFFE/Kubernetes/Tetragon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemAttestation {
    /// SPIFFE ID: `"spiffe://aegis.local/ns/<ns>/sa/<sa>"`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    /// SHA-256 of the X.509 SVID certificate (DER-encoded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub svid_cert_hash: Option<String>,
    /// Trust domain from the SVID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    /// Kubernetes metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<KubernetesMetadata>,
    /// Binary path of the attesting process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
    /// IMA hash of the binary (if Tetragon provides it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_hash_ima: Option<String>,
}

/// Kubernetes workload metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesMetadata {
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_image_digest: Option<String>,
}

/// Optional transport bindings for multi-network identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportBindings {
    /// Reticulum transport binding (for Plane A-R).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reticulum: Option<ReticulumBinding>,
}

/// Reticulum network transport binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReticulumBinding {
    pub profile: String,
    pub destination_hash: String,
    #[serde(default)]
    pub announce_period_secs: u64,
    #[serde(default)]
    pub supports: Vec<String>,
}

/// Runtime proof combining kernel-level evidence with workload identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProof {
    pub schema: String,
    pub fact_id: String,
    /// Proof type: `"execution"`, `"file_access"`, `"network"`.
    pub proof_type: String,
    pub timestamp: String,
    /// Kernel-level execution evidence from Tetragon.
    pub execution: ExecutionEvidence,
    /// Workload identity from SPIRE.
    pub identity: WorkloadIdentity,
    /// Kubernetes context.
    pub kubernetes: KubernetesMetadata,
    /// Network enforcement context (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_enforcement: Option<NetworkEnforcement>,
    /// Cross-reference chain linking all layers.
    pub attestation_chain: AttestationChain,
}

/// Kernel-level execution evidence from Tetragon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEvidence {
    pub binary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_hash_ima: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    pub pid: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u64>,
    pub exec_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_exec_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<Value>,
}

/// SPIRE workload identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentity {
    pub spiffe_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub svid_serial: Option<String>,
    pub trust_domain: String,
}

/// Network enforcement context from Tetragon/Cilium.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEnforcement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tetragon_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cilium_network_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_connections: Vec<ObservedConnection>,
}

/// An observed network connection from Tetragon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedConnection {
    pub daddr: String,
    pub dport: u16,
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

/// Cross-reference chain linking kernel, identity, and log layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationChain {
    /// Tetragon exec_id linking to the kernel event.
    pub tetragon_exec_id: String,
    /// SHA-256 of the SPIRE SVID certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spire_svid_hash: Option<String>,
    /// Hash of the ClawdStrike guard receipt (if a guard evaluated this action).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clawdstrike_receipt_hash: Option<String>,
    /// Envelope hash of this proof in the AegisNet/Spine log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aegisnet_envelope_hash: Option<String>,
}

impl NodeAttestation {
    /// Convert to a `serde_json::Value` for embedding in a Spine envelope fact.
    pub fn to_fact_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

impl RuntimeProof {
    /// Convert to a `serde_json::Value` for embedding in a Spine envelope fact.
    pub fn to_fact_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_node_attestation() -> NodeAttestation {
        NodeAttestation {
            schema: NODE_ATTESTATION_SCHEMA.to_string(),
            fact_id: "na_test_001".to_string(),
            node_id: "aegis:ed25519:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233".to_string(),
            system_attestation: SystemAttestation {
                spiffe_id: Some("spiffe://aegis.local/ns/clawdstrike/sa/checkpointer".to_string()),
                svid_cert_hash: Some("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string()),
                trust_domain: Some("aegis.local".to_string()),
                kubernetes: Some(KubernetesMetadata {
                    namespace: "clawdstrike".to_string(),
                    pod: Some("checkpointer-0".to_string()),
                    node: Some("ip-10-0-1-42.ec2.internal".to_string()),
                    service_account: Some("checkpointer".to_string()),
                    container_image: Some("ghcr.io/backbay-labs/spine-checkpointer:v0.1.0".to_string()),
                    container_image_digest: Some("sha256:abcdef1234567890".to_string()),
                }),
                binary: Some("/usr/local/bin/spine-checkpointer".to_string()),
                binary_hash_ima: Some("sha256:1234567890abcdef".to_string()),
            },
            transports: None,
            issued_at: "2026-02-07T00:00:00Z".to_string(),
        }
    }

    fn sample_runtime_proof() -> RuntimeProof {
        RuntimeProof {
            schema: RUNTIME_PROOF_SCHEMA.to_string(),
            fact_id: "rp_test_001".to_string(),
            proof_type: "execution".to_string(),
            timestamp: "2026-02-07T00:00:01Z".to_string(),
            execution: ExecutionEvidence {
                binary: "/usr/bin/curl".to_string(),
                binary_hash_ima: Some("sha256:fedcba0987654321".to_string()),
                arguments: Some("https://example.com".to_string()),
                pid: 12345,
                uid: Some(1000),
                exec_id: "abc123def456".to_string(),
                parent_exec_id: Some("parent789".to_string()),
                capabilities: Some("NET_RAW".to_string()),
                namespaces: None,
            },
            identity: WorkloadIdentity {
                spiffe_id: "spiffe://aegis.local/ns/default/sa/agent".to_string(),
                svid_serial: Some("123456".to_string()),
                trust_domain: "aegis.local".to_string(),
            },
            kubernetes: KubernetesMetadata {
                namespace: "default".to_string(),
                pod: Some("agent-pod-0".to_string()),
                node: Some("worker-1".to_string()),
                service_account: Some("agent".to_string()),
                container_image: None,
                container_image_digest: None,
            },
            network_enforcement: None,
            attestation_chain: AttestationChain {
                tetragon_exec_id: "abc123def456".to_string(),
                spire_svid_hash: Some("0xdeadbeef".to_string()),
                clawdstrike_receipt_hash: None,
                aegisnet_envelope_hash: None,
            },
        }
    }

    #[test]
    fn node_attestation_serde_roundtrip() {
        let na = sample_node_attestation();
        let json = serde_json::to_string(&na).unwrap();
        let restored: NodeAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.schema, NODE_ATTESTATION_SCHEMA);
        assert_eq!(restored.node_id, na.node_id);
        assert_eq!(
            restored.system_attestation.spiffe_id,
            na.system_attestation.spiffe_id
        );
    }

    #[test]
    fn runtime_proof_serde_roundtrip() {
        let rp = sample_runtime_proof();
        let json = serde_json::to_string(&rp).unwrap();
        let restored: RuntimeProof = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.schema, RUNTIME_PROOF_SCHEMA);
        assert_eq!(restored.execution.binary, "/usr/bin/curl");
        assert_eq!(restored.identity.spiffe_id, rp.identity.spiffe_id);
    }

    #[test]
    fn node_attestation_rejects_unknown_fields() {
        let json = r#"{
            "schema": "clawdstrike.spine.fact.node_attestation.v1",
            "fact_id": "test",
            "node_id": "aegis:ed25519:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
            "system_attestation": { "spiffe_id": "spiffe://aegis.local/ns/x/sa/y" },
            "issued_at": "2026-01-01T00:00:00Z",
            "unexpected_field": true
        }"#;
        let result = serde_json::from_str::<NodeAttestation>(json);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn runtime_proof_rejects_unknown_fields() {
        let rp = sample_runtime_proof();
        let mut value = serde_json::to_value(&rp).unwrap();
        value["extra_field"] = serde_json::json!("bad");
        let result = serde_json::from_value::<RuntimeProof>(value);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn node_attestation_to_fact_value() {
        let na = sample_node_attestation();
        let val = na.to_fact_value().unwrap();
        assert_eq!(
            val.get("schema").and_then(|v| v.as_str()).unwrap(),
            NODE_ATTESTATION_SCHEMA
        );
    }

    #[test]
    fn runtime_proof_to_fact_value() {
        let rp = sample_runtime_proof();
        let val = rp.to_fact_value().unwrap();
        assert_eq!(
            val.get("schema").and_then(|v| v.as_str()).unwrap(),
            RUNTIME_PROOF_SCHEMA
        );
    }

    #[test]
    fn node_attestation_optional_fields_omitted() {
        let na = NodeAttestation {
            schema: NODE_ATTESTATION_SCHEMA.to_string(),
            fact_id: "na_minimal".to_string(),
            node_id: "aegis:ed25519:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233".to_string(),
            system_attestation: SystemAttestation {
                spiffe_id: None,
                svid_cert_hash: None,
                trust_domain: None,
                kubernetes: None,
                binary: None,
                binary_hash_ima: None,
            },
            transports: None,
            issued_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&na).unwrap();
        assert!(!json.contains("transports"));
        assert!(!json.contains("spiffe_id"));

        // Roundtrip still works
        let restored: NodeAttestation = serde_json::from_str(&json).unwrap();
        assert!(restored.transports.is_none());
        assert!(restored.system_attestation.spiffe_id.is_none());
    }
}
