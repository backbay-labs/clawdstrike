"""Hush - Python SDK for clawdstrike security verification."""

from hush.core import sha256, keccak256, verify_signature, sign_message, generate_keypair
from hush.receipt import (
    RECEIPT_SCHEMA_VERSION,
    PublicKeySet,
    Receipt,
    SignedReceipt,
    Signatures,
    VerificationResult,
    Verdict,
    Provenance,
    ViolationRef,
    validate_receipt_version,
)
from hush.policy import Policy, PolicyEngine, PolicySettings, GuardConfigs
from hush.guards import (
    Severity,
    GuardResult,
    GuardContext,
    GuardAction,
    Guard,
    ForbiddenPathGuard,
    ForbiddenPathConfig,
    EgressAllowlistGuard,
    EgressAllowlistConfig,
    SecretLeakGuard,
    SecretLeakConfig,
    PatchIntegrityGuard,
    PatchIntegrityConfig,
    McpToolGuard,
    McpToolConfig,
)
from hush.merkle import (
    hash_leaf,
    hash_node,
    compute_root,
    generate_proof,
    MerkleTree,
    MerkleProof,
)
from hush.canonical import canonicalize, canonical_hash
from hush.native import NATIVE_AVAILABLE

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # Core crypto
    "sha256",
    "keccak256",
    "verify_signature",
    "sign_message",
    "generate_keypair",
    # Receipt
    "RECEIPT_SCHEMA_VERSION",
    "validate_receipt_version",
    "Receipt",
    "SignedReceipt",
    "Signatures",
    "PublicKeySet",
    "VerificationResult",
    "Verdict",
    "Provenance",
    "ViolationRef",
    # Policy
    "Policy",
    "PolicyEngine",
    "PolicySettings",
    "GuardConfigs",
    # Guards base
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
    # Guards
    "ForbiddenPathGuard",
    "ForbiddenPathConfig",
    "EgressAllowlistGuard",
    "EgressAllowlistConfig",
    "SecretLeakGuard",
    "SecretLeakConfig",
    "PatchIntegrityGuard",
    "PatchIntegrityConfig",
    "McpToolGuard",
    "McpToolConfig",
    # Merkle
    "hash_leaf",
    "hash_node",
    "compute_root",
    "generate_proof",
    "MerkleTree",
    "MerkleProof",
    # Canonical JSON
    "canonicalize",
    "canonical_hash",
    # Native backend
    "NATIVE_AVAILABLE",
]
