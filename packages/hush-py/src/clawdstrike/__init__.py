"""Clawdstrike - Python SDK for clawdstrike security verification."""

from clawdstrike.core import sha256, keccak256, verify_signature, sign_message, generate_keypair
from clawdstrike.receipt import (
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
from clawdstrike.policy import Policy, PolicyEngine, PolicySettings, GuardConfigs
from clawdstrike.guards import (
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
from clawdstrike.merkle import (
    hash_leaf,
    hash_node,
    compute_root,
    generate_proof,
    MerkleTree,
    MerkleProof,
)
from clawdstrike.canonical import canonicalize, canonical_hash
from clawdstrike.native import NATIVE_AVAILABLE
from clawdstrike.certification_badge import verify_certification_badge

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
    # Certification badges
    "verify_certification_badge",
    # Native backend
    "NATIVE_AVAILABLE",
]
