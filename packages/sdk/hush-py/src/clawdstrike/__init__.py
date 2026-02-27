"""Clawdstrike - Python SDK for clawdstrike security verification."""

from clawdstrike.canonical import canonical_hash, canonicalize
from clawdstrike.certification_badge import verify_certification_badge
from clawdstrike.clawdstrike import Clawdstrike, ClawdstrikeSession
from clawdstrike.core import generate_keypair, keccak256, sha256, sign_message, verify_signature
from clawdstrike.exceptions import (
    ClawdstrikeError,
    ConfigurationError,
    GuardError,
    NativeBackendError,
    PolicyError,
    ReceiptError,
)
from clawdstrike.guards import (
    Action,
    AsyncGuard,
    CustomAction,
    EgressAllowlistConfig,
    EgressAllowlistGuard,
    FileAccessAction,
    FileWriteAction,
    ForbiddenPathConfig,
    ForbiddenPathGuard,
    Guard,
    GuardAction,
    GuardContext,
    GuardResult,
    JailbreakConfig,
    JailbreakGuard,
    McpToolAction,
    McpToolConfig,
    McpToolGuard,
    NetworkEgressAction,
    PatchAction,
    PatchIntegrityConfig,
    PatchIntegrityGuard,
    PathAllowlistConfig,
    PathAllowlistGuard,
    PromptInjectionConfig,
    PromptInjectionGuard,
    PromptInjectionLevel,
    SecretLeakConfig,
    SecretLeakGuard,
    SecretPattern,
    Severity,
    ShellCommandAction,
    ShellCommandConfig,
    ShellCommandGuard,
)
from clawdstrike.merkle import (
    MerkleProof,
    MerkleTree,
    compute_root,
    generate_proof,
    hash_leaf,
    hash_node,
)
from clawdstrike.native import NATIVE_AVAILABLE
from clawdstrike.policy import (
    GuardConfigs,
    Policy,
    PolicyEngine,
    PolicyResolver,
    PolicySettings,
    PostureConfig,
    PostureState,
    PostureTransition,
)
from clawdstrike.receipt import (
    RECEIPT_SCHEMA_VERSION,
    Provenance,
    PublicKeySet,
    Receipt,
    Signatures,
    SignedReceipt,
    Verdict,
    VerificationResult,
    ViolationRef,
    validate_receipt_version,
)
from clawdstrike.types import Decision, DecisionStatus, SessionOptions, SessionSummary

__version__ = "0.2.0"

__all__ = [
    "__version__",
    # Exceptions
    "ClawdstrikeError",
    "PolicyError",
    "GuardError",
    "ReceiptError",
    "ConfigurationError",
    "NativeBackendError",
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
    "PolicyResolver",
    "GuardConfigs",
    "PostureConfig",
    "PostureState",
    "PostureTransition",
    # Guards base
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
    "AsyncGuard",
    # Typed action variants
    "Action",
    "FileAccessAction",
    "FileWriteAction",
    "NetworkEgressAction",
    "ShellCommandAction",
    "McpToolAction",
    "PatchAction",
    "CustomAction",
    # Decision / Facade
    "Decision",
    "DecisionStatus",
    "SessionOptions",
    "SessionSummary",
    "Clawdstrike",
    "ClawdstrikeSession",
    # Guards
    "ForbiddenPathGuard",
    "ForbiddenPathConfig",
    "EgressAllowlistGuard",
    "EgressAllowlistConfig",
    "SecretLeakGuard",
    "SecretLeakConfig",
    "SecretPattern",
    "PatchIntegrityGuard",
    "PatchIntegrityConfig",
    "McpToolGuard",
    "McpToolConfig",
    "PromptInjectionGuard",
    "PromptInjectionConfig",
    "PromptInjectionLevel",
    "JailbreakGuard",
    "JailbreakConfig",
    "ShellCommandGuard",
    "ShellCommandConfig",
    "PathAllowlistGuard",
    "PathAllowlistConfig",
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
