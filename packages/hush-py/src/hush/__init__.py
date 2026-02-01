"""Hush - Python SDK for hushclaw security verification."""

from hush.core import sha256, keccak256, verify_signature, sign_message, generate_keypair
from hush.receipt import Receipt, SignedReceipt
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
    "Receipt",
    "SignedReceipt",
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
]
