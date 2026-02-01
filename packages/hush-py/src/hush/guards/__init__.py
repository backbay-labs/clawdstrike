"""Security guards for hushclaw.

Guards implement checks that can allow, block, or log actions.
"""

from hush.guards.base import (
    Severity,
    GuardResult,
    GuardContext,
    GuardAction,
    Guard,
)
from hush.guards.forbidden_path import ForbiddenPathGuard, ForbiddenPathConfig
from hush.guards.egress_allowlist import EgressAllowlistGuard, EgressAllowlistConfig
from hush.guards.secret_leak import SecretLeakGuard, SecretLeakConfig
from hush.guards.patch_integrity import PatchIntegrityGuard, PatchIntegrityConfig
from hush.guards.mcp_tool import McpToolGuard, McpToolConfig

__all__ = [
    # Base types
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
