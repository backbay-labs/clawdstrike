"""Security guards for clawdstrike.

Guards implement checks that can allow, block, or log actions.
"""

from clawdstrike.guards.base import (
    Severity,
    GuardResult,
    GuardContext,
    GuardAction,
    Guard,
)
from clawdstrike.guards.forbidden_path import ForbiddenPathGuard, ForbiddenPathConfig
from clawdstrike.guards.egress_allowlist import EgressAllowlistGuard, EgressAllowlistConfig
from clawdstrike.guards.secret_leak import SecretLeakGuard, SecretLeakConfig, SecretPattern
from clawdstrike.guards.patch_integrity import PatchIntegrityGuard, PatchIntegrityConfig
from clawdstrike.guards.mcp_tool import McpToolGuard, McpToolConfig
from clawdstrike.guards.prompt_injection import (
    PromptInjectionGuard,
    PromptInjectionConfig,
    PromptInjectionLevel,
)
from clawdstrike.guards.jailbreak import JailbreakGuard, JailbreakConfig

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
]
