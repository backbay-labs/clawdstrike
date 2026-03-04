"""Security guards for clawdstrike.

Guards implement checks that can allow, block, or log actions.
"""

from clawdstrike.guards.base import (
    Action,
    AsyncGuard,
    CustomAction,
    FileAccessAction,
    FileWriteAction,
    Guard,
    GuardAction,
    GuardContext,
    GuardResult,
    McpToolAction,
    NetworkEgressAction,
    PatchAction,
    Severity,
    ShellCommandAction,
)
from clawdstrike.guards.egress_allowlist import EgressAllowlistConfig, EgressAllowlistGuard
from clawdstrike.guards.forbidden_path import ForbiddenPathConfig, ForbiddenPathGuard
from clawdstrike.guards.jailbreak import JailbreakConfig, JailbreakGuard
from clawdstrike.guards.mcp_tool import McpToolConfig, McpToolGuard
from clawdstrike.guards.patch_integrity import PatchIntegrityConfig, PatchIntegrityGuard
from clawdstrike.guards.path_allowlist import PathAllowlistConfig, PathAllowlistGuard
from clawdstrike.guards.prompt_injection import (
    PromptInjectionConfig,
    PromptInjectionGuard,
    PromptInjectionLevel,
)
from clawdstrike.guards.secret_leak import SecretLeakConfig, SecretLeakGuard, SecretPattern
from clawdstrike.guards.shell_command import ShellCommandConfig, ShellCommandGuard
from clawdstrike.guards.spider_sense import (
    PatternDb,
    PatternEntry,
    ScreeningResult,
    SpiderSenseConfig,
    SpiderSenseDetector,
    SpiderSenseDetectorConfig,
    SpiderSenseGuard,
    SpiderSenseMetrics,
    SpiderSenseMetricsHook,
)

__all__ = [
    # Base types
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
    # Spider Sense
    "SpiderSenseGuard",
    "SpiderSenseConfig",
    "SpiderSenseDetector",
    "SpiderSenseDetectorConfig",
    "SpiderSenseMetrics",
    "SpiderSenseMetricsHook",
    "PatternDb",
    "PatternEntry",
    "ScreeningResult",
]
