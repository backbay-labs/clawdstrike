"""Policy loading and evaluation.

Provides Policy loading from YAML and PolicyEngine for running guards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult
from hush.guards.forbidden_path import ForbiddenPathGuard, ForbiddenPathConfig
from hush.guards.egress_allowlist import EgressAllowlistGuard, EgressAllowlistConfig
from hush.guards.secret_leak import SecretLeakGuard, SecretLeakConfig
from hush.guards.patch_integrity import PatchIntegrityGuard, PatchIntegrityConfig
from hush.guards.mcp_tool import McpToolGuard, McpToolConfig


@dataclass
class PolicySettings:
    """Global policy settings."""

    fail_fast: bool = False
    verbose_logging: bool = False
    session_timeout_secs: int = 3600


@dataclass
class GuardConfigs:
    """Configuration for all guards."""

    forbidden_path: Optional[ForbiddenPathConfig] = None
    egress_allowlist: Optional[EgressAllowlistConfig] = None
    secret_leak: Optional[SecretLeakConfig] = None
    patch_integrity: Optional[PatchIntegrityConfig] = None
    mcp_tool: Optional[McpToolConfig] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GuardConfigs:
        """Create from dictionary."""
        return cls(
            forbidden_path=ForbiddenPathConfig(**data["forbidden_path"])
                if "forbidden_path" in data else None,
            egress_allowlist=EgressAllowlistConfig(**data["egress_allowlist"])
                if "egress_allowlist" in data else None,
            secret_leak=SecretLeakConfig(**data["secret_leak"])
                if "secret_leak" in data else None,
            patch_integrity=PatchIntegrityConfig(**data["patch_integrity"])
                if "patch_integrity" in data else None,
            mcp_tool=McpToolConfig(**data["mcp_tool"])
                if "mcp_tool" in data else None,
        )


@dataclass
class Policy:
    """Complete policy configuration."""

    version: str = "1.0.0"
    name: str = ""
    description: str = ""
    guards: GuardConfigs = field(default_factory=GuardConfigs)
    settings: PolicySettings = field(default_factory=PolicySettings)

    @classmethod
    def from_yaml(cls, yaml_str: str) -> Policy:
        """Parse from YAML string."""
        data = yaml.safe_load(yaml_str) or {}

        guards_data = data.get("guards", {})
        settings_data = data.get("settings", {})

        return cls(
            version=data.get("version", "1.0.0"),
            name=data.get("name", ""),
            description=data.get("description", ""),
            guards=GuardConfigs.from_dict(guards_data) if guards_data else GuardConfigs(),
            settings=PolicySettings(**settings_data) if settings_data else PolicySettings(),
        )

    @classmethod
    def from_yaml_file(cls, path: str) -> Policy:
        """Load from YAML file."""
        with open(path, "r") as f:
            return cls.from_yaml(f.read())

    def to_yaml(self) -> str:
        """Export to YAML string."""
        data: Dict[str, Any] = {
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "guards": {},
            "settings": {
                "fail_fast": self.settings.fail_fast,
                "verbose_logging": self.settings.verbose_logging,
                "session_timeout_secs": self.settings.session_timeout_secs,
            },
        }

        # Only include configured guards
        if self.guards.forbidden_path:
            data["guards"]["forbidden_path"] = {
                "patterns": self.guards.forbidden_path.patterns,
                "exceptions": self.guards.forbidden_path.exceptions,
            }
        if self.guards.egress_allowlist:
            data["guards"]["egress_allowlist"] = {
                "allow": self.guards.egress_allowlist.allow,
                "block": self.guards.egress_allowlist.block,
                "default_action": self.guards.egress_allowlist.default_action,
            }
        if self.guards.secret_leak:
            data["guards"]["secret_leak"] = {
                "secrets": self.guards.secret_leak.secrets,
                "enabled": self.guards.secret_leak.enabled,
            }
        if self.guards.patch_integrity:
            data["guards"]["patch_integrity"] = {
                "max_additions": self.guards.patch_integrity.max_additions,
                "max_deletions": self.guards.patch_integrity.max_deletions,
                "require_balance": self.guards.patch_integrity.require_balance,
                "max_imbalance_ratio": self.guards.patch_integrity.max_imbalance_ratio,
            }
        if self.guards.mcp_tool:
            data["guards"]["mcp_tool"] = {
                "allow": self.guards.mcp_tool.allow,
                "block": self.guards.mcp_tool.block,
                "default_action": self.guards.mcp_tool.default_action,
            }

        return yaml.dump(data, default_flow_style=False, sort_keys=False)


class PolicyEngine:
    """Engine for evaluating actions against a policy."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.guards = self._create_guards()

    def _create_guards(self) -> List[Guard]:
        """Create guard instances from policy configuration."""
        guards: List[Guard] = []

        # Create guards with config if provided, otherwise use defaults
        guards.append(
            ForbiddenPathGuard(self.policy.guards.forbidden_path)
            if self.policy.guards.forbidden_path
            else ForbiddenPathGuard()
        )
        guards.append(
            EgressAllowlistGuard(self.policy.guards.egress_allowlist)
            if self.policy.guards.egress_allowlist
            else EgressAllowlistGuard()
        )
        guards.append(
            SecretLeakGuard(self.policy.guards.secret_leak)
            if self.policy.guards.secret_leak
            else SecretLeakGuard()
        )
        guards.append(
            PatchIntegrityGuard(self.policy.guards.patch_integrity)
            if self.policy.guards.patch_integrity
            else PatchIntegrityGuard()
        )
        guards.append(
            McpToolGuard(self.policy.guards.mcp_tool)
            if self.policy.guards.mcp_tool
            else McpToolGuard()
        )

        return guards

    def check(self, action: GuardAction, context: GuardContext) -> List[GuardResult]:
        """Check an action against all guards.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            List of GuardResults from all applicable guards
        """
        results: List[GuardResult] = []

        for guard in self.guards:
            if guard.handles(action):
                result = guard.check(action, context)
                results.append(result)

                # Stop early if fail_fast and action is blocked
                if self.policy.settings.fail_fast and not result.allowed:
                    break

        return results

    def is_allowed(self, action: GuardAction, context: GuardContext) -> bool:
        """Check if an action is allowed (convenience method).

        Args:
            action: The action to check
            context: Execution context

        Returns:
            True if all guards allow the action
        """
        results = self.check(action, context)
        return all(r.allowed for r in results)


__all__ = [
    "Policy",
    "PolicyEngine",
    "PolicySettings",
    "GuardConfigs",
]
