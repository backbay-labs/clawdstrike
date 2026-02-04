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

POLICY_SCHEMA_VERSION = "1.1.0"


def _parse_semver_strict(version: str) -> Optional[tuple[int, int, int]]:
    parts = version.split(".")
    if len(parts) != 3:
        return None
    try:
        major, minor, patch = (int(p) for p in parts)
    except ValueError:
        return None
    if major < 0 or minor < 0 or patch < 0:
        return None
    return major, minor, patch


def _validate_policy_version(version: str) -> None:
    if _parse_semver_strict(version) is None:
        raise ValueError(f"Invalid policy version: {version!r} (expected X.Y.Z)")
    if version != POLICY_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported policy version: {version!r} (supported: {POLICY_SCHEMA_VERSION})"
        )


def _require_mapping(value: Any, *, path: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"Expected mapping for {path}, got {type(value).__name__}")
    return value


def _reject_unknown_keys(data: Dict[str, Any], allowed: set[str], *, path: str) -> None:
    unknown = set(data.keys()) - allowed
    if unknown:
        unknown_str = ", ".join(sorted(unknown))
        raise ValueError(f"Unknown {path} field(s): {unknown_str}")


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
        allowed = {
            "forbidden_path",
            "egress_allowlist",
            "secret_leak",
            "patch_integrity",
            "mcp_tool",
        }
        _reject_unknown_keys(data, allowed, path="guards")

        def parse_guard_config(
            config_type: Any, value: Any, *, path: str
        ) -> Optional[Any]:
            if value is None:
                return None
            if not isinstance(value, dict):
                raise ValueError(
                    f"Expected mapping for {path}, got {type(value).__name__}"
                )
            try:
                return config_type(**value)
            except TypeError as e:
                raise ValueError(f"Invalid {path} config: {e}") from e

        return cls(
            forbidden_path=parse_guard_config(
                ForbiddenPathConfig,
                data.get("forbidden_path"),
                path="guards.forbidden_path",
            ),
            egress_allowlist=parse_guard_config(
                EgressAllowlistConfig,
                data.get("egress_allowlist"),
                path="guards.egress_allowlist",
            ),
            secret_leak=parse_guard_config(
                SecretLeakConfig,
                data.get("secret_leak"),
                path="guards.secret_leak",
            ),
            patch_integrity=parse_guard_config(
                PatchIntegrityConfig,
                data.get("patch_integrity"),
                path="guards.patch_integrity",
            ),
            mcp_tool=parse_guard_config(
                McpToolConfig,
                data.get("mcp_tool"),
                path="guards.mcp_tool",
            ),
        )


@dataclass
class Policy:
    """Complete policy configuration."""

    version: str = POLICY_SCHEMA_VERSION
    name: str = ""
    description: str = ""
    guards: GuardConfigs = field(default_factory=GuardConfigs)
    settings: PolicySettings = field(default_factory=PolicySettings)

    @classmethod
    def from_yaml(cls, yaml_str: str) -> Policy:
        """Parse from YAML string."""
        data = yaml.safe_load(yaml_str) or {}
        if not isinstance(data, dict):
            raise ValueError("Policy YAML must be a mapping (YAML object)")

        _reject_unknown_keys(
            data, {"version", "name", "description", "guards", "settings"}, path="policy"
        )

        version = data.get("version", POLICY_SCHEMA_VERSION)
        if not isinstance(version, str):
            raise ValueError("policy.version must be a string")
        _validate_policy_version(version)

        guards_data = _require_mapping(data.get("guards"), path="policy.guards")
        settings_data = _require_mapping(data.get("settings"), path="policy.settings")

        return cls(
            version=version,
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
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
