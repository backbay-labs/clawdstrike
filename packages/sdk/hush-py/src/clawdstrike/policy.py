"""Policy loading and evaluation.

Provides Policy loading from YAML and PolicyEngine for running guards.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

from clawdstrike.guards.base import Guard, GuardAction, GuardContext, GuardResult
from clawdstrike.guards.forbidden_path import ForbiddenPathGuard, ForbiddenPathConfig
from clawdstrike.guards.egress_allowlist import EgressAllowlistGuard, EgressAllowlistConfig
from clawdstrike.guards.secret_leak import SecretLeakGuard, SecretLeakConfig, SecretPattern
from clawdstrike.guards.patch_integrity import PatchIntegrityGuard, PatchIntegrityConfig
from clawdstrike.guards.mcp_tool import McpToolGuard, McpToolConfig
from clawdstrike.guards.prompt_injection import (
    PromptInjectionGuard,
    PromptInjectionConfig,
)
from clawdstrike.guards.jailbreak import JailbreakGuard, JailbreakConfig

POLICY_SCHEMA_VERSION = "1.2.0"
POLICY_SUPPORTED_VERSIONS = {"1.1.0", "1.2.0"}

# Built-in ruleset directory (relative to this file)
_RULESETS_DIR = Path(__file__).resolve().parents[5] / "rulesets"

MAX_EXTENDS_DEPTH = 32


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
    if version not in POLICY_SUPPORTED_VERSIONS:
        supported = ", ".join(sorted(POLICY_SUPPORTED_VERSIONS))
        raise ValueError(
            f"Unsupported policy version: {version!r} (supported: {supported})"
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


class PolicyResolver:
    """Resolves policy extends references to YAML content."""

    def resolve(self, reference: str, from_path: Optional[Path] = None) -> tuple[str, str, Optional[Path]]:
        """Resolve a reference to (yaml_content, canonical_key, location_path).

        Supports:
        - Built-in rulesets: 'clawdstrike:strict', 'strict', etc.
        - Local file paths (relative to from_path)
        """
        # Try built-in rulesets
        ruleset_id = reference.removeprefix("clawdstrike:") if reference.startswith("clawdstrike:") else reference
        builtin_names = {
            "default", "strict", "ai-agent", "ai-agent-posture", "cicd", "permissive",
        }

        if ruleset_id in builtin_names:
            ruleset_file = _RULESETS_DIR / f"{ruleset_id}.yaml"
            if ruleset_file.exists():
                yaml_content = ruleset_file.read_text()
                return yaml_content, f"ruleset:{ruleset_id}", ruleset_file

        # Try as file path
        if from_path is not None:
            base_dir = from_path.parent if from_path.is_file() else from_path
            extends_path = base_dir / reference
        else:
            extends_path = Path(reference)

        if extends_path.exists():
            yaml_content = extends_path.read_text()
            canonical = str(extends_path.resolve())
            return yaml_content, f"file:{canonical}", extends_path

        raise ValueError(f"Unknown ruleset or file not found: {reference}")


_DEFAULT_RESOLVER = PolicyResolver()


@dataclass
class PostureState:
    """A single posture state."""

    description: str = ""
    capabilities: List[str] = field(default_factory=list)
    budgets: Dict[str, int] = field(default_factory=dict)


@dataclass
class PostureTransition:
    """A posture transition rule."""

    from_state: str = ""
    to_state: str = ""
    on: str = ""
    after: Optional[str] = None


@dataclass
class PostureConfig:
    """Posture configuration."""

    initial: str = ""
    states: Dict[str, PostureState] = field(default_factory=dict)
    transitions: List[PostureTransition] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PostureConfig:
        states: Dict[str, PostureState] = {}
        for name, state_data in data.get("states", {}).items():
            if not isinstance(state_data, dict):
                continue
            states[name] = PostureState(
                description=str(state_data.get("description", "")),
                capabilities=list(state_data.get("capabilities", [])),
                budgets=dict(state_data.get("budgets", {})),
            )

        transitions: List[PostureTransition] = []
        for t_data in data.get("transitions", []):
            if not isinstance(t_data, dict):
                continue
            transitions.append(PostureTransition(
                from_state=str(t_data.get("from", "")),
                to_state=str(t_data.get("to", "")),
                on=str(t_data.get("on", "")),
                after=t_data.get("after"),
            ))

        return cls(
            initial=str(data.get("initial", "")),
            states=states,
            transitions=transitions,
        )


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
    prompt_injection: Optional[PromptInjectionConfig] = None
    jailbreak: Optional[JailbreakConfig] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GuardConfigs:
        """Create from dictionary."""
        allowed = {
            "forbidden_path",
            "egress_allowlist",
            "secret_leak",
            "patch_integrity",
            "mcp_tool",
            "prompt_injection",
            "jailbreak",
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

        # Special handling for secret_leak: convert pattern dicts to SecretPattern objects
        secret_leak_data = data.get("secret_leak")
        secret_leak_config = None
        if secret_leak_data is not None:
            if not isinstance(secret_leak_data, dict):
                raise ValueError(
                    f"Expected mapping for guards.secret_leak, got {type(secret_leak_data).__name__}"
                )
            patterns_data = secret_leak_data.get("patterns")
            patterns = None
            if patterns_data is not None:
                patterns = [
                    SecretPattern(**p) if isinstance(p, dict) else p
                    for p in patterns_data
                ]
            secret_leak_config = SecretLeakConfig(
                patterns=patterns if patterns is not None else SecretLeakConfig().patterns,
                skip_paths=secret_leak_data.get("skip_paths", []),
                enabled=secret_leak_data.get("enabled", True),
                secrets=secret_leak_data.get("secrets", []),
            )

        # Special handling for patch_integrity: pass forbidden_patterns
        patch_data = data.get("patch_integrity")
        patch_config = None
        if patch_data is not None:
            if not isinstance(patch_data, dict):
                raise ValueError(
                    f"Expected mapping for guards.patch_integrity, got {type(patch_data).__name__}"
                )
            patch_config = PatchIntegrityConfig(
                max_additions=patch_data.get("max_additions", 1000),
                max_deletions=patch_data.get("max_deletions", 500),
                require_balance=patch_data.get("require_balance", False),
                max_imbalance_ratio=patch_data.get("max_imbalance_ratio", 5.0),
                forbidden_patterns=patch_data.get("forbidden_patterns", []),
            )

        # Special handling for jailbreak: nested 'detector' field
        jailbreak_data = data.get("jailbreak")
        jailbreak_config = None
        if jailbreak_data is not None:
            if not isinstance(jailbreak_data, dict):
                raise ValueError(
                    f"Expected mapping for guards.jailbreak, got {type(jailbreak_data).__name__}"
                )
            detector_data = jailbreak_data.get("detector", {})
            jailbreak_config = JailbreakConfig(
                enabled=jailbreak_data.get("enabled", True),
                block_threshold=detector_data.get("block_threshold", 70),
                warn_threshold=detector_data.get("warn_threshold", 30),
                max_input_bytes=detector_data.get("max_input_bytes", 200_000),
                session_aggregation=detector_data.get("session_aggregation", True),
            )

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
            secret_leak=secret_leak_config,
            patch_integrity=patch_config,
            mcp_tool=parse_guard_config(
                McpToolConfig,
                data.get("mcp_tool"),
                path="guards.mcp_tool",
            ),
            prompt_injection=parse_guard_config(
                PromptInjectionConfig,
                data.get("prompt_injection"),
                path="guards.prompt_injection",
            ),
            jailbreak=jailbreak_config,
        )


@dataclass
class Policy:
    """Complete policy configuration."""

    version: str = POLICY_SCHEMA_VERSION
    name: str = ""
    description: str = ""
    extends: Optional[str] = None
    merge_strategy: str = "deep_merge"
    guards: GuardConfigs = field(default_factory=GuardConfigs)
    settings: PolicySettings = field(default_factory=PolicySettings)
    posture: Optional[PostureConfig] = None

    @classmethod
    def from_yaml(cls, yaml_str: str) -> Policy:
        """Parse from YAML string (no extends resolution)."""
        data = yaml.safe_load(yaml_str) or {}
        if not isinstance(data, dict):
            raise ValueError("Policy YAML must be a mapping (YAML object)")

        _reject_unknown_keys(
            data,
            {"version", "name", "description", "extends", "merge_strategy",
             "guards", "settings", "posture", "custom_guards"},
            path="policy",
        )

        version = data.get("version", POLICY_SCHEMA_VERSION)
        if not isinstance(version, str):
            raise ValueError("policy.version must be a string")
        _validate_policy_version(version)

        guards_data = _require_mapping(data.get("guards"), path="policy.guards")
        settings_data = _require_mapping(data.get("settings"), path="policy.settings")

        posture = None
        posture_data = data.get("posture")
        if posture_data is not None:
            parsed_version = _parse_semver_strict(version)
            if parsed_version is not None and parsed_version < (1, 2, 0):
                raise ValueError("posture requires policy version 1.2.0")
            posture = PostureConfig.from_dict(posture_data)

        return cls(
            version=version,
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            extends=data.get("extends"),
            merge_strategy=str(data.get("merge_strategy", "deep_merge")),
            guards=GuardConfigs.from_dict(guards_data) if guards_data else GuardConfigs(),
            settings=PolicySettings(**settings_data) if settings_data else PolicySettings(),
            posture=posture,
        )

    @classmethod
    def from_yaml_file(cls, path: str) -> Policy:
        """Load from YAML file."""
        with open(path, "r") as f:
            return cls.from_yaml(f.read())

    @classmethod
    def from_yaml_with_extends(
        cls,
        yaml_str: str,
        base_path: Optional[str] = None,
        resolver: Optional[PolicyResolver] = None,
    ) -> Policy:
        """Parse from YAML string with extends resolution.

        If the policy has an 'extends' field, loads the base and merges.
        Detects circular dependencies.
        """
        if resolver is None:
            resolver = _DEFAULT_RESOLVER
        from_path = Path(base_path) if base_path else None
        return cls._resolve_extends(yaml_str, from_path, resolver, set(), 0)

    @classmethod
    def from_yaml_file_with_extends(
        cls,
        path: str,
        resolver: Optional[PolicyResolver] = None,
    ) -> Policy:
        """Load from YAML file with extends resolution."""
        with open(path, "r") as f:
            yaml_str = f.read()
        return cls.from_yaml_with_extends(yaml_str, base_path=path, resolver=resolver)

    @classmethod
    def _resolve_extends(
        cls,
        yaml_str: str,
        from_path: Optional[Path],
        resolver: PolicyResolver,
        visited: Set[str],
        depth: int,
    ) -> Policy:
        if depth > MAX_EXTENDS_DEPTH:
            raise ValueError(f"Policy extends depth exceeded (limit: {MAX_EXTENDS_DEPTH})")

        child = cls.from_yaml(yaml_str)

        if child.extends:
            resolved_yaml, canonical_key, location = resolver.resolve(
                child.extends, from_path
            )

            if canonical_key in visited:
                raise ValueError(f"Circular policy extension detected: {child.extends}")
            visited.add(canonical_key)

            base = cls._resolve_extends(resolved_yaml, location, resolver, visited, depth + 1)
            return base.merge(child)

        return child

    def merge(self, child: Policy) -> Policy:
        """Merge this (base) policy with a child policy."""
        return Policy(
            version=child.version if child.version != self.version else self.version,
            name=child.name if child.name else self.name,
            description=child.description if child.description else self.description,
            extends=None,
            merge_strategy="deep_merge",
            guards=self._merge_guards(child.guards),
            settings=PolicySettings(
                fail_fast=child.settings.fail_fast if child.settings.fail_fast != PolicySettings().fail_fast else self.settings.fail_fast,
                verbose_logging=child.settings.verbose_logging if child.settings.verbose_logging != PolicySettings().verbose_logging else self.settings.verbose_logging,
                session_timeout_secs=child.settings.session_timeout_secs if child.settings.session_timeout_secs != PolicySettings().session_timeout_secs else self.settings.session_timeout_secs,
            ),
            posture=child.posture if child.posture else self.posture,
        )

    def _merge_guards(self, child: GuardConfigs) -> GuardConfigs:
        """Deep merge guard configs (child overrides base)."""
        return GuardConfigs(
            forbidden_path=child.forbidden_path or self.guards.forbidden_path,
            egress_allowlist=child.egress_allowlist or self.guards.egress_allowlist,
            secret_leak=child.secret_leak or self.guards.secret_leak,
            patch_integrity=child.patch_integrity or self.guards.patch_integrity,
            mcp_tool=child.mcp_tool or self.guards.mcp_tool,
            prompt_injection=child.prompt_injection or self.guards.prompt_injection,
            jailbreak=child.jailbreak or self.guards.jailbreak,
        )

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
        guards.append(
            PromptInjectionGuard(self.policy.guards.prompt_injection)
            if self.policy.guards.prompt_injection
            else PromptInjectionGuard()
        )
        guards.append(
            JailbreakGuard(self.policy.guards.jailbreak)
            if self.policy.guards.jailbreak
            else JailbreakGuard()
        )

        return guards

    def check(self, action: GuardAction, context: GuardContext) -> List[GuardResult]:
        """Check an action against all guards."""
        results: List[GuardResult] = []

        for guard in self.guards:
            if guard.handles(action):
                result = guard.check(action, context)
                results.append(result)

                if self.policy.settings.fail_fast and not result.allowed:
                    break

        return results

    def is_allowed(self, action: GuardAction, context: GuardContext) -> bool:
        """Check if an action is allowed (convenience method)."""
        results = self.check(action, context)
        return all(r.allowed for r in results)


__all__ = [
    "Policy",
    "PolicyEngine",
    "PolicySettings",
    "PolicyResolver",
    "GuardConfigs",
    "PostureConfig",
    "PostureState",
    "PostureTransition",
]
