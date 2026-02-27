"""Policy loading and evaluation.

Provides Policy loading from YAML and PolicyEngine for running guards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

from clawdstrike.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity
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

# Built-in ruleset directory.
# Try package-relative path first (works in both monorepo and installed layouts),
# then fall back to importlib.resources for installed packages.
def _find_rulesets_dir() -> Path:
    # Relative from this file: packages/sdk/hush-py/src/clawdstrike -> repo root
    pkg_relative = Path(__file__).resolve().parent / "../../../../../rulesets"
    if pkg_relative.is_dir():
        return pkg_relative.resolve()
    # Fallback: try importlib.resources (rulesets shipped as package data)
    try:
        import importlib.resources as _res
        ref = _res.files("clawdstrike") / "rulesets"
        p = Path(str(ref))
        if p.is_dir():
            return p
    except Exception as exc:
        import warnings
        warnings.warn(
            f"Could not locate 'clawdstrike' rulesets via importlib.resources: {exc}",
            stacklevel=2,
        )
    # Last resort: return the relative path and let callers handle missing files
    return pkg_relative.resolve()


_RULESETS_DIR = _find_rulesets_dir()

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

        initial = str(data.get("initial", ""))
        if initial and states and initial not in states:
            raise ValueError(
                f"Posture initial state {initial!r} not found in states: {sorted(states.keys())}"
            )

        for t in transitions:
            if states:
                if t.from_state and t.from_state not in states:
                    raise ValueError(
                        f"Posture transition references unknown from_state {t.from_state!r}"
                    )
                if t.to_state and t.to_state not in states:
                    raise ValueError(
                        f"Posture transition references unknown to_state {t.to_state!r}"
                    )

        return cls(
            initial=initial,
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
    _raw_guards: Dict[str, Any] = field(default_factory=dict, repr=False)
    _raw_settings: Dict[str, Any] = field(default_factory=dict, repr=False)

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
            _raw_guards=dict(guards_data) if guards_data else {},
            _raw_settings=dict(settings_data) if settings_data else {},
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
        """Merge this (base) policy with a child policy.

        Child settings explicitly declared in YAML override base settings.
        Settings not declared in the child inherit from the base.
        """
        merged_settings_data: Dict[str, Any] = {
            "fail_fast": self.settings.fail_fast,
            "verbose_logging": self.settings.verbose_logging,
            "session_timeout_secs": self.settings.session_timeout_secs,
        }
        merged_settings_data.update(child._raw_settings)

        return Policy(
            version=child.version if child.version != self.version else self.version,
            name=child.name if child.name else self.name,
            description=child.description if child.description else self.description,
            extends=None,
            merge_strategy="deep_merge",
            guards=self._merge_guards(child.guards, child._raw_guards),
            settings=PolicySettings(**merged_settings_data),
            posture=child.posture if child.posture else self.posture,
            _raw_guards={},
            _raw_settings=merged_settings_data,
        )

    def _merge_guards(self, child: GuardConfigs, child_raw: Dict[str, Any]) -> GuardConfigs:
        """Deep merge guard configs.

        The child policy may omit fields, but guard dataclasses fill omitted fields with defaults.
        To avoid silently dropping inherited restrictions, consult the raw YAML mapping to detect
        which fields were explicitly specified by the child.
        """
        raw = child_raw or {}

        def guard_raw(key: str) -> Dict[str, Any]:
            g = raw.get(key)
            return g if isinstance(g, dict) else {}

        def merge_str_list(base_list: List[str], child_list: List[str]) -> List[str]:
            out = list(base_list)
            for item in child_list:
                if item not in out:
                    out.append(item)
            return out

        def merge_secret_patterns(
            base_patterns: List[SecretPattern],
            child_patterns: List[SecretPattern],
        ) -> List[SecretPattern]:
            out = list(base_patterns)
            idx_by_name = {sp.name: i for i, sp in enumerate(out) if getattr(sp, "name", None)}
            for sp in child_patterns:
                i = idx_by_name.get(sp.name)
                if i is None:
                    idx_by_name[sp.name] = len(out)
                    out.append(sp)
                else:
                    out[i] = sp
            return out

        # Forbidden path guard
        forbidden_path = self.guards.forbidden_path
        if forbidden_path is None:
            forbidden_path = child.forbidden_path
        elif child.forbidden_path is not None:
            g = guard_raw("forbidden_path")
            patterns = forbidden_path.patterns
            if "patterns" in g:
                patterns = merge_str_list(patterns, child.forbidden_path.patterns)
            exceptions = forbidden_path.exceptions
            if "exceptions" in g:
                exceptions = merge_str_list(exceptions, child.forbidden_path.exceptions)
            forbidden_path = ForbiddenPathConfig(patterns=patterns, exceptions=exceptions)

        # Egress allowlist guard
        egress_allowlist = self.guards.egress_allowlist
        if egress_allowlist is None:
            egress_allowlist = child.egress_allowlist
        elif child.egress_allowlist is not None:
            g = guard_raw("egress_allowlist")
            allow = egress_allowlist.allow
            if "allow" in g:
                allow = merge_str_list(allow, child.egress_allowlist.allow)
            block = egress_allowlist.block
            if "block" in g:
                block = merge_str_list(block, child.egress_allowlist.block)
            default_action = egress_allowlist.default_action
            if "default_action" in g:
                default_action = child.egress_allowlist.default_action
            egress_allowlist = EgressAllowlistConfig(
                allow=allow,
                block=block,
                default_action=default_action,
            )

        # Secret leak guard
        secret_leak = self.guards.secret_leak
        if secret_leak is None:
            secret_leak = child.secret_leak
        elif child.secret_leak is not None:
            g = guard_raw("secret_leak")
            sl_patterns: List[SecretPattern] = secret_leak.patterns
            if "patterns" in g:
                sl_patterns = merge_secret_patterns(sl_patterns, child.secret_leak.patterns)
            skip_paths = secret_leak.skip_paths
            if "skip_paths" in g:
                skip_paths = merge_str_list(skip_paths, child.secret_leak.skip_paths)
            enabled = secret_leak.enabled
            if "enabled" in g:
                enabled = child.secret_leak.enabled
            secrets = secret_leak.secrets
            if "secrets" in g:
                secrets = merge_str_list(secrets, child.secret_leak.secrets)
            secret_leak = SecretLeakConfig(
                patterns=sl_patterns,
                skip_paths=skip_paths,
                enabled=enabled,
                secrets=secrets,
            )

        # Patch integrity guard
        patch_integrity = self.guards.patch_integrity
        if patch_integrity is None:
            patch_integrity = child.patch_integrity
        elif child.patch_integrity is not None:
            g = guard_raw("patch_integrity")
            max_additions = patch_integrity.max_additions
            if "max_additions" in g:
                max_additions = child.patch_integrity.max_additions
            max_deletions = patch_integrity.max_deletions
            if "max_deletions" in g:
                max_deletions = child.patch_integrity.max_deletions
            require_balance = patch_integrity.require_balance
            if "require_balance" in g:
                require_balance = child.patch_integrity.require_balance
            max_imbalance_ratio = patch_integrity.max_imbalance_ratio
            if "max_imbalance_ratio" in g:
                max_imbalance_ratio = child.patch_integrity.max_imbalance_ratio
            forbidden_patterns = patch_integrity.forbidden_patterns
            if "forbidden_patterns" in g:
                forbidden_patterns = merge_str_list(
                    forbidden_patterns, child.patch_integrity.forbidden_patterns
                )
            patch_integrity = PatchIntegrityConfig(
                max_additions=max_additions,
                max_deletions=max_deletions,
                require_balance=require_balance,
                max_imbalance_ratio=max_imbalance_ratio,
                forbidden_patterns=forbidden_patterns,
            )

        # MCP tool guard
        mcp_tool = self.guards.mcp_tool
        if mcp_tool is None:
            mcp_tool = child.mcp_tool
        elif child.mcp_tool is not None:
            g = guard_raw("mcp_tool")
            allow = mcp_tool.allow
            if "allow" in g:
                allow = merge_str_list(allow, child.mcp_tool.allow)
            block = mcp_tool.block
            if "block" in g:
                block = merge_str_list(block, child.mcp_tool.block)
            require_confirmation = mcp_tool.require_confirmation
            if "require_confirmation" in g:
                require_confirmation = merge_str_list(
                    require_confirmation, child.mcp_tool.require_confirmation
                )
            default_action = mcp_tool.default_action
            if "default_action" in g:
                default_action = child.mcp_tool.default_action
            max_args_size = mcp_tool.max_args_size
            if "max_args_size" in g:
                max_args_size = child.mcp_tool.max_args_size
            additional_allow = mcp_tool.additional_allow
            if "additional_allow" in g:
                additional_allow = merge_str_list(
                    additional_allow, child.mcp_tool.additional_allow
                )
            remove_allow = mcp_tool.remove_allow
            if "remove_allow" in g:
                remove_allow = merge_str_list(remove_allow, child.mcp_tool.remove_allow)
            additional_block = mcp_tool.additional_block
            if "additional_block" in g:
                additional_block = merge_str_list(
                    additional_block, child.mcp_tool.additional_block
                )
            remove_block = mcp_tool.remove_block
            if "remove_block" in g:
                remove_block = merge_str_list(remove_block, child.mcp_tool.remove_block)
            enabled = mcp_tool.enabled
            if "enabled" in g:
                enabled = child.mcp_tool.enabled
            mcp_tool = McpToolConfig(
                allow=allow,
                block=block,
                require_confirmation=require_confirmation,
                default_action=default_action,
                max_args_size=max_args_size,
                additional_allow=additional_allow,
                remove_allow=remove_allow,
                additional_block=additional_block,
                remove_block=remove_block,
                enabled=enabled,
            )

        # Prompt injection guard
        prompt_injection = self.guards.prompt_injection
        if prompt_injection is None:
            prompt_injection = child.prompt_injection
        elif child.prompt_injection is not None:
            g = guard_raw("prompt_injection")
            enabled = prompt_injection.enabled
            if "enabled" in g:
                enabled = child.prompt_injection.enabled
            warn_at_or_above = prompt_injection.warn_at_or_above
            if "warn_at_or_above" in g:
                warn_at_or_above = child.prompt_injection.warn_at_or_above
            block_at_or_above = prompt_injection.block_at_or_above
            if "block_at_or_above" in g:
                block_at_or_above = child.prompt_injection.block_at_or_above
            max_scan_bytes = prompt_injection.max_scan_bytes
            if "max_scan_bytes" in g:
                max_scan_bytes = child.prompt_injection.max_scan_bytes
            prompt_injection = PromptInjectionConfig(
                enabled=enabled,
                warn_at_or_above=warn_at_or_above,
                block_at_or_above=block_at_or_above,
                max_scan_bytes=max_scan_bytes,
            )

        # Jailbreak detection guard
        jailbreak = self.guards.jailbreak
        if jailbreak is None:
            jailbreak = child.jailbreak
        elif child.jailbreak is not None:
            g = guard_raw("jailbreak")
            enabled = jailbreak.enabled
            if "enabled" in g:
                enabled = child.jailbreak.enabled
            block_threshold = jailbreak.block_threshold
            if "block_threshold" in g:
                block_threshold = child.jailbreak.block_threshold
            warn_threshold = jailbreak.warn_threshold
            if "warn_threshold" in g:
                warn_threshold = child.jailbreak.warn_threshold
            max_input_bytes = jailbreak.max_input_bytes
            if "max_input_bytes" in g:
                max_input_bytes = child.jailbreak.max_input_bytes
            session_aggregation = jailbreak.session_aggregation
            if "session_aggregation" in g:
                session_aggregation = child.jailbreak.session_aggregation
            jailbreak = JailbreakConfig(
                enabled=enabled,
                block_threshold=block_threshold,
                warn_threshold=warn_threshold,
                max_input_bytes=max_input_bytes,
                session_aggregation=session_aggregation,
            )

        return GuardConfigs(
            forbidden_path=forbidden_path,
            egress_allowlist=egress_allowlist,
            secret_leak=secret_leak,
            patch_integrity=patch_integrity,
            mcp_tool=mcp_tool,
            prompt_injection=prompt_injection,
            jailbreak=jailbreak,
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

        result: str = yaml.dump(data, default_flow_style=False, sort_keys=False)
        return result


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
                try:
                    result = guard.check(action, context)
                except Exception as e:
                    result = GuardResult.block(
                        guard=guard.name,
                        severity=Severity.CRITICAL,
                        message=f"Guard evaluation error (fail-closed): {e}",
                    )
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
