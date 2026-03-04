"""Policy loading and evaluation.

Provides Policy loading from YAML and PolicyEngine for running guards.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum as _Enum
from pathlib import Path
from typing import Any

import yaml

from clawdstrike._version import parse_semver_strict
from clawdstrike.exceptions import PolicyError
from clawdstrike.guards.base import Action, Guard, GuardContext, GuardResult, Severity
from clawdstrike.guards.egress_allowlist import EgressAllowlistConfig, EgressAllowlistGuard
from clawdstrike.guards.forbidden_path import ForbiddenPathConfig, ForbiddenPathGuard
from clawdstrike.guards.jailbreak import JailbreakConfig, JailbreakGuard
from clawdstrike.guards.mcp_tool import McpToolConfig, McpToolGuard
from clawdstrike.guards.patch_integrity import PatchIntegrityConfig, PatchIntegrityGuard
from clawdstrike.guards.path_allowlist import PathAllowlistConfig, PathAllowlistGuard
from clawdstrike.guards.prompt_injection import (
    PromptInjectionConfig,
    PromptInjectionGuard,
)
from clawdstrike.guards.secret_leak import SecretLeakConfig, SecretLeakGuard, SecretPattern
from clawdstrike.guards.shell_command import ShellCommandConfig, ShellCommandGuard
from clawdstrike.guards.spider_sense import SpiderSenseConfig, SpiderSenseGuard

POLICY_SCHEMA_VERSION = "1.2.0"
POLICY_SUPPORTED_VERSIONS = {"1.1.0", "1.2.0", "1.3.0"}

# Built-in ruleset directory.
# Try package-relative path first (works in both monorepo and installed layouts),
# then fall back to importlib.resources for installed packages.
def _find_rulesets_dir() -> Path:
    # Try importlib.resources first (pip-installed packages)
    try:
        import importlib.resources as _res
        ref = _res.files("clawdstrike") / "rulesets"
        p = Path(str(ref))
        if p.is_dir():
            return p
    except Exception:
        pass  # importlib.resources not available; fall back to monorepo path
    # Fallback: monorepo relative path (dev layout)
    pkg_relative = Path(__file__).resolve().parent / "../../../../../rulesets"
    if pkg_relative.is_dir():
        return pkg_relative.resolve()
    # Last resort
    return pkg_relative.resolve()


_RULESETS_DIR = _find_rulesets_dir()

MAX_EXTENDS_DEPTH = 32


def _validate_policy_version(version: str) -> None:
    if parse_semver_strict(version) is None:
        raise PolicyError(f"Invalid policy version: {version!r} (expected X.Y.Z)")
    if version not in POLICY_SUPPORTED_VERSIONS:
        supported = ", ".join(sorted(POLICY_SUPPORTED_VERSIONS))
        raise PolicyError(
            f"Unsupported policy version: {version!r} (supported: {supported})"
        )


def _require_mapping(value: Any, *, path: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyError(f"Expected mapping for {path}, got {type(value).__name__}")
    return value


def _reject_unknown_keys(data: dict[str, Any], allowed: set[str], *, path: str) -> None:
    unknown = set(data.keys()) - allowed
    if unknown:
        unknown_str = ", ".join(sorted(unknown))
        raise PolicyError(f"Unknown {path} field(s): {unknown_str}")


def _parse_extends(value: Any, *, path: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        if not value.strip():
            raise PolicyError(f"{path} must be a non-empty string")
        return [value]
    if isinstance(value, list):
        refs: list[str] = []
        for i, ref in enumerate(value):
            if not isinstance(ref, str) or not ref.strip():
                raise PolicyError(f"{path}[{i}] must be a non-empty string")
            refs.append(ref)
        return refs
    raise PolicyError(f"Expected string or list for {path}, got {type(value).__name__}")


class _MergeMode(_Enum):
    OVERRIDE = "override"
    MERGE_LIST = "merge_list"
    MERGE_PATTERNS = "merge_patterns"


_GUARD_MERGE_SPECS: dict[str, dict[str, _MergeMode]] = {
    "forbidden_path": {
        "patterns": _MergeMode.MERGE_LIST,
        "exceptions": _MergeMode.MERGE_LIST,
    },
    "egress_allowlist": {
        "allow": _MergeMode.MERGE_LIST,
        "block": _MergeMode.MERGE_LIST,
        "default_action": _MergeMode.OVERRIDE,
    },
    "secret_leak": {
        "patterns": _MergeMode.MERGE_PATTERNS,
        "skip_paths": _MergeMode.MERGE_LIST,
        "enabled": _MergeMode.OVERRIDE,
        "secrets": _MergeMode.MERGE_LIST,
    },
    "patch_integrity": {
        "max_additions": _MergeMode.OVERRIDE,
        "max_deletions": _MergeMode.OVERRIDE,
        "require_balance": _MergeMode.OVERRIDE,
        "max_imbalance_ratio": _MergeMode.OVERRIDE,
        "forbidden_patterns": _MergeMode.MERGE_LIST,
    },
    "mcp_tool": {
        "allow": _MergeMode.MERGE_LIST,
        "block": _MergeMode.MERGE_LIST,
        "require_confirmation": _MergeMode.MERGE_LIST,
        "default_action": _MergeMode.OVERRIDE,
        "max_args_size": _MergeMode.OVERRIDE,
        "additional_allow": _MergeMode.MERGE_LIST,
        "remove_allow": _MergeMode.MERGE_LIST,
        "additional_block": _MergeMode.MERGE_LIST,
        "remove_block": _MergeMode.MERGE_LIST,
        "enabled": _MergeMode.OVERRIDE,
    },
    "prompt_injection": {
        "enabled": _MergeMode.OVERRIDE,
        "warn_at_or_above": _MergeMode.OVERRIDE,
        "block_at_or_above": _MergeMode.OVERRIDE,
        "max_scan_bytes": _MergeMode.OVERRIDE,
    },
    "jailbreak": {
        "enabled": _MergeMode.OVERRIDE,
        "block_threshold": _MergeMode.OVERRIDE,
        "warn_threshold": _MergeMode.OVERRIDE,
        "max_input_bytes": _MergeMode.OVERRIDE,
        "session_aggregation": _MergeMode.OVERRIDE,
    },
    "shell_command": {
        "blocked_patterns": _MergeMode.MERGE_LIST,
        "additional_blocked": _MergeMode.MERGE_LIST,
        "allowed_commands": _MergeMode.MERGE_LIST,
        "enabled": _MergeMode.OVERRIDE,
    },
    "path_allowlist": {
        "allowed_paths": _MergeMode.MERGE_LIST,
        "enabled": _MergeMode.OVERRIDE,
    },
    "spider_sense": {
        "enabled": _MergeMode.OVERRIDE,
        "similarity_threshold": _MergeMode.OVERRIDE,
        "ambiguity_band": _MergeMode.OVERRIDE,
        "top_k": _MergeMode.OVERRIDE,
        "patterns": _MergeMode.OVERRIDE,
        "embedding_api_url": _MergeMode.OVERRIDE,
        "embedding_api_key": _MergeMode.OVERRIDE,
        "embedding_model": _MergeMode.OVERRIDE,
        "pattern_db_path": _MergeMode.OVERRIDE,
        "pattern_db_version": _MergeMode.OVERRIDE,
        "pattern_db_checksum": _MergeMode.OVERRIDE,
        "pattern_db_signature": _MergeMode.OVERRIDE,
        "pattern_db_signature_key_id": _MergeMode.OVERRIDE,
        "pattern_db_public_key": _MergeMode.OVERRIDE,
        "pattern_db_trust_store_path": _MergeMode.OVERRIDE,
        "pattern_db_trusted_keys": _MergeMode.OVERRIDE,
        "pattern_db_manifest_path": _MergeMode.OVERRIDE,
        "pattern_db_manifest_trust_store_path": _MergeMode.OVERRIDE,
        "pattern_db_manifest_trusted_keys": _MergeMode.OVERRIDE,
        "llm_api_url": _MergeMode.OVERRIDE,
        "llm_api_key": _MergeMode.OVERRIDE,
        "llm_model": _MergeMode.OVERRIDE,
        "llm_prompt_template_id": _MergeMode.OVERRIDE,
        "llm_prompt_template_version": _MergeMode.OVERRIDE,
        "llm_timeout_ms": _MergeMode.OVERRIDE,
        "llm_fail_mode": _MergeMode.OVERRIDE,
        "async_config": _MergeMode.OVERRIDE,
        "embedding_timeout_secs": _MergeMode.OVERRIDE,
    },
}


def _merge_str_list(base_list: list[str], child_list: list[str]) -> list[str]:
    out = list(base_list)
    for item in child_list:
        if item not in out:
            out.append(item)
    return out


def _merge_secret_patterns(
    base: list[SecretPattern],
    child: list[SecretPattern],
) -> list[SecretPattern]:
    out = list(base)
    idx_by_name = {sp.name: i for i, sp in enumerate(out)}
    for sp in child:
        i = idx_by_name.get(sp.name)
        if i is None:
            idx_by_name[sp.name] = len(out)
            out.append(sp)
        else:
            out[i] = sp
    return out


class PolicyResolver:
    """Resolves policy extends references to YAML content."""

    def resolve(
        self, reference: str, from_path: Path | None = None,
    ) -> tuple[str, str, Path | None]:
        """Resolve a reference to (yaml_content, canonical_key, location_path).

        Supports:
        - Built-in rulesets: 'clawdstrike:strict', 'strict', etc.
        - Local file paths (relative to from_path)
        """
        # Try built-in rulesets
        if reference.startswith("clawdstrike:"):
            ruleset_id = reference.removeprefix("clawdstrike:")
        else:
            ruleset_id = reference
        builtin_names = {
            "default", "strict", "ai-agent", "ai-agent-posture", "cicd", "permissive", "spider-sense",
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

        raise PolicyError(f"Unknown ruleset or file not found: {reference}")


_DEFAULT_RESOLVER = PolicyResolver()


@dataclass
class PostureState:
    """A single posture state."""

    description: str = ""
    capabilities: list[str] = field(default_factory=list)
    budgets: dict[str, int] = field(default_factory=dict)


@dataclass
class PostureTransition:
    """A posture transition rule."""

    from_state: str = ""
    to_state: str = ""
    on: str = ""
    after: str | None = None


@dataclass
class PostureConfig:
    """Posture configuration."""

    initial: str = ""
    states: dict[str, PostureState] = field(default_factory=dict)
    transitions: list[PostureTransition] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PostureConfig:
        states: dict[str, PostureState] = {}
        for name, state_data in data.get("states", {}).items():
            if not isinstance(state_data, dict):
                continue
            states[name] = PostureState(
                description=str(state_data.get("description", "")),
                capabilities=list(state_data.get("capabilities", [])),
                budgets=dict(state_data.get("budgets", {})),
            )

        transitions: list[PostureTransition] = []
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
            raise PolicyError(
                f"Posture initial state {initial!r} not found in states: {sorted(states.keys())}"
            )

        for t in transitions:
            if states:
                if t.from_state and t.from_state not in states:
                    raise PolicyError(
                        f"Posture transition references unknown from_state {t.from_state!r}"
                    )
                if t.to_state and t.to_state not in states:
                    raise PolicyError(
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

    forbidden_path: ForbiddenPathConfig | None = None
    egress_allowlist: EgressAllowlistConfig | None = None
    secret_leak: SecretLeakConfig | None = None
    patch_integrity: PatchIntegrityConfig | None = None
    mcp_tool: McpToolConfig | None = None
    prompt_injection: PromptInjectionConfig | None = None
    jailbreak: JailbreakConfig | None = None
    shell_command: ShellCommandConfig | None = None
    path_allowlist: PathAllowlistConfig | None = None
    spider_sense: SpiderSenseConfig | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardConfigs:
        """Create from dictionary."""
        allowed = {
            "forbidden_path",
            "egress_allowlist",
            "secret_leak",
            "patch_integrity",
            "mcp_tool",
            "prompt_injection",
            "jailbreak",
            "shell_command",
            "path_allowlist",
            "spider_sense",
        }
        _reject_unknown_keys(data, allowed, path="guards")

        def parse_guard_config(
            config_type: Any, value: Any, *, path: str
        ) -> Any | None:
            if value is None:
                return None
            if not isinstance(value, dict):
                raise PolicyError(
                    f"Expected mapping for {path}, got {type(value).__name__}"
                )
            try:
                return config_type(**value)
            except TypeError as e:
                raise PolicyError(f"Invalid {path} config: {e}") from e

        # Special handling for secret_leak: convert pattern dicts to SecretPattern objects
        secret_leak_data = data.get("secret_leak")
        secret_leak_config = None
        if secret_leak_data is not None:
            if not isinstance(secret_leak_data, dict):
                got = type(secret_leak_data).__name__
                raise PolicyError(
                    f"Expected mapping for guards.secret_leak, got {got}"
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
                raise PolicyError(
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
                raise PolicyError(
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

        spider_data = data.get("spider_sense")
        spider_config = None
        if spider_data is not None:
            if isinstance(spider_data, bool):
                raise PolicyError(
                    "Expected mapping for guards.spider_sense; "
                    "use guards.spider_sense.enabled: false to disable"
                )
            elif isinstance(spider_data, dict):
                spider_kwargs = dict(spider_data)
                async_value = spider_kwargs.pop("async", None)
                if async_value is not None and not isinstance(async_value, dict):
                    got = type(async_value).__name__
                    raise PolicyError(
                        f"Expected mapping for guards.spider_sense.async, got {got}"
                    )
                if async_value is not None:
                    spider_kwargs["async_config"] = async_value
                try:
                    spider_config = SpiderSenseConfig(**spider_kwargs)
                except TypeError as e:
                    raise PolicyError(f"Invalid guards.spider_sense config: {e}") from e
            else:
                got = type(spider_data).__name__
                raise PolicyError(
                    f"Expected mapping for guards.spider_sense, got {got}"
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
            shell_command=parse_guard_config(
                ShellCommandConfig,
                data.get("shell_command"),
                path="guards.shell_command",
            ),
            path_allowlist=parse_guard_config(
                PathAllowlistConfig,
                data.get("path_allowlist"),
                path="guards.path_allowlist",
            ),
            spider_sense=spider_config,
        )


@dataclass
class Policy:
    """Complete policy configuration."""

    version: str = POLICY_SCHEMA_VERSION
    name: str = ""
    description: str = ""
    extends: str | list[str] | None = None
    merge_strategy: str = "deep_merge"
    guards: GuardConfigs = field(default_factory=GuardConfigs)
    settings: PolicySettings = field(default_factory=PolicySettings)
    posture: PostureConfig | None = None
    _raw_guards: dict[str, Any] = field(default_factory=dict, repr=False)
    _raw_settings: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_yaml(cls, yaml_str: str) -> Policy:
        """Parse from YAML string (no extends resolution)."""
        data = yaml.safe_load(yaml_str) or {}
        if not isinstance(data, dict):
            raise PolicyError("Policy YAML must be a mapping (YAML object)")

        _reject_unknown_keys(
            data,
            {"version", "name", "description", "extends", "merge_strategy",
             "guards", "settings", "posture", "custom_guards"},
            path="policy",
        )

        version = data.get("version", POLICY_SCHEMA_VERSION)
        if not isinstance(version, str):
            raise PolicyError("policy.version must be a string")
        _validate_policy_version(version)
        _parse_extends(data.get("extends"), path="policy.extends")

        guards_data = _require_mapping(data.get("guards"), path="policy.guards")
        settings_data = _require_mapping(data.get("settings"), path="policy.settings")

        posture = None
        posture_data = data.get("posture")
        if posture_data is not None:
            parsed_version = parse_semver_strict(version)
            if parsed_version is not None and parsed_version < (1, 2, 0):
                raise PolicyError("posture requires policy version 1.2.0")
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
    def from_yaml_file(cls, path: str | os.PathLike[str]) -> Policy:
        """Load from YAML file."""
        p = Path(path)
        with open(p) as f:
            return cls.from_yaml_with_extends(f.read(), base_path=str(p))

    @classmethod
    def from_yaml_with_extends(
        cls,
        yaml_str: str,
        base_path: str | None = None,
        resolver: PolicyResolver | None = None,
    ) -> Policy:
        """Parse from YAML string with extends resolution.

        If the policy has an 'extends' field, loads the base and merges.
        Detects circular dependencies.
        """
        if resolver is None:
            resolver = _DEFAULT_RESOLVER
        from_path = Path(base_path) if base_path else None
        return cls._resolve_extends(yaml_str, from_path, resolver, set(), {}, 0)

    @classmethod
    def from_yaml_file_with_extends(
        cls,
        path: str | os.PathLike[str],
        resolver: PolicyResolver | None = None,
    ) -> Policy:
        """Load from YAML file with extends resolution."""
        p = Path(path)
        with open(p) as f:
            yaml_str = f.read()
        return cls.from_yaml_with_extends(yaml_str, base_path=str(p), resolver=resolver)

    @classmethod
    def _resolve_extends(
        cls,
        yaml_str: str,
        from_path: Path | None,
        resolver: PolicyResolver,
        resolving: set[str],
        memo: dict[str, Policy],
        depth: int,
    ) -> Policy:
        if depth > MAX_EXTENDS_DEPTH:
            raise PolicyError(f"Policy extends depth exceeded (limit: {MAX_EXTENDS_DEPTH})")

        child = cls.from_yaml(yaml_str)
        refs = _parse_extends(child.extends, path="policy.extends")
        if not refs:
            return child

        merged_base: Policy | None = None
        for ref in refs:
            resolved_yaml, canonical_key, location = resolver.resolve(ref, from_path)

            if canonical_key in resolving:
                raise PolicyError(f"Circular policy extension detected: {ref}")

            if canonical_key in memo:
                parent = memo[canonical_key]
            else:
                resolving.add(canonical_key)
                try:
                    parent = cls._resolve_extends(
                        resolved_yaml,
                        location,
                        resolver,
                        resolving,
                        memo,
                        depth + 1,
                    )
                finally:
                    resolving.discard(canonical_key)
                memo[canonical_key] = parent

            merged_base = parent if merged_base is None else merged_base.merge(parent)

        if merged_base is None:
            return child
        return merged_base.merge(child)

    def merge(self, child: Policy) -> Policy:
        """Merge this (base) policy with a child policy.

        Child settings explicitly declared in YAML override base settings.
        Settings not declared in the child inherit from the base.
        """
        merged_settings_data: dict[str, Any] = {
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

    def _merge_guards(self, child: GuardConfigs, child_raw: dict[str, Any]) -> GuardConfigs:
        """Deep merge guard configs using data-driven merge specs.

        The child policy may omit fields, but guard dataclasses fill omitted fields with defaults.
        To avoid silently dropping inherited restrictions, consult the raw YAML mapping to detect
        which fields were explicitly specified by the child.
        """
        raw = child_raw or {}
        result_kwargs: dict[str, Any] = {}

        for guard_name in GuardConfigs.__dataclass_fields__:
            base_cfg = getattr(self.guards, guard_name)
            child_cfg = getattr(child, guard_name)
            guard_raw = raw.get(guard_name)

            if base_cfg is None:
                result_kwargs[guard_name] = child_cfg
                continue
            if child_cfg is None or not isinstance(guard_raw, dict):
                result_kwargs[guard_name] = base_cfg
                continue

            spec = _GUARD_MERGE_SPECS.get(guard_name, {})
            merged_fields: dict[str, Any] = {}

            for field_name in base_cfg.__dataclass_fields__:
                base_val = getattr(base_cfg, field_name)
                child_val = getattr(child_cfg, field_name)
                mode = spec.get(field_name, _MergeMode.OVERRIDE)
                raw_present = field_name in guard_raw
                if guard_name == "spider_sense" and field_name == "async_config":
                    raw_present = raw_present or "async" in guard_raw

                if not raw_present:
                    merged_fields[field_name] = base_val
                elif mode == _MergeMode.MERGE_LIST:
                    merged_fields[field_name] = _merge_str_list(base_val, child_val)
                elif mode == _MergeMode.MERGE_PATTERNS:
                    merged_fields[field_name] = _merge_secret_patterns(base_val, child_val)
                else:
                    merged_fields[field_name] = child_val

            result_kwargs[guard_name] = type(base_cfg)(**merged_fields)

        return GuardConfigs(**result_kwargs)

    def to_yaml(self) -> str:
        """Export to YAML string."""
        data: dict[str, Any] = {
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
        if self.guards.shell_command:
            data["guards"]["shell_command"] = {
                "blocked_patterns": self.guards.shell_command.blocked_patterns,
                "additional_blocked": self.guards.shell_command.additional_blocked,
                "allowed_commands": self.guards.shell_command.allowed_commands,
                "enabled": self.guards.shell_command.enabled,
            }
        if self.guards.path_allowlist:
            data["guards"]["path_allowlist"] = {
                "allowed_paths": self.guards.path_allowlist.allowed_paths,
                "enabled": self.guards.path_allowlist.enabled,
            }
        if self.guards.prompt_injection:
            data["guards"]["prompt_injection"] = {
                "enabled": self.guards.prompt_injection.enabled,
                "warn_at_or_above": self.guards.prompt_injection.warn_at_or_above,
                "block_at_or_above": self.guards.prompt_injection.block_at_or_above,
                "max_scan_bytes": self.guards.prompt_injection.max_scan_bytes,
            }
        if self.guards.jailbreak:
            data["guards"]["jailbreak"] = {
                "enabled": self.guards.jailbreak.enabled,
                "detector": {
                    "block_threshold": self.guards.jailbreak.block_threshold,
                    "warn_threshold": self.guards.jailbreak.warn_threshold,
                    "max_input_bytes": self.guards.jailbreak.max_input_bytes,
                    "session_aggregation": self.guards.jailbreak.session_aggregation,
                },
            }
        if self.guards.spider_sense:
            spider = self.guards.spider_sense
            spider_data: dict[str, Any] = {
                "enabled": spider.enabled,
                "similarity_threshold": spider.similarity_threshold,
                "ambiguity_band": spider.ambiguity_band,
                "top_k": spider.top_k,
            }
            if spider.patterns is not None:
                spider_data["patterns"] = spider.patterns
            if spider.embedding_api_url is not None:
                spider_data["embedding_api_url"] = spider.embedding_api_url
            if spider.embedding_api_key is not None:
                spider_data["embedding_api_key"] = spider.embedding_api_key
            if spider.embedding_model is not None:
                spider_data["embedding_model"] = spider.embedding_model
            if spider.pattern_db_path is not None:
                spider_data["pattern_db_path"] = spider.pattern_db_path
            if spider.pattern_db_version is not None:
                spider_data["pattern_db_version"] = spider.pattern_db_version
            if spider.pattern_db_checksum is not None:
                spider_data["pattern_db_checksum"] = spider.pattern_db_checksum
            if spider.pattern_db_signature is not None:
                spider_data["pattern_db_signature"] = spider.pattern_db_signature
            if spider.pattern_db_signature_key_id is not None:
                spider_data["pattern_db_signature_key_id"] = spider.pattern_db_signature_key_id
            if spider.pattern_db_public_key is not None:
                spider_data["pattern_db_public_key"] = spider.pattern_db_public_key
            if spider.pattern_db_trust_store_path is not None:
                spider_data["pattern_db_trust_store_path"] = spider.pattern_db_trust_store_path
            if spider.pattern_db_trusted_keys is not None:
                spider_data["pattern_db_trusted_keys"] = spider.pattern_db_trusted_keys
            if spider.pattern_db_manifest_path is not None:
                spider_data["pattern_db_manifest_path"] = spider.pattern_db_manifest_path
            if spider.pattern_db_manifest_trust_store_path is not None:
                spider_data["pattern_db_manifest_trust_store_path"] = spider.pattern_db_manifest_trust_store_path
            if spider.pattern_db_manifest_trusted_keys is not None:
                spider_data["pattern_db_manifest_trusted_keys"] = spider.pattern_db_manifest_trusted_keys
            if spider.llm_api_url is not None:
                spider_data["llm_api_url"] = spider.llm_api_url
            if spider.llm_api_key is not None:
                spider_data["llm_api_key"] = spider.llm_api_key
            if spider.llm_model is not None:
                spider_data["llm_model"] = spider.llm_model
            if spider.llm_prompt_template_id is not None:
                spider_data["llm_prompt_template_id"] = spider.llm_prompt_template_id
            if spider.llm_prompt_template_version is not None:
                spider_data["llm_prompt_template_version"] = spider.llm_prompt_template_version
            if spider.llm_timeout_ms is not None:
                spider_data["llm_timeout_ms"] = spider.llm_timeout_ms
            if spider.llm_fail_mode is not None:
                spider_data["llm_fail_mode"] = spider.llm_fail_mode
            if spider.async_config is not None:
                spider_data["async"] = spider.async_config
            data["guards"]["spider_sense"] = spider_data

        result: str = yaml.dump(data, default_flow_style=False, sort_keys=False)
        return result


class PolicyEngine:
    """Engine for evaluating actions against a policy."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.guards = self._create_guards()

    def _create_guards(self) -> list[Guard]:
        """Create guard instances from policy configuration."""
        guards: list[Guard] = []

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
        guards.append(
            ShellCommandGuard(self.policy.guards.shell_command)
            if self.policy.guards.shell_command
            else ShellCommandGuard()
        )
        guards.append(
            PathAllowlistGuard(self.policy.guards.path_allowlist)
            if self.policy.guards.path_allowlist
            else PathAllowlistGuard()
        )
        if self.policy.guards.spider_sense:
            guards.append(SpiderSenseGuard(self.policy.guards.spider_sense))

        return guards

    def check(self, action: Action, context: GuardContext) -> list[GuardResult]:
        """Check an action against all guards."""
        results: list[GuardResult] = []

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

    def is_allowed(self, action: Action, context: GuardContext) -> bool:
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
