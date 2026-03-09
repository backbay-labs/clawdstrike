"""Origin context types and helpers for origin-aware policy enforcement."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, TypeAlias, cast

_FIELD_ALIASES: dict[str, str] = {
    "tenantId": "tenant_id",
    "spaceId": "space_id",
    "spaceType": "space_type",
    "threadId": "thread_id",
    "actorId": "actor_id",
    "actorType": "actor_type",
    "actorRole": "actor_role",
    "externalParticipants": "external_participants",
    "provenanceConfidence": "provenance_confidence",
}

_CANONICAL_FIELD_ORDER = (
    "provider",
    "tenant_id",
    "space_id",
    "space_type",
    "thread_id",
    "actor_id",
    "actor_type",
    "actor_role",
    "visibility",
    "external_participants",
    "tags",
    "sensitivity",
    "provenance_confidence",
    "metadata",
)
_CANONICAL_FIELDS = set(_CANONICAL_FIELD_ORDER)
_PROVENANCE_CONFIDENCE_VALUES = frozenset(("strong", "medium", "weak", "unknown"))

ProvenanceConfidence: TypeAlias = Literal["strong", "medium", "weak", "unknown"]


def _clone_json_value(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _coerce_required_str(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError(f"origin.{field_name} must be a non-empty string")
    return value


def _coerce_optional_str(value: Any, *, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"origin.{field_name} must be a string")
    return value


def _coerce_optional_bool(value: Any, *, field_name: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise TypeError(f"origin.{field_name} must be a bool")
    return value


def _coerce_optional_tags(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise TypeError("origin.tags must be a list of strings")
    tags: list[str] = []
    for tag in value:
        if not isinstance(tag, str):
            raise TypeError("origin.tags must be a list of strings")
        tags.append(tag)
    return tags


def _coerce_optional_provenance_confidence(value: Any) -> ProvenanceConfidence | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("origin.provenance_confidence must be a string")
    if value not in _PROVENANCE_CONFIDENCE_VALUES:
        raise ValueError(
            "origin.provenance_confidence must be one of: "
            + ", ".join(sorted(_PROVENANCE_CONFIDENCE_VALUES))
        )
    return cast(ProvenanceConfidence, value)


def _coerce_optional_metadata(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise TypeError("origin.metadata must be a mapping")
    metadata: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise TypeError("origin.metadata keys must be strings")
        metadata[key] = item
    try:
        cloned = _clone_json_value(metadata)
    except TypeError as exc:
        raise TypeError("origin.metadata must be JSON-serializable") from exc
    if not isinstance(cloned, dict):
        raise TypeError("origin.metadata must be a mapping")
    return cast(dict[str, Any], cloned)


def normalize_origin_dict(data: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize an origin mapping to the canonical snake_case wire shape."""

    normalized: dict[str, Any] = {}
    for key, value in data.items():
        if not isinstance(key, str):
            raise TypeError("origin field names must be strings")
        canonical_key = _FIELD_ALIASES.get(key, key)
        if canonical_key not in _CANONICAL_FIELDS:
            raise ValueError(f"Unknown origin field: {key}")
        if canonical_key in normalized:
            raise ValueError(f"Duplicate origin field: {canonical_key}")
        normalized[canonical_key] = value
    return normalized


@dataclass(frozen=True)
class OriginContext:
    """Canonical origin context used by origin-aware policies."""

    provider: str
    tenant_id: str | None = None
    space_id: str | None = None
    space_type: str | None = None
    thread_id: str | None = None
    actor_id: str | None = None
    actor_type: str | None = None
    actor_role: str | None = None
    visibility: str | None = None
    external_participants: bool | None = None
    tags: list[str] | None = None
    sensitivity: str | None = None
    provenance_confidence: ProvenanceConfidence | None = None
    metadata: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "provider",
            _coerce_required_str(self.provider, field_name="provider"),
        )
        object.__setattr__(
            self,
            "tenant_id",
            _coerce_optional_str(self.tenant_id, field_name="tenant_id"),
        )
        object.__setattr__(
            self,
            "space_id",
            _coerce_optional_str(self.space_id, field_name="space_id"),
        )
        object.__setattr__(
            self,
            "space_type",
            _coerce_optional_str(self.space_type, field_name="space_type"),
        )
        object.__setattr__(
            self,
            "thread_id",
            _coerce_optional_str(self.thread_id, field_name="thread_id"),
        )
        object.__setattr__(
            self,
            "actor_id",
            _coerce_optional_str(self.actor_id, field_name="actor_id"),
        )
        object.__setattr__(
            self,
            "actor_type",
            _coerce_optional_str(self.actor_type, field_name="actor_type"),
        )
        object.__setattr__(
            self,
            "actor_role",
            _coerce_optional_str(self.actor_role, field_name="actor_role"),
        )
        object.__setattr__(
            self,
            "visibility",
            _coerce_optional_str(self.visibility, field_name="visibility"),
        )
        object.__setattr__(
            self,
            "external_participants",
            _coerce_optional_bool(
                self.external_participants,
                field_name="external_participants",
            ),
        )
        tags = _coerce_optional_tags(self.tags)
        object.__setattr__(self, "tags", list(tags) if tags is not None else None)
        object.__setattr__(
            self,
            "sensitivity",
            _coerce_optional_str(self.sensitivity, field_name="sensitivity"),
        )
        object.__setattr__(
            self,
            "provenance_confidence",
            _coerce_optional_provenance_confidence(self.provenance_confidence),
        )
        metadata = _coerce_optional_metadata(self.metadata)
        object.__setattr__(self, "metadata", metadata)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> OriginContext:
        """Create an OriginContext from canonical or camelCase field names."""

        normalized = dict(normalize_origin_dict(data))
        normalized.setdefault("provider", None)
        return cls(**cast(dict[str, Any], normalized))

    def to_dict(self) -> dict[str, Any]:
        """Serialize the origin context using canonical snake_case keys."""

        result: dict[str, Any] = {}
        for key in _CANONICAL_FIELD_ORDER:
            value = getattr(self, key)
            if value is not None:
                if key == "tags":
                    result[key] = list(value)
                elif key == "metadata":
                    result[key] = _clone_json_value(value)
                else:
                    result[key] = value
        return result


def normalize_origin_input(
    origin: OriginContext | Mapping[str, Any] | None,
) -> OriginContext | None:
    """Convert mapping input to OriginContext and preserve canonical instances."""

    if origin is None or isinstance(origin, OriginContext):
        return origin
    return OriginContext.from_dict(origin)


__all__ = [
    "OriginContext",
    "ProvenanceConfidence",
    "normalize_origin_dict",
    "normalize_origin_input",
]
