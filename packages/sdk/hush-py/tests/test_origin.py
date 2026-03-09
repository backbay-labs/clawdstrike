"""Tests for origin type helpers."""

import pytest

from clawdstrike.origin import (
    OriginContext,
    normalize_origin_dict,
    normalize_origin_input,
)


def test_origin_context_accepts_camel_case_aliases() -> None:
    origin = OriginContext.from_dict({
        "provider": "slack",
        "tenantId": "T123",
        "spaceId": "C456",
        "spaceType": "channel",
        "threadId": "thread-1",
        "actorId": "U789",
        "actorType": "user",
        "actorRole": "incident_commander",
        "visibility": "internal",
        "externalParticipants": False,
        "tags": ["prod", "sev1"],
        "sensitivity": "restricted",
        "provenanceConfidence": "strong",
        "metadata": {"source": "slash-command"},
    })

    assert origin.tenant_id == "T123"
    assert origin.space_id == "C456"
    assert origin.actor_role == "incident_commander"
    assert origin.external_participants is False
    assert origin.provenance_confidence == "strong"
    assert origin.metadata == {"source": "slash-command"}


def test_origin_context_roundtrip_uses_snake_case() -> None:
    origin = OriginContext.from_dict({
        "provider": "slack",
        "tenantId": "T123",
        "spaceId": "C456",
        "externalParticipants": True,
        "tags": ["customer"],
        "metadata": {"source": "bot"},
    })

    origin_dict = origin.to_dict()

    assert origin_dict == {
        "provider": "slack",
        "tenant_id": "T123",
        "space_id": "C456",
        "external_participants": True,
        "tags": ["customer"],
        "metadata": {"source": "bot"},
    }
    assert list(origin_dict) == [
        "provider",
        "tenant_id",
        "space_id",
        "external_participants",
        "tags",
        "metadata",
    ]


def test_normalize_origin_input_preserves_context_instances() -> None:
    origin = OriginContext(provider="github", actor_role="reviewer")

    assert normalize_origin_input(origin) is origin


def test_normalize_origin_dict_rejects_duplicate_aliases() -> None:
    with pytest.raises(ValueError, match="Duplicate origin field: tenant_id"):
        normalize_origin_dict({
            "tenant_id": "T123",
            "tenantId": "T456",
        })


def test_origin_context_requires_provider() -> None:
    with pytest.raises(TypeError, match="origin.provider must be a non-empty string"):
        OriginContext.from_dict({"spaceId": "C456"})


def test_origin_context_direct_init_validates_optional_fields() -> None:
    with pytest.raises(TypeError, match="origin.external_participants must be a bool"):
        OriginContext(provider="slack", external_participants="yes")  # type: ignore[arg-type]


def test_origin_context_direct_init_clones_mutable_fields() -> None:
    tags = ["pager"]
    metadata = {"source": "slash-command", "nested": {"thread": "abc"}}
    origin = OriginContext(provider="slack", tags=tags, metadata=metadata)

    tags.append("external")
    metadata["source"] = "mutated"
    metadata["nested"]["thread"] = "mutated"

    assert origin.to_dict()["tags"] == ["pager"]
    assert origin.to_dict()["metadata"] == {
        "source": "slash-command",
        "nested": {"thread": "abc"},
    }

    serialized = origin.to_dict()
    serialized["metadata"]["source"] = "serialized"
    serialized["metadata"]["nested"]["thread"] = "serialized"

    assert origin.to_dict()["metadata"] == {
        "source": "slash-command",
        "nested": {"thread": "abc"},
    }


def test_origin_context_rejects_non_json_serializable_metadata() -> None:
    with pytest.raises(TypeError, match="origin.metadata must be JSON-serializable"):
        OriginContext(provider="slack", metadata={"bad": object()})


def test_origin_context_rejects_invalid_provenance_confidence() -> None:
    with pytest.raises(ValueError, match="origin.provenance_confidence must be one of"):
        OriginContext.from_dict({
            "provider": "slack",
            "provenanceConfidence": "definitely",
        })
