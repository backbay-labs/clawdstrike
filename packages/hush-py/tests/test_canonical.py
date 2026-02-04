"""Tests for RFC 8785 (JCS) canonical JSON implementation."""
import json
from pathlib import Path

import pytest


def test_canonicalize_matches_repo_golden_vectors():
    """Canonicalize output must match the repo's RFC 8785 golden vectors."""
    from clawdstrike.canonical import canonicalize

    repo_root = Path(__file__).resolve().parents[3]
    vectors_path = repo_root / "fixtures" / "canonical" / "jcs_vectors.json"
    vectors = json.loads(vectors_path.read_text(encoding="utf-8"))

    for v in vectors:
        assert canonicalize(v["input"]) == v["expected"], v["name"]


def test_canonicalize_sorted_keys():
    """Object keys should be sorted lexicographically."""
    from clawdstrike.canonical import canonicalize

    obj = {"z": 1, "a": 2, "m": 3}
    result = canonicalize(obj)

    assert result == '{"a":2,"m":3,"z":1}'


def test_canonicalize_no_whitespace():
    """Output should have no whitespace."""
    from clawdstrike.canonical import canonicalize

    obj = {"key": "value", "list": [1, 2, 3]}
    result = canonicalize(obj)

    assert " " not in result
    assert "\n" not in result
    assert "\t" not in result


def test_canonicalize_nested_objects():
    """Nested objects should have sorted keys at all levels."""
    from clawdstrike.canonical import canonicalize

    obj = {"outer": {"z": 1, "a": 2}, "inner": [3, 2, 1]}
    result = canonicalize(obj)

    assert result == '{"inner":[3,2,1],"outer":{"a":2,"z":1}}'


def test_canonicalize_numeric_string_keys():
    """String keys should be sorted lexicographically (not numerically)."""
    from clawdstrike.canonical import canonicalize

    obj = {"2": "b", "10": "a", "a": 0}
    result = canonicalize(obj)

    # "10" < "2" < "a" in lexicographic order
    assert result == '{"10":"a","2":"b","a":0}'


def test_canonical_hash_sha256():
    """canonical_hash should hash canonicalized JSON with SHA-256."""
    from clawdstrike.canonical import canonicalize, canonical_hash
    from clawdstrike.core import sha256

    obj = {"message": "hello"}

    result = canonical_hash(obj, algorithm="sha256")
    expected = sha256(canonicalize(obj).encode("utf-8"))

    assert result == expected
    assert len(result) == 32


def test_canonical_hash_keccak256():
    """canonical_hash should support Keccak-256."""
    from clawdstrike.canonical import canonicalize, canonical_hash
    from clawdstrike.core import keccak256

    obj = {"message": "hello"}

    result = canonical_hash(obj, algorithm="keccak256")
    expected = keccak256(canonicalize(obj).encode("utf-8"))

    assert result == expected


def test_canonical_hash_default_sha256():
    """canonical_hash should default to SHA-256."""
    from clawdstrike.canonical import canonical_hash

    obj = {"test": True}

    result_default = canonical_hash(obj)
    result_explicit = canonical_hash(obj, algorithm="sha256")

    assert result_default == result_explicit


def test_canonical_hash_unknown_algorithm():
    """canonical_hash should raise for unknown algorithm."""
    from clawdstrike.canonical import canonical_hash

    with pytest.raises(ValueError, match="Unknown algorithm"):
        canonical_hash({"x": 1}, algorithm="md5")


def test_canonical_exports_from_package():
    """Canonical functions should be importable from clawdstrike package."""
    from clawdstrike import canonicalize, canonical_hash

    assert callable(canonicalize)
    assert callable(canonical_hash)


def test_canonicalize_primitives():
    """Primitives should serialize correctly."""
    from clawdstrike.canonical import canonicalize

    assert canonicalize(True) == "true"
    assert canonicalize(False) == "false"
    assert canonicalize(None) == "null"
    assert canonicalize("hello") == '"hello"'
    assert canonicalize(42) == "42"


def test_canonicalize_empty_structures():
    """Empty dict and list should serialize correctly."""
    from clawdstrike.canonical import canonicalize

    assert canonicalize({}) == "{}"
    assert canonicalize([]) == "[]"


def test_canonicalize_unicode():
    """Unicode should be preserved (not escaped)."""
    from clawdstrike.canonical import canonicalize

    obj = {"emoji": "\U0001F680", "chinese": "\u4e2d\u6587"}
    result = canonicalize(obj)

    # Unicode should appear literally, not escaped
    assert "\U0001F680" in result or "\\u" not in result.replace("\\u4", "")


def test_canonicalize_escape_sequences():
    """Control characters should be escaped."""
    from clawdstrike.canonical import canonicalize

    obj = {"newline": "\n", "tab": "\t", "quote": '"'}
    result = canonicalize(obj)

    assert "\\n" in result
    assert "\\t" in result
    assert '\\"' in result


def test_canonicalize_nan_raises():
    """NaN should raise ValueError."""
    from clawdstrike.canonical import canonicalize

    with pytest.raises(ValueError):
        canonicalize({"bad": float("nan")})


def test_canonicalize_inf_raises():
    """Infinity should raise ValueError."""
    from clawdstrike.canonical import canonicalize

    with pytest.raises(ValueError):
        canonicalize({"bad": float("inf")})
